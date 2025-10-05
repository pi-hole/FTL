/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "toml_reader.h"
#include "config/setupVars.h"
#include "log.h"
// getprio(), setprio()
#include <sys/resource.h>
// argv_dnsmasq
#include "args.h"
// INT_MAX
#include <limits.h>
#include "datastructure.h"
// openFTLtoml()
#include "config/toml_helper.h"
// delete_all_sessions()
#include "api/api.h"
// readEnvValue()
#include "config/env.h"

// Private prototypes
static bool parseTOML(toml_result_t *toml, const unsigned int version);
static void reportDebugFlags(void);

// Migrate dns.revServer -> dns.revServers[0]
static bool migrate_dns_revServer(toml_datum_t toml, struct config *newconf)
{
	bool restart = false;
	toml_datum_t dns = toml_table_find(toml, "dns");
	if(dns.type != TOML_UNKNOWN)
	{
		toml_datum_t revServer = toml_table_find(dns, "revServer");
		if(revServer.type != TOML_UNKNOWN)
		{
			// Read old config
			toml_datum_t active = toml_table_find(revServer, "active");
			toml_datum_t cidr = toml_table_find(revServer, "cidr");
			toml_datum_t target = toml_table_find(revServer, "target");
			toml_datum_t domain = toml_table_find(revServer, "domain");

			// Necessary condition: all values must exist and CIDR and target must not be empty
			if(active.type == TOML_BOOLEAN &&
			   cidr.type == TOML_STRING &&
			   target.type == TOML_STRING &&
			   strlen(cidr.u.s) > 0 &&
			   domain.type == TOML_STRING &&
			   strlen(target.u.s) > 0)
			{
				// Build comma-separated string of all values
				char *old = calloc((active.u.boolean ? 4 : 5) + strlen(cidr.u.s) + strlen(target.u.s) + strlen(domain.u.s) + 4, sizeof(char));
				if(old)
				{
					// Add to new config
					sprintf(old, "%s,%s,%s,%s", active.u.boolean ? "true" : "false", cidr.u.s, target.u.s, domain.u.s);
					log_debug(DEBUG_CONFIG, "Config setting dns.revServer MIGRATED to dns.revServers[0]: %s", old);
					cJSON_AddItemToArray(newconf->dns.revServers.v.json, cJSON_CreateString(old));
					restart = true;
				}
			}
			else
			{
				// Invalid config - ignored but logged in case
				// the user wants to know and restore it later
				// manually after fixing whatever the problem is
				log_warn("Config setting dns.revServer INVALID - ignoring: %s %s %s %s",
				         active.type == TOML_BOOLEAN ? active.u.boolean ? "true" : "false" : "NULL",
				         cidr.type == TOML_STRING ? cidr.u.s : "NULL",
				         target.type == TOML_STRING ? target.u.s : "NULL",
				         domain.type == TOML_STRING ? domain.u.s : "NULL");
			}
		}
		else
		{
			// Perfectly fine - it just means this old option does
			// not exist and, hence, does not need to be migrated
			log_debug(DEBUG_CONFIG, "dns.revServer does not exist - nothing to migrate");
		}
	}
	else
	{
		// This is actually a problem as the old config file
		// should always contain a "dns" section
		log_warn("dns config tab does not exist - config file corrupt or incomplete");
	}

	return restart;
}

// Migrate dns.domain -> dns.domain.name
static bool migrate_dns_domain(toml_datum_t toml, struct config *newconf)
{
	bool restart = false;
	toml_datum_t dns = toml_table_find(toml, "dns");
	if(dns.type != TOML_UNKNOWN)
	{
		toml_datum_t domain = toml_table_find(dns, "domain");
		if(domain.type == TOML_STRING && strlen(domain.u.s) > 0)
		{
			// Migrate to new config
			log_debug(DEBUG_CONFIG, "Config setting dns.domain MIGRATED to dns.domain.name: %s", domain.u.s);
			if(newconf->dns.domain.name.t == CONF_STRING_ALLOCATED && newconf->dns.domain.name.v.s != NULL)
				free(newconf->dns.domain.name.v.s);
			newconf->dns.domain.name.v.s = strdup(domain.u.s);
			newconf->dns.domain.name.t = CONF_STRING_ALLOCATED;
			restart = true;
		}
		else
		{
			// Perfectly fine - it just means this old option does
			// not exist and, hence, does not need to be migrated
			log_debug(DEBUG_CONFIG, "dns.domain does not exist - nothing to migrate");
		}
	}
	else
	{
		// This is actually a problem as the old config file
		// should always contain a "dns" section
		log_warn("dns config tab does not exist - config file corrupt or incomplete");
	}

	return restart;
}


// Migrate config from old to new, returns true if a restart is required to
// apply the changes
static bool migrate_config(toml_datum_t toml, struct config *newconf)
{
	bool restart = false;

	// Migrate dns.revServer -> dns.revServers[0]
	restart |= migrate_dns_revServer(toml, newconf);
	// Migrate dns.domain -> dns.domain.name
	restart |= migrate_dns_domain(toml, newconf);

	return restart;
}

bool readFTLtoml(struct config *oldconf, struct config *newconf,
                 toml_datum_t toml, const bool verbose, bool *restart,
                 const unsigned int version, const bool teleporter)
{
	// Parse lines in the config file if we did not receive a pointer to a TOML
	// table from an imported Teleporter file
	toml_result_t result = { 0 };
	if(!teleporter)
	{
		if(!parseTOML(&result, version))
		{
			log_err("Cannot parse TOML file: %s", result.errmsg);
			return false;
		}
		// Get top table
		toml = result.toptab;
	}

	// First, get an array of keys of config items that have been forced
	// through environment variables
	cJSON *env_vars = read_forced_vars(version);

	// Try to read debug config. This is done before the full config
	// parsing to allow for debug output further down
	// First try to read env variable, if this fails, read TOML
	if(teleporter || !readEnvValue(&newconf->debug.config, newconf, env_vars, NULL))
	{
		toml_datum_t conf_debug = toml_table_find(toml, "debug");
		if(conf_debug.type == TOML_TABLE)
			readTOMLvalue(&newconf->debug.config, "config", conf_debug, newconf);
	}
	set_debug_flags(newconf);

	log_debug(DEBUG_CONFIG, "Reading %s TOML config file",
	          teleporter ? "teleporter" : version == 0 ? "default" : "backup");

	// Read all known config items
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		// oldconf can be NULL when reading a Teleporter file
		struct conf_item *old_conf_item = oldconf != NULL ? get_conf_item(oldconf, i) : NULL;
		struct conf_item *new_conf_item = get_conf_item(newconf, i);

		// First try to read this config option from an environment variable
		// Skip reading environment variables when importing from Teleporter
		// If this succeeds, skip searching the TOML file for this config item
		bool reset = false;
		if(!teleporter && readEnvValue(new_conf_item, newconf, env_vars, &reset))
		{
			new_conf_item->f |= FLAG_ENV_VAR;
			continue;
		}

		// Skip this variable if it has been reset (forced by
		// environment variable before but not anymore)
		if(reset)
		{
			if(new_conf_item->t == CONF_ALL_DEBUG_BOOL)
			{
				// Reset all debug flags to false if debug.all
				// has been reset
				set_all_debug(newconf, false);
				set_debug_flags(newconf);
			}
			log_info("Skipping %s as it has been reset", new_conf_item->k);
			continue;
		}

		// Get config path depth
		unsigned int level = config_path_depth(new_conf_item->p);

		// Parse tree of properties
		bool item_available = true;
		toml_datum_t table[MAX_CONFIG_PATH_DEPTH] = { 0 };
		for(unsigned int j = 0; j < level-1; j++)
		{
			// Get table at this level
			table[j] = toml_table_find(j > 0 ? table[j-1] : toml, new_conf_item->p[j]);
			if(table[j].type == TOML_UNKNOWN)
			{
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST", new_conf_item->k);
				item_available = false;
				break;
			}
		}

		// Skip this config item if it does not exist
		if(!item_available)
			continue;

		// Try to parse config item
		readTOMLvalue(new_conf_item, new_conf_item->p[level-1], table[level-2], newconf);

		// Check if we need to restart FTL
		if(old_conf_item != NULL &&
		   !compare_config_item(new_conf_item->t, &old_conf_item->v, &new_conf_item->v))
		{
			log_debug(DEBUG_CONFIG, "%s CHANGED", new_conf_item->k);
			if(new_conf_item->f & FLAG_RESTART_FTL && restart != NULL)
			{
				log_info("Restarting FTL due to change of %s", new_conf_item->k);
				*restart = true;
			}

			// Check if this item changed the password, if so, we need to
			// invalidate all currently active sessions
			if(new_conf_item->f & FLAG_INVALIDATE_SESSIONS)
				delete_all_sessions();
		}
	}

	// Migrate config from old to new
	if(migrate_config(toml, newconf) && restart != NULL)
	{
		log_info("Restarting FTL due to migration of configuration");
		*restart = true;
	}

	// Report debug config if enabled
	set_debug_flags(newconf);
	if(verbose)
		reportDebugFlags();

	// Print FTL environment variables (if used)
	printFTLenv();

	// Free memory allocated by the TOML parser and return success
	if(!teleporter)
		toml_free(result);
	cJSON_Delete(env_vars);
	return true;
}

// Parse TOML config file
static bool parseTOML(toml_result_t *toml, const unsigned int version)
{
	// Try to open default config file. Use fallback if not found
	bool locked = false;
	FILE *fp = openFTLtoml("r", version, &locked);
	if(fp == NULL)
		return false;

	// Parse lines in the config file
	*toml = toml_parse_file(fp);

	// Close file and release exclusive lock
	closeFTLtoml(fp, locked);

	// Check for errors
	if(!toml->ok)
	{
		log_err("Cannot parse config file: %s", toml->errmsg);
		return false;
	}

	log_debug(DEBUG_CONFIG, "TOML file parsing: OK");
	return true;
}

bool getLogFilePathTOML(void)
{
	log_debug(DEBUG_CONFIG, "Reading TOML config file: log file path");

	toml_result_t conf = { 0 };
	
	if(!parseTOML(&conf, 0))
		return false;

	toml_datum_t files = toml_table_find(conf.toptab, "files");
	if(files.type != TOML_TABLE)
	{
		log_debug(DEBUG_CONFIG, "files DOES NOT EXIST or is not a table");
		toml_free(conf);
		return false;
	}

	toml_datum_t log = toml_table_find(files, "log");
	if(log.type != TOML_TABLE)
	{
		log_debug(DEBUG_CONFIG, "files.log DOES NOT EXIST or is not a table");
		toml_free(conf);
		return false;
	}

	toml_datum_t ftl = toml_table_find(log, "ftl");
	if(ftl.type != TOML_STRING)
	{
		log_debug(DEBUG_CONFIG, "files.log DOES NOT EXIST or is not a string");
		toml_free(conf);
		return false;
	}

	// Only replace string when it is different
	if(strcmp(config.files.log.ftl.v.s,ftl.u.s) != 0)
	{
		config.files.log.ftl.t = CONF_STRING_ALLOCATED;
		config.files.log.ftl.v.s = strdup(ftl.u.s); // Allocated string
	}

	toml_free(conf);
	return true;
}

static void reportDebugFlags(void)
{
	// Print debug settings
	log_debug(DEBUG_ANY, "************************");
	log_debug(DEBUG_ANY, "*    DEBUG SETTINGS    *");

	// Read all known debug config items
	for(unsigned int debug_flag = 1; debug_flag < DEBUG_ELEMENTS; debug_flag++)
	{
		// Get name of debug flag
		// We do not need to add an offset as this loop starts counting
		// at 1
		const char *name = debugstr(debug_flag);
		// Calculate number of spaces to nicely align output
		int spaces = 20 - strlen(name);
		// Print debug flag
		// We skip the first 6 characters of the flags as they are always "DEBUG_"
		log_debug(DEBUG_ANY, "* %s:%*s %s  *", name+6, spaces, "", debug_flags[debug_flag] ? "YES" : "NO ");
	}
	log_debug(DEBUG_ANY, "************************");
}
