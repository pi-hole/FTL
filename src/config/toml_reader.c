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
// log_teleporter_skipped()
#include "database/message-table.h"

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


// The default Content-Security-Policy before img-src was allowed to load
// data: URIs
#define CSP_HEADER_OLD "Content-Security-Policy: default-src 'none'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'"
#define CSP_HEADER_NEW "Content-Security-Policy: default-src 'none'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; img-src 'self' data:; manifest-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'"

static bool migrate_webserver_csp(struct config *newconf)
{
	cJSON *header = NULL;
	int idx = 0;

	// Only replace the policy if it is 1:1 the old default - anyone who
	// wrote their own Content-Security-Policy keeps it
	cJSON_ArrayForEach(header, newconf->webserver.headers.v.json)
	{
		if(cJSON_IsString(header) && strcmp(header->valuestring, CSP_HEADER_OLD) == 0)
		{
			log_debug(DEBUG_CONFIG, "Config setting webserver.headers MIGRATED to CSP img-src 'self' data:");
			cJSON_ReplaceItemInArray(newconf->webserver.headers.v.json, idx,
			                         cJSON_CreateString(CSP_HEADER_NEW));
			return true;
		}
		idx++;
	}

	log_debug(DEBUG_CONFIG, "webserver.headers does not carry the old CSP default - nothing to migrate");

	return false;
}

// Migrate the unsupported files.log.dnsmasq = "-" sentinel to the default
// path (see https://github.com/pi-hole/FTL/pull/2960).  Checks the effective
// value so a valid env override is never clobbered by a stale "-" in the TOML.
static bool migrate_files_log_dnsmasq(struct config *newconf)
{
	bool restart = false;
	if(newconf->files.log.dnsmasq.v.s != NULL &&
	   strcmp(newconf->files.log.dnsmasq.v.s, "-") == 0)
	{
		log_warn("files.log.dnsmasq = \"-\" (log to stderr) is no longer supported, using %s instead (see https://github.com/pi-hole/FTL/pull/2960)",
		         newconf->files.log.dnsmasq.d.s);
		if(newconf->files.log.dnsmasq.t == CONF_STRING_ALLOCATED)
			free(newconf->files.log.dnsmasq.v.s);
		newconf->files.log.dnsmasq.v.s = newconf->files.log.dnsmasq.d.s;
		newconf->files.log.dnsmasq.t = CONF_STRING;
		log_debug(DEBUG_CONFIG, "Config setting files.log.dnsmasq MIGRATED to %s", newconf->files.log.dnsmasq.d.s);
		restart = true;
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
	// Migrate the old Content-Security-Policy default to allow data: images
	restart |= migrate_webserver_csp(newconf);
	// Migrate files.log.dnsmasq = "-" to the default path
	restart |= migrate_files_log_dnsmasq(newconf);

	return restart;
}

// Settings the last Teleporter import left alone, see readFTLtoml()
static const char *teleporter_skipped[16] = { NULL };
static unsigned int n_teleporter_skipped = 0;

// Tell the user about them once the import went through, forget them otherwise
void report_teleporter_skipped(const bool imported)
{
	for(unsigned int i = 0; imported && i < n_teleporter_skipped; i++)
		log_teleporter_skipped(teleporter_skipped[i]);
	n_teleporter_skipped = 0;
}

bool readFTLtoml(struct config *oldconf, struct config *newconf,
                 toml_datum_t toml, const bool verbose, bool *restart,
                 const unsigned int version, const bool teleporter,
                 char err[VALIDATOR_ERRBUF_LEN])
{
	// A config reload running next to an import must not empty its list
	if(teleporter)
		n_teleporter_skipped = 0;

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

			// webserver.api.password writes the hash next to it rather
			// than a value of its own. That hash is as forced by the
			// environment as the password is - it is recomputed from it
			// at every start - so a cluster must neither hand it around
			// nor read the recomputation as somebody setting a password
			if(new_conf_item->t == CONF_PASSWORD)
				get_conf_item(newconf, i - 1)->f |= FLAG_ENV_VAR;

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

		// An option the API may not set is equally not settable by uploading a
		// file through the API. A Teleporter archive carries a whole
		// pihole.toml, so without this it would be a way around
		// FLAG_API_READ_ONLY - in the same file that may name a program for
		// dnsmasq to run. Everything else in the archive is imported as usual
		// and the value configured on this host is kept, so restoring a backup
		// taken elsewhere does not fail, it just does not carry these over.
		// The message table entry makes that visible in the web interface
		// rather than only in the log.
		//
		// Importing the same archive with "pihole-FTL --teleporter <file>" does
		// apply them: that already requires access to the host, which is the
		// whole point of the distinction.
		//
		// A value forced through an environment variable is kept either way:
		// the environment wins over pihole.toml on every start, so the
		// archive's value would only hold until the restart the import
		// itself triggers, and PATCH /api/config refuses it too.
		if(teleporter && ((!cli_mode && new_conf_item->f & (FLAG_API_READ_ONLY | FLAG_API_CLI_READ_ONLY)) ||
		                  new_conf_item->f & FLAG_ENV_VAR))
		{
			// Parse into a scratch copy so the archive's value can be looked
			// at without replacing the one we keep. Only a real difference is
			// worth reporting - an archive exported on this host carries these
			// items unchanged, and warning about those would be pure noise.
			struct conf_item scratch = *new_conf_item;
			if(scratch.t == CONF_JSON_STRING_ARRAY)
				scratch.v.json = cJSON_Duplicate(scratch.v.json, true);
			else if(scratch.t == CONF_STRING_ALLOCATED)
				scratch.v.s = strdup(scratch.v.s);

			readTOMLvalue(&scratch, scratch.p[level-1], table[level-2], newconf);

			// Reported by the caller once the whole archive is accepted
			if(!compare_config_item(scratch.t, &scratch.v, &new_conf_item->v) &&
			   n_teleporter_skipped < ArraySize(teleporter_skipped))
				teleporter_skipped[n_teleporter_skipped++] = new_conf_item->k;

			// The type may have been promoted to an allocated one while parsing
			if(scratch.t == CONF_JSON_STRING_ARRAY)
				cJSON_Delete(scratch.v.json);
			else if(scratch.t == CONF_STRING_ALLOCATED)
				free(scratch.v.s);

			continue;
		}

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

	// Hold what we just read to the same rules the API, the CLI and environment
	// variables obey. readTOMLvalue() only parses, so this is what stops a value
	// no other path accepts - an embedded newline carrying a second dnsmasq
	// directive, say - from reaching the running configuration through a file.
	//
	// It runs here rather than per item above because the migrations assign
	// values of their own after the loop, and because the rules spanning
	// several items need the whole file read first.
	//
	// An archive is refused outright, naming the offending item. Doing the same
	// for the config file would take DNS down for the entire network over a
	// single bad value, so there the item goes back to its default instead.
	const bool valid = validate_config(newconf, !teleporter, err);

	// Free memory allocated by the TOML parser and return
	if(!teleporter)
		toml_free(result);
	cJSON_Delete(env_vars);
	return valid;
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
		log_debug(DEBUG_CONFIG, "files.log.ftl DOES NOT EXIST or is not a string");
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
