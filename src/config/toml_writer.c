/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TOML config writer routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "config.h"
// get_timestr(), get_FTL_version())
#include "log.h"
#include "tomlc17/tomlc17.h"
#include "toml_writer.h"
#include "toml_helper.h"
// get_blocking_mode_str()
#include "datastructure.h"
// watch_config()
#include "config/inotify.h"
// files_different()
#include "files.h"
// git_branch()
#include "version.h"
// sanitize_dns_hosts()
#include "config/validator.h"

// defined in config/config.c
extern uint8_t last_checksum[SHA256_DIGEST_SIZE];

bool writeFTLtoml(const bool verbose, FILE *fp)
{
	// Return early without writing if we are in config read-only mode
	if(config.misc.readOnly.v.b)
	{
		log_debug(DEBUG_CONFIG, "Config file is read-only, not writing");

		// We need to (re-)calculate the checksum here as it'd otherwise
		// be outdated (in non-read-only mode, it's calculated at the
		// end of this function)
		if(!sha256sum(GLOBALTOMLPATH, last_checksum, false))
			log_err("Unable to create checksum of %s", GLOBALTOMLPATH);
		return true;
	}

	// open temporary config file for writing *unless* we are provided with
	// a file pointer to an already opened file
	bool locked = false;
	const bool opened = fp == NULL;
	if(fp == NULL)
	{
		// Try to open a temporary config file for writing
		fp = openFTLtoml("w", 0, &locked);
		if(fp == NULL)
			return false;
	}

	// Write header
	fprintf(fp, "# Pi-hole configuration file (%s)", get_FTL_version());
	if(strcmp(git_branch(), "master") != 0)
		fprintf(fp, " on branch %s", git_branch());
	fputs("\n# Encoding: UTF-8\n", fp);
	fputs("# This file is managed by pihole-FTL\n", fp);
	char timestring[TIMESTR_SIZE];
	get_timestr(timestring, time(NULL), false, false);
	fputs("# Last updated on ", fp);
	fputs(timestring, fp);
	fputs("\n\n", fp);

	// Iterate over configuration and store it into the file
	char *last_path = (char*)"";
	unsigned int modified = 0;
	cJSON *env_vars = cJSON_CreateArray();
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(&config, i);

		// Skip write-only items
		if(conf_item->f & FLAG_PSEUDO_ITEM)
			continue;

		// Get path depth
		unsigned int level = config_path_depth(conf_item->p);

		// Write path if it is different from the last one
		if(level > 1 && strcmp(last_path, conf_item->p[level-2]) != 0)
		{
			indentTOML(fp, level-2);
			fputc('[', fp);
			// Write path elements separated by dots
			for(unsigned int j = 0; j < level - 1; j++)
				fprintf(fp, "%s%s", j > 0 ? "." : "", conf_item->p[j]);
			fputc(']', fp);
			fputc('\n', fp);
			// Remember last path
			last_path = conf_item->p[level-2];
		}

		// Write comment
		print_comment(fp, conf_item->h, "", 85, level-1);
		if(conf_item->a != NULL)
		{
			// Write possible values if applicable
			print_toml_allowed_values(conf_item->a, fp, level-1);
		}

		// Write value
		indentTOML(fp, level-1);
		fprintf(fp, "%s = ", conf_item->p[level-1]);
		
		// Sanitize dns.hosts entries before writing them to TOML
		if(conf_item == &config.dns.hosts)
		{
			sanitize_dns_hosts(&conf_item->v);
		}
		
		writeTOMLvalue(fp, level-1, conf_item->t, &conf_item->v);

		// Compare with default value and add a comment on difference
		bool changed = false;
		if(conf_item->t == CONF_STRING || conf_item->t == CONF_STRING_ALLOCATED)
			changed = strcmp(conf_item->v.s, conf_item->d.s) != 0;
		else if(conf_item->t == CONF_JSON_STRING_ARRAY)
			changed = !cJSON_Compare(conf_item->v.json, conf_item->d.json, true);
		else
			changed = memcmp(&conf_item->v, &conf_item->d, sizeof(conf_item->v)) != 0;

		if(changed)
		{

			// Print info if this value is overwritten by an env var
			if(conf_item->f & FLAG_ENV_VAR)
				cJSON_AddItemToArray(env_vars, cJSON_CreateStringReference(conf_item->k));

			fprintf(fp, " ### CHANGED%s, default = ", conf_item->f & FLAG_ENV_VAR ? " (env)" : "");
			writeTOMLvalue(fp, -1, conf_item->t, &conf_item->d);
			modified++;
		}

		// Add newlines after each entry
		fputs("\n\n", fp);
	}

	// Print config file statistics at the end of the file as comment
	fputs("# Configuration statistics:\n", fp);
	fprintf(fp, "# %zu total entries out of which %zu %s default\n",
	        CONFIG_ELEMENTS, CONFIG_ELEMENTS - modified,
		CONFIG_ELEMENTS - modified == 1 ? "entry is" : "entries are");
	fprintf(fp, "# --> %u %s modified\n",
	        modified, modified == 1 ? "entry is" : "entries are");

	const unsigned int num_env_vars = cJSON_GetArraySize(env_vars);
	if(num_env_vars > 0)
	{
		fprintf(fp, "# %u %s forced through environment:\n",
			num_env_vars, num_env_vars == 1 ? "entry is" : "entries are");

		for(unsigned int i = 0; i < num_env_vars; i++)
		{
			const char *env_var = cJSON_GetArrayItem(env_vars, i)->valuestring;
			fprintf(fp, "#   - %s\n", env_var);
		}
	}
	else
		fputc('\n', fp);

	// Log some statistics in verbose mode
	if(verbose || config.debug.config.v.b)
	{
		log_info("Wrote config file:");
		log_info(" - %zu total entries", CONFIG_ELEMENTS);
		log_info(" - %zu %s default", CONFIG_ELEMENTS - modified,
		         CONFIG_ELEMENTS - modified == 1 ? "entry is" : "entries are");
		log_info(" - %u %s modified", modified,
		         modified == 1 ? "entry is" : "entries are");
		log_info(" - %u %s forced through environment", num_env_vars,
		         num_env_vars == 1 ? "entry is" : "entries are");
	}

	// Free cJSON array
	cJSON_Delete(env_vars);

	// Close file and release exclusive lock unless we are provided with a
	// file pointer in which case we assume that the caller takes care of
	// this
	if(opened)
		closeFTLtoml(fp, locked);
	else
		return true;

	// Move temporary file to the final location if it is different
	// We skip the first 8 lines as they contain the header and will always
	// be different
	if(files_different(GLOBALTOMLPATH".tmp", GLOBALTOMLPATH, 8))
	{
		// Stop watching for changes in the config file
		watch_config(false);

		// Rotate config file
		rotate_files(GLOBALTOMLPATH, NULL);

		// Move file
		if(rename(GLOBALTOMLPATH".tmp", GLOBALTOMLPATH) != 0)
		{
			log_warn("Cannot move temporary config file to final location (%s), content not updated", strerror(errno));
			// Restart watching for changes in the config file
			watch_config(true);
			return false;
		}

		// Restart watching for changes in the config file
		watch_config(true);

		// Log that we have written the config file if either in verbose or
		// debug mode
		if(verbose || config.debug.config.v.b)
			log_info("Config file written to %s", GLOBALTOMLPATH);
	}
	else
	{
		// Remove temporary file
		if(unlink(GLOBALTOMLPATH".tmp") != 0)
		{
			log_warn("Cannot remove temporary config file (%s), content not updated", strerror(errno));
			return false;
		}

		// Log that the config file has not changed if in debug mode
		log_debug(DEBUG_CONFIG, "pihole.toml unchanged");
	}

	if(!sha256sum(GLOBALTOMLPATH, last_checksum, false))
		log_err("Unable to create checksum of %s", GLOBALTOMLPATH);

	return true;
}
