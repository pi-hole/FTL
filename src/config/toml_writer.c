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
#include "tomlc99/toml.h"
#include "toml_writer.h"
#include "toml_helper.h"
// get_blocking_mode_str()
#include "datastructure.h"
// watch_config()
#include "config/inotify.h"
// files_different()
#include "files.h"

bool writeFTLtoml(const bool verbose)
{
	// Try to open a temporary config file for writing
	FILE *fp;
	if((fp = openFTLtoml(GLOBALTOMLPATH".tmp", "w")) == NULL)
	{
		log_warn("Cannot write to FTL config file (%s), content not updated", strerror(errno));
		return false;
	}

	// Write header
	fputs("# This file is managed by pihole-FTL\n#\n", fp);
	fputs("# Do not edit the file while FTL is\n", fp);
	fputs("# running or your changes may be overwritten\n#\n", fp);
	char timestring[TIMESTR_SIZE] = "";
	get_timestr(timestring, time(NULL), false, false);
	fputs("# Last updated on ", fp);
	fputs(timestring, fp);
	fputs("\n# by FTL ", fp);
	fputs(get_FTL_version(), fp);
	fputs("\n\n", fp);

	// Iterate over configuration and store it into the file
	char *last_path = (char*)"";
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
			print_toml_allowed_values(conf_item->a, fp, 85, level-1);
		}

		// Print info if this value is overwritten by an env var
		if(conf_item->f & FLAG_ENV_VAR)
			print_comment(fp, ">>> This config is overwritten by an environmental variable <<<", "", 85, level-1);

		// Write value
		indentTOML(fp, level-1);
		fprintf(fp, "%s = ", conf_item->p[level-1]);
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
			fprintf(fp, " ### CHANGED, default = ");
			writeTOMLvalue(fp, -1, conf_item->t, &conf_item->d);
		}

		// Add newlines after each entry
		fputs("\n\n", fp);
	}

	// Close file and release exclusive lock
	closeFTLtoml(fp);

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
		log_debug(DEBUG_CONFIG, "Config file unchanged");
	}

	return true;
}
