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
// get_timestr()
#include "log.h"
#include "tomlc99/toml.h"
#include "toml_writer.h"
#include "toml_helper.h"
// get_blocking_mode_str()
#include "datastructure.h"

bool writeFTLtoml(void)
{
	// Try to open global config file
	FILE *fp;
	if((fp = openFTLtoml("w")) == NULL)
	{
		log_warn("Cannot write to FTL config file, content not updated");
		return false;
	}

	// Store lines in the config file
	log_info("Writing config file");

	// Write header
	fputs("# This file is managed by pihole-FTL\n#\n", fp);
	fputs("# Do not edit the file while FTL is\n", fp);
	fputs("# running or your changes may be overwritten\n#\n", fp);
	char timestring[84] = "";
	get_timestr(timestring, time(NULL), false);
	fprintf(fp, "# Last update: %s\n\n", timestring);

	// Iterate over configuration and store it into the file
	char *last_path = (char*)"";
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(i);

		// Get path depth
		unsigned int level = config_path_depth(conf_item);

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
		indentTOML(fp, level-1);
		fprintf(fp, "# %s\n", conf_item->h);
		if(conf_item->a != NULL)
		{
			// Write possible values if applicable
			indentTOML(fp, level-1);
			fprintf(fp, "# Possible values are: %s\n", conf_item->a);
		}

		// Write value
		indentTOML(fp, level-1);
		fprintf(fp, "%s = ", conf_item->p[level-1]);
		writeTOMLvalue(fp, conf_item->t, &conf_item->v);

		// Compare with default value and add a comment on difference
		if(memcmp(&conf_item->v, &conf_item->d, sizeof(conf_item->v)) != 0)
		{
			fprintf(fp, " ### CHANGED, default = ");
			writeTOMLvalue(fp, conf_item->t, &conf_item->d);
		}

		// Add newlines after each entry
		fputs("\n\n", fp);
	}

	// Close and flush file
	fclose(fp);

	return true;
}