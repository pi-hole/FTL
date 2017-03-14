/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Log parsing routine
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

ConfigStruct config;
char *parse_FTLconf(FILE *fp, const char * key);

char *conflinebuffer = NULL;

void read_FTLconf(void)
{

	FILE *fp;
	char * buffer;

	if((fp = fopen(FTLfiles.conf, "r")) == NULL)
	{
		logg("Notice: Opening of pihole-FTL.conf failed!");
		logg("        Falling back to default settings");
		return;
	}

	// Parse lines in the config file

	// SOCKET_LISTENING
	// defaults to: listen only local
	config.socket_listenlocal = true;
	buffer = parse_FTLconf(fp, "SOCKET_LISTENING");
	if(buffer != NULL)
	{
		logg_str("SOCKET_LISTENING: ", buffer);
		if(strcmp(buffer, "all") == 0)
			config.socket_listenlocal = false;
	}

	// INCLUDE_YESTERDAY
	// defaults to: no
	config.include_yesterday = false;
	buffer = parse_FTLconf(fp, "INCLUDE_YESTERDAY");
	if(buffer != NULL)
	{
		logg_str("INCLUDE_YESTERDAY: ", buffer);
		if((strcmp(buffer, "true") == 0) || (strcmp(buffer, "yes") == 0))
			config.include_yesterday = true;
	}

	free(conflinebuffer);
	conflinebuffer = NULL;
	fclose(fp);
}

char *parse_FTLconf(FILE *fp, const char * key)
{

	char * keystr = calloc(strlen(key)+2,sizeof(char));
	conflinebuffer = calloc(1024,sizeof(char));

	sprintf(keystr, "%s=", key);

	// Go to beginning of file
	fseek(fp, 0L, SEEK_SET);

	while(fgets(conflinebuffer, 1023, fp) != NULL)
	{
		// Strip newline from fgets output
		conflinebuffer[strlen(conflinebuffer) - 1] = '\0';

		// Skip comment lines
		if(conflinebuffer[0] == '#' || conflinebuffer[0] == ';')
			continue;

		// Skip lines with other keys
		if((strstr(conflinebuffer, keystr)) == NULL)
			continue;

		// otherwise: key found
		free(keystr);
		return (find_equals(conflinebuffer) + 1);
	}

	// Key not found -> return NULL
	free(keystr);
	return NULL;
}
