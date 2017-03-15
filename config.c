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
	}

	// Parse lines in the config file
	logg("Starting config file parsing");

	// SOCKET_LISTENING
	// defaults to: listen only local
	config.socket_listenlocal = true;
	buffer = parse_FTLconf(fp, "SOCKET_LISTENING");
	if(buffer != NULL)
	{
		if(strcmp(buffer, "all") == 0)
			config.socket_listenlocal = false;
	}
	if(config.socket_listenlocal)
		logg("   SOCKET_LISTENING: only local");
	else
		logg("   SOCKET_LISTENING: all destinations");

	// TIMEFRAME
	// defaults to: ROLLING
	config.rolling_24h = true;
	config.include_yesterday = true;
	bool msg = false;
	buffer = parse_FTLconf(fp, "TIMEFRAME");
	if(buffer != NULL)
	{
		if(strcmp(buffer, "YESTERDAY") == 0)
		{
			config.include_yesterday = true;
			config.rolling_24h = false;
			msg = true;
			logg("   TIMEFRAME: Yesterday + Today");
		}
		else if(strcmp(buffer, "TODAY") == 0)
		{
			config.include_yesterday = false;
			config.rolling_24h = false;
			msg = true;
			logg("   TIMEFRAME: Today");
		}
	}
	if(!msg)
		logg("   TIMEFRAME: Rolling 24h");

	logg("Finished config file parsing");
	free(conflinebuffer);
	conflinebuffer = NULL;
	if(fp != NULL)
		fclose(fp);
}

char *parse_FTLconf(FILE *fp, const char * key)
{
	// Return NULL if fp is an invalid file pointer
	if(fp == NULL)
		return NULL;

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
