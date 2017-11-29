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

ConfigStruct config;
char *parse_FTLconf(FILE *fp, const char * key);

char *conflinebuffer = NULL;

void read_FTLconf(void)
{

	FILE *fp;
	char * buffer;

	if((fp = fopen(FTLfiles.conf, "r")) == NULL)
	{
		logg("Notice: Found no readable FTL config file");
		logg("        Using default settings");
	}

	// Parse lines in the config file
	logg("Starting config file parsing");

	// SOCKET_LISTENING
	// defaults to: listen only local
	config.socket_listenlocal = true;
	buffer = parse_FTLconf(fp, "SOCKET_LISTENING");

	if(buffer != NULL && strcmp(buffer, "all") == 0)
		config.socket_listenlocal = false;

	if(config.socket_listenlocal)
		logg("   SOCKET_LISTENING: only local");
	else
		logg("   SOCKET_LISTENING: all destinations");

	// TIMEFRAME
	// defaults to: ROLLING
	config.rolling_24h = true;
	config.include_yesterday = true;
	buffer = parse_FTLconf(fp, "TIMEFRAME");

	if(buffer != NULL && strcmp(buffer, "yesterday") == 0)
	{
		config.include_yesterday = true;
		config.rolling_24h = false;
		logg("   TIMEFRAME: Yesterday + Today");
	}
	else if(buffer != NULL && strcmp(buffer, "today") == 0)
	{
		config.include_yesterday = false;
		config.rolling_24h = false;
		logg("   TIMEFRAME: Today");
	}

	if(config.rolling_24h)
		logg("   TIMEFRAME: Rolling 24h");

	// QUERY_DISPLAY
	// defaults to: Yes
	config.query_display = true;
	buffer = parse_FTLconf(fp, "QUERY_DISPLAY");

	if(buffer != NULL && strcmp(buffer, "no") == 0)
		config.query_display = false;

	if(config.query_display)
		logg("   QUERY_DISPLAY: Show queries");
	else
		logg("   QUERY_DISPLAY: Hide queries");

	// AAAA_QUERY_ANALYSIS
	// defaults to: Yes
	config.analyze_AAAA = true;
	buffer = parse_FTLconf(fp, "AAAA_QUERY_ANALYSIS");

	if(buffer != NULL && strcmp(buffer, "no") == 0)
		config.analyze_AAAA = false;

	if(config.analyze_AAAA)
		logg("   AAAA_QUERY_ANALYSIS: Show AAAA queries");
	else
		logg("   AAAA_QUERY_ANALYSIS: Hide AAAA queries");

	// MAXDBDAYS
	// defaults to: 365 days
	config.maxDBdays = 365;
	buffer = parse_FTLconf(fp, "MAXDBDAYS");

	int value = 0;
	if(buffer != NULL && sscanf(buffer, "%i", &value))
		if(value >= 0)
			config.maxDBdays = value;

	if(config.maxDBdays == 0)
		logg("   MAXDBDAYS: --- (DB disabled)", config.maxDBdays);
	else
		logg("   MAXDBDAYS: max age for stored queries is %i days", config.maxDBdays);

	// RESOLVE_IPV6
	// defaults to: Yes
	config.resolveIPv6 = true;
	buffer = parse_FTLconf(fp, "RESOLVE_IPV6");

	if(buffer != NULL && strcmp(buffer, "no") == 0)
		config.resolveIPv6 = false;

	if(config.resolveIPv6)
		logg("   RESOLVE_IPV6: Resolve IPv6 addresses");
	else
		logg("   RESOLVE_IPV6: Don\'t resolve IPv6 addresses");

	// RESOLVE_IPV4
	// defaults to: Yes
	config.resolveIPv4 = true;
	buffer = parse_FTLconf(fp, "RESOLVE_IPV4");
	if(buffer != NULL && strcmp(buffer, "no") == 0)
		config.resolveIPv4 = false;
	if(config.resolveIPv4)
		logg("   RESOLVE_IPV4: Resolve IPv4 addresses");
	else
		logg("   RESOLVE_IPV4: Don\'t resolve IPv4 addresses");

	// DBFILE
	// defaults to: "/etc/pihole/pihole-FTL.db"
	buffer = parse_FTLconf(fp, "DBFILE");

	if(buffer != NULL && sscanf(buffer, "%127ms", &FTLfiles.db))
	{
		// Using custom path
	}
	else
	{
		FTLfiles.db = strdup("/etc/pihole/pihole-FTL.db");
	}

	// Test if memory allocation was successful
	if(FTLfiles.db == NULL)
	{
		logg("FATAL: Allocating memory for FTLfiles.db failed (%i). Exiting.", errno);
		exit(EXIT_FAILURE);
	}

	logg("   DBFILE: Using %s", FTLfiles.db);

	logg("Finished config file parsing");

	// Release memory
	if(conflinebuffer != NULL)
	{
		free(conflinebuffer);
		conflinebuffer = NULL;
	}

	if(fp != NULL)
		fclose(fp);
}

char *parse_FTLconf(FILE *fp, const char * key)
{
	// Return NULL if fp is an invalid file pointer
	if(fp == NULL)
		return NULL;

	char * keystr = calloc(strlen(key)+2,sizeof(char));
	if(keystr == NULL)
	{
		logg("WARN: parse_FTLconf failed: could not allocate memory for keystr");
		return NULL;
	}
	sprintf(keystr, "%s=", key);

	// Go to beginning of file
	fseek(fp, 0L, SEEK_SET);

	size_t size;
	errno = 0;
	while(getline(&conflinebuffer, &size, fp) != -1)
	{
		// Strip (possible) newline
		conflinebuffer[strcspn(conflinebuffer, "\n")] = '\0';

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

	if(errno == ENOMEM)
		logg("WARN: parse_FTLconf failed: could not allocate memory for getline");

	// Key not found -> return NULL
	free(keystr);

	return NULL;
}
