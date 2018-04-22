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
	logg("Starting config file parsing (%s)", FTLfiles.conf);

	// SOCKET_LISTENING
	// defaults to: listen only local
	config.socket_listenlocal = true;
	buffer = parse_FTLconf(fp, "SOCKET_LISTENING");

	if(buffer != NULL && strcasecmp(buffer, "all") == 0)
		config.socket_listenlocal = false;

	if(config.socket_listenlocal)
		logg("   SOCKET_LISTENING: only local");
	else
		logg("   SOCKET_LISTENING: all destinations");

	// AAAA_QUERY_ANALYSIS
	// defaults to: Yes
	config.analyze_AAAA = true;
	buffer = parse_FTLconf(fp, "AAAA_QUERY_ANALYSIS");

	if(buffer != NULL && strcasecmp(buffer, "no") == 0)
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

	if(buffer != NULL && strcasecmp(buffer, "no") == 0)
		config.resolveIPv6 = false;

	if(config.resolveIPv6)
		logg("   RESOLVE_IPV6: Resolve IPv6 addresses");
	else
		logg("   RESOLVE_IPV6: Don\'t resolve IPv6 addresses");

	// RESOLVE_IPV4
	// defaults to: Yes
	config.resolveIPv4 = true;
	buffer = parse_FTLconf(fp, "RESOLVE_IPV4");
	if(buffer != NULL && strcasecmp(buffer, "no") == 0)
		config.resolveIPv4 = false;
	if(config.resolveIPv4)
		logg("   RESOLVE_IPV4: Resolve IPv4 addresses");
	else
		logg("   RESOLVE_IPV4: Don\'t resolve IPv4 addresses");

	// DBINTERVAL
	// How often do we store queries in FTL's database [minutes]?
	// this value can be a floating point number, e.g. "DBINTERVAL=0.5"
	// defaults to: once per minute
	config.DBinterval = 60;
	buffer = parse_FTLconf(fp, "DBINTERVAL");

	float fvalue = 0;
	if(buffer != NULL && sscanf(buffer, "%f", &fvalue))
		// check if the read value is
		// - larger than 0.1min (6sec), and
		// - smaller than 1440.0min (once a day)
		if(fvalue >= 0.1f && fvalue <= 1440.0f)
			config.DBinterval = (int)(fvalue * 60);

	if(config.DBinterval == 60)
		logg("   DBINTERVAL: saving to DB file every minute");
	else
		logg("   DBINTERVAL: saving to DB file every %i seconds", config.DBinterval);

	// DBFILE
	// defaults to: "/etc/pihole/pihole-FTL.db"
	buffer = parse_FTLconf(fp, "DBFILE");

	errno = 0;
	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	if(!(buffer != NULL && sscanf(buffer, "%127ms", &FTLfiles.db)))
	{
		// Use standard path if no custom path was obtained from the config file
		FTLfiles.db = strdup("/etc/pihole/pihole-FTL.db");
	}

	// Test if memory allocation was successful
	if(FTLfiles.db == NULL && errno != 0)
	{
		logg("FATAL: Allocating memory for FTLfiles.db failed (%s, %i). Exiting.", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	else if(FTLfiles.db != NULL && strlen(FTLfiles.db) > 0)
		logg("   DBFILE: Using %s", FTLfiles.db);
	else
		logg("   DBFILE: Not using database due to empty filename");

	// FTLPORT
	// On which port should FTL be listening?
	// defaults to: 4711
	config.port = 4711;
	buffer = parse_FTLconf(fp, "FTLPORT");

	value = 0;
	if(buffer != NULL && sscanf(buffer, "%i", &value))
		if(value > 0 && value <= 65535)
			config.port = value;

	// MAXLOGAGE
	// Up to how many hours in the past should queries be imported from the database?
	// defaults to: 24.0
	config.maxlogage = 24*3600;
	buffer = parse_FTLconf(fp, "MAXLOGAGE");

	fvalue = 0;
	if(buffer != NULL && sscanf(buffer, "%f", &fvalue))
		if(fvalue >= 0.0f && value <= 744.0f)
			config.maxlogage = (int)(fvalue * 3600);
	logg("   MAXLOGAGE: Importing up to %.1f hours of log data", (float)config.maxlogage/3600.0f);

	// PRIVACYLEVEL
	// Specify if we want to anonymize the DNS queries somehow, available options are:
	// PRIVACY_SHOW_ALL (0) = don't hide anything
	// PRIVACY_HIDE_DOMAINS (1) = show and store all domains as "hidden", return nothing for Top Domains + Top Ads
	// PRIVACY_HIDE_DOMAINS_CLIENTS (2) = as above, show all domains as "hidden" and all clients as "127.0.0.1"
	//                                    (or "::1"), return nothing for any Top Lists
	// PRIVACY_MAXIMUM (3) = Disabled basically everything except the anonymous stastics, there will be no entries
	//                       added to the database, no entries visible in the query log and no Top Item Lists
	// defaults to: PRIVACY_SHOW_ALL
	config.privacylevel = PRIVACY_SHOW_ALL;
	get_privacy_level(fp);
	logg("   PRIVACYLEVEL: Set to %i", config.privacylevel);

	// IGNORE_LOCALHOST
	// defaults to: No
	config.ignore_localhost = false;
	buffer = parse_FTLconf(fp, "IGNORE_LOCALHOST");

	if(buffer != NULL && strcasecmp(buffer, "yes") == 0)
		config.ignore_localhost = true;

	if(config.ignore_localhost)
		logg("   IGNORE_LOCALHOST: Hide queries from localhost");
	else
		logg("   IGNORE_LOCALHOST: Show queries from localhost");

	// BLOCKINGMODE
	// defaults to: MODE_IP
	config.blockingmode = MODE_IP;
	buffer = parse_FTLconf(fp, "BLOCKINGMODE");

	if(buffer != NULL)
	{
		if(strcasecmp(buffer, "NXDOMAIN") == 0)
			config.blockingmode = MODE_NX;
	}

	switch(config.blockingmode)
	{
		case MODE_NX:
			logg("   BLOCKINGMODE: NXDOMAIN for blocked domains");
			break;
		default:
			logg("   BLOCKINGMODE: Pi-hole's IP for blocked domains");
			break;
	}

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

void get_privacy_level(FILE *fp)
{
	// See if we got a file handle, if not we have to open
	// the config file ourselves
	bool opened = false;
	if(fp == NULL)
	{
		if((fp = fopen(FTLfiles.conf, "r")) == NULL)
			// Return silently if there is no config file available
			return;
		opened = true;
	}

	int value = 0;
	char *buffer = parse_FTLconf(fp, "PRIVACYLEVEL");
	if(buffer != NULL && sscanf(buffer, "%i", &value) == 1)
		// Check for change and validity of privacy level (set in FTL.h)
		if(value != config.privacylevel &&
		   value >= PRIVACY_SHOW_ALL &&
		   value <= PRIVACY_MAXIMUM)
		{
			logg("Notice: Changing privacy level from %i to %i", config.privacylevel, value);
			config.privacylevel = value;
		}

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
}
