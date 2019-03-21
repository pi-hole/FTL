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
static char *parse_FTLconf(FILE *fp, const char * key);
static void release_config_memory(void);
void getpath(FILE* fp, const char *option, const char *defaultloc, char **pointer);

char *conflinebuffer = NULL;

void getLogFilePath(void)
{
	FILE *fp;
	char * buffer;

	// Try to open default config file. Use fallback if not found
	if( ((fp = fopen(FTLfiles.conf, "r")) == NULL) &&
	    ((fp = fopen(FTLfiles.snapConf, "r")) == NULL) &&
	    ((fp = fopen("pihole-FTL.conf", "r")) == NULL))
	{
		printf("Notice: Found no readable FTL config file");
	}

	// Read LOGFILE value if available
	// defaults to: "/var/log/pihole-FTL.log"
	buffer = parse_FTLconf(fp, "LOGFILE");

	errno = 0;
	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	if(buffer == NULL || sscanf(buffer, "%127ms", &FTLfiles.log) != 1)
	{
		// Use standard path if no custom path was obtained from the config file
		FTLfiles.log = strdup("/var/log/pihole-FTL.log");
	}

	// Test if memory allocation was successful
	if(FTLfiles.log == NULL)
	{
		printf("FATAL: Allocating memory for FTLfiles.log failed (%s, %i). Exiting.",
		       strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	else if(strlen(FTLfiles.log) == 0)
	{
		printf("Fatal: Log file location cannot be empty");
		exit(EXIT_FAILURE);
	}
	else
		logg("Using log file %s", FTLfiles.log);
}

void read_FTLconf(void)
{
	FILE *fp;
	char * buffer;

	// Try to open default config file. Use fallback if not found
	if( ((fp = fopen(FTLfiles.conf, "r")) == NULL) &&
	    ((fp = fopen(FTLfiles.snapConf, "r")) == NULL) &&
	    ((fp = fopen("pihole-FTL.conf", "r")) == NULL))
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
		logg("   MAXDBDAYS: --- (DB disabled)");
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
	// defaults to: 24.0 via MAXLOGAGE defined in FTL.h
	config.maxlogage = MAXLOGAGE*3600;
	buffer = parse_FTLconf(fp, "MAXLOGAGE");

	fvalue = 0;
	if(buffer != NULL && sscanf(buffer, "%f", &fvalue))
		if(fvalue >= 0.0f && fvalue <= 1.0f*MAXLOGAGE)
			config.maxlogage = (int)(fvalue * 3600);
	logg("   MAXLOGAGE: Importing up to %.1f hours of log data", (float)config.maxlogage/3600.0f);

	// PRIVACYLEVEL
	// Specify if we want to anonymize the DNS queries somehow, available options are:
	// PRIVACY_SHOW_ALL (0) = don't hide anything
	// PRIVACY_HIDE_DOMAINS (1) = show and store all domains as "hidden", return nothing for Top Domains + Top Ads
	// PRIVACY_HIDE_DOMAINS_CLIENTS (2) = as above, show all domains as "hidden" and all clients as "127.0.0.1"
	//                                    (or "::1"), return nothing for any Top Lists
	// PRIVACY_MAXIMUM (3) = Disabled basically everything except the anonymous statistics, there will be no entries
	//                       added to the database, no entries visible in the query log and no Top Item Lists
	// PRIVACY_NOSTATS (4) = Disable any analysis on queries. No counters are available in this mode.
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
	get_blocking_mode(fp);
	switch(config.blockingmode)
	{
		case MODE_NX:
			logg("   BLOCKINGMODE: NXDOMAIN for blocked domains");
			break;
		case MODE_NULL:
			logg("   BLOCKINGMODE: Null IPs for blocked domains");
			break;
		case MODE_IP_NODATA_AAAA:
			logg("   BLOCKINGMODE: Pi-hole's IP + NODATA-IPv6 for blocked domains");
			break;
		case MODE_NODATA:
			logg("   BLOCKINGMODE: Using NODATA for blocked domains");
			break;
		case MODE_IP:
			logg("   BLOCKINGMODE: Pi-hole's IPs for blocked domains");
			break;
	}

	// ANALYZE_ONLY_A_AND_AAAA
	// defaults to: No
	config.analyze_only_A_AAAA = false;
	buffer = parse_FTLconf(fp, "ANALYZE_ONLY_A_AND_AAAA");

	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.analyze_only_A_AAAA = true;

	if(config.analyze_only_A_AAAA)
		logg("   ANALYZE_ONLY_A_AND_AAAA: Enabled. Analyzing only A and AAAA queries");
	else
		logg("   ANALYZE_ONLY_A_AND_AAAA: Disabled. Analyzing all queries");

	// DBIMPORT
	// defaults to: Yes
	config.DBimport = true;
	buffer = parse_FTLconf(fp, "DBIMPORT");
	if(buffer != NULL && strcasecmp(buffer, "no") == 0)
		config.DBimport = false;
	if(config.DBimport)
		logg("   DBIMPORT: Importing history from database");
	else
		logg("   DBIMPORT: Not importing history from database");

	// PIDFILE
	getpath(fp, "PIDFILE", "/var/run/pihole-FTL.pid", &FTLfiles.pid);

	// PORTFILE
	getpath(fp, "PORTFILE", "/var/run/pihole-FTL.port", &FTLfiles.port);

	// SOCKETFILE
	getpath(fp, "SOCKETFILE", "/var/run/pihole/FTL.sock", &FTLfiles.socketfile);

	// WHITELISTFILE
	getpath(fp, "WHITELISTFILE", "/etc/pihole/whitelist.txt", &files.whitelist);

	// BLACKLISTFILE
	getpath(fp, "BLACKLISTFILE", "/etc/pihole/black.list", &files.blacklist);

	// GRAVITYFILE
	getpath(fp, "GRAVITYFILE", "/etc/pihole/gravity.list", &files.gravity);

	// REGEXLISTFILE
	getpath(fp, "REGEXLISTFILE", "/etc/pihole/regex.list", &files.regexlist);

	// SETUPVARSFILE
	getpath(fp, "SETUPVARSFILE", "/etc/pihole/setupVars.conf", &files.setupVars);

	// AUDITLISTFILE
	getpath(fp, "AUDITLISTFILE", "/etc/pihole/auditlog.list", &files.auditlist);

	// MACVENDORDB
	getpath(fp, "MACVENDORDB", "/etc/pihole/macvendor.db", &FTLfiles.macvendordb);

	// PARSE_ARP_CACHE
	// defaults to: true
	config.parse_arp_cache = true;
	buffer = parse_FTLconf(fp, "PARSE_ARP_CACHE");

	if(buffer != NULL && strcasecmp(buffer, "false") == 0)
		config.parse_arp_cache = false;

	if(config.parse_arp_cache)
		logg("   PARSE_ARP_CACHE: Active");
	else
		logg("   PARSE_ARP_CACHE: Inactive");

	// Read DEBUG_... setting from pihole-FTL.conf
	read_debuging_settings(fp);

	logg("Finished config file parsing");

	// Release memory
	release_config_memory();

	if(fp != NULL)
		fclose(fp);
}

void getpath(FILE* fp, const char *option, const char *defaultloc, char **pointer)
{
	// This subroutine is used to read paths from pihole-FTL.conf
	// fp:         File pointer to opened and readable config file
	// option:     Option string ("key") to try to read
	// defaultloc: Value used if key is not found in file
	// pointer:    Location where read (or default) parameter is stored
	char *buffer = parse_FTLconf(fp, option);

	errno = 0;
	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	if(buffer == NULL || sscanf(buffer, "%127ms", pointer) != 1)
	{
		// Use standard path if no custom path was obtained from the config file
		*pointer = strdup(defaultloc);
	}

	// Test if memory allocation was successful
	if(*pointer == NULL)
	{
		logg("FATAL: Allocating memory for %s failed (%s, %i). Exiting.", option, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	else if(strlen(*pointer) == 0)
	{
		logg("   %s: Empty file name is not possible!", option);
		exit(EXIT_FAILURE);
	}
	else
	{
		logg("   %s: Using %s", option, *pointer);
	}
}

static char *parse_FTLconf(FILE *fp, const char * key)
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

	size_t size = 0;
	errno = 0;
	while(getline(&conflinebuffer, &size, fp) != -1)
	{
		// Skip comment lines
		if(conflinebuffer[0] == '#' || conflinebuffer[0] == ';')
			continue;

		// Skip lines with other keys
		if((strstr(conflinebuffer, keystr)) == NULL)
			continue;

		// otherwise: key found
		free(keystr);
		// Note: value is still a pointer into the conflinebuffer
		//       its memory will get released in release_config_memory()
		char* value = find_equals(conflinebuffer) + 1;
		// Trim whitespace at beginning and end, this function
		// modifies the string inplace
		trim_whitespace(value);
		return value;
	}

	if(errno == ENOMEM)
		logg("WARN: parse_FTLconf failed: could not allocate memory for getline");

	// Key not found -> return NULL
	free(keystr);

	return NULL;
}

void release_config_memory(void)
{
	if(conflinebuffer != NULL)
	{
		free(conflinebuffer);
		conflinebuffer = NULL;
	}
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
	{
		// Check for change and validity of privacy level (set in FTL.h)
		if(value >= PRIVACY_SHOW_ALL &&
		   value <= PRIVACY_NOSTATS &&
		   value > config.privacylevel)
		{
			logg("Notice: Increasing privacy level from %i to %i", config.privacylevel, value);
			config.privacylevel = value;
		}
	}

	// Release memory
	release_config_memory();

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
}

void get_blocking_mode(FILE *fp)
{
	// Set default value
	config.blockingmode = MODE_NULL;

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

	// Get config string (if present)
	char *buffer = parse_FTLconf(fp, "BLOCKINGMODE");
	if(buffer != NULL)
	{
		if(strcasecmp(buffer, "NXDOMAIN") == 0)
			config.blockingmode = MODE_NX;
		else if(strcasecmp(buffer, "NULL") == 0)
			config.blockingmode = MODE_NULL;
		else if(strcasecmp(buffer, "IP-NODATA-AAAA") == 0)
			config.blockingmode = MODE_IP_NODATA_AAAA;
		else if(strcasecmp(buffer, "IP") == 0)
			config.blockingmode = MODE_IP;
		else if(strcasecmp(buffer, "NODATA") == 0)
			config.blockingmode = MODE_NODATA;
		else
			logg("Ignoring unknown blocking mode, fallback is NULL blocking");
	}

	// Release memory
	release_config_memory();

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
}

void read_debuging_settings(FILE *fp)
{
	// Set default (no debug instructions set)
	config.debug = 0;

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

	// DEBUG_DATABASE
	// defaults to: false
	char* buffer = parse_FTLconf(fp, "DEBUG_DATABASE");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_DATABASE;

	// DEBUG_NETWORKING
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_NETWORKING");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_NETWORKING;

	// DEBUG_LOCKS
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_LOCKS");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_LOCKS;

	// DEBUG_QUERIES
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_QUERIES");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_QUERIES;

	// DEBUG_FLAGS
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_FLAGS");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_FLAGS;

	// DEBUG_SHMEM
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_SHMEM");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_SHMEM;

	// DEBUG_GC
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_GC");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_GC;

	// DEBUG_ARP
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_ARP");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_ARP;

	// DEBUG_REGEX or REGEX_DEBUGMODE (legacy config option)
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_REGEX");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_REGEX;
	buffer = parse_FTLconf(fp, "REGEX_DEBUGMODE");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_REGEX;

	// DEBUG_API
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_API");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_API;

	// DEBUG_OVERTIME
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_OVERTIME");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_OVERTIME;

	// DEBUG_EXTBLOCKED
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_EXTBLOCKED");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_EXTBLOCKED;

	// DEBUG_CAPS
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_CAPS");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug |= DEBUG_CAPS;

	// DEBUG_ALL
	// defaults to: false
	buffer = parse_FTLconf(fp, "DEBUG_ALL");
	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.debug = ~0;

	if(config.debug)
	{
		logg("************************");
		logg("* Debugging enabled    *");
		logg("* DEBUG_DATABASE   %s *", (config.debug & DEBUG_DATABASE)? "YES":"NO ");
		logg("* DEBUG_NETWORKING %s *", (config.debug & DEBUG_NETWORKING)? "YES":"NO ");
		logg("* DEBUG_LOCKS      %s *", (config.debug & DEBUG_LOCKS)? "YES":"NO ");
		logg("* DEBUG_QUERIES    %s *", (config.debug & DEBUG_QUERIES)? "YES":"NO ");
		logg("* DEBUG_FLAGS      %s *", (config.debug & DEBUG_FLAGS)? "YES":"NO ");
		logg("* DEBUG_SHMEM      %s *", (config.debug & DEBUG_SHMEM)? "YES":"NO ");
		logg("* DEBUG_GC         %s *", (config.debug & DEBUG_GC)? "YES":"NO ");
		logg("* DEBUG_ARP        %s *", (config.debug & DEBUG_ARP)? "YES":"NO ");
		logg("* DEBUG_REGEX      %s *", (config.debug & DEBUG_REGEX)? "YES":"NO ");
		logg("* DEBUG_API        %s *", (config.debug & DEBUG_API)? "YES":"NO ");
		logg("* DEBUG_OVERTIME   %s *", (config.debug & DEBUG_OVERTIME)? "YES":"NO ");
		logg("* DEBUG_EXTBLOCKED %s *", (config.debug & DEBUG_EXTBLOCKED)? "YES":"NO ");
		logg("* DEBUG_CAPS       %s *", (config.debug & DEBUG_CAPS)? "YES":"NO ");
		logg("************************");
	}

	// Have to close the config file if we opened it
	if(opened)
	{
		fclose(fp);

		// Release memory only when we opened the file
		// Otherwise, it may still be needed outside of
		// this function (initial config parsing)
		release_config_memory();
	}
}
