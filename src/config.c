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
#include "config.h"
#include "setupVars.h"
#include "log.h"
// nice()
#include <unistd.h>
// argv_dnsmasq
#include "args.h"
// INT_MAX
#include <limits.h>
// debug_dnsmasq_lines
#include "hooks/log.h"

ConfigStruct config;
FTLFileNamesStruct FTLfiles = {
	// Default path for config file (regular installations)
	"/etc/pihole/pihole-FTL.conf",
	// Alternative path for config file (snap installations)
	"/var/snap/pihole/common/etc/pihole/pihole-FTL.conf",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

httpsettingsStruct httpsettings;

// Private global variables
static char *conflinebuffer = NULL;
static size_t size = 0;

// Private prototypes
static char *parse_FTLconf(FILE *fp, const char * key);
static void release_config_memory(void);
static void getpath(FILE* fp, const char *option, const char *defaultloc, char **pointer);
static void set_nice(const char *buffer, int fallback);
static bool read_bool(const char *option, const bool fallback);

void getLogFilePath(void)
{
	FILE *fp;
	char * buffer;

	// Try to open default config file. Use fallback if not found
	if( ((fp = fopen(FTLfiles.conf, "r")) == NULL) &&
	    ((fp = fopen(FTLfiles.snapConf, "r")) == NULL) &&
	    ((fp = fopen("pihole-FTL.conf", "r")) == NULL))
	{
		printf("Notice: Found no readable FTL config file\n");
	}

	// Read LOGFILE value if available
	// defaults to: "/var/log/pihole-FTL.log"
	buffer = parse_FTLconf(fp, "LOGFILE");

	errno = 0;
	// No option set => use default log location
	if(buffer == NULL)
	{
		// Use standard path if no custom path was obtained from the config file
		FTLfiles.log = strdup("/var/log/pihole-FTL.log");

		// Test if memory allocation was successful
		if(FTLfiles.log == NULL)
		{
			printf("FATAL: Allocating memory for FTLfiles.log failed (%s, %i). Exiting.",
			       strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
	}
	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	else if(sscanf(buffer, "%127ms", &FTLfiles.log) == 0)
	{
		// Empty file string
		FTLfiles.log = NULL;
		log_info("Using syslog facility");
	}
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
		log_notice("Found no readable FTL config file, using default settings");
	}

	// Parse lines in the config file
	log_info("Starting config file parsing (%s)", FTLfiles.conf);

	// SOCKET_LISTENING
	// defaults to: listen only local
	config.socket_listenlocal = true;
	buffer = parse_FTLconf(fp, "SOCKET_LISTENING");

	if(buffer != NULL && strcasecmp(buffer, "all") == 0)
		config.socket_listenlocal = false;

	if(config.socket_listenlocal)
		log_info("   SOCKET_LISTENING: only local");
	else
		log_info("   SOCKET_LISTENING: all destinations");

	// AAAA_QUERY_ANALYSIS
	// defaults to: Yes
	buffer = parse_FTLconf(fp, "AAAA_QUERY_ANALYSIS");
	config.analyze_AAAA = read_bool(buffer, true);

	if(config.analyze_AAAA)
		log_info("   AAAA_QUERY_ANALYSIS: Show AAAA queries");
	else
		log_info("   AAAA_QUERY_ANALYSIS: Hide AAAA queries");

	// MAXDBDAYS
	// defaults to: 365 days
	config.maxDBdays = 365;
	buffer = parse_FTLconf(fp, "MAXDBDAYS");

	int value = 0;
	const int maxdbdays_max = INT_MAX / 24 / 60 / 60;
	if(buffer != NULL && sscanf(buffer, "%i", &value))
	{
		// Prevent possible overflow
		if(value > maxdbdays_max)
			value = maxdbdays_max;

		// Only use valid values
		if(value == -1 || value >= 0)
			config.maxDBdays = value;
	}

	if(config.maxDBdays == 0)
		log_info("   MAXDBDAYS: --- (DB disabled)");
	else if(config.maxDBdays == -1)
		log_info("   MAXDBDAYS: --- (cleaning disabled)");
	else
		log_info("   MAXDBDAYS: max age for stored queries is %i days", config.maxDBdays);

	// RESOLVE_IPV6
	// defaults to: Yes
	buffer = parse_FTLconf(fp, "RESOLVE_IPV6");
	config.resolveIPv6 = read_bool(buffer, true);

	if(config.resolveIPv6)
		log_info("   RESOLVE_IPV6: Resolve IPv6 addresses");
	else
		log_info("   RESOLVE_IPV6: Don\'t resolve IPv6 addresses");

	// RESOLVE_IPV4
	// defaults to: Yes
	buffer = parse_FTLconf(fp, "RESOLVE_IPV4");
	config.resolveIPv4 = read_bool(buffer, true);

	if(config.resolveIPv4)
		log_info("   RESOLVE_IPV4: Resolve IPv4 addresses");
	else
		log_info("   RESOLVE_IPV4: Don\'t resolve IPv4 addresses");

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
		log_info("   DBINTERVAL: saving to DB file every minute");
	else
		log_info("   DBINTERVAL: saving to DB file every %lli seconds", (long long)config.DBinterval);

	// DBFILE
	// defaults to: "/etc/pihole/pihole-FTL.db"
	buffer = parse_FTLconf(fp, "DBFILE");

	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	if(!(buffer != NULL && sscanf(buffer, "%127ms", &FTLfiles.FTL_db)))
	{
		// Use standard path if no custom path was obtained from the config file
		FTLfiles.FTL_db = strdup("/etc/pihole/pihole-FTL.db");
	}

	if(FTLfiles.FTL_db != NULL && strlen(FTLfiles.FTL_db) > 0)
		log_info("   DBFILE: Using %s", FTLfiles.FTL_db);
	else
	{
		// Use standard path if path was set to zero but override
		// MAXDBDAYS=0 to ensure no queries are stored in the database
		FTLfiles.FTL_db = strdup("/etc/pihole/pihole-FTL.db");
		config.maxDBdays = 0;
		log_info("   DBFILE: Using %s (not storing queries)", FTLfiles.FTL_db);
	}

	// MAXLOGAGE
	// Up to how many hours in the past should queries be imported from the database?
	// defaults to: 24.0 via MAXLOGAGE defined in FTL.h
	config.maxlogage = MAXLOGAGE*3600;
	buffer = parse_FTLconf(fp, "MAXLOGAGE");

	fvalue = 0;
	const char *hint = "";
	if(buffer != NULL && sscanf(buffer, "%f", &fvalue))
	{
		if(fvalue >= 0.0f && fvalue <= 1.0f*MAXLOGAGE)
			config.maxlogage = (int)(fvalue * 3600);
		else if(fvalue > 1.0f*MAXLOGAGE)
			hint = " (value has been clipped to " str(MAXLOGAGE) " hours)";
	}
	log_info("   MAXLOGAGE: Importing up to %.1f hours of log data%s",
	     (float)config.maxlogage/3600.0f, hint);

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
	log_info("   PRIVACYLEVEL: Set to %i", config.privacylevel);

	// IGNORE_LOCALHOST
	// defaults to: false
	buffer = parse_FTLconf(fp, "IGNORE_LOCALHOST");
	config.ignore_localhost = read_bool(buffer, false);

	if(buffer != NULL && strcasecmp(buffer, "yes") == 0)
		config.ignore_localhost = true;

	if(config.ignore_localhost)
		log_info("   IGNORE_LOCALHOST: Hide queries from localhost");
	else
		log_info("   IGNORE_LOCALHOST: Show queries from localhost");

	// BLOCKINGMODE
	// defaults to: MODE_IP
	get_blocking_mode(fp);
	switch(config.blockingmode)
	{
		case MODE_NX:
			log_info("   BLOCKINGMODE: NXDOMAIN for blocked domains");
			break;
		case MODE_NULL:
			log_info("   BLOCKINGMODE: Null IPs for blocked domains");
			break;
		case MODE_IP_NODATA_AAAA:
			log_info("   BLOCKINGMODE: Pi-hole's IP + NODATA-IPv6 for blocked domains");
			break;
		case MODE_NODATA:
			log_info("   BLOCKINGMODE: Using NODATA for blocked domains");
			break;
		case MODE_IP:
			log_info("   BLOCKINGMODE: Pi-hole's IPs for blocked domains");
			break;
	}

	// ANALYZE_ONLY_A_AND_AAAA
	// defaults to: false
	buffer = parse_FTLconf(fp, "ANALYZE_ONLY_A_AND_AAAA");
	config.analyze_only_A_AAAA = read_bool(buffer, false);

	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.analyze_only_A_AAAA = true;

	if(config.analyze_only_A_AAAA)
		log_info("   ANALYZE_ONLY_A_AND_AAAA: Enabled. Analyzing only A and AAAA queries");
	else
		log_info("   ANALYZE_ONLY_A_AND_AAAA: Disabled. Analyzing all queries");

	// DBIMPORT
	// defaults to: Yes
	buffer = parse_FTLconf(fp, "DBIMPORT");
	config.DBimport = read_bool(buffer, true);

	if(config.DBimport)
	{
		log_info("   DBIMPORT: Importing history from database");
		if(config.maxDBdays == 0)
			log_info("      Hint: Exporting queries has been disabled (MAXDBDAYS=0)!");
	}
	else
		log_info("   DBIMPORT: Not importing history from database");

	// PIDFILE
	getpath(fp, "PIDFILE", "/run/pihole-FTL.pid", &FTLfiles.pid);

	// SETUPVARSFILE
	getpath(fp, "SETUPVARSFILE", "/etc/pihole/setupVars.conf", &FTLfiles.setupVars);

	// MACVENDORDB
	getpath(fp, "MACVENDORDB", "/etc/pihole/macvendor.db", &FTLfiles.macvendor_db);

	// GRAVITYDB
	getpath(fp, "GRAVITYDB", "/etc/pihole/gravity.db", &FTLfiles.gravity_db);

	// PARSE_ARP_CACHE
	// defaults to: true
	buffer = parse_FTLconf(fp, "PARSE_ARP_CACHE");
	config.parse_arp_cache = read_bool(buffer, true);

	if(config.parse_arp_cache)
		log_info("   PARSE_ARP_CACHE: Active");
	else
		log_info("   PARSE_ARP_CACHE: Inactive");

	// CNAME_DEEP_INSPECT
	// defaults to: true
	buffer = parse_FTLconf(fp, "CNAME_DEEP_INSPECT");
	config.cname_inspection = read_bool(buffer, true);

	if(config.cname_inspection)
		log_info("   CNAME_DEEP_INSPECT: Active");
	else
		log_info("   CNAME_DEEP_INSPECT: Inactive");

	// DELAY_STARTUP
	// defaults to: zero (seconds)
	buffer = parse_FTLconf(fp, "DELAY_STARTUP");

	config.delay_startup = 0;
	if(buffer != NULL && sscanf(buffer, "%u", &config.delay_startup) &&
	   (config.delay_startup > 0 && config.delay_startup <= 300))
		log_info("   DELAY_STARTUP: Requested to wait %u seconds during startup.", config.delay_startup);
	else
		log_info("   DELAY_STARTUP: No delay requested.");

	// BLOCK_ESNI
	// defaults to: true
	buffer = parse_FTLconf(fp, "BLOCK_ESNI");
	config.block_esni = read_bool(buffer, true);

	if(config.block_esni)
		log_info("   BLOCK_ESNI: Enabled, blocking _esni.{blocked domain}");
	else
		log_info("   BLOCK_ESNI: Disabled");

	// WEBROOT
	getpath(fp, "WEBROOT", "/var/www/html", &httpsettings.webroot);

	// WEBPORT
	// On which port should FTL's API be listening?
	// defaults to: 8080
	uint16_t port = 8080;
	buffer = parse_FTLconf(fp, "WEBPORT");

	value = 0;
	if(buffer != NULL && sscanf(buffer, "%i", &value))
		if(value > 0 && value <= __UINT16_MAX__)
			port = value;
	snprintf(httpsettings.port, sizeof(httpsettings.port), "%u,[::]:%u", port, port);
	log_info("   WEBPORT: Port %s", httpsettings.port);

	// WEBHOME
	// From which sub-directory is the web interface served from?
	// Defaults to: /admin/ (both slashes are needed!)
	getpath(fp, "WEBHOME", "/admin/", &httpsettings.webhome);

	// WEBACL
	// An Access Control List (ACL) allows restrictions to be
	// put on the list of IP addresses which have access to our
	// web server.
	// The ACL is a comma separated list of IP subnets, where
	// each subnet is pre-pended by either a - or a + sign.
	// A plus sign means allow, where a minus sign means deny.
	// If a subnet mask is omitted, such as -1.2.3.4, this means
	// to deny only that single IP address.
	// Subnet masks may vary from 0 to 32, inclusive. The default
	// setting is to allow all accesses. On each request the full
	// list is traversed, and the last match wins.
	//
	// Example 1: "-0.0.0.0/0,+127.0.0.1"
	//            ---> deny all accesses, except from localhost (IPv4)
	// Example 2: "-0.0.0.0/0,+192.168/16"
	//            ---> deny all accesses, except from the
	//                 192.168/16 subnet
	//
	buffer = parse_FTLconf(fp, "WEBACL");
	if(buffer != NULL)
	{
		httpsettings.acl = strdup(buffer);
		log_info("   WEBACL: Using access control list.");
	}
	else
	{
		// Default: allow all access
		httpsettings.acl = "+0.0.0.0/0";
		log_info("   WEBACL: Allowing all access.");
	}

	// API_AUTH_FOR_LOCALHOST
	// defaults to: false
	buffer = parse_FTLconf(fp, "API_AUTH_FOR_LOCALHOST");
	httpsettings.api_auth_for_localhost = read_bool(buffer, true);

	if(httpsettings.api_auth_for_localhost)
		log_info("   API_AUTH_FOR_LOCALHOST: Local devices need to login");
	else
		log_info("   API_AUTH_FOR_LOCALHOST: Local devices do not need to login");

	// API_SESSION_TIMEOUT
	// How long should a session be considered valid after login?
	// defaults to: 300 seconds
	httpsettings.session_timeout = 300;
	buffer = parse_FTLconf(fp, "API_SESSION_TIMEOUT");

	value = 0;
	if(buffer != NULL && sscanf(buffer, "%i", &value) && value > 0)
	{
		httpsettings.session_timeout = value;
	}
	log_info("   API_SESSION_TIMEOUT: %u seconds", httpsettings.session_timeout);

	// API_PRETTY_JSON
	// defaults to: false
	buffer = parse_FTLconf(fp, "API_PRETTY_JSON");
	httpsettings.prettyJSON = read_bool(buffer, false);

	if(httpsettings.prettyJSON)
		log_info("   API_PRETTY_JSON: Enabled. Using additional formatting in API output.");
	else
		log_info("   API_PRETTY_JSON: Disabled. Compact API output.");

	// API_ERROR_LOG
	getpath(fp, "API_ERROR_LOG", "/var/log/pihole/PH7.log", &httpsettings.log_error);

	// API_INFO_LOG
	getpath(fp, "API_INFO_LOG", "/var/log/pihole/HTTP_info.log", &httpsettings.log_info);

	// NICE
	// Shall we change the nice of the current process?
	// defaults to: -10 (can be disabled by setting value to -999)
	//
	// The nice value is an attribute that can be used to influence the CPU
	// scheduler to favor or disfavor a process in scheduling decisions.
	//
	// The range of the nice value varies across UNIX systems. On modern Linux,
	// the range is -20 (high priority) to +19 (low priority). On some other
	// systems, the range is -20..20. Very early Linux kernels (Before Linux
	// 2.0) had the range -infinity..15.
	buffer = parse_FTLconf(fp, "NICE");
	set_nice(buffer, -10);

	// MAXNETAGE
	// IP addresses (and associated host names) older than the specified number
	// of days are removed to avoid dead entries in the network overview table
	// defaults to: the same value as MAXDBDAYS
	config.network_expire = config.maxDBdays;
	buffer = parse_FTLconf(fp, "MAXNETAGE");

	int ivalue = 0;
	if(buffer != NULL &&
	    sscanf(buffer, "%i", &ivalue) &&
	    ivalue > 0 && ivalue <= 8760) // 8760 days = 24 years
			config.network_expire = ivalue;

	if(config.network_expire > 0u)
		log_info("   MAXNETAGE: Removing IP addresses and host names from network table after %u days",
		     config.network_expire);
	else
		log_info("   MAXNETAGE: No automated removal of IP addresses and host names from the network table");

	// NAMES_FROM_NETDB
	// Should we use the fallback option to try to obtain client names from
	// checking the network table? Assume this is an IPv6 client without a
	// host names itself but the network table tells us that this is the same
	// device where we have a host names for its IPv4 address. In this case,
	// we use the host name associated to the other address as this is the same
	// device. This behavior can be disabled using NAMES_FROM_NETDB=false
	// defaults to: true
	buffer = parse_FTLconf(fp, "NAMES_FROM_NETDB");
	config.names_from_netdb = read_bool(buffer, true);

	if(config.names_from_netdb)
		log_info("   NAMES_FROM_NETDB: Enabled, trying to get names from network database");
	else
		log_info("   NAMES_FROM_NETDB: Disabled");

	// EDNS0_ECS
	// Should we overwrite the query source when client information is
	// provided through EDNS0 client subnet (ECS) information?
	// defaults to: true
	buffer = parse_FTLconf(fp, "EDNS0_ECS");
	config.edns0_ecs = read_bool(buffer, true);

	if(config.edns0_ecs)
		log_info("   EDNS0_ECS: Overwrite client from ECS information");
	else
		log_info("   EDNS0_ECS: Don't use ECS information");

	// REFRESH_HOSTNAMES
	// defaults to: IPV4
	buffer = parse_FTLconf(fp, "REFRESH_HOSTNAMES");

	if(buffer != NULL && strcasecmp(buffer, "ALL") == 0)
	{
		config.refresh_hostnames = REFRESH_ALL;
		log_info("   REFRESH_HOSTNAMES: Periodically refreshing all names");
	}
	else if(buffer != NULL && strcasecmp(buffer, "NONE") == 0)
	{
		config.refresh_hostnames = REFRESH_NONE;
		log_info("   REFRESH_HOSTNAMES: Not periodically refreshing names");
	}
	else if(buffer != NULL && strcasecmp(buffer, "UNKNOWN") == 0)
	{
		config.refresh_hostnames = REFRESH_UNKNOWN;
		log_info("   REFRESH_HOSTNAMES: Only refreshing recently active clients with unknown hostnames");
	}
	else
	{
		config.refresh_hostnames = REFRESH_IPV4_ONLY;
		log_info("   REFRESH_HOSTNAMES: Periodically refreshing IPv4 names");
	}

	// WEBDOMAIN
	getpath(fp, "WEBDOMAIN", "pi.hole", &httpsettings.webdomain);

	// RATE_LIMIT
	// defaults to: 1000 queries / 60 seconds
	config.rate_limit.count = 1000;
	config.rate_limit.interval = 60;
	buffer = parse_FTLconf(fp, "RATE_LIMIT");

	unsigned int count = 0, interval = 0;
	if(buffer != NULL && sscanf(buffer, "%u/%u", &count, &interval) == 2)
	{
		config.rate_limit.count = count;
		config.rate_limit.interval = interval;
	}

	if(config.rate_limit.count > 0)
		log_info("   RATE_LIMIT: Rate-limiting client making more than %u queries in %u second%s",
		     config.rate_limit.count, config.rate_limit.interval, config.rate_limit.interval == 1 ? "" : "s");
	else
		log_info("   RATE_LIMIT: Disabled");

	// REPLY_ADDR4
	// Use a specific IP address instead of automatically detecting the
	// IPv4 interface address a query arrived on
	// defaults to: not set
	config.reply_addr.overwrite_v4 = false;
	config.reply_addr.v4.s_addr = 0;
	buffer = parse_FTLconf(fp, "REPLY_ADDR4");
	if(buffer != NULL && inet_pton(AF_INET, buffer, &config.reply_addr.v4))
		config.reply_addr.overwrite_v4 = true;

	if(config.reply_addr.overwrite_v4)
	{
		char addr[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &config.reply_addr.v4, addr, INET_ADDRSTRLEN);
		log_info("   REPLY_ADDR4: Using IPv4 address %s in IP blocking mode", addr);
	}
	else
		log_info("   REPLY_ADDR4: Automatic interface-dependent detection of address");

	// REPLY_ADDR6
	// Use a specific IP address instead of automatically detecting the
	// IPv6 interface address a query arrived on
	// defaults to: not set
	config.reply_addr.overwrite_v6 = false;
	memset(&config.reply_addr.v6, 0, sizeof(config.reply_addr.v6));
	buffer = parse_FTLconf(fp, "REPLY_ADDR6");
	if(buffer != NULL && inet_pton(AF_INET6, buffer, &config.reply_addr.v6))
		config.reply_addr.overwrite_v6 = true;

	if(config.reply_addr.overwrite_v6)
	{
		char addr[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, &config.reply_addr.v6, addr, INET6_ADDRSTRLEN);
		log_info("   REPLY_ADDR6: Using IPv6 address %s in IP blocking mode", addr);
	}
	else
		log_info("   REPLY_ADDR6: Automatic interface-dependent detection of address");

	// Read DEBUG_... setting from pihole-FTL.conf
	// This option should be the last one as it causes
	// some rather verbose output into the log when
	// listing all the enabled/disabled debugging options
	read_debuging_settings(fp);

	log_info("Finished config file parsing");

	// Release memory
	release_config_memory();

	if(fp != NULL)
		fclose(fp);
}

static void getpath(FILE* fp, const char *option, const char *defaultloc, char **pointer)
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
		log_crit("Allocating memory for %s failed (%s, %i). Exiting.", option, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	else if(strlen(*pointer) == 0)
	{
		log_info("   %s: Empty path is not possible, using %s",
		         option, defaultloc);
		*pointer = strdup(defaultloc);
	}
	else
	{
		log_info("   %s: Using %s", option, *pointer);
	}
}

static char *parse_FTLconf(FILE *fp, const char * key)
{
	// Return NULL if fp is an invalid file pointer
	if(fp == NULL)
		return NULL;

	char *keystr = calloc(strlen(key)+2, sizeof(char));
	if(keystr == NULL)
	{
		log_crit("Could not allocate memory (keystr) in parse_FTLconf()");
		return NULL;
	}
	sprintf(keystr, "%s=", key);

	// Go to beginning of file
	fseek(fp, 0L, SEEK_SET);

	if(config.debug & DEBUG_EXTRA)
		log_debug(DEBUG_EXTRA, "initial: conflinebuffer = %p, keystr = %p, size = %zu", conflinebuffer, keystr, size);

	errno = 0;
	while(getline(&conflinebuffer, &size, fp) != -1)
	{
		if(config.debug & DEBUG_EXTRA)
		{
			log_debug(DEBUG_EXTRA, "conflinebuffer = %p, keystr = %p, size = %zu", conflinebuffer, keystr, size);
			log_debug(DEBUG_EXTRA, "  while reading line \"%s\" looking for \"%s\"", conflinebuffer, keystr);
		}
		// Check if memory allocation failed
		if(conflinebuffer == NULL)
			break;

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
		char *value = find_equals(conflinebuffer) + 1;
		// Trim whitespace at beginning and end, this function
		// modifies the string inplace
		trim_whitespace(value);
		return value;
	}

	if(errno == ENOMEM)
		log_crit("Could not allocate memory (getline) in parse_FTLconf()");

	// Free keystr memory
	free(keystr);

	// Key not found or memory error -> return NULL
	return NULL;
}

void release_config_memory(void)
{
	if(conflinebuffer != NULL)
	{
		free(conflinebuffer);
		conflinebuffer = NULL;
		size = 0;
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
		   value <= PRIVACY_MAXIMUM &&
		   value > config.privacylevel)
		{
			log_notice("Increasing privacy level from %i to %i", config.privacylevel, value);
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
			log_warn("Unknown blocking mode, using NULL as fallback");
	}

	// Release memory
	release_config_memory();

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
}

// Routine for setting the debug flags in the config struct
static void setDebugOption(FILE* fp, const char* option, enum debug_flag bitmask)
{
	const char* buffer = parse_FTLconf(fp, option);

	// Return early if the key has not been found in FTL's config file
	if(buffer == NULL)
		return;

	// Set bit if value equals "true", clear bit otherwise
	if(read_bool(buffer, false))
		config.debug |= bitmask;
	else
		config.debug &= ~bitmask;
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

	// DEBUG_ALL
	// defaults to: false
	// ~0 is a shortcut for "all bits set"
	setDebugOption(fp, "DEBUG_ALL", ~(int16_t)0);


	for(enum debug_flag flag = DEBUG_DATABASE; flag < DEBUG_EXTRA; flag <<= 1)
	{
		// DEBUG_DATABASE
		setDebugOption(fp, debugstr(flag), flag);
	}
	debug_dnsmasq_lines = config.debug & DEBUG_DNSMASQ_LINES ? 1 : 0;

	if(config.debug != 0)
	{
		log_debug(DEBUG_ANY, "Debugging enabled:");

		for(enum debug_flag flag = DEBUG_DATABASE; flag < DEBUG_EXTRA; flag <<= 1)
			log_debug(DEBUG_ANY, "    %s = %s", debugstr(flag), (config.debug & flag)? "YES":"NO ");

		// Enable debug logging in dnsmasq (only effective before starting the resolver)
		argv_dnsmasq[2] = "--log-debug";
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

static void set_nice(const char *buffer, const int fallback)
{
	int value, nice_set, nice_target = fallback;

	// Try to read niceness value
	// Attempts to set a nice value outside the range are clamped to the range.
	if(buffer != NULL && sscanf(buffer, "%i", &value) == 1)
		nice_target = value;

	// Skip setting niceness if set to -999
	if(nice_target == -999)
	{
		log_info("   NICE: Not changing nice value");
		return;
	}

	// Adjust if != -999
	errno = 0;
	if((nice_set = nice(nice_target)) == -1 &&
	   errno == EPERM)
	{
		// ERROR EPERM: The calling process attempted to increase its priority
		// by supplying a negative value but has insufficient privileges.
		// On Linux, the RLIMIT_NICE resource limit can be used to define a limit to
		// which an unprivileged process's nice value can be raised. We are not
		// affected by this limit when pihole-FTL is running with CAP_SYS_NICE
		log_info("   NICE: Cannot change niceness to %d (permission denied)",
		     nice_target);
		return;
	}
	if(nice_set == nice_target)
	{
		log_info("   NICE: Set process niceness to %d%s",
		     nice_set, (nice_set == fallback) ? " (default)" : "");
	}
	else
	{
		log_info("   NICE: Set process niceness to %d (asked for %d)",
		     nice_set, nice_target);
	}
}

static bool read_bool(const char *option, const bool fallback)
{
	if(option == NULL)
		return fallback;

	else if(strcasecmp(option, "false") == 0 ||
	        strcasecmp(option, "no") == 0)
		return false;

	else if(strcasecmp(option, "true") == 0 ||
	        strcasecmp(option, "yes") == 0)
		return true;

	return fallback;
}
