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
// saveport()
#include "api/socket.h"
// argv_dnsmasq
#include "args.h"

// INT_MAX
#include <limits.h>

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
	NULL,
	NULL,
	NULL
};

pthread_mutex_t lock;

// Private global variables
static char *conflinebuffer = NULL;
static size_t size = 0;

// Private prototypes
static char *parse_FTLconf(FILE *fp, const char * key);
static void getpath(FILE* fp, const char *option, const char *defaultloc, char **pointer);
static void set_nice(const char *buffer, int fallback);
static bool read_bool(const char *option, const bool fallback);

void init_config_mutex(void)
{
	// Initialize the lock attributes
	pthread_mutexattr_t lock_attr = {};
	pthread_mutexattr_init(&lock_attr);

	// Initialize the lock
	pthread_mutex_init(&lock, &lock_attr);

	// Destroy the lock attributes since we're done with it
	pthread_mutexattr_destroy(&lock_attr);
}

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
	// defaults to: "/var/log/pihole/FTL.log"
	buffer = parse_FTLconf(fp, "LOGFILE");

	errno = 0;
	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	if(buffer == NULL || sscanf(buffer, "%127ms", &FTLfiles.log) != 1)
	{
		// Use standard path if no custom path was obtained from the config file
		FTLfiles.log = strdup("/var/log/pihole/FTL.log");
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
	buffer = parse_FTLconf(fp, "AAAA_QUERY_ANALYSIS");
	config.analyze_AAAA = read_bool(buffer, true);

	if(config.analyze_AAAA)
		logg("   AAAA_QUERY_ANALYSIS: Show AAAA queries");
	else
		logg("   AAAA_QUERY_ANALYSIS: Hide AAAA queries");

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
		logg("   MAXDBDAYS: --- (DB disabled)");
	else if(config.maxDBdays == -1)
		logg("   MAXDBDAYS: --- (cleaning disabled)");
	else
		logg("   MAXDBDAYS: max age for stored queries is %i days", config.maxDBdays);

	// RESOLVE_IPV6
	// defaults to: Yes
	buffer = parse_FTLconf(fp, "RESOLVE_IPV6");
	config.resolveIPv6 = read_bool(buffer, true);

	if(config.resolveIPv6)
		logg("   RESOLVE_IPV6: Resolve IPv6 addresses");
	else
		logg("   RESOLVE_IPV6: Don\'t resolve IPv6 addresses");

	// RESOLVE_IPV4
	// defaults to: Yes
	buffer = parse_FTLconf(fp, "RESOLVE_IPV4");
	config.resolveIPv4 = read_bool(buffer, true);

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
		logg("   DBINTERVAL: saving to DB file every %lli seconds", (long long)config.DBinterval);

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
		logg("   DBFILE: Using %s", FTLfiles.FTL_db);
	else
	{
		// Use standard path if path was set to zero but override
		// MAXDBDAYS=0 to ensure no queries are stored in the database
		FTLfiles.FTL_db = strdup("/etc/pihole/pihole-FTL.db");
		config.maxDBdays = 0;
		logg("   DBFILE: Using %s (not storing queries)", FTLfiles.FTL_db);
	}

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
	const char *hint = "";
	if(buffer != NULL && sscanf(buffer, "%f", &fvalue))
	{
		if(fvalue >= 0.0f && fvalue <= 1.0f*MAXLOGAGE)
			config.maxlogage = (int)(fvalue * 3600);
		else if(fvalue > 1.0f*MAXLOGAGE)
			hint = " (value has been clipped to " str(MAXLOGAGE) " hours)";
	}
	logg("   MAXLOGAGE: Importing up to %.1f hours of log data%s",
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
	logg("   PRIVACYLEVEL: Set to %i", config.privacylevel);

	// IGNORE_LOCALHOST
	// defaults to: false
	buffer = parse_FTLconf(fp, "IGNORE_LOCALHOST");
	config.ignore_localhost = read_bool(buffer, false);

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
	// defaults to: false
	buffer = parse_FTLconf(fp, "ANALYZE_ONLY_A_AND_AAAA");
	config.analyze_only_A_AAAA = read_bool(buffer, false);

	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.analyze_only_A_AAAA = true;

	if(config.analyze_only_A_AAAA)
		logg("   ANALYZE_ONLY_A_AND_AAAA: Enabled. Analyzing only A and AAAA queries");
	else
		logg("   ANALYZE_ONLY_A_AND_AAAA: Disabled. Analyzing all queries");

	// DBIMPORT
	// defaults to: Yes
	buffer = parse_FTLconf(fp, "DBIMPORT");
	config.DBimport = read_bool(buffer, true);

	if(config.DBimport)
	{
		logg("   DBIMPORT: Importing history from database");
		if(config.maxDBdays == 0)
			logg("      Hint: Exporting queries has been disabled (MAXDBDAYS=0)!");
	}
	else
		logg("   DBIMPORT: Not importing history from database");

	// PIDFILE
	getpath(fp, "PIDFILE", "/run/pihole-FTL.pid", &FTLfiles.pid);

	// PORTFILE
	getpath(fp, "PORTFILE", "/run/pihole-FTL.port", &FTLfiles.port);
	saveport(config.port);

	// SOCKETFILE
	getpath(fp, "SOCKETFILE", "/run/pihole/FTL.sock", &FTLfiles.socketfile);

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
		logg("   PARSE_ARP_CACHE: Active");
	else
		logg("   PARSE_ARP_CACHE: Inactive");

	// CNAME_DEEP_INSPECT
	// defaults to: true
	buffer = parse_FTLconf(fp, "CNAME_DEEP_INSPECT");
	config.cname_inspection = read_bool(buffer, true);

	if(config.cname_inspection)
		logg("   CNAME_DEEP_INSPECT: Active");
	else
		logg("   CNAME_DEEP_INSPECT: Inactive");

	// DELAY_STARTUP
	// defaults to: zero (seconds)
	buffer = parse_FTLconf(fp, "DELAY_STARTUP");

	config.delay_startup = 0;
	if(buffer != NULL && sscanf(buffer, "%u", &config.delay_startup) &&
	   (config.delay_startup > 0 && config.delay_startup <= 300))
		logg("   DELAY_STARTUP: Requested to wait %u seconds during startup.", config.delay_startup);
	else
		logg("   DELAY_STARTUP: No delay requested.");

	// BLOCK_ESNI
	// defaults to: true
	buffer = parse_FTLconf(fp, "BLOCK_ESNI");
	config.block_esni = read_bool(buffer, true);

	if(config.block_esni)
		logg("   BLOCK_ESNI: Enabled, blocking _esni.{blocked domain}");
	else
		logg("   BLOCK_ESNI: Disabled");

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
		logg("   MAXNETAGE: Removing IP addresses and host names from network table after %u days",
		     config.network_expire);
	else
		logg("   MAXNETAGE: No automated removal of IP addresses and host names from the network table");

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
		logg("   NAMES_FROM_NETDB: Enabled, trying to get names from network database");
	else
		logg("   NAMES_FROM_NETDB: Disabled");

	// EDNS0_ECS
	// Should we overwrite the query source when client information is
	// provided through EDNS0 client subnet (ECS) information?
	// defaults to: true
	buffer = parse_FTLconf(fp, "EDNS0_ECS");
	config.edns0_ecs = read_bool(buffer, true);

	if(config.edns0_ecs)
		logg("   EDNS0_ECS: Overwrite client from ECS information");
	else
		logg("   EDNS0_ECS: Don't use ECS information");

	// REFRESH_HOSTNAMES
	// defaults to: IPV4
	buffer = parse_FTLconf(fp, "REFRESH_HOSTNAMES");

	if(buffer != NULL && strcasecmp(buffer, "ALL") == 0)
	{
		config.refresh_hostnames = REFRESH_ALL;
		logg("   REFRESH_HOSTNAMES: Periodically refreshing all names");
	}
	else if(buffer != NULL && strcasecmp(buffer, "NONE") == 0)
	{
		config.refresh_hostnames = REFRESH_NONE;
		logg("   REFRESH_HOSTNAMES: Not periodically refreshing names");
	}
	else if(buffer != NULL && strcasecmp(buffer, "UNKNOWN") == 0)
	{
		config.refresh_hostnames = REFRESH_UNKNOWN;
		logg("   REFRESH_HOSTNAMES: Only refreshing recently active clients with unknown hostnames");
	}
	else
	{
		config.refresh_hostnames = REFRESH_IPV4_ONLY;
		logg("   REFRESH_HOSTNAMES: Periodically refreshing IPv4 names");
	}

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
		logg("   RATE_LIMIT: Rate-limiting client making more than %u queries in %u second%s",
		     config.rate_limit.count, config.rate_limit.interval, config.rate_limit.interval == 1 ? "" : "s");
	else
		logg("   RATE_LIMIT: Disabled");

	// LOCAL_IPV4
	// Use a specific IP address instead of automatically detecting the
	// IPv4 interface address a query arrived on for A hostname queries
	// defaults to: not set
	config.reply_addr.own_host.overwrite_v4 = false;
	config.reply_addr.own_host.v4.s_addr = 0;
	buffer = parse_FTLconf(fp, "LOCAL_IPV4");
	if(buffer != NULL && inet_pton(AF_INET, buffer, &config.reply_addr.own_host.v4))
		config.reply_addr.own_host.overwrite_v4 = true;

	if(config.reply_addr.own_host.overwrite_v4)
	{
		char addr[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &config.reply_addr.own_host.v4, addr, INET_ADDRSTRLEN);
		logg("   LOCAL_IPV4: Using IPv4 address %s for pi.hole and hostname", addr);
	}
	else
		logg("   LOCAL_IPV4: Automatic interface-dependent detection of address");

	// LOCAL_IPV6
	// Use a specific IP address instead of automatically detecting the
	// IPv6 interface address a query arrived on for AAAA hostname queries
	// defaults to: not set
	config.reply_addr.own_host.overwrite_v6 = false;
	memset(&config.reply_addr.own_host.v6, 0, sizeof(config.reply_addr.own_host.v6));
	buffer = parse_FTLconf(fp, "LOCAL_IPV6");
	if(buffer != NULL && inet_pton(AF_INET6, buffer, &config.reply_addr.own_host.v6))
		config.reply_addr.own_host.overwrite_v6 = true;

	if(config.reply_addr.own_host.overwrite_v6)
	{
		char addr[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, &config.reply_addr.own_host.v6, addr, INET6_ADDRSTRLEN);
		logg("   LOCAL_IPV6: Using IPv6 address %s for pi.hole and hostname", addr);
	}
	else
		logg("   LOCAL_IPV6: Automatic interface-dependent detection of address");

	// BLOCK_IPV4
	// Use a specific IPv4 address for IP blocking mode replies
	// defaults to: REPLY_ADDR4 setting
	config.reply_addr.ip_blocking.overwrite_v4 = false;
	config.reply_addr.ip_blocking.v4.s_addr = 0;
	buffer = parse_FTLconf(fp, "BLOCK_IPV4");
	if(buffer != NULL && inet_pton(AF_INET, buffer, &config.reply_addr.ip_blocking.v4))
		config.reply_addr.ip_blocking.overwrite_v4 = true;

	if(config.reply_addr.ip_blocking.overwrite_v4)
	{
		char addr[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &config.reply_addr.ip_blocking.v4, addr, INET_ADDRSTRLEN);
		logg("   BLOCK_IPV4: Using IPv4 address %s in IP blocking mode", addr);
	}
	else
		logg("   BLOCK_IPV4: Automatic interface-dependent detection of address");

	// BLOCK_IPV6
	// Use a specific IPv6 address for IP blocking mode replies
	// defaults to: REPLY_ADDR6 setting
	config.reply_addr.ip_blocking.overwrite_v6 = false;
	memset(&config.reply_addr.ip_blocking.v6, 0, sizeof(config.reply_addr.own_host.v6));
	buffer = parse_FTLconf(fp, "BLOCK_IPV6");
	if(buffer != NULL && inet_pton(AF_INET6, buffer, &config.reply_addr.ip_blocking.v6))
		config.reply_addr.ip_blocking.overwrite_v6 = true;

	if(config.reply_addr.ip_blocking.overwrite_v6)
	{
		char addr[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, &config.reply_addr.ip_blocking.v6, addr, INET6_ADDRSTRLEN);
		logg("   BLOCK_IPV6: Using IPv6 address %s in IP blocking mode", addr);
	}
	else
		logg("   BLOCK_IPV6: Automatic interface-dependent detection of address");

	// REPLY_ADDR4 (deprecated setting)
	// Use a specific IP address instead of automatically detecting the
	// IPv4 interface address a query arrived on A hostname and IP blocked queries
	// defaults to: not set
	struct in_addr reply_addr4;
	buffer = parse_FTLconf(fp, "REPLY_ADDR4");
	if(buffer != NULL && inet_pton(AF_INET, buffer, &reply_addr4))
	{
		if(config.reply_addr.own_host.overwrite_v4 || config.reply_addr.ip_blocking.overwrite_v4)
		{
			logg("   WARNING: Ignoring REPLY_ADDR4 as LOCAL_IPV4 or BLOCK_IPV4 has been specified.");
		}
		else
		{
			config.reply_addr.own_host.overwrite_v4 = true;
			memcpy(&config.reply_addr.own_host.v4, &reply_addr4, sizeof(reply_addr4));
			config.reply_addr.ip_blocking.overwrite_v4 = true;
			memcpy(&config.reply_addr.ip_blocking.v4, &reply_addr4, sizeof(reply_addr4));

			char addr[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &reply_addr4, addr, INET_ADDRSTRLEN);
			logg("   REPLY_ADDR4: Using IPv4 address %s instead of automatically determined IP address", addr);
		}
	}

	// REPLY_ADDR6 (deprecated setting)
	// Use a specific IP address instead of automatically detecting the
	// IPv4 interface address a query arrived on A hostname and IP blocked queries
	// defaults to: not set
	struct in6_addr reply_addr6;
	buffer = parse_FTLconf(fp, "REPLY_ADDR6");
	if(buffer != NULL && inet_pton(AF_INET, buffer, &reply_addr6))
	{
		if(config.reply_addr.own_host.overwrite_v6 || config.reply_addr.ip_blocking.overwrite_v6)
		{
			logg("   WARNING: Ignoring REPLY_ADDR6 as LOCAL_IPV6 or BLOCK_IPV6 has been specified.");
		}
		else
		{
			config.reply_addr.own_host.overwrite_v6 = true;
			memcpy(&config.reply_addr.own_host.v6, &reply_addr6, sizeof(reply_addr6));
			config.reply_addr.ip_blocking.overwrite_v6 = true;
			memcpy(&config.reply_addr.ip_blocking.v6, &reply_addr6, sizeof(reply_addr6));

			char addr[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &reply_addr6, addr, INET6_ADDRSTRLEN);
			logg("   REPLY_ADDR6: Using IPv6 address %s instead of automatically determined IP address", addr);
		}
	}

	// SHOW_DNSSEC
	// Should FTL analyze and include automatically generated DNSSEC queries in the Query Log?
	// defaults to: true
	buffer = parse_FTLconf(fp, "SHOW_DNSSEC");
	config.show_dnssec = read_bool(buffer, true);

	if(config.show_dnssec)
		logg("   SHOW_DNSSEC: Enabled, showing automatically generated DNSSEC queries");
	else
		logg("   SHOW_DNSSEC: Disabled");

	// MOZILLA_CANARY
	// Should FTL handle use-application-dns.net specifically and always return NXDOMAIN?
	// defaults to: true
	buffer = parse_FTLconf(fp, "MOZILLA_CANARY");
	config.special_domains.mozilla_canary = read_bool(buffer, true);

	if(config.special_domains.mozilla_canary)
		logg("   MOZILLA_CANARY: Enabled");
	else
		logg("   MOZILLA_CANARY: Disabled");

	// PIHOLE_PTR
	// Should FTL return "pi.hole" as name for PTR requests to local IP addresses?
	// defaults to: PI.HOLE
	buffer = parse_FTLconf(fp, "PIHOLE_PTR");

	if(buffer != NULL && (strcasecmp(buffer, "none") == 0 ||
	                      strcasecmp(buffer, "false") == 0))
	{
		config.pihole_ptr = PTR_NONE;
		logg("   PIHOLE_PTR: internal PTR generation disabled");
	}
	else if(buffer != NULL && strcasecmp(buffer, "hostname") == 0)
	{
		config.pihole_ptr = PTR_HOSTNAME;
		logg("   PIHOLE_PTR: internal PTR generation enabled (hostname)");
	}
	else if(buffer != NULL && strcasecmp(buffer, "hostnamefqdn") == 0)
	{
		config.pihole_ptr = PTR_HOSTNAMEFQDN;
		logg("   PIHOLE_PTR: internal PTR generation enabled (fully-qualified hostname)");
	}
	else
	{
		config.pihole_ptr = PTR_PIHOLE;
		logg("   PIHOLE_PTR: internal PTR generation enabled (pi.hole)");
	}

	// ADDR2LINE
	// Should FTL try to call addr2line when generating backtraces?
	// defaults to: true
	buffer = parse_FTLconf(fp, "ADDR2LINE");
	config.addr2line = read_bool(buffer, true);

	if(config.addr2line)
		logg("   ADDR2LINE: Enabled");
	else
		logg("   ADDR2LINE: Disabled");

	// REPLY_WHEN_BUSY
	// How should FTL handle queries when the gravity database is not available?
	// defaults to: DROP
	buffer = parse_FTLconf(fp, "REPLY_WHEN_BUSY");

	if(buffer != NULL && strcasecmp(buffer, "ALLOW") == 0)
	{
		config.reply_when_busy = BUSY_ALLOW;
		logg("   REPLY_WHEN_BUSY: Permit queries when the database is busy");
	}
	else if(buffer != NULL && strcasecmp(buffer, "REFUSE") == 0)
	{
		config.reply_when_busy = BUSY_REFUSE;
		logg("   REPLY_WHEN_BUSY: Refuse queries when the database is busy");
	}
	else if(buffer != NULL && strcasecmp(buffer, "BLOCK") == 0)
	{
		config.reply_when_busy = BUSY_BLOCK;
		logg("   REPLY_WHEN_BUSY: Block queries when the database is busy");
	}
	else
	{
		config.reply_when_busy = BUSY_DROP;
		logg("   REPLY_WHEN_BUSY: Drop queries when the database is busy");
	}

	// BLOCK_TTL
	// defaults to: 2 seconds
	config.block_ttl = 2;
	buffer = parse_FTLconf(fp, "BLOCK_TTL");

	unsigned int uval = 0;
	if(buffer != NULL && sscanf(buffer, "%u", &uval))
		config.block_ttl = uval;

	if(config.block_ttl == 1)
		logg("   BLOCK_TTL: 1 second");
	else
		logg("   BLOCK_TTL: %u seconds", config.block_ttl);

	// BLOCK_ICLOUD_PR
	// Should FTL handle the iCloud privacy relay domains specifically and
	// always return NXDOMAIN?
	// defaults to: true
	buffer = parse_FTLconf(fp, "BLOCK_ICLOUD_PR");
	config.special_domains.icloud_private_relay = read_bool(buffer, true);

	if(config.special_domains.icloud_private_relay)
		logg("   BLOCK_ICLOUD_PR: Enabled");
	else
		logg("   BLOCK_ICLOUD_PR: Disabled");

	// CHECK_LOAD
	// Should FTL check the 15 min average of CPU load and complain if the
	// load is larger than the number of available CPU cores?
	// defaults to: true
	buffer = parse_FTLconf(fp, "CHECK_LOAD");
	config.check.load = read_bool(buffer, true);

	if(config.check.load)
		logg("   CHECK_LOAD: Enabled");
	else
		logg("   CHECK_LOAD: Disabled");

	// CHECK_SHMEM
	// Limit above which FTL should complain about a shared-memory shortage
	// defaults to: 90%
	config.check.shmem = 90;
	buffer = parse_FTLconf(fp, "CHECK_SHMEM");

	if(buffer != NULL &&
	    sscanf(buffer, "%i", &ivalue) &&
	    ivalue >= 0 && ivalue <= 100)
			config.check.shmem = ivalue;

	logg("   CHECK_SHMEM: Warning if shared-memory usage exceeds %d%%", config.check.shmem);

	// CHECK_DISK
	// Limit above which FTL should complain about disk shortage for checked files
	// defaults to: 90%
	config.check.disk = 90;
	buffer = parse_FTLconf(fp, "CHECK_DISK");

	if(buffer != NULL &&
	    sscanf(buffer, "%i", &ivalue) &&
	    ivalue >= 0 && ivalue <= 100)
			config.check.disk = ivalue;

	logg("   CHECK_DISK: Warning if certain disk usage exceeds %d%%", config.check.disk);

	// Read DEBUG_... setting from pihole-FTL.conf
	read_debuging_settings(fp);

	logg("Finished config file parsing");

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

static char *parse_FTLconf(FILE *fp, const char *key)
{
	// Return NULL if fp is an invalid file pointer
	if(fp == NULL)
		return NULL;

	char *keystr = calloc(strlen(key)+2, sizeof(char));
	if(keystr == NULL)
	{
		logg("WARN: parse_FTLconf failed: could not allocate memory for keystr");
		return NULL;
	}
	sprintf(keystr, "%s=", key);

	// Lock mutex
	const int lret = pthread_mutex_lock(&lock);
	if(config.debug & DEBUG_LOCKS)
		logg("Obtained config lock");
	if(lret != 0)
		logg("Error when obtaining config lock: %s", strerror(lret));

	// Go to beginning of file
	fseek(fp, 0L, SEEK_SET);

	if(config.debug & DEBUG_EXTRA)
		logg("initial: conflinebuffer = %p, keystr = %p, size = %zu", conflinebuffer, keystr, size);

	// Set size to zero if conflinebuffer is not available here
	// This causes getline() to allocate memory for the buffer itself
	if(conflinebuffer == NULL && size != 0)
		size = 0;

	errno = 0;
	while(getline(&conflinebuffer, &size, fp) != -1)
	{
		if(config.debug & DEBUG_EXTRA)
		{
			logg("conflinebuffer = %p, keystr = %p, size = %zu", conflinebuffer, keystr, size);
			logg("  while reading line \"%s\" looking for \"%s\"", conflinebuffer, keystr);
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

		// *** MATCH ****

		// Note: value is still a pointer into the conflinebuffer,
		// no need to duplicate memory here
		char *value = find_equals(conflinebuffer) + 1;

		// Trim whitespace at beginning and end, this function modifies
		// the string inplace
		trim_whitespace(value);

		const int uret = pthread_mutex_unlock(&lock);
		if(config.debug & DEBUG_LOCKS)
			logg("Released config lock (match)");
		if(uret != 0)
			logg("Error when releasing config lock (match): %s", strerror(uret));

		// Free keystr memory
		free(keystr);
		return value;
	}

	if(errno == ENOMEM)
		logg("WARN: parse_FTLconf failed: could not allocate memory for getline");

	const int uret = pthread_mutex_unlock(&lock);
	if(config.debug & DEBUG_LOCKS)
		logg("Released config lock (no match)");
	if(uret != 0)
		logg("Error when releasing config lock (no match): %s", strerror(uret));

	// Key not found or memory error -> return NULL
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
	{
		// Check for change and validity of privacy level (set in FTL.h)
		if(value >= PRIVACY_SHOW_ALL &&
		   value <= PRIVACY_MAXIMUM &&
		   value > config.privacylevel)
		{
			logg("Notice: Increasing privacy level from %i to %i", config.privacylevel, value);
			config.privacylevel = value;
		}
	}

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

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
}

// Routine for setting the debug flags in the config struct
static void setDebugOption(FILE* fp, const char* option, enum debug_flags bitmask)
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

	// DEBUG_DATABASE
	// defaults to: false
	setDebugOption(fp, "DEBUG_DATABASE", DEBUG_DATABASE);

	// DEBUG_NETWORKING
	// defaults to: false
	setDebugOption(fp, "DEBUG_NETWORKING", DEBUG_NETWORKING);

	// DEBUG_LOCKS
	// defaults to: false
	setDebugOption(fp, "DEBUG_LOCKS", DEBUG_LOCKS);

	// DEBUG_QUERIES
	// defaults to: false
	setDebugOption(fp, "DEBUG_QUERIES", DEBUG_QUERIES);

	// DEBUG_FLAGS
	// defaults to: false
	setDebugOption(fp, "DEBUG_FLAGS", DEBUG_FLAGS);

	// DEBUG_SHMEM
	// defaults to: false
	setDebugOption(fp, "DEBUG_SHMEM", DEBUG_SHMEM);

	// DEBUG_GC
	// defaults to: false
	setDebugOption(fp, "DEBUG_GC", DEBUG_GC);

	// DEBUG_ARP
	// defaults to: false
	setDebugOption(fp, "DEBUG_ARP", DEBUG_ARP);

	// DEBUG_REGEX or REGEX_DEBUGMODE (legacy config option)
	// defaults to: false
	setDebugOption(fp, "REGEX_DEBUGMODE", DEBUG_REGEX);
	setDebugOption(fp, "DEBUG_REGEX", DEBUG_REGEX);

	// DEBUG_API
	// defaults to: false
	setDebugOption(fp, "DEBUG_API", DEBUG_API);

	// DEBUG_OVERTIME
	// defaults to: false
	setDebugOption(fp, "DEBUG_OVERTIME", DEBUG_OVERTIME);

	// DEBUG_EXTBLOCKED (deprecated, now included in DEBUG_QUERIES)

	// DEBUG_STATUS
	// defaults to: false
	setDebugOption(fp, "DEBUG_STATUS", DEBUG_STATUS);

	// DEBUG_CAPS
	// defaults to: false
	setDebugOption(fp, "DEBUG_CAPS", DEBUG_CAPS);

	// DEBUG_DNSSEC
	// defaults to: false
	setDebugOption(fp, "DEBUG_DNSSEC", DEBUG_DNSSEC);

	// DEBUG_VECTORS
	// defaults to: false
	setDebugOption(fp, "DEBUG_VECTORS", DEBUG_VECTORS);

	// DEBUG_RESOLVER
	// defaults to: false
	setDebugOption(fp, "DEBUG_RESOLVER", DEBUG_RESOLVER);

	// DEBUG_EDNS0
	// defaults to: false
	setDebugOption(fp, "DEBUG_EDNS0", DEBUG_EDNS0);

	// DEBUG_CLIENTS
	// defaults to: false
	setDebugOption(fp, "DEBUG_CLIENTS", DEBUG_CLIENTS);

	// DEBUG_ALIASCLIENTS
	// defaults to: false
	setDebugOption(fp, "DEBUG_ALIASCLIENTS", DEBUG_ALIASCLIENTS);

	// DEBUG_EVENTS
	// defaults to: false
	setDebugOption(fp, "DEBUG_EVENTS", DEBUG_EVENTS);

	// DEBUG_HELPER
	// defaults to: false
	setDebugOption(fp, "DEBUG_HELPER", DEBUG_HELPER);

	// DEBUG_EXTRA
	// defaults to: false
	setDebugOption(fp, "DEBUG_EXTRA", DEBUG_EXTRA);

	if(config.debug)
	{
		logg("*****************************");
		logg("* Debugging enabled         *");
		logg("* DEBUG_DATABASE        %s *", (config.debug & DEBUG_DATABASE)? "YES":"NO ");
		logg("* DEBUG_NETWORKING      %s *", (config.debug & DEBUG_NETWORKING)? "YES":"NO ");
		logg("* DEBUG_LOCKS           %s *", (config.debug & DEBUG_LOCKS)? "YES":"NO ");
		logg("* DEBUG_QUERIES         %s *", (config.debug & DEBUG_QUERIES)? "YES":"NO ");
		logg("* DEBUG_FLAGS           %s *", (config.debug & DEBUG_FLAGS)? "YES":"NO ");
		logg("* DEBUG_SHMEM           %s *", (config.debug & DEBUG_SHMEM)? "YES":"NO ");
		logg("* DEBUG_GC              %s *", (config.debug & DEBUG_GC)? "YES":"NO ");
		logg("* DEBUG_ARP             %s *", (config.debug & DEBUG_ARP)? "YES":"NO ");
		logg("* DEBUG_REGEX           %s *", (config.debug & DEBUG_REGEX)? "YES":"NO ");
		logg("* DEBUG_API             %s *", (config.debug & DEBUG_API)? "YES":"NO ");
		logg("* DEBUG_OVERTIME        %s *", (config.debug & DEBUG_OVERTIME)? "YES":"NO ");
		logg("* DEBUG_STATUS          %s *", (config.debug & DEBUG_STATUS)? "YES":"NO ");
		logg("* DEBUG_CAPS            %s *", (config.debug & DEBUG_CAPS)? "YES":"NO ");
		logg("* DEBUG_VECTORS         %s *", (config.debug & DEBUG_VECTORS)? "YES":"NO ");
		logg("* DEBUG_RESOLVER        %s *", (config.debug & DEBUG_RESOLVER)? "YES":"NO ");
		logg("* DEBUG_EDNS0           %s *", (config.debug & DEBUG_EDNS0)? "YES":"NO ");
		logg("* DEBUG_CLIENTS         %s *", (config.debug & DEBUG_CLIENTS)? "YES":"NO ");
		logg("* DEBUG_ALIASCLIENTS    %s *", (config.debug & DEBUG_ALIASCLIENTS)? "YES":"NO ");
		logg("* DEBUG_EVENTS          %s *", (config.debug & DEBUG_EVENTS)? "YES":"NO ");
		logg("* DEBUG_HELPER          %s *", (config.debug & DEBUG_HELPER)? "YES":"NO ");
		logg("* DEBUG_EXTRA           %s *", (config.debug & DEBUG_EXTRA)? "YES":"NO ");
		logg("*****************************");

		// Enable debug logging in dnsmasq (only effective before starting the resolver)
		argv_dnsmasq[2] = "--log-debug";
	}

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
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
		logg("   NICE: Not changing nice value");
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
		logg("   NICE: Cannot change niceness to %d (permission denied)",
		     nice_target);
		return;
	}
	if(nice_set == nice_target)
	{
		logg("   NICE: Set process niceness to %d%s",
		     nice_set, (nice_set == fallback) ? " (default)" : "");
	}
	else
	{
		logg("   NICE: Set process niceness to %d (asked for %d)",
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
