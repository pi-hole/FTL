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
#include "legacy_reader.h"
#include "config.h"
#include "setupVars.h"
#include "log.h"
// nice()
#include <unistd.h>
// argv_dnsmasq
#include "args.h"
// INT_MAX
#include <limits.h>

// Private global variables
static char *conflinebuffer = NULL;
static size_t size = 0;
static pthread_mutex_t lock;

// Private prototypes
static char *parseFTLconf(FILE *fp, const char * key);
static void releaseConfigMemory(void);
static void getPath(FILE* fp, const char *option, char **ptr);
static void setnice(const char *buffer, int fallback);
static bool parseBool(const char *option, bool *ptr);
static void readDebugingSettingsLegacy(FILE *fp);
static void getBlockingModeLegacy(FILE *fp);
static void getPrivacyLevelLegacy(FILE *fp);

static FILE *openFTLconf(const char **path)
{
	FILE *fp;
	// First check if there is a local file overwriting the global one
	*path = "pihole-FTL.conf";
	if((fp = fopen(*path, "r")) != NULL)
		return fp;

	// Local file not present, try system file
	*path = "/etc/pihole/pihole-FTL.conf";
	fp = fopen(*path, "r");

	return fp;
}

bool getLogFilePathLegacy(FILE *fp)
{
	const char *path = NULL;
	if(fp == NULL)
		fp = openFTLconf(&path);
	if(fp == NULL)
		return false;

	// Read LOGFILE value if available
	// defaults to: "/var/log/pihole-FTL.log"
	char *buffer = parseFTLconf(fp, "LOGFILE");

	errno = 0;
	// No option set => use default log location
	if(buffer == NULL)
	{
		// Use standard path if no custom path was obtained from the config file
		config.files.log = strdup("/var/log/pihole-FTL.log");

		// Test if memory allocation was successful
		if(config.files.log == NULL)
		{
			printf("FATAL: Allocating memory for config.files.log failed (%s, %i). Exiting.",
			       strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
	}
	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	else if(sscanf(buffer, "%127ms", &config.files.log) == 0)
	{
		// Empty file string
		config.files.log = NULL;
		log_info("Using syslog facility");
	}

	fclose(fp);
	return true;
}

// Returns which file was read
const char *readFTLlegacy(void)
{
	char *buffer;
	const char *path = NULL;
	FILE *fp = openFTLconf(&path);
	if(fp == NULL)
		return NULL;

	log_notice("Reading legacy config file");

	// SOCKET_LISTENING
	// defaults to: listen only local
	buffer = parseFTLconf(fp, "SOCKET_LISTENING");

	if(buffer != NULL && strcasecmp(buffer, "all") == 0)
		config.socket_listenlocal = false;

	// AAAA_QUERY_ANALYSIS
	// defaults to: Yes
	buffer = parseFTLconf(fp, "AAAA_QUERY_ANALYSIS");
	parseBool(buffer, &config.analyze_AAAA);

	// MAXDBDAYS
	// defaults to: 365 days
	buffer = parseFTLconf(fp, "MAXDBDAYS");

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

	// RESOLVE_IPV6
	// defaults to: Yes
	buffer = parseFTLconf(fp, "RESOLVE_IPV6");
	parseBool(buffer, &config.resolveIPv6);

	// RESOLVE_IPV4
	// defaults to: Yes
	buffer = parseFTLconf(fp, "RESOLVE_IPV4");
	parseBool(buffer, &config.resolveIPv4);

	// DBINTERVAL
	// How often do we store queries in FTL's database [minutes]?
	// this value can be a floating point number, e.g. "DBINTERVAL=0.5"
	// defaults to: once per minute
	buffer = parseFTLconf(fp, "DBINTERVAL");

	float fvalue = 0;
	if(buffer != NULL && sscanf(buffer, "%f", &fvalue))
		// check if the read value is
		// - larger than 0.1min (6sec), and
		// - smaller than 1440.0min (once a day)
		if(fvalue >= 0.1f && fvalue <= 1440.0f)
			config.DBinterval = (int)(fvalue * 60);

	// DBFILE
	// defaults to: "/etc/pihole/pihole-FTL.db"
	buffer = parseFTLconf(fp, "DBFILE");

	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	if(!(buffer != NULL && sscanf(buffer, "%127ms", &config.files.database)))
	{
		// Use standard path if no custom path was obtained from the config file
		config.files.database = strdup(defaults.files.database);
	}

	if(config.files.database == NULL || strlen(config.files.database) == 0)
	{
		// Use standard path if path was set to zero but override
		// MAXDBDAYS=0 to ensure no queries are stored in the database
		config.files.database = strdup(defaults.files.database);
		config.maxDBdays = 0;
	}

	// MAXLOGAGE
	// Up to how many hours in the past should queries be imported from the database?
	// defaults to: 24.0 via MAXLOGAGE defined in FTL.h
	buffer = parseFTLconf(fp, "MAXLOGAGE");

	fvalue = 0;
	if(buffer != NULL && sscanf(buffer, "%f", &fvalue))
	{
		if(fvalue >= 0.0f && fvalue <= 1.0f*MAXLOGAGE)
			config.maxHistory = (int)(fvalue * 3600);
	}

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
	getPrivacyLevelLegacy(fp);

	// IGNORE_LOCALHOST
	// defaults to: false
	buffer = parseFTLconf(fp, "IGNORE_LOCALHOST");
	parseBool(buffer, &config.ignore_localhost);

	if(buffer != NULL && strcasecmp(buffer, "yes") == 0)
		config.ignore_localhost = true;

	// BLOCKINGMODE
	// defaults to: MODE_IP
	getBlockingModeLegacy(fp);

	// ANALYZE_ONLY_A_AND_AAAA
	// defaults to: false
	buffer = parseFTLconf(fp, "ANALYZE_ONLY_A_AND_AAAA");
	parseBool(buffer, &config.analyze_only_A_AAAA);

	if(buffer != NULL && strcasecmp(buffer, "true") == 0)
		config.analyze_only_A_AAAA = true;

	// DBIMPORT
	// defaults to: Yes
	buffer = parseFTLconf(fp, "DBIMPORT");
	parseBool(buffer, &config.DBimport);

	// PIDFILE
	getPath(fp, "PIDFILE", &config.files.pid);

	// SETUPVARSFILE
	getPath(fp, "SETUPVARSFILE", &config.files.setupVars);

	// MACVENDORDB
	getPath(fp, "MACVENDORDB", &config.files.macvendor);

	// GRAVITYDB
	getPath(fp, "GRAVITYDB", &config.files.gravity);

	// PARSE_ARP_CACHE
	// defaults to: true
	buffer = parseFTLconf(fp, "PARSE_ARP_CACHE");
	parseBool(buffer, &config.parse_arp_cache);

	// CNAME_DEEP_INSPECT
	// defaults to: true
	buffer = parseFTLconf(fp, "CNAME_DEEP_INSPECT");
	parseBool(buffer, &config.cname_deep_inspection);

	// DELAY_STARTUP
	// defaults to: zero (seconds)
	buffer = parseFTLconf(fp, "DELAY_STARTUP");
	config.delay_startup = defaults.delay_startup;

	unsigned int unum;
	if(buffer != NULL && sscanf(buffer, "%u", &unum) && unum > 0 && unum <= 300)
		config.delay_startup = unum;

	// BLOCK_ESNI
	// defaults to: true
	buffer = parseFTLconf(fp, "BLOCK_ESNI");
	parseBool(buffer, &config.blockESNI);

	// WEBROOT
	getPath(fp, "WEBROOT", &config.http.paths.webroot);

	// WEBPORT
	// On which port should FTL's API be listening?
	// defaults to: 8080
	buffer = parseFTLconf(fp, "WEBPORT");

	value = 0;
	if(buffer != NULL && strlen(buffer) > 0)
		config.http.port = strdup(buffer);

	// WEBHOME
	// From which sub-directory is the web interface served from?
	// Defaults to: /admin/ (both slashes are needed!)
	getPath(fp, "WEBHOME", &config.http.paths.webhome);

	// WEBACL
	// Default: allow all access
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
	buffer = parseFTLconf(fp, "WEBACL");
	if(buffer != NULL)
		config.http.acl = strdup(buffer);

	// API_AUTH_FOR_LOCALHOST
	// defaults to: true
	buffer = parseFTLconf(fp, "API_AUTH_FOR_LOCALHOST");
	parseBool(buffer, &config.http.localAPIauth);

	// API_SESSION_TIMEOUT
	// How long should a session be considered valid after login?
	// defaults to: 300 seconds
	buffer = parseFTLconf(fp, "API_SESSION_TIMEOUT");

	value = 0;
	if(buffer != NULL && sscanf(buffer, "%i", &value) && value > 0)
		config.http.sessionTimeout = value;

	// API_PRETTY_JSON
	// defaults to: false
	buffer = parseFTLconf(fp, "API_PRETTY_JSON");
	parseBool(buffer, &config.http.prettyJSON);

	// API_ERROR_LOG
	getPath(fp, "API_ERROR_LOG", &config.files.ph7_error);

	// API_INFO_LOG
	getPath(fp, "API_INFO_LOG", &config.files.http_info);

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
	buffer = parseFTLconf(fp, "NICE");
	setnice(buffer, defaults.nice);

	// MAXNETAGE
	// IP addresses (and associated host names) older than the specified number
	// of days are removed to avoid dead entries in the network overview table
	// defaults to: the same value as MAXDBDAYS
	buffer = parseFTLconf(fp, "MAXNETAGE");

	int ivalue = 0;
	if(buffer != NULL &&
	    sscanf(buffer, "%i", &ivalue) &&
	    ivalue > 0 && ivalue <= 8760) // 8760 days = 24 years
			config.network_expire = ivalue;

	// NAMES_FROM_NETDB
	// Should we use the fallback option to try to obtain client names from
	// checking the network table? Assume this is an IPv6 client without a
	// host names itself but the network table tells us that this is the same
	// device where we have a host names for its IPv4 address. In this case,
	// we use the host name associated to the other address as this is the same
	// device. This behavior can be disabled using NAMES_FROM_NETDB=false
	// defaults to: true
	buffer = parseFTLconf(fp, "NAMES_FROM_NETDB");
	parseBool(buffer, &config.networkNames);

	// EDNS0_ECS
	// Should we overwrite the query source when client information is
	// provided through EDNS0 client subnet (ECS) information?
	// defaults to: true
	buffer = parseFTLconf(fp, "EDNS0_ECS");
	parseBool(buffer, &config.edns0_ecs);

	// REFRESH_HOSTNAMES
	// defaults to: IPV4
	buffer = parseFTLconf(fp, "REFRESH_HOSTNAMES");

	if(buffer != NULL && strcasecmp(buffer, "ALL") == 0)
		config.refresh_hostnames = REFRESH_ALL;
	else if(buffer != NULL && strcasecmp(buffer, "NONE") == 0)
		config.refresh_hostnames = REFRESH_NONE;
	else if(buffer != NULL && strcasecmp(buffer, "UNKNOWN") == 0)
		config.refresh_hostnames = REFRESH_UNKNOWN;
	else
		config.refresh_hostnames = REFRESH_IPV4_ONLY;

	// WEBDOMAIN
	getPath(fp, "WEBDOMAIN", &config.http.domain);

	// RATE_LIMIT
	// defaults to: 1000 queries / 60 seconds
	buffer = parseFTLconf(fp, "RATE_LIMIT");

	unsigned int count = 0, interval = 0;
	if(buffer != NULL && sscanf(buffer, "%u/%u", &count, &interval) == 2)
	{
		config.rate_limit.count = count;
		config.rate_limit.interval = interval;
	}

	// REPLY_ADDR4
	// Use a specific IP address instead of automatically detecting the
	// IPv4 interface address a query arrived on
	// defaults to: not set
	buffer = parseFTLconf(fp, "REPLY_ADDR4");
	if(buffer != NULL && inet_pton(AF_INET, buffer, &config.reply_addr.v4))
		config.reply_addr.overwrite_v4 = true;

	if(config.reply_addr.overwrite_v4)
	{
		char addr[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &config.reply_addr.v4, addr, INET_ADDRSTRLEN);
	}

	// REPLY_ADDR6
	// Use a specific IP address instead of automatically detecting the
	// IPv6 interface address a query arrived on
	// defaults to: not set
	buffer = parseFTLconf(fp, "REPLY_ADDR6");
	if(buffer != NULL && inet_pton(AF_INET6, buffer, &config.reply_addr.v6))
		config.reply_addr.overwrite_v6 = true;

	if(config.reply_addr.overwrite_v6)
	{
		char addr[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, &config.reply_addr.v6, addr, INET6_ADDRSTRLEN);
	}

	// SHOW_DNSSEC
	// Should FTL analyze and include automatically generated DNSSEC queries in the Query Log?
	// defaults to: true
	buffer = parseFTLconf(fp, "SHOW_DNSSEC");
	parseBool(buffer, &config.show_dnssec);

	// MOZILLA_CANARY
	// Should FTL handle use-application-dns.net specifically and always return NXDOMAIN?
	// defaults to: true
	buffer = parseFTLconf(fp, "MOZILLA_CANARY");
	parseBool(buffer, &config.special_domains.mozilla_canary);

	// PIHOLE_PTR
	// Should FTL return "pi.hole" as name for PTR requests to local IP addresses?
	// defaults to: true
	buffer = parseFTLconf(fp, "PIHOLE_PTR");

	if(buffer != NULL)
	{
		if(strcasecmp(buffer, "none") == 0 ||
		   strcasecmp(buffer, "false") == 0)
			config.pihole_ptr = PTR_NONE;
		else if(strcasecmp(buffer, "hostname") == 0)
			config.pihole_ptr = PTR_HOSTNAME;
		else if(strcasecmp(buffer, "hostnamefqdn") == 0)
			config.pihole_ptr = PTR_HOSTNAMEFQDN;
	}

	// ADDR2LINE
	// Should FTL try to call addr2line when generating backtraces?
	// defaults to: true
	buffer = parseFTLconf(fp, "ADDR2LINE");
	parseBool(buffer, &config.addr2line);

	// REPLY_WHEN_BUSY
	// How should FTL handle queries when the gravity database is not available?
	// defaults to: BLOCK
	buffer = parseFTLconf(fp, "REPLY_WHEN_BUSY");

	if(buffer != NULL)
	{
		if(strcasecmp(buffer, "DROP") == 0)
			config.reply_when_busy = BUSY_DROP;
		else if(strcasecmp(buffer, "REFUSE") == 0)
			config.reply_when_busy = BUSY_REFUSE;
		else if(strcasecmp(buffer, "BLOCK") == 0)
			config.reply_when_busy = BUSY_BLOCK;
	}

	// BLOCK_TTL
	// defaults to: 2 seconds
	config.block_ttl = 2;
	buffer = parseFTLconf(fp, "BLOCK_TTL");

	unsigned int uval = 0;
	if(buffer != NULL && sscanf(buffer, "%u", &uval))
		config.block_ttl = uval;

	// BLOCK_ICLOUD_PR
	// Should FTL handle the iCloud privacy relay domains specifically and
	// always return NXDOMAIN??
	// defaults to: true
	buffer = parseFTLconf(fp, "BLOCK_ICLOUD_PR");
	parseBool(buffer, &config.special_domains.icloud_private_relay);

	// CHECK_LOAD
	// Should FTL check the 15 min average of CPU load and complain if the
	// load is larger than the number of available CPU cores?
	// defaults to: true
	buffer = parseFTLconf(fp, "CHECK_LOAD");
	parseBool(buffer, &config.check.load);

	// CHECK_SHMEM
	// Limit above which FTL should complain about a shared-memory shortage
	// defaults to: 90%
	config.check.shmem = 90;
	buffer = parseFTLconf(fp, "CHECK_SHMEM");

	if(buffer != NULL && sscanf(buffer, "%i", &ivalue) &&
	   ivalue >= 0 && ivalue <= 100)
		config.check.shmem = ivalue;

	// CHECK_DISK
	// Limit above which FTL should complain about disk shortage for checked files
	// defaults to: 90%
	config.check.disk = 90;
	buffer = parseFTLconf(fp, "CHECK_DISK");

	if(buffer != NULL && sscanf(buffer, "%i", &ivalue) &&
	   ivalue >= 0 && ivalue <= 100)
			config.check.disk = ivalue;

	// Read DEBUG_... setting from pihole-FTL.conf
	// This option should be the last one as it causes
	// some rather verbose output into the log when
	// listing all the enabled/disabled debugging options
	readDebugingSettingsLegacy(fp);

	// Release memory
	releaseConfigMemory();

	if(fp != NULL)
		fclose(fp);

	return path;
}

static void getPath(FILE* fp, const char *option, char **ptr)
{
	// This subroutine is used to read paths from pihole-FTL.conf
	// fp:         File ptr to opened and readable config file
	// option:     Option string ("key") to try to read
	// defaultloc: Value used if key is not found in file
	// ptr:        Location where read (or default) parameter is stored
	char *buffer = parseFTLconf(fp, option);

	errno = 0;
	// Use sscanf() to obtain filename from config file parameter only if buffer != NULL
	if(buffer == NULL || sscanf(buffer, "%127ms", ptr) != 1)
	{
		// Use standard path if no custom path was obtained from the config file
		return;
	}

	// Test if memory allocation was successful
	if(*ptr == NULL)
	{
		log_crit("Allocating memory for %s failed (%s, %i). Exiting.", option, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	else if(strlen(*ptr) == 0)
	{
		log_info("   %s: Empty path is not possible, using default",
		         option);
	}
}

static char *parseFTLconf(FILE *fp, const char * key)
{
	// Return NULL if fp is an invalid file pointer
	if(fp == NULL)
		return NULL;

	char *keystr = calloc(strlen(key)+2, sizeof(char));
	if(keystr == NULL)
	{
		log_crit("Could not allocate memory (keystr) in parseFTLconf()");
		return NULL;
	}
	sprintf(keystr, "%s=", key);

	// Lock mutex
	const int lret = pthread_mutex_lock(&lock);
	log_debug(DEBUG_LOCKS, "Obtained config lock");
	if(lret != 0)
		log_err("Error when obtaining config lock: %s", strerror(lret));

	// Go to beginning of file
	fseek(fp, 0L, SEEK_SET);

	errno = 0;
	while(getline(&conflinebuffer, &size, fp) != -1)
	{
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
		//       its memory will get released in releaseConfigMemory()
		char *value = find_equals(conflinebuffer) + 1;
		// Trim whitespace at beginning and end, this function
		// modifies the string inplace
		trim_whitespace(value);

		const int uret = pthread_mutex_unlock(&lock);
		log_debug(DEBUG_LOCKS, "Released config lock (match)");
		if(uret != 0)
			log_err("Error when releasing config lock (no match): %s", strerror(uret));

		return value;
	}

	if(errno == ENOMEM)
		log_crit("Could not allocate memory (getline) in parseFTLconf()");

	const int uret = pthread_mutex_unlock(&lock);
	log_debug(DEBUG_LOCKS, "Released config lock (no match)");
	if(uret != 0)
		log_err("Error when releasing config lock (no match): %s", strerror(uret));

	// Free keystr memory
	free(keystr);

	// Key not found or memory error -> return NULL
	return NULL;
}

void releaseConfigMemory(void)
{
	if(conflinebuffer != NULL)
	{
		free(conflinebuffer);
		conflinebuffer = NULL;
		size = 0;
	}
}

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

static void getPrivacyLevelLegacy(FILE *fp)
{
	// See if we got a file handle, if not we have to open
	// the config file ourselves
	bool opened = false;
	const char *path = NULL;
	if(fp == NULL)
	{
		if((fp = openFTLconf(&path)) == NULL)
			// Return silently if there is no config file available
			return;
		opened = true;
	}

	int value = 0;
	char *buffer = parseFTLconf(fp, "PRIVACYLEVEL");
	if(buffer != NULL && sscanf(buffer, "%i", &value) == 1)
	{
		// Check for change and validity of privacy level (set in FTL.h)
		if(value >= PRIVACY_SHOW_ALL &&
		   value <= PRIVACY_MAXIMUM &&
		   value > config.privacylevel)
		{
			config.privacylevel = value;
		}
	}

	// Release memory
	releaseConfigMemory();

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
}

static void getBlockingModeLegacy(FILE *fp)
{
	// Set default value
	config.blockingmode = defaults.blockingmode;

	// See if we got a file handle, if not we have to open
	// the config file ourselves
	bool opened = false;
	const char *path = NULL;
	if(fp == NULL)
	{
		if((fp = openFTLconf(&path)) == NULL)
			// Return silently if there is no config file available
			return;
		opened = true;
	}

	// Get config string (if present)
	char *buffer = parseFTLconf(fp, "BLOCKINGMODE");
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
	releaseConfigMemory();

	// Have to close the config file if we opened it
	if(opened)
		fclose(fp);
}

// Routine for setting the debug flags in the config struct
static void setDebugOption(FILE* fp, const char* option, enum debug_flag bitmask)
{
	const char *buffer = parseFTLconf(fp, option);

	// Return early if the key has not been found in FTL's config file
	if(buffer == NULL)
		return;

	// Set bit if value equals "true", clear bit otherwise
	bool bit = false;
	if(parseBool(buffer, &bit))
	{
		if(bit)
			config.debug |= bitmask;
		else
			config.debug &= ~bitmask;
	}
}

static void readDebugingSettingsLegacy(FILE *fp)
{
	// Set default (no debug instructions set)
	config.debug = 0;

	// See if we got a file handle, if not we have to open
	// the config file ourselves
	bool opened = false;
	const char *path = NULL;
	if(fp == NULL)
	{
		if((fp = openFTLconf(&path)) == NULL)
			// Return silently if there is no config file available
			return;
		opened = true;
	}

	// DEBUG_ALL
	// defaults to: false
	// ~0 is a shortcut for "all bits set"
	setDebugOption(fp, "DEBUG_ALL", ~(enum debug_flag)0);

	for(enum debug_flag flag = DEBUG_DATABASE; flag < DEBUG_EXTRA; flag <<= 1)
	{
		// DEBUG_DATABASE
		const char *name, *desc;
		debugstr(flag, &name, &desc);
		setDebugOption(fp, name, flag);
	}

	if(config.debug != 0)
	{
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
		releaseConfigMemory();
	}
}

static void setnice(const char *buffer, const int fallback)
{
	int value, nice_set, nice_target = fallback;

	// Try to read niceness value
	// Attempts to set a nice value outside the range are clamped to the range.
	if(buffer != NULL && sscanf(buffer, "%i", &value) == 1)
		nice_target = value;

	config.nice = nice_target;

	// Skip setting niceness if set to -999
	if(nice_target == -999)
		return;

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
}

// Returns true if we found a setting
static bool parseBool(const char *option, bool *ptr)
{
	if(option == NULL)
		return false;

	else if(strcasecmp(option, "false") == 0 ||
	        strcasecmp(option, "no") == 0)
	{
		*ptr = false;
		return true;
	}

	else if(strcasecmp(option, "true") == 0 ||
	        strcasecmp(option, "yes") == 0)
	{
		*ptr = true;
		return true;
	}

	return false;
}
