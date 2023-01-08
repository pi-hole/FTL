/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "config.h"
#include "toml_reader.h"
#include "toml_writer.h"
#include "../setupVars.h"
#include "../log.h"
#include "../log.h"
// readFTLlegacy()
#include "legacy_reader.h"
// file_exists()
#include "../files.h"

struct config config = { 0 };
int dns_port = -1;

void set_all_debug(const bool status)
{
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(i);

		// Skip config entries whose path's are not starting in "debug."
		if(strcmp("debug", conf_item->p[0]) != 0)
			continue;

		// Set status
		conf_item->v.b = status;
	}

	// Update debug flags
	set_debug_flags();
}

// Extract and store key from full path
static char **gen_config_path(const char *pathin)
{
	char *path = (char*)pathin;
	char *saveptr = path;

	// Allocate memory for the path elements
	char **paths = calloc(MAX_CONFIG_PATH_DEPTH, sizeof(char*));

	// Sanity check
	if(!pathin)
	{
		log_err("Config path is empty");
		return paths;
	}

	size_t pathlen = 0;
	// Extract all path elements
	while(*path != '\0')
	{
		// Advance to either the next delimiter
		// But only until the end of the string
		while(*path != '.' && *path != '\0')
			path++;

		// Get length of the extracted string
		size_t len = path - saveptr;
		// Create a private copy of this element in the chain of elements
		paths[pathlen] = calloc(len + 1, sizeof(char));
		// No need to NULL-terminate, strncpy does this for us
		strncpy(paths[pathlen], saveptr, len);

		// Did we reach the end of the string?
		if(*path == '\0')
			break;

		// Advance to next character
		saveptr = ++path;
		// Advance to next path element
		pathlen++;

		// Safetly measure: Exit if this path is too deep
		if(pathlen > MAX_CONFIG_PATH_DEPTH-1)
			break;
	}

	return paths;
}

struct conf_item *get_conf_item(const unsigned int n)
{
	// Sanity check
	if(n > CONFIG_ELEMENTS-1)
	{
		log_err("Config item with index %u requested but we have only %u elements", n, (unsigned int)CONFIG_ELEMENTS-1);
		return NULL;
	}

	// Return n-th config element
	return (void*)&config + n*sizeof(struct conf_item);
}

struct conf_item *get_debug_item(const enum debug_flag debug)
{
	// Sanity check
	if(debug > DEBUG_MAX-1)
	{
		log_err("Debug config item with index %u requested but we have only %u debug elements", debug, DEBUG_MAX-1);
		return NULL;
	}

	// Return n-th config element
	return (void*)&config.debug + debug*sizeof(struct conf_item);
}

unsigned int __attribute__ ((pure)) config_path_depth(struct conf_item *conf_item)
{
	// Determine depth of this config path
	for(unsigned int i = 0; i < MAX_CONFIG_PATH_DEPTH; i++)
		if(conf_item->p[i] == NULL)
			return i;

	// This should never happen as we have a maximum depth of
	// MAX_CONFIG_PATH_DEPTH
	return MAX_CONFIG_PATH_DEPTH;

}

void initConfig(void)
{
	// struct dns
	config.dns.CNAMEdeepInspect.k = "dns.CNAMEdeepInspect";
	config.dns.CNAMEdeepInspect.h = "Should FTL walk CNAME paths?";
	config.dns.CNAMEdeepInspect.t = CONF_BOOL;
	config.dns.CNAMEdeepInspect.d.b = true;

	config.dns.blockESNI.k = "dns.blockESNI";
	config.dns.blockESNI.h = "Should _esni. subdomains be blocked by default?";
	config.dns.blockESNI.t = CONF_BOOL;
	config.dns.blockESNI.d.b = true;

	config.dns.EDNS0ECS.k = "dns.EDNS0ECS";
	config.dns.EDNS0ECS.h = "Should FTL analyze possible ECS information to obtain client IPs hidden behind NATs?";
	config.dns.EDNS0ECS.t = CONF_BOOL;
	config.dns.EDNS0ECS.d.b = true;

	config.dns.ignoreLocalhost.k = "dns.ignoreLocalhost";
	config.dns.ignoreLocalhost.h = "Should FTL hide queries made by localhost?";
	config.dns.ignoreLocalhost.t = CONF_BOOL;
	config.dns.ignoreLocalhost.d.b = false;

	config.dns.showDNSSEC.k = "dns.showDNSSEC";
	config.dns.showDNSSEC.h = "Should FTL should internally generated DNSSEC queries?";
	config.dns.showDNSSEC.t = CONF_BOOL;
	config.dns.showDNSSEC.d.b = true;

	config.dns.analyzeAAAA.k = "dns.analyzeAAAA";
	config.dns.analyzeAAAA.h = "Should FTL analyze AAAA queries?";
	config.dns.analyzeAAAA.t = CONF_BOOL;
	config.dns.analyzeAAAA.d.b = true;

	config.dns.analyzeOnlyAandAAAA.k = "dns.analyzeOnlyAandAAAA";
	config.dns.analyzeOnlyAandAAAA.h = "Should FTL analyze *only* A and AAAA queries?";
	config.dns.analyzeOnlyAandAAAA.t = CONF_BOOL;
	config.dns.analyzeOnlyAandAAAA.d.b = false;

	config.dns.piholePTR.k = "dns.piholePTR";
	config.dns.piholePTR.h = "Should FTL return \"pi.hole\" as name for PTR requests to local IP addresses?";
	config.dns.piholePTR.a = "[ \"NONE\", \"HOSTNAME\", \"HOSTNAMEFQDN\", \"PI.HOLE\" ]";
	config.dns.piholePTR.t = CONF_ENUM_PTR_TYPE;
	config.dns.piholePTR.d.ptr_type = PTR_PIHOLE;

	config.dns.replyWhenBusy.k = "dns.replyWhenBusy";
	config.dns.replyWhenBusy.h = "How should FTL handle queries when the gravity database is not available?";
	config.dns.replyWhenBusy.a = "[ \"BLOCK\", \"ALLOW\", \"REFUSE\", \"DROP\" ]";
	config.dns.replyWhenBusy.t = CONF_ENUM_BUSY_TYPE;
	config.dns.replyWhenBusy.d.busy_reply = BUSY_ALLOW;

	config.dns.blockTTL.k = "dns.blockTTL";
	config.dns.blockTTL.h = "TTL for blocked queries [seconds]";
	config.dns.blockTTL.t = CONF_UINT;
	config.dns.blockTTL.d.ui = 2;

	config.dns.blockingmode.k = "dns.blockingmode";
	config.dns.blockingmode.h = "How should FTL reply to blocked queries?";
	config.dns.blockingmode.a = "[ \"NULL\", \"IP-NODATA-AAAA\", \"IP\", \"NXDOMAIN\", \"NODATA\" ]";
	config.dns.blockingmode.t = CONF_ENUM_BLOCKING_MODE;
	config.dns.blockingmode.d.blocking_mode = MODE_NULL;

	// sub-struct dns.rate_limit
	config.dns.rateLimit.count.k = "dns.rateLimit.count";
	config.dns.rateLimit.count.h = "How many queries are permitted...";
	config.dns.rateLimit.count.t = CONF_UINT;
	config.dns.rateLimit.count.d.ui = 1000;

	config.dns.rateLimit.interval.k = "dns.rateLimit.interval";
	config.dns.rateLimit.interval.h = "... in the set interval before rate-limiting?";
	config.dns.rateLimit.interval.t = CONF_UINT;
	config.dns.rateLimit.interval.d.ui = 60;

	// sub-struct dns.special_domains
	config.dns.specialDomains.mozillaCanary.k = "dns.specialDomains.mozillaCanary";
	config.dns.specialDomains.mozillaCanary.h = "Should FTL handle use-application-dns.net specifically and always return NXDOMAIN?";
	config.dns.specialDomains.mozillaCanary.t = CONF_BOOL;
	config.dns.specialDomains.mozillaCanary.d.b = true;

	config.dns.specialDomains.iCloudPrivateRelay.k = "dns.specialDomains.iCloudPrivateRelay";
	config.dns.specialDomains.iCloudPrivateRelay.h = "Should FTL handle the iCloud privacy relay domains specifically and always return NXDOMAIN?";
	config.dns.specialDomains.iCloudPrivateRelay.t = CONF_BOOL;
	config.dns.specialDomains.iCloudPrivateRelay.d.b = true;

	// sub-struct dns.reply_addr
	config.dns.reply.host.overwrite_v4.k = "dns.reply.host.overwrite_v4";
	config.dns.reply.host.overwrite_v4.h = "Use a specific IPv4 address for the Pi-hole host?";
	config.dns.reply.host.overwrite_v4.t = CONF_BOOL;
	config.dns.reply.host.overwrite_v4.d.b = false;

	config.dns.reply.host.v4.k = "dns.reply.host.IPv4";
	config.dns.reply.host.v4.h = "Custom IPv4 address for the Pi-hole host";
	config.dns.reply.host.v4.a = "<valid IPv4 address> or empty string (\"\")";
	config.dns.reply.host.v4.t = CONF_STRUCT_IN_ADDR;
	memset(&config.dns.reply.host.v4.d.in_addr, 0, sizeof(struct in_addr));

	config.dns.reply.host.overwrite_v6.k = "dns.reply.host.overwrite_v6";
	config.dns.reply.host.overwrite_v6.h = "Use a specific IPv6 address for the Pi-hole host?";
	config.dns.reply.host.overwrite_v6.t = CONF_BOOL;
	config.dns.reply.host.overwrite_v6.d.b = false;

	config.dns.reply.host.v6.k = "dns.reply.host.IPv6";
	config.dns.reply.host.v6.h = "Custom IPv6 address for the Pi-hole host";
	config.dns.reply.host.v6.a = "<valid IPv6 address> or empty string (\"\")";
	config.dns.reply.host.v6.t = CONF_STRUCT_IN6_ADDR;
	memset(&config.dns.reply.host.v6.d.in6_addr, 0, sizeof(struct in6_addr));

	config.dns.reply.blocking.overwrite_v4.k = "dns.reply.blocking.overwrite_v4";
	config.dns.reply.blocking.overwrite_v4.h = "Use a specific IPv4 address in IP blocking mode?";
	config.dns.reply.blocking.overwrite_v4.t = CONF_BOOL;
	config.dns.reply.blocking.overwrite_v4.d.b = false;

	config.dns.reply.blocking.v4.k = "dns.reply.blocking.IPv4";
	config.dns.reply.blocking.v4.h = "Custom IPv4 address for IP blocking mode";
	config.dns.reply.blocking.v4.a = "<valid IPv4 address> or empty string (\"\")";
	config.dns.reply.blocking.v4.t = CONF_STRUCT_IN_ADDR;
	memset(&config.dns.reply.blocking.v4.d.in_addr, 0, sizeof(struct in_addr));

	config.dns.reply.blocking.overwrite_v6.k = "dns.reply.blocking.overwrite_v6";
	config.dns.reply.blocking.overwrite_v6.h = "Use a specific IPv6 address in IP blocking mode?";
	config.dns.reply.blocking.overwrite_v6.t = CONF_BOOL;
	config.dns.reply.blocking.overwrite_v6.d.b = false;

	config.dns.reply.blocking.v6.k = "dns.reply.blocking.IPv6";
	config.dns.reply.blocking.v6.h = "Custom IPv6 address for IP blocking mode";
	config.dns.reply.blocking.v6.a = "<valid IPv6 address> or empty string (\"\")";
	config.dns.reply.blocking.v6.t = CONF_STRUCT_IN6_ADDR;
	memset(&config.dns.reply.blocking.v6.d.in6_addr, 0, sizeof(struct in6_addr));


	// struct resolver
	config.resolver.resolveIPv6.k = "resolver.resolveIPv6";
	config.resolver.resolveIPv6.h = "Should FTL try to resolve IPv6 addresses to hostnames?";
	config.resolver.resolveIPv6.t = CONF_BOOL;
	config.resolver.resolveIPv6.d.b = true;

	config.resolver.resolveIPv4.k = "resolver.resolveIPv4";
	config.resolver.resolveIPv4.h = "Should FTL try to resolve IPv4 addresses to hostnames?";
	config.resolver.resolveIPv4.t = CONF_BOOL;
	config.resolver.resolveIPv4.d.b = true;

	config.resolver.networkNames.k = "resolver.networkNames";
	config.resolver.networkNames.h = "Try to obtain client names from the network table?";
	config.resolver.networkNames.t = CONF_BOOL;
	config.resolver.networkNames.d.b = true;

	config.resolver.refreshNames.k = "resolver.refreshNames";
	config.resolver.refreshNames.h = "How (and if) hourly PTR lookups should be made";
	config.resolver.refreshNames.a = "[ \"IPV4_ONLY\", \"ALL\", \"UNKNOWN\", \"NONE\" ]";
	config.resolver.refreshNames.t = CONF_ENUM_REFRESH_HOSTNAMES;
	config.resolver.refreshNames.d.refresh_hostnames = REFRESH_IPV4_ONLY;


	// struct database
	config.database.DBimport.k = "database.DBimport";
	config.database.DBimport.h = "Should FTL load information from the database on startup to be aware of the most recent history?";
	config.database.DBimport.t = CONF_BOOL;
	config.database.DBimport.d.b = true;

	config.database.DBexport.k = "database.DBexport";
	config.database.DBexport.h =  "Should FTL store queries in the long-term database?";
	config.database.DBexport.t = CONF_BOOL;
	config.database.DBexport.d.b = true;

	config.database.maxDBdays.k = "database.maxDBdays";
	config.database.maxDBdays.h = "How long should queries be stored in the database [days]?";
	config.database.maxDBdays.t = CONF_INT;
	config.database.maxDBdays.d.i = 365;

	config.database.maxHistory.k = "database.maxHistory";
	config.database.maxHistory.h = "How much history should be imported from the database [seconds]? (max 24*60*60 = 86400)";
	config.database.maxHistory.t = CONF_UINT;
	config.database.maxHistory.d.ui = MAXLOGAGE*3600;

	config.database.DBinterval.k = "database.DBinterval";
	config.database.DBinterval.h = "How often do we store queries in FTL's database [seconds]?";
	config.database.DBinterval.t = CONF_UINT;
	config.database.DBinterval.d.ui = 60;

	// sub-struct database.network
	config.database.network.parseARPcache.k = "database.network.parseARPcache";
	config.database.network.parseARPcache.h = "Should FTL anaylze the local ARP cache?";
	config.database.network.parseARPcache.t = CONF_BOOL;
	config.database.network.parseARPcache.d.b = true;

	config.database.network.expire.k = "database.network.expire";
	config.database.network.expire.h = "How long should IP addresses be kept in the network_addresses table [days]?";
	config.database.network.expire.t = CONF_UINT;
	config.database.network.expire.d.ui = config.database.maxDBdays.d.ui;


	// struct http
	config.http.localAPIauth.k = "http.localAPIauth";
	config.http.localAPIauth.h = "Does local clients need to authenticate to access the API?";
	config.http.localAPIauth.t = CONF_BOOL;
	config.http.localAPIauth.d.b = true;

	config.http.prettyJSON.k = "http.prettyJSON";
	config.http.prettyJSON.h = "Should FTL prettify the API output?";
	config.http.prettyJSON.t = CONF_BOOL;
	config.http.prettyJSON.d.b = false;

	config.http.sessionTimeout.k = "http.sessionTimeout";
	config.http.sessionTimeout.h = "How long should a session be considered valid after login [seconds]?";
	config.http.sessionTimeout.t = CONF_UINT;
	config.http.sessionTimeout.d.ui = 300;

	config.http.domain.k = "http.domain";
	config.http.domain.h = "On which domain is the web interface served?";
	config.http.domain.a = "<valid domain>";
	config.http.domain.t = CONF_STRING;
	config.http.domain.d.s = (char*)"pi.hole";

	// Webserver access control list
	//
	// Allows restrictions to be put on the list of IP addresses which have
	// access to our web server. The ACL is a comma separated list of IP
	// subnets, where each subnet is pre-pended by either a - or a + sign. A
	// plus sign means allow, where a minus sign means deny. If a subnet mask is
	// omitted, such as -1.2.3.4, this means to deny only that single IP
	// address. The default setting is to allow all accesses.
	//
	// On each request the full list is traversed, and the last (!) match wins.
	//
	// Example 1: acl = \"-0.0.0.0/0,+127.0.0.1\" ---> deny all accesses, except
	// from 127.0.0.1
	//
	// Example 2: acl = \"-0.0.0.0/0,+192.168.0.0/16\" ---> deny all accesses,
	// except from the 192.168/16 subnet
	//
	// IPv6 addresses are specified in CIDR-form [a:b::c]/64
	config.http.acl.k = "http.acl";
	config.http.acl.h = "Webserver access control list";
	config.http.acl.a = "<valid ACL>";
	config.http.acl.t = CONF_STRING;
	config.http.acl.d.s = (char*)"+0.0.0.0/0";

	config.http.port.k = "http.port";
	config.http.port.h = "Ports to be used by the webserver";
	config.http.port.a = "comma-separated list of <[ip_address:]port>";
	config.http.port.t = CONF_STRING;
	config.http.port.d.s = (char*)"8080,[::]:8080";

	// sub-struct paths
	config.http.paths.webroot.k = "http.paths.webroot";
	config.http.paths.webroot.h = "Server root on the host";
	config.http.paths.webroot.a = "<valid path>";
	config.http.paths.webroot.t = CONF_STRING;
	config.http.paths.webroot.d.s = (char*)"/var/www/html";

	config.http.paths.webhome.k = "http.paths.webhome";
	config.http.paths.webhome.h = "Sub-directory of the root containing the web interface";
	config.http.paths.webhome.a = "<valid subpath>, both slashes are needed!";
	config.http.paths.webhome.t = CONF_STRING;
	config.http.paths.webhome.d.s = (char*)"/admin/";


	// struct files
	// config.files.log is set in a separate function
	config.files.pid.k = "files.pid";
	config.files.pid.h = "The location of FTL's PID file";
	config.files.pid.a = "<any writable file>";
	config.files.pid.t = CONF_STRING;
	config.files.pid.d.s = (char*)"/run/pihole-FTL.pid";

	config.files.database.k = "files.database";
	config.files.database.h = "The location of FTL's long-term database";
	config.files.database.a = "<any FTL database>";
	config.files.database.t = CONF_STRING;
	config.files.database.d.s = (char*)"/etc/pihole/pihole-FTL.db";

	config.files.gravity.k = "files.gravity";
	config.files.gravity.h = "The location of Pi-hole's gravity database";
	config.files.gravity.a = "<any Pi-hole gravity database>";
	config.files.gravity.t = CONF_STRING;
	config.files.gravity.d.s = (char*)"/etc/pihole/gravity.db";

	config.files.macvendor.k = "files.macvendor";
	config.files.macvendor.h = "The database containing MAC -> Vendor information for the network table";
	config.files.macvendor.a = "<any Pi-hole macvendor database>";
	config.files.macvendor.t = CONF_STRING;
	config.files.macvendor.d.s = (char*)"/etc/pihole/macvendor.db";

	config.files.setupVars.k = "files.setupVars";
	config.files.setupVars.h = "The config file of Pi-hole";
	config.files.setupVars.a = "<any Pi-hole setupVars file>";
	config.files.setupVars.t = CONF_STRING;
	config.files.setupVars.d.s = (char*)"/etc/pihole/setupVars.conf";

	config.files.http_info.k = "files.http_info";
	config.files.http_info.h = "The log file used by the webserver";
	config.files.http_info.a = "<any writable file>";
	config.files.http_info.t = CONF_STRING;
	config.files.http_info.d.s = (char*)"/var/log/pihole/HTTP_info.log";

	config.files.ph7_error.k = "files.ph7_error";
	config.files.ph7_error.h = "The log file used by the dynamic interpreter PH7";
	config.files.ph7_error.a = "<any writable file>";
	config.files.ph7_error.t = CONF_STRING;
	config.files.ph7_error.d.s = (char*)"/var/log/pihole/PH7.log";


	// struct misc
	config.misc.nice.k = "misc.nice";
	config.misc.nice.h = "Set niceness of pihole-FTL (can be disabled by setting to -999)";
	config.misc.nice.t = CONF_INT;
	config.misc.nice.d.i = -10;

	config.misc.addr2line.k = "misc.addr2line";
	config.misc.addr2line.h = "The log file used by the dynamic interpreter PH7";
	config.misc.addr2line.t = CONF_BOOL;
	config.misc.addr2line.d.b = true;

	config.misc.privacylevel.k = "misc.privacylevel";
	config.misc.privacylevel.h = "Privacy level";
	config.misc.privacylevel.t = CONF_ENUM_PRIVACY_LEVEL;
	config.misc.privacylevel.d.privacy_level = PRIVACY_SHOW_ALL;

	config.misc.delay_startup.k = "misc.delay_startup";
	config.misc.delay_startup.h = "Should FTL try to call addr2line when generating backtraces?";
	config.misc.delay_startup.t = CONF_UINT;
	config.misc.delay_startup.d.ui = 0;

	// sub-struct misc.check
	config.misc.check.load.k = "misc.check.load";
	config.misc.check.load.h = "Should FTL check the 15 min average of CPU load and complain if the load is larger than the number of available CPU cores?";
	config.misc.check.load.t = CONF_BOOL;
	config.misc.check.load.d.b = true;

	config.misc.check.disk.k = "misc.check.disk";
	config.misc.check.disk.h = "Limit above which FTL should complain about a shared-memory shortage [percent]";
	config.misc.check.disk.t = CONF_UINT;
	config.misc.check.disk.d.ui = 90;

	config.misc.check.shmem.k = "misc.check.shmem";
	config.misc.check.shmem.h = "Limit above which FTL should complain about disk shortage for checked files [percent]";
	config.misc.check.shmem.t = CONF_UINT;
	config.misc.check.shmem.d.ui = 90;


	// struct debug
	config.debug.database.k = "debug.database";
	config.debug.database.h = "Enable extra logging of database actions";
	config.debug.database.t = CONF_BOOL;
	config.debug.database.d.b = false;

	config.debug.networking.k = "debug.networking";
	config.debug.networking.h = "Enable extra logging of detected interfaces";
	config.debug.networking.t = CONF_BOOL;
	config.debug.networking.d.b = false;

	config.debug.locks.k = "debug.locks";
	config.debug.locks.h = "Enable extra logging of shared memory lock actions";
	config.debug.locks.t = CONF_BOOL;
	config.debug.locks.d.b = false;

	config.debug.queries.k = "debug.queries";
	config.debug.queries.h = "Print extensive query information";
	config.debug.queries.t = CONF_BOOL;
	config.debug.queries.d.b = false;

	config.debug.flags.k = "debug.flags";
	config.debug.flags.h = "Print flags of queries received by the DNS hooks";
	config.debug.flags.t = CONF_BOOL;
	config.debug.flags.d.b = false;

	config.debug.shmem.k = "debug.shmem";
	config.debug.shmem.h = "Print information about shared memory buffers";
	config.debug.shmem.t = CONF_BOOL;
	config.debug.shmem.d.b = false;

	config.debug.gc.k = "debug.gc";
	config.debug.gc.h = "Print information about garbage collection";
	config.debug.gc.t = CONF_BOOL;
	config.debug.gc.d.b = false;

	config.debug.arp.k = "debug.arp";
	config.debug.arp.h = "Print information about ARP table processing";
	config.debug.arp.t = CONF_BOOL;
	config.debug.arp.d.b = false;

	config.debug.regex.k = "debug.regex";
	config.debug.regex.h = "Enable extra logging of regex matching details";
	config.debug.regex.t = CONF_BOOL;
	config.debug.regex.d.b = false;

	config.debug.api.k = "debug.api";
	config.debug.api.h = "Enable extra logging of API activities";
	config.debug.api.t = CONF_BOOL;
	config.debug.api.d.b = false;

	config.debug.overtime.k = "debug.overtime";
	config.debug.overtime.h = "Print information about overTime memory operations";
	config.debug.overtime.t = CONF_BOOL;
	config.debug.overtime.d.b = false;

	config.debug.status.k = "debug.status";
	config.debug.status.h = "Enable extra logging of query status changes";
	config.debug.status.t = CONF_BOOL;
	config.debug.status.d.b = false;

	config.debug.caps.k = "debug.caps";
	config.debug.caps.h = "Print information about capabilities granted to the pihole-FTL process";
	config.debug.caps.t = CONF_BOOL;
	config.debug.caps.d.b = false;

	config.debug.dnssec.k = "debug.dnssec";
	config.debug.dnssec.h = "Print information about DNSSEC activity";
	config.debug.dnssec.t = CONF_BOOL;
	config.debug.dnssec.d.b = false;

	config.debug.vectors.k = "debug.vectors";
	config.debug.vectors.h = "Print vector operation details";
	config.debug.vectors.t = CONF_BOOL;
	config.debug.vectors.d.b = false;

	config.debug.resolver.k = "debug.resolver";
	config.debug.resolver.h = "Extensive information about hostname resolution like which DNS servers are used";
	config.debug.resolver.t = CONF_BOOL;
	config.debug.resolver.d.b = false;

	config.debug.edns0.k = "debug.edns0";
	config.debug.edns0.h = "Print EDNS(0) debugging information";
	config.debug.edns0.t = CONF_BOOL;
	config.debug.edns0.d.b = false;

	config.debug.clients.k = "debug.clients";
	config.debug.clients.h = "Enable extra client detail logging";
	config.debug.clients.t = CONF_BOOL;
	config.debug.clients.d.b = false;

	config.debug.aliasclients.k = "debug.aliasclients";
	config.debug.aliasclients.h = "Print aliasclient details";
	config.debug.aliasclients.t = CONF_BOOL;
	config.debug.aliasclients.d.b = false;

	config.debug.events.k = "debug.events";
	config.debug.events.h = "Log information about processed internal events";
	config.debug.events.t = CONF_BOOL;
	config.debug.events.d.b = false;

	config.debug.helper.k = "debug.helper";
	config.debug.helper.h = "Enable logging of script helper activity";
	config.debug.helper.t = CONF_BOOL;
	config.debug.helper.d.b = false;

	config.debug.config.k = "debug.config";
	config.debug.config.h = "Print config parsing details";
	config.debug.config.t = CONF_BOOL;
	config.debug.config.d.b = false;

	config.debug.extra.k = "debug.extra";
	config.debug.extra.h = "Special debug flag that may be used for debugging specific issues";
	config.debug.extra.t = CONF_BOOL;
	config.debug.extra.d.b = false;

	config.debug.reserved.k = "debug.reserved";
	config.debug.reserved.h = "Reserved debug flag";
	config.debug.reserved.t = CONF_BOOL;
	config.debug.reserved.d.b = false;

	// Post-processing:
	// Initialize and verify config data
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(i);

		// Initialize config value with default one for all *except* the log file path
		if(conf_item != &config.files.log)
			memcpy(&conf_item->v, &conf_item->d, sizeof(conf_item->d));

		// Parse and split paths
		conf_item->p = gen_config_path(conf_item->k);

		// Verify all config options are defined above
		if(!conf_item->p)
			log_err("Config option %u/%u is not set!", i, (unsigned int)CONFIG_ELEMENTS);
		else
			if(conf_item->p[3])
				log_debug(DEBUG_CONFIG, "Config option %u is %s.%s.%s.%s", i, conf_item->p[0], conf_item->p[1], conf_item->p[2], conf_item->p[3]);
			else if(conf_item->p[2])
				log_debug(DEBUG_CONFIG, "Config option %u is %s.%s.%s", i, conf_item->p[0], conf_item->p[1], conf_item->p[2]);
			else if(conf_item->p[1])
				log_debug(DEBUG_CONFIG, "Config option %u is %s.%s", i, conf_item->p[0], conf_item->p[1]);
			else
				log_debug(DEBUG_CONFIG, "Config option %u is %s", i, conf_item->p[0]);
	}
}

void readFTLconf(const bool rewrite)
{
	// First try to read TOML config file
	if(readFTLtoml())
	{
		// If successful, we write the config file back to disk
		// to ensure that all options are present and comments
		// about options deviating from the default are present
		if(rewrite)
			writeFTLtoml();
		return;
	}

	// On error, try to read legacy (pre-v6.0) config file. If successful,
	// we move the legacy config file out of our way
	const char *path = "";
	if((path = readFTLlegacy()) != NULL)
	{
		const char *target = "/etc/pihole/pihole-FTL.conf.bck";
		log_debug(DEBUG_CONFIG, "Moving %s to %s", path, target);
		if(rename(path, target) != 0)
			log_warn("Unable to move %s to %s: %s", path, target, strerror(errno));
	}

	// We initialize the TOML config file (every user gets one) only if none is already
	// present (may be containing errors)
	if(!file_exists(GLOBALTOMLPATH))
		writeFTLtoml();
}

bool getLogFilePath(void)
{
	// Initialize memory
	memset(&config, 0, sizeof(config));

	// Initialize the config file path
	config.files.log.k = "files.log";
	config.files.log.h = "The location of FTL's log file";
	config.files.log.a = "<any writable file>";
	config.files.log.t = CONF_STRING;
	config.files.log.d.s = (char*)"/var/log/pihole/FTL.log";
	config.files.log.v.s = config.files.log.d.s;

	// Check if the config file contains a different path
	if(!getLogFilePathTOML())
		return getLogFilePathLegacy(NULL);

	return true;
}
