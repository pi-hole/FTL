/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TOML config writer routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "config.h"
// get_timestr()
#include "../log.h"
#include "tomlc99/toml.h"
#include "toml_writer.h"
#include "toml_helper.h"
// get_blocking_mode_str()
#include "../datastructure.h"

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

	fputs("# This file is managed by pihole-FTL\n#\n", fp);
	fputs("# Do not edit the file while FTL is\n", fp);
	fputs("# running or your changes may be overwritten\n#\n", fp);
	char timestring[84] = "";
	get_timestr(timestring, time(NULL), false);
	fprintf(fp, "# Last update: %s\n\n", timestring);



	// [dns] section
	catTOMLsection(fp, 0, "dns");

	// BLOCKINGMODE=NULL|IP-NODATA-AAAA|IP|NXDOMAIN
	const char *blockingmode = get_blocking_mode_str(config.dns.blockingmode);
	const char *defblockingmode = get_blocking_mode_str(defaults.dns.blockingmode);
	catTOMLstring(fp, 1, "blockingmode", "How should FTL reply to blocked queries?", "[ \"NULL\", \"IP-NODATA-AAAA\", \"IP\", \"NXDOMAIN\" ]", blockingmode, defblockingmode);
	catTOMLbool(fp, 1, "CNAMEdeepInspect", "Should FTL walk CNAME paths?", config.dns.CNAMEdeepInspect, defaults.dns.CNAMEdeepInspect);
	catTOMLbool(fp, 1, "blockESNI", "Should _esni. subdomains be blocked by default?", config.dns.blockESNI, defaults.dns.blockESNI);
	catTOMLbool(fp, 1, "EDNS0ECS", "Should FTL analyze possible ECS information to obtain client IPs hidden behind NATs?", config.dns.EDNS0ECS, defaults.dns.EDNS0ECS);
	catTOMLbool(fp, 1, "ignoreLocalhost", "Should FTL hide queries made by localhost?", config.dns.ignoreLocalhost, defaults.dns.ignoreLocalhost);
	catTOMLbool(fp, 1, "showDNSSEC", "Should FTL should internally generated DNSSEC queries?", config.dns.showDNSSEC, defaults.dns.showDNSSEC);

	const char *ptrStr = get_ptr_type_str(config.dns.piholePTR);
	catTOMLstring(fp, 1, "piholePTR", "Should FTL return \"pi.hole\" as name for PTR requests to local IP addresses?", "[ \"NONE\", \"HOSTNAME\", \"HOSTNAMEFQDN\", \"PI.HOLE\" ]", ptrStr, "PI.HOLE");

	const char *replyWhenBusy = get_busy_reply_str(config.dns.replyWhenBusy);
	catTOMLstring(fp, 1, "replyWhenBusy", "How should FTL handle queries when the gravity database is not available?", "[ \"BLOCK\", \"ALLOW\", \"REFUSE\", \"DROP\" ]", replyWhenBusy, "ALLOW");
	catTOMLuint(fp, 1, "blockTTL", "TTL for blocked queries [seconds]", config.dns.blockTTL, defaults.dns.blockTTL);
	catTOMLbool(fp, 1, "analyzeAAAA", "Should FTL analyze AAAA queries?", config.dns.analyzeAAAA, defaults.dns.analyzeAAAA);
	catTOMLbool(fp, 1, "analyzeOnlyAandAAAA", "Should FTL analyze only A and AAAA queries?", config.dns.analyzeOnlyAandAAAA, defaults.dns.analyzeOnlyAandAAAA);



	// [dns.specialDomains] subsection
	catTOMLsection(fp, 1, "dns.specialDomains");
	catTOMLbool(fp, 2, "mozillaCanary", "Should FTL handle use-application-dns.net specifically and always return NXDOMAIN?", config.dns.specialDomains.mozillaCanary, defaults.dns.specialDomains.mozillaCanary);
	catTOMLbool(fp, 2, "iCloudPrivateRelay", "Should FTL handle the iCloud privacy relay domains specifically and always return NXDOMAIN?", config.dns.specialDomains.iCloudPrivateRelay, defaults.dns.specialDomains.iCloudPrivateRelay);



	// [dns.reply] subsection
	catTOMLsection(fp, 1, "dns.reply");
	char addr4[INET_ADDRSTRLEN] = { 0 };
	char addr6[INET6_ADDRSTRLEN] = { 0 };
	// [dns.reply.host] subsection
	catTOMLsection(fp, 2, "dns.reply.host");
	if(config.dns.reply.host.overwrite_v4)
		inet_ntop(AF_INET, &config.dns.reply.host.v4, addr4, INET_ADDRSTRLEN);
	catTOMLstring(fp, 3, "IPv4", "Use a specific IPv4 address for the Pi-hole host", "<valid IPv4 address> or empty string (\"\")", addr4, "");
	if(config.dns.reply.host.overwrite_v6)
		inet_ntop(AF_INET6, &config.dns.reply.host.v6, addr6, INET6_ADDRSTRLEN);
	catTOMLstring(fp, 3, "IPv6", "Use a specific IPv6 address for the Pi-hole host", "<valid IPv6 address> or empty string (\"\")", addr6, "");

	// [dns.reply.blocking] subsection
	catTOMLsection(fp, 2, "dns.reply.blocking");
	memset(addr4, 0, INET_ADDRSTRLEN);
	if(config.dns.reply.blocking.overwrite_v4)
		inet_ntop(AF_INET, &config.dns.reply.blocking.v4, addr4, INET_ADDRSTRLEN);
	catTOMLstring(fp, 3, "IPv4", "Use a specific IPv4 address in IP blocking mode", "<valid IPv4 address> or empty string (\"\")", addr4, "");
	memset(addr6, 0, INET6_ADDRSTRLEN);
	if(config.dns.reply.blocking.overwrite_v6)
		inet_ntop(AF_INET6, &config.dns.reply.blocking.v6, addr6, INET6_ADDRSTRLEN);
	catTOMLstring(fp, 3, "IPv6", "Use a specific IPv6 address in IP blocking mode", "<valid IPv6 address> or empty string (\"\")", addr6, "");



	// [dns.rateLimit] subsection
	catTOMLsection(fp, 1, "dns.rateLimit");
	catTOMLuint(fp, 2, "count", "How many queries are permitted...", config.dns.rateLimit.count, defaults.dns.rateLimit.count);
	catTOMLuint(fp, 2, "interval", "..in the set interval before rate-limiting?", config.dns.rateLimit.interval, defaults.dns.rateLimit.interval);



	// [resolver] section
	catTOMLsection(fp, 0, "resolver");
	catTOMLbool(fp, 1, "resolveIPv4", "Should FTL try to resolve IPv4 addresses to hostnames?", config.resolver.resolveIPv4, defaults.resolver.resolveIPv4);
	catTOMLbool(fp, 1, "resolveIPv6", "Should FTL try to resolve IPv6 addresses to hostnames?", config.resolver.resolveIPv6, defaults.resolver.resolveIPv6);
	const char *refresh = get_refresh_hostnames_str(config.resolver.refreshNames);
	const char *refresh_default = get_refresh_hostnames_str(defaults.resolver.refreshNames);
	catTOMLbool(fp, 1, "networkNames", "Try to obtain client names from the network table", config.resolver.networkNames, defaults.resolver.networkNames);
	catTOMLstring(fp, 1, "refreshNames", "How (and if) hourly PTR lookups should be made", "[ \"IPV4_ONLY\", \"ALL\", \"UNKNOWN\", \"NONE\" ]", refresh, refresh_default);



	// [database] section
	catTOMLsection(fp, 0, "database");
	catTOMLbool(fp, 1, "DBimport", "Should FTL load information from the database on startup to be aware of the most recent history?", config.database.DBimport, defaults.database.DBimport);
	catTOMLbool(fp, 1, "DBexport", "Should FTL store queries in the long-term database?", config.database.DBexport, defaults.database.DBexport);
	catTOMLuint(fp, 1, "maxHistory", "How much history should be imported from the database [seconds]? (max 24*60*60 = 86400)", config.database.maxHistory, defaults.database.maxHistory);
	catTOMLint(fp, 1, "maxDBdays", "How long should queries be stored in the database [days]?", config.database.maxDBdays, defaults.database.maxDBdays);
	catTOMLint(fp, 1, "DBinterval", "How often do we store queries in FTL's database [seconds]?", config.database.DBinterval, defaults.database.DBinterval);



	// [database.network] section
	catTOMLsection(fp, 1, "database.network");
	catTOMLbool(fp, 2, "parseARPcache", "Should FTL anaylze the local ARP cache?", config.database.network.parseARPcache, defaults.database.network.parseARPcache);
	catTOMLint(fp, 2, "expire", "How long should IP addresses be kept in the network_addresses table [days]?", config.database.network.expire, defaults.database.network.expire);



	// [http] section
	catTOMLsection(fp, 0, "http");
	catTOMLbool(fp, 1, "localAPIauth", "Does local clients need to authenticate to access the API?", config.http.localAPIauth, defaults.http.localAPIauth);
	catTOMLbool(fp, 1, "prettyJSON", "Should FTL insert extra spaces to prettify the API output?", config.http.prettyJSON, defaults.http.prettyJSON);
	catTOMLuint(fp, 1, "sessionTimeout", "How long should a session be considered valid after login [seconds]?", config.http.sessionTimeout, defaults.http.sessionTimeout);
	catTOMLstring(fp, 1, "domain", "On which domain is the web interface served?", "<valid domain>", config.http.domain, defaults.http.domain);
//	Webserver access control list
//	Allows restrictions to be put on the list of IP addresses which have access to our web server.
//	The ACL is a comma separated list of IP subnets, where each subnet is pre-pended by either a - or a + sign.
//	A plus sign means allow, where a minus sign means deny. If a subnet mask is omitted, such as -1.2.3.4, this means
//	to deny only that single IP address. The default setting is to allow all accesses.
//	On each request the full list is traversed, and the last (!) match wins.
//	Example 1: acl = \"-0.0.0.0/0,+127.0.0.1\" ---> deny all accesses, except from 127.0.0.1
//	Example 2: acl = \"-0.0.0.0/0,+192.168.0.0/16\" ---> deny all accesses, except from the 192.168/16 subnet
//	IPv6 addresses are specified in form [a:b::c]/64
	catTOMLstring(fp, 1, "acl", "Webserver access control list.", "<valid ACL>", config.http.acl, defaults.http.acl);
	catTOMLstring(fp, 1, "port", "Ports to be used by the webserver", "list of <[ip_address:]port>", config.http.port, defaults.http.port);



	// [http.paths] section
	catTOMLsection(fp, 1, "http.paths");
	catTOMLstring(fp, 2, "webroot", "Server root on the host", "<valid path>", config.http.paths.webroot, defaults.http.paths.webroot);
	catTOMLstring(fp, 2, "webhome", "Sub-directory of the root containing the web interface", "<valid subpath>, both slashes are needed!", config.http.paths.webhome, defaults.http.paths.webhome);



	// [files] section
	catTOMLsection(fp, 0, "files");
	catTOMLstring(fp, 1, "log", "The location of FTL's log file", "<any writable file>", config.files.log, defaults.files.log);
	catTOMLstring(fp, 1, "pid", "The location of FTL's PID file", "<any writable file>", config.files.pid, defaults.files.pid);
	catTOMLstring(fp, 1, "database", "The location of FTL's long-term database", "<any FTL database>", config.files.database, defaults.files.database);
	catTOMLstring(fp, 1, "gravity", "The location of Pi-hole's gravity database", "<any gravity database>", config.files.gravity, defaults.files.gravity);
	catTOMLstring(fp, 1, "macvendor", "The database containing MAC -> Vendor information for the network table", "<any macvendor database>", config.files.macvendor, defaults.files.macvendor);
	catTOMLstring(fp, 1, "setupVars", "The config file of Pi-hole", "<any setupVars file>", config.files.setupVars, defaults.files.setupVars);
	catTOMLstring(fp, 1, "HTTPinfo", "The log file used by the webserver", "<any writable database>", config.files.http_info, defaults.files.http_info);
	catTOMLstring(fp, 1, "PH7error", "The log file used by the dynamic interpreter PH7", "<any writable file>", config.files.ph7_error, defaults.files.ph7_error);



	// [misc] section
	catTOMLsection(fp, 0, "misc");
	catTOMLuint(fp, 1, "privacyLevel", "Privacy level", config.misc.privacylevel, defaults.misc.privacylevel);
	catTOMLint(fp, 1, "nice", "Set niceness of pihole-FTL (can be disabled by setting to -999)", config.misc.nice, defaults.misc.nice);
	catTOMLuint(fp, 1, "delayStartup", "Artificially delay FTL's startup (0 to 300 seconds)", config.misc.delay_startup, defaults.misc.delay_startup);
	catTOMLbool(fp, 1, "addr2line", "Should FTL try to call addr2line when generating backtraces?", config.misc.addr2line, defaults.misc.addr2line);



	// [misc.check] subsection
	catTOMLsection(fp, 1, "misc.check");
	catTOMLbool(fp, 2, "load", "Should FTL check the 15 min average of CPU load and complain if the load is larger than the number of available CPU cores?", config.misc.check.load, defaults.misc.check.load);
	catTOMLuint(fp, 2, "shmem", "Limit above which FTL should complain about a shared-memory shortage", config.misc.check.shmem, defaults.misc.check.shmem);
	catTOMLuint(fp, 2, "disk", "Limit above which FTL should complain about disk shortage for checked files", config.misc.check.disk, defaults.misc.check.disk);



	// [debug] section
	catTOMLsection(fp, 0, "debug");
	catTOMLbool(fp, 1, "all", "Temporarily enable all debug flags", false, false);
	char buffer[64];
	for(enum debug_flag flag = DEBUG_DATABASE; flag < DEBUG_EXTRA; flag <<= 1)
	{
		const char *name, *desc;
		debugstr(flag, &name, &desc);
		memset(buffer, 0, sizeof(buffer));
		strcpy(buffer, name+6); // offset "debug_"
		strtolower(buffer);
		catTOMLbool(fp, 1, buffer, desc, config.debug & flag, false);
	}

	// Close and flush file
	fclose(fp);

	return true;
}