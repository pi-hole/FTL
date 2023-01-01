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

ConfigStruct config;
ConfigStruct defaults;

void setDefaults(void)
{
	// top-level properties
	defaults.debug = 0;

	// struct dns
	defaults.dns.CNAMEdeepInspect = true;
	defaults.dns.blockESNI = true;
	defaults.dns.EDNS0ECS = true;
	defaults.dns.ignoreLocalhost = false;

	defaults.dns.piholePTR = PTR_PIHOLE;
	defaults.dns.replyWhenBusy = BUSY_ALLOW;
	defaults.dns.showDNSSEC = true;
	defaults.dns.blockTTL = 2;
	defaults.dns.analyzeAAAA = true;
	defaults.dns.analyzeOnlyAandAAAA = false;
	defaults.dns.blockingmode = MODE_NULL;
	// sub-struct rate_limit
	defaults.dns.rateLimit.count = 1000;
	defaults.dns.rateLimit.interval = 60;
	// sub-struct special_domains
	defaults.dns.specialDomains.mozillaCanary = true;
	defaults.dns.specialDomains.iCloudPrivateRelay = true;
	// sub-struct reply_addr
	defaults.dns.reply.blocking.overwrite_v4 = false;
	memset(&defaults.dns.reply.blocking.v4, 0, sizeof(config.dns.reply.blocking.v4));
	defaults.dns.reply.blocking.overwrite_v6 = false;
	memset(&defaults.dns.reply.blocking.v6, 0, sizeof(config.dns.reply.blocking.v6));
	defaults.dns.reply.host.overwrite_v4 = false;
	memset(&defaults.dns.reply.host.v4, 0, sizeof(config.dns.reply.host.v4));
	defaults.dns.reply.host.overwrite_v6 = false;
	memset(&defaults.dns.reply.host.v6, 0, sizeof(config.dns.reply.host.v6));

	// struct resolver
	defaults.resolver.resolveIPv6 = true;
	defaults.resolver.resolveIPv4 = true;
	defaults.resolver.networkNames = true;
	defaults.resolver.refreshNames = REFRESH_IPV4_ONLY;

	// struct database
	defaults.database.DBimport = true;
	defaults.database.maxDBdays = 365;
	defaults.database.maxHistory = MAXLOGAGE*3600;
	defaults.database.DBinterval = 60;
	// sub-struct network
	defaults.database.network.parseARPcache = true;
	defaults.database.network.expire = defaults.database.maxDBdays;

	// struct misc
	defaults.misc.nice = -10;
	defaults.misc.delay_startup = 0;
	defaults.misc.addr2line = true;
	defaults.misc.privacylevel = PRIVACY_SHOW_ALL;

	// sub-struct check
	defaults.misc.check.load = true;
	defaults.misc.check.disk = 90;
	defaults.misc.check.shmem = 90;

	// struct http
	defaults.http.localAPIauth = true;
	defaults.http.prettyJSON = false;
	defaults.http.sessionTimeout = 300;
	defaults.http.domain = (char*)"pi.hole";
	defaults.http.acl = (char*)"+0.0.0.0/0";
	defaults.http.port = (char*)"8080,[::]:8080";
	defaults.http.paths.webroot = (char*)"/var/www/html";
	defaults.http.paths.webhome = (char*)"/admin/";

	// struct files
	defaults.files.database = (char*)"/etc/pihole/pihole-FTL.db";
	defaults.files.pid = (char*)"/run/pihole-FTL.pid";
	defaults.files.setupVars = (char*)"/etc/pihole/setupVars.conf";
	defaults.files.macvendor = (char*)"/etc/pihole/macvendor.db";
	defaults.files.gravity = (char*)"/etc/pihole/gravity.db";
	defaults.files.http_info = (char*)"/var/log/pihole/HTTP_info.log";
	defaults.files.ph7_error = (char*)"/var/log/pihole/PH7.log";

	// Copy default values into config struct
	memcpy(&config, &defaults, sizeof(config));
}

void readFTLconf(void)
{
	// First try to read TOML config file
	if(readFTLtoml())
		return;

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
	// Set default
	defaults.files.log = (char*)"/var/log/pihole/FTL.log";
	config.files.log = defaults.files.log;

	// Check if the config file contains a different path
	if(!getLogFilePathTOML())
		return getLogFilePathLegacy(NULL);

	return true;
}
