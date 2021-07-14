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
#include "toml_reader.h"
#include "toml_writer.h"
#include "setupVars.h"
#include "log.h"
#include "../log.h"
// readFTLlegacy()
#include "legacy_reader.h"
// file_exists()
#include "../files.h"

ConfigStruct config;
ConfigStruct defaults;

void setDefaults(void)
{
	// bools
	defaults.socket_listenlocal = true;
	defaults.analyze_AAAA = true;
	defaults.resolveIPv6 = true;
	defaults.resolveIPv4 = true;
	defaults.ignore_localhost = false;
	defaults.analyze_only_A_AAAA = false;
	defaults.DBimport = true;
	defaults.parse_arp_cache = true;
	defaults.cname_deep_inspection = true;
	defaults.blockESNI = true;
	defaults.networkNames = true;
	defaults.edns0_ecs = true;
	defaults.show_dnssec = true;
	defaults.special_domains.mozilla_canary = true;
	defaults.pihole_ptr = true;

	// enums
	defaults.privacylevel = PRIVACY_SHOW_ALL;
	defaults.blockingmode = MODE_NULL;
	defaults.refresh_hostnames = REFRESH_IPV4_ONLY;
	defaults.debug = 0;

	// integer
	defaults.nice = -10;
	defaults.maxDBdays = 365;
	defaults.network_expire = defaults.maxDBdays;

	// unsigned integer
	defaults.maxHistory = MAXLOGAGE*3600;
	defaults.delay_startup = 0;
	defaults.DBinterval = 60;

	// struct rate_limit
	defaults.rate_limit.count = 1000;
	defaults.rate_limit.interval = 60;

	// struct reply_addr
	defaults.reply_addr.overwrite_v4 = false;
	memset(&defaults.reply_addr.v4, 0, sizeof(config.reply_addr.v4));
	defaults.reply_addr.overwrite_v6 = false;
	memset(&defaults.reply_addr.v6, 0, sizeof(config.reply_addr.v6));

	// struct http
	defaults.http.localAPIauth = true;
	defaults.http.prettyJSON = false;
	defaults.http.sessionTimeout = 300;
	defaults.http.domain = (char*)"pi.hole";
	defaults.http.acl = (char*)"+0.0.0.0/0";
	defaults.http.port = (char*)"8080,[::]:8080";
	defaults.http.paths.webroot = (char*)"/var/www/html";
	defaults.http.paths.webhome = (char*)"/admin/";

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
	defaults.files.log = (char*)"/var/log/pihole-FTL.log";
	config.files.log = defaults.files.log;

	// Check if the config file contains a different path
	if(!getLogFilePathTOML())
		return getLogFilePathLegacy(NULL);

	return true;
}