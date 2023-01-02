/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/ftl
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// struct fifologData
#include "fifo.h"
// sysinfo()
#include <sys/sysinfo.h>
// get_blockingstatus()
#include "setupVars.h"
// counters
#include "shmem.h"
// get_FTL_db_filesize()
#include "files.h"
// get_sqlite3_version()
#include "database/common.h"
// get_number_of_queries_in_DB()
#include "database/query-table.h"
// getgrgid()
#include <grp.h>
// config struct
#include "config/config.h"
// struct clientsData
#include "datastructure.h"
// Routing information and flags
#include <net/route.h>
// Interate through directories
#include <dirent.h>

int api_config(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	cJSON *config_j = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(config_j, "debug",config.debug); /* TODO: Split into individual fields */

	cJSON *dns = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(dns, "CNAMEdeepInspect", config.dns.CNAMEdeepInspect);
	JSON_ADD_BOOL_TO_OBJECT(dns, "blockESNI", config.dns.blockESNI);
	JSON_ADD_BOOL_TO_OBJECT(dns, "EDNS0ECS", config.dns.EDNS0ECS);
	JSON_ADD_BOOL_TO_OBJECT(dns, "ignoreLocalhost", config.dns.ignoreLocalhost);
	JSON_ADD_BOOL_TO_OBJECT(dns, "showDNSSEC", config.dns.showDNSSEC);
	JSON_ADD_BOOL_TO_OBJECT(dns, "analyzeAAAA", config.dns.analyzeAAAA);
	JSON_ADD_BOOL_TO_OBJECT(dns, "analyzeOnlyAandAAAA", config.dns.analyzeOnlyAandAAAA);
	const char *piholePTR = get_ptr_type_str(config.dns.piholePTR);
	JSON_REF_STR_IN_OBJECT(dns, "piholePTR", piholePTR);
	const char *replyWhenBusy = get_busy_reply_str(config.dns.replyWhenBusy);
	JSON_REF_STR_IN_OBJECT(dns, "replyWhenBusy", replyWhenBusy);
	JSON_ADD_NUMBER_TO_OBJECT(dns, "blockTTL", config.dns.blockTTL);
	const char *blockingmode = get_blocking_mode_str(config.dns.blockingmode);
	JSON_REF_STR_IN_OBJECT(dns, "blockingmode", blockingmode);
	JSON_ADD_NUMBER_TO_OBJECT(dns, "port", config.dns.port);
	cJSON *specialDomains = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(specialDomains, "mozillaCanary", config.dns.specialDomains.mozillaCanary);
	JSON_ADD_BOOL_TO_OBJECT(specialDomains, "iCloudPrivateRelay", config.dns.specialDomains.iCloudPrivateRelay);
	JSON_ADD_ITEM_TO_OBJECT(dns, "specialDomains", specialDomains);
	cJSON *reply = JSON_NEW_OBJECT();
	cJSON *host = JSON_NEW_OBJECT();
	{
		if(config.dns.reply.host.overwrite_v4)
		{
			JSON_COPY_STR_TO_OBJECT(host, "IPv4", inet_ntoa(config.dns.reply.host.v4));
		}
		else
		{
			JSON_ADD_NULL_TO_OBJECT(host, "IPv4");
		}
		char ip6[INET6_ADDRSTRLEN] = { 0 };
		if(config.dns.reply.host.overwrite_v6)
		{
			JSON_COPY_STR_TO_OBJECT(host, "IPv6", inet_ntop(AF_INET6, &config.dns.reply.host.v6, ip6, INET6_ADDRSTRLEN));
		}
		else
		{
			JSON_ADD_NULL_TO_OBJECT(host, "IPv6");
		}
	}
	JSON_ADD_ITEM_TO_OBJECT(reply, "host", host);
	cJSON *blocking = JSON_NEW_OBJECT();
	{
		if(config.dns.reply.blocking.overwrite_v4)
		{
			JSON_COPY_STR_TO_OBJECT(blocking, "IPv4", inet_ntoa(config.dns.reply.blocking.v4));
		}
		else
		{
			JSON_ADD_NULL_TO_OBJECT(blocking, "IPv4");
		}
		char ip6[INET6_ADDRSTRLEN] = { 0 };
		if(config.dns.reply.blocking.overwrite_v6)
		{
			JSON_COPY_STR_TO_OBJECT(blocking, "IPv6", inet_ntop(AF_INET6, &config.dns.reply.blocking.v6, ip6, INET6_ADDRSTRLEN));
		}
		else
		{
			JSON_ADD_NULL_TO_OBJECT(blocking, "IPv6");
		}
	}
	JSON_ADD_ITEM_TO_OBJECT(reply, "blocking", blocking);
	JSON_ADD_ITEM_TO_OBJECT(dns, "reply", reply);
	cJSON *rateLimit = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(rateLimit, "count", config.dns.rateLimit.count);
	JSON_ADD_NUMBER_TO_OBJECT(rateLimit, "interval", config.dns.rateLimit.interval);
	JSON_ADD_ITEM_TO_OBJECT(dns, "rateLimit", rateLimit);
	JSON_ADD_ITEM_TO_OBJECT(config_j, "dns", dns);

	cJSON *resolver = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(resolver, "resolveIPv4", config.resolver.resolveIPv4);
	JSON_ADD_BOOL_TO_OBJECT(resolver, "resolveIPv6", config.resolver.resolveIPv6);
	JSON_ADD_BOOL_TO_OBJECT(resolver, "networkNames", config.resolver.networkNames);
	const char *refreshstr = get_refresh_hostnames_str(config.resolver.refreshNames);
	JSON_REF_STR_IN_OBJECT(resolver, "refreshNames", refreshstr);
	JSON_ADD_ITEM_TO_OBJECT(config_j, "resolver", resolver);

	cJSON *database = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(database, "DBimport", config.database.DBimport);
	JSON_ADD_BOOL_TO_OBJECT(database, "DBexport", config.database.DBexport);
	JSON_ADD_NUMBER_TO_OBJECT(database, "maxHistory", config.database.maxHistory);
	JSON_ADD_NUMBER_TO_OBJECT(database, "maxDBdays", config.database.maxDBdays);
	JSON_ADD_NUMBER_TO_OBJECT(database, "DBinterval", config.database.DBinterval);
	cJSON *network = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(network, "parseARPcache", config.database.network.parseARPcache);
	JSON_ADD_NUMBER_TO_OBJECT(network, "expire", config.database.network.expire);
	JSON_ADD_ITEM_TO_OBJECT(database, "network", network);
	JSON_ADD_ITEM_TO_OBJECT(config_j, "database", database);

	cJSON *http = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(http, "localAPIauth", config.http.localAPIauth);
	JSON_ADD_BOOL_TO_OBJECT(http, "prettyJSON", config.http.prettyJSON);
	JSON_ADD_NUMBER_TO_OBJECT(http, "sessionTimeout", config.http.sessionTimeout);
	JSON_REF_STR_IN_OBJECT(http, "domain", config.http.domain);
	JSON_REF_STR_IN_OBJECT(http, "acl", config.http.acl);
	JSON_REF_STR_IN_OBJECT(http, "port", config.http.port);
	cJSON *paths = JSON_NEW_OBJECT();
	JSON_REF_STR_IN_OBJECT(paths, "webroot", config.http.paths.webroot);
	JSON_REF_STR_IN_OBJECT(paths, "webhome", config.http.paths.webhome);
	JSON_ADD_ITEM_TO_OBJECT(http, "paths", paths);
	JSON_ADD_ITEM_TO_OBJECT(config_j, "http", http);

	cJSON *files = JSON_NEW_OBJECT();
	JSON_REF_STR_IN_OBJECT(files, "log", config.files.log);
	JSON_REF_STR_IN_OBJECT(files, "pid", config.files.pid);
	JSON_REF_STR_IN_OBJECT(files, "database", config.files.database);
	JSON_REF_STR_IN_OBJECT(files, "gravity", config.files.gravity);
	JSON_REF_STR_IN_OBJECT(files, "macvendor", config.files.macvendor);
	JSON_REF_STR_IN_OBJECT(files, "setupVars", config.files.setupVars);
	JSON_REF_STR_IN_OBJECT(files, "http_info", config.files.http_info);
	JSON_REF_STR_IN_OBJECT(files, "ph7_error", config.files.ph7_error);
	JSON_ADD_ITEM_TO_OBJECT(config_j, "files", files);

	cJSON *misc = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(misc, "nice", config.misc.nice);
	JSON_ADD_NUMBER_TO_OBJECT(misc, "delay_startup", config.misc.delay_startup);
	JSON_ADD_BOOL_TO_OBJECT(misc, "addr2line", config.misc.addr2line);
	JSON_ADD_NUMBER_TO_OBJECT(misc, "privacylevel", config.misc.privacylevel);
	cJSON *check = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(check, "load", config.misc.check.load);
	JSON_ADD_NUMBER_TO_OBJECT(check, "shmem", config.misc.check.shmem);
	JSON_ADD_NUMBER_TO_OBJECT(check, "disk", config.misc.check.disk);
	JSON_ADD_ITEM_TO_OBJECT(misc, "check", check);
	JSON_ADD_ITEM_TO_OBJECT(config_j, "misc", misc);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "config", config_j);
	JSON_SEND_OBJECT(json);
}
