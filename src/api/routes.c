/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API routes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
// struct mg_connection
#include "../civetweb/civetweb.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
#include "../shmem.h"
#include "../config.h"

int api_handler(struct mg_connection *conn, void *ignored)
{
	// Lock during API access
	lock_shm();

	int ret = 0;

	const struct mg_request_info *request = mg_get_request_info(conn);
	if(config.debug & DEBUG_API)
		logg("Requested API URI: %s %s", request->request_method, request->local_uri);

	/******************************** /api/dns ********************************/
	if(startsWith("/api/dns/blocking", request->local_uri))
	{
		ret = api_dns_blockingstatus(conn);
	}
	else if(startsWith("/api/dns/cacheinfo", request->local_uri))
	{
		ret = api_dns_cacheinfo(conn);
	}
	/******************************** /api/list, /api/group ****************************/
	else if(startsWith("/api/list", request->local_uri))
	{
		ret = api_list(conn);
	}
	else if(startsWith("/api/group", request->local_uri))
	{
		ret = api_list(conn);
	}
	/******************************** /api/ftl ****************************/
	else if(startsWith("/api/ftl/client", request->local_uri))
	{
		ret = api_ftl_client(conn);
	}
	else if(startsWith("/api/ftl/dnsmasq_log", request->local_uri))
	{
		ret = api_ftl_dnsmasq_log(conn);
	}
	else if(startsWith("/api/ftl/database", request->local_uri))
	{
		ret = api_ftl_database(conn);
	}
	else if(startsWith("/api/ftl/system", request->local_uri))
	{
		ret = api_ftl_system(conn);
	}
	/******************************** /api/network ****************************/
	else if(startsWith("/api/network", request->local_uri))
	{
		ret = api_network(conn);
	}
	/******************************** /api/stats **************************/
	else if(startsWith("/api/stats/summary", request->local_uri))
	{
		ret = api_stats_summary(conn);
	}
	else if(startsWith("/api/stats/overTime/history", request->local_uri))
	{
		ret = api_stats_overTime_history(conn);
	}
	else if(startsWith("/api/stats/overTime/clients", request->local_uri))
	{
		ret = api_stats_overTime_clients(conn);
	}
	else if(startsWith("/api/stats/query_types", request->local_uri))
	{
		ret = api_stats_query_types(conn);
	}
	else if(startsWith("/api/stats/upstreams", request->local_uri))
	{
		ret = api_stats_upstreams(conn);
	}
	else if(startsWith("/api/stats/top_domains", request->local_uri))
	{
		ret = api_stats_top_domains(false, conn);
	}
	else if(startsWith("/api/stats/top_blocked", request->local_uri))
	{
		ret = api_stats_top_domains(true, conn);
	}
	else if(startsWith("/api/stats/top_clients", request->local_uri))
	{
		ret = api_stats_top_clients(false, conn);
	}
	else if(startsWith("/api/stats/top_blocked_clients", request->local_uri))
	{
		ret = api_stats_top_clients(true, conn);
	}
	else if(startsWith("/api/stats/history", request->local_uri))
	{
		ret = api_stats_history(conn);
	}
	else if(startsWith("/api/stats/recent_blocked", request->local_uri))
	{
		ret = api_stats_recentblocked(conn);
	}
	else if(startsWith("/api/stats/database/overTime/history", request->local_uri))
	{
		ret = api_stats_database_overTime_history(conn);
	}
	else if(startsWith("/api/stats/database/top_domains", request->local_uri))
	{
		ret = api_stats_database_top_items(false, true, conn);
	}
	else if(startsWith("/api/stats/database/top_blocked", request->local_uri))
	{
		ret = api_stats_database_top_items(true, true, conn);
	}
	else if(startsWith("/api/stats/database/top_clients", request->local_uri))
	{
		ret = api_stats_database_top_items(false, false, conn);
	}
	else if(startsWith("/api/stats/database/summary", request->local_uri))
	{
		ret = api_stats_database_summary(conn);
	}
	else if(startsWith("/api/stats/database/overTime/clients", request->local_uri))
	{
		ret = api_stats_database_overTime_clients(conn);
	}
	else if(startsWith("/api/stats/database/query_types", request->local_uri))
	{
		ret = api_stats_database_query_types(conn);
	}
	else if(startsWith("/api/stats/database/upstreams", request->local_uri))
	{
		ret = api_stats_database_upstreams(conn);
	}
	/******************************** /api/version ****************************/
	else if(startsWith("/api/version", request->local_uri))
	{
		ret = api_version(conn);
	}
	/******************************** /api/auth ****************************/
	else if(startsWith("/api/auth", request->local_uri))
	{
		ret = api_auth(conn);
	}
	/******************************** /api/settings ****************************/
	else if(startsWith("/api/settings/web", request->local_uri))
	{
		ret = api_settings_web(conn);
	}
	/******************************** not found or invalid request**************/
	if(ret == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "path", request->local_uri);
		ret = send_json_error(conn, 404,
		                      "not_found",
		                      "Not found",
		                      json);
	}

	// Unlock after API access
	unlock_shm();

	return ret;
}
