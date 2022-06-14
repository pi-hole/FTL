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
#include "api.h"
#include "../shmem.h"

int api_handler(struct mg_connection *conn, void *ignored)
{
	// Prepare API info struct
	struct ftl_conn api = {
		conn,
		mg_get_request_info(conn),
		http_method(conn),
		NULL,
		NULL,
		{ 0 }
	};
	read_and_parse_payload(&api);

	log_debug(DEBUG_API, "Requested API URI: %s %s ? %s",
	          api.request->request_method,
	          api.request->local_uri_raw,
	          api.request->query_string);

	int ret = 0;
	/******************************** /api/dns ********************************/
	if(startsWith("/api/dns/blocking", &api))
	{
		// Locks handled internally
		ret = api_dns_blocking(&api);
	}
	else if(startsWith("/api/dns/cache", &api))
	{
		// Locks handled internally
		ret = api_dns_cache(&api);
	}
	else if(startsWith("/api/dns/port", &api))
	{
		// Locks not needed
		ret = api_dns_port(&api);
	}
	/************ /api/domains, /api/groups, /api/lists, /api/clients ********/
	else if(startsWith("/api/domains", &api))
	{
		// Locks handled internally
		ret = api_list(&api);
	}
	else if(startsWith("/api/groups", &api))
	{
		// Locks handled internally
		ret = api_list(&api);
	}
	else if(startsWith("/api/lists", &api))
	{
		// Locks handled internally
		ret = api_list(&api);
	}
	else if(startsWith("/api/clients", &api))
	{
		// Locks handled internally
		ret = api_list(&api);
	}
	/******************************** /api/ftl ****************************/
	else if(startsWith("/api/ftl/client", &api))
	{
		// Locks not needed
		ret = api_ftl_client(&api);
	}
	else if(startsWith("/api/ftl/logs/dns", &api))
	{
		// Locks handled internally
		ret = api_ftl_logs_dns(&api);
	}
	else if(startsWith("/api/ftl/sysinfo", &api))
	{
		// Locks not needed
		ret = api_ftl_sysinfo(&api);
	}
	else if(startsWith("/api/ftl/dbinfo", &api))
	{
		// Locks not needed
		ret = api_ftl_dbinfo(&api);
	}
	else if(startsWith("/api/ftl/maxhistory", &api))
	{
		// Locks not needed
		ret = api_ftl_maxhistory(&api);
	}
	else if(startsWith("/api/ftl/gateway", &api))
	{
		// Locks not needed
		ret = api_ftl_gateway(&api);
	}
	/******************************** /api/network ****************************/
	else if(startsWith("/api/network", &api))
	{
		ret = api_network(&api);
	}
	/******************************** /api/history **************************/
	else if(startsWith("/api/history/clients", &api))
	{
		lock_shm();
		ret = api_history_clients(&api);
		unlock_shm();
	}
	else if(startsWith("/api/history", &api))
	{
		lock_shm();
		ret = api_history(&api);
		unlock_shm();
	}
	/******************************** /api/queries **************************/
	else if(startsWith("/api/queries/suggestions", &api))
	{
		lock_shm();
		ret = api_queries_suggestions(&api);
		unlock_shm();
	}
	else if(startsWith("/api/queries", &api))
	{
		lock_shm();
		ret = api_queries(&api);
		unlock_shm();
	}
	/******************************** /api/stats **************************/
	else if(startsWith("/api/stats/summary", &api))
	{
		lock_shm();
		ret = api_stats_summary(&api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/query_types", &api))
	{
		lock_shm();
		ret = api_stats_query_types(&api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/upstreams", &api))
	{
		lock_shm();
		ret = api_stats_upstreams(&api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/top_domains", &api))
	{
		lock_shm();
		ret = api_stats_top_domains(false, &api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/top_blocked", &api))
	{
		lock_shm();
		ret = api_stats_top_domains(true, &api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/top_clients", &api))
	{
		lock_shm();
		ret = api_stats_top_clients(false, &api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/top_blocked_clients", &api))
	{
		lock_shm();
		ret = api_stats_top_clients(true, &api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/recent_blocked", &api))
	{
		lock_shm();
		ret = api_stats_recentblocked(&api);
		unlock_shm();
	}
	else if(startsWith("/api/stats/database/overTime/history", &api))
	{
		// Locks not needed
		ret = api_stats_database_overTime_history(&api);
	}
	else if(startsWith("/api/stats/database/top_domains", &api))
	{
		// Locks not needed
		ret = api_stats_database_top_items(false, true, &api);
	}
	else if(startsWith("/api/stats/database/top_blocked", &api))
	{
		// Locks not needed
		ret = api_stats_database_top_items(true, true, &api);
	}
	else if(startsWith("/api/stats/database/top_clients", &api))
	{
		// Locks not needed
		ret = api_stats_database_top_items(false, false, &api);
	}
	else if(startsWith("/api/stats/database/summary", &api))
	{
		// Locks not needed
		ret = api_stats_database_summary(&api);
	}
	else if(startsWith("/api/stats/database/overTime/clients", &api))
	{
		// Locks not needed
		ret = api_stats_database_overTime_clients(&api);
	}
	else if(startsWith("/api/stats/database/query_types", &api))
	{
		// Locks not needed
		ret = api_stats_database_query_types(&api);
	}
	else if(startsWith("/api/stats/database/upstreams", &api))
	{
		// Locks not needed
		ret = api_stats_database_upstreams(&api);
	}
	/******************************** /api/version ****************************/
	else if(startsWith("/api/version", &api))
	{
		// Locks not needed
		ret = api_version(&api);
	}
	/******************************** /api/auth ****************************/
	else if(startsWith("/api/auth", &api))
	{
		// Locks not needed
		ret = api_auth(&api);
	}
	/******************************** /api/settings ****************************/
	else if(startsWith("/api/settings/web", &api))
	{
		// Locks not needed
		ret = api_settings_web(&api);
	}
	/******************************** /api/settings ****************************/
	else if((api.item = startsWith("/api/docs", &api)) != NULL)
	{
		// Locks not needed
		ret = api_docs(&api);
	}
	/******************************** not found or invalid request**************/
	if(ret == 0)
	{
		ret = send_json_error(&api, 404,
		                      "not_found",
		                      "Not found",
		                      api.request->local_uri_raw);
	}

	// Free JSON-parsed payload memory (if allocated)
	if(api.payload.json != NULL)
	{
		cJSON_Delete(api.payload.json);
		api.payload.json = NULL;
	}

	// Free action path (if allocated)
	if(api.action_path != NULL)
	{
		free(api.action_path);
		api.action_path = NULL;
	}

	return ret;
}
