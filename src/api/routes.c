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

	if(config.debug & DEBUG_API)
		logg("Requested API URI: %s %s", api.request->request_method, api.request->local_uri);

	/******************************** /api/dns ********************************/
	if(startsWith("/api/dns/blocking", &api))
	{
		ret = api_dns_blocking(&api);
	}
	else if(startsWith("/api/dns/cache", &api))
	{
		ret = api_dns_cache(&api);
	}
	/************ /api/domains, /api/groups, /api/lists, /api/clients ********/
	else if(startsWith("/api/domains", &api))
	{
		ret = api_list(&api);
	}
	else if(startsWith("/api/groups", &api))
	{
		ret = api_list(&api);
	}
	else if(startsWith("/api/lists", &api))
	{
		ret = api_list(&api);
	}
	else if(startsWith("/api/clients", &api))
	{
		ret = api_list(&api);
	}
	/******************************** /api/ftl ****************************/
	else if(startsWith("/api/ftl/client", &api))
	{
		ret = api_ftl_client(&api);
	}
	else if(startsWith("/api/ftl/dnsmasq_log", &api))
	{
		ret = api_ftl_dnsmasq_log(&api);
	}
	else if(startsWith("/api/ftl/database", &api))
	{
		ret = api_ftl_database(&api);
	}
	else if(startsWith("/api/ftl/system", &api))
	{
		ret = api_ftl_system(&api);
	}
	/******************************** /api/network ****************************/
	else if(startsWith("/api/network", &api))
	{
		ret = api_network(&api);
	}
	/******************************** /api/stats **************************/
	else if(startsWith("/api/stats/summary", &api))
	{
		ret = api_stats_summary(&api);
	}
	else if(startsWith("/api/stats/overTime/history", &api))
	{
		ret = api_stats_overTime_history(&api);
	}
	else if(startsWith("/api/stats/overTime/clients", &api))
	{
		ret = api_stats_overTime_clients(&api);
	}
	else if(startsWith("/api/stats/query_types", &api))
	{
		ret = api_stats_query_types(&api);
	}
	else if(startsWith("/api/stats/upstreams", &api))
	{
		ret = api_stats_upstreams(&api);
	}
	else if(startsWith("/api/stats/top_domains", &api))
	{
		ret = api_stats_top_domains(false, &api);
	}
	else if(startsWith("/api/stats/top_blocked", &api))
	{
		ret = api_stats_top_domains(true, &api);
	}
	else if(startsWith("/api/stats/top_clients", &api))
	{
		ret = api_stats_top_clients(false, &api);
	}
	else if(startsWith("/api/stats/top_blocked_clients", &api))
	{
		ret = api_stats_top_clients(true, &api);
	}
	else if(startsWith("/api/stats/history", &api))
	{
		ret = api_stats_history(&api);
	}
	else if(startsWith("/api/stats/recent_blocked", &api))
	{
		ret = api_stats_recentblocked(&api);
	}
	else if(startsWith("/api/stats/database/overTime/history", &api))
	{
		ret = api_stats_database_overTime_history(&api);
	}
	else if(startsWith("/api/stats/database/top_domains", &api))
	{
		ret = api_stats_database_top_items(false, true, &api);
	}
	else if(startsWith("/api/stats/database/top_blocked", &api))
	{
		ret = api_stats_database_top_items(true, true, &api);
	}
	else if(startsWith("/api/stats/database/top_clients", &api))
	{
		ret = api_stats_database_top_items(false, false, &api);
	}
	else if(startsWith("/api/stats/database/summary", &api))
	{
		ret = api_stats_database_summary(&api);
	}
	else if(startsWith("/api/stats/database/overTime/clients", &api))
	{
		ret = api_stats_database_overTime_clients(&api);
	}
	else if(startsWith("/api/stats/database/query_types", &api))
	{
		ret = api_stats_database_query_types(&api);
	}
	else if(startsWith("/api/stats/database/upstreams", &api))
	{
		ret = api_stats_database_upstreams(&api);
	}
	/******************************** /api/version ****************************/
	else if(startsWith("/api/version", &api))
	{
		ret = api_version(&api);
	}
	/******************************** /api/auth ****************************/
	else if(startsWith("/api/auth", &api))
	{
		ret = api_auth(&api);
	}
	/******************************** /api/settings ****************************/
	else if(startsWith("/api/settings/web", &api))
	{
		ret = api_settings_web(&api);
	}
	/******************************** /api/settings ****************************/
	else if((api.item = startsWith("/api/docs", &api)) != NULL)
	{
		ret = api_docs(&api);
	}
	/******************************** not found or invalid request**************/
	if(ret == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		cJSON *string_item = cJSON_CreateStringReference((const char*)api.request->local_uri);
		cJSON_AddItemToObject(json, "path", string_item);
		ret = send_json_error(&api, 404,
		                      "not_found",
		                      "Not found",
		                      json);
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

	// Unlock after API access
	unlock_shm();

	return ret;
}
