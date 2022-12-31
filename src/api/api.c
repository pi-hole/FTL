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

static int api_endpoints(struct ftl_conn *api);

static struct {
	const char *uri;
	int (*func)(struct ftl_conn *api);
	const bool opts[2];
} api_request[] = {
	// URI                                      FUNCTION                               OPTIONS
	{ "/api/dns/blocking",                      api_dns_blocking,                      { false, false } },
	{ "/api/dns/cache",                         api_dns_cache,                         { false, false } },
	{ "/api/dns/port",                          api_dns_port,                          { false, false } },
	{ "/api/domains",                           api_list,                              { false, false } },
	{ "/api/groups",                            api_list,                              { false, false } },
	{ "/api/lists",                             api_list,                              { false, false } },
	{ "/api/clients",                           api_list,                              { false, false } },
	{ "/api/ftl/client",                        api_ftl_client,                        { false, false } },
	{ "/api/ftl/logs/dns",                      api_ftl_logs_dns,                      { false, false } },
	{ "/api/ftl/sysinfo",                       api_ftl_sysinfo,                       { false, false } },
	{ "/api/ftl/dbinfo",                        api_ftl_dbinfo,                        { false, false } },
	{ "/api/ftl/maxhistory",                    api_ftl_maxhistory,                    { false, false } },
	{ "/api/ftl/gateway",                       api_ftl_gateway,                       { false, false } },
	{ "/api/ftl/interfaces",                    api_ftl_interfaces,                    { false, false } },
	{ "/api/ftl/endpoints",                     api_endpoints,                         { false, false } },
	{ "/api/network",                           api_network,                           { false, false } },
	{ "/api/history/clients",                   api_history_clients,                   { false, false } },
	{ "/api/history",                           api_history,                           { false, false } },
	{ "/api/queries/suggestions",               api_queries_suggestions,               { false, false } },
	{ "/api/queries",                           api_queries,                           { false, false } },
	{ "/api/stats/summary",                     api_stats_summary,                     { false, false } },
	{ "/api/stats/query_types",                 api_stats_query_types,                 { false, false } },
	{ "/api/stats/upstreams",                   api_stats_upstreams,                   { false, false } },
	{ "/api/stats/top_domains",                 api_stats_top_domains,                 { false, false } },
	{ "/api/stats/top_blocked",                 api_stats_top_domains,                 { true,  false } },
	{ "/api/stats/top_clients",                 api_stats_top_clients,                 { false, false } },
	{ "/api/stats/top_blocked_clients",         api_stats_top_clients,                 { true,  false } },
	{ "/api/stats/recent_blocked",              api_stats_recentblocked,               { false, false } },
	{ "/api/stats/database/overTime/history",   api_stats_database_overTime_history,   { false, false } },
	{ "/api/stats/database/top_domains",        api_stats_database_top_items,          { false, true  } },
	{ "/api/stats/database/top_blocked",        api_stats_database_top_items,          { true,  true  } },
	{ "/api/stats/database/top_clients",        api_stats_database_top_items,          { false, false } },
	{ "/api/stats/database/summary",            api_stats_database_summary,            { false, false } },
	{ "/api/stats/database/overTime/clients",   api_stats_database_overTime_clients,   { false, false } },
	{ "/api/stats/database/query_types",        api_stats_database_query_types,        { false, false } },
	{ "/api/stats/database/upstreams",          api_stats_database_upstreams,          { false, false } },
	{ "/api/version",                           api_version,                           { false, false } },
	{ "/api/auth",                              api_auth,                              { false, false } },
	{ "/api/settings/web",                      api_settings_web,                      { false, false } },
	{ "/api/docs",                              api_docs,                              { false, false } },
};
#define API_ENDPOINTS "/api/endpoints"

int api_handler(struct mg_connection *conn, void *ignored)
{
	// Prepare API info struct
	struct ftl_conn api = {
		conn,
		mg_get_request_info(conn),
		http_method(conn),
		NULL,
		NULL,
		{ 0 },
		{ false, false }
	};
	read_and_parse_payload(&api);

	log_debug(DEBUG_API, "Requested API URI: %s %s ? %s",
	          api.request->request_method,
	          api.request->local_uri_raw,
	          api.request->query_string);

	int ret = 0;

	// Loop over all API endpoints and check if the requested URI matches
	for(unsigned int i = 0; i < sizeof(api_request)/sizeof(api_request[0]); i++)
	{
		// Check if the requested URI starts with the API endpoint
		if((api.item = startsWith(api_request[i].uri, &api)) != NULL)
		{
			// Copy options to API struct
			memcpy(api.opts, api_request[i].opts, sizeof(api.opts));
			// Call the API function and get the return code
			ret = api_request[i].func(&api);
		}
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

static int api_endpoints(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	cJSON *json = JSON_NEW_OBJECT();
	cJSON *endpoints = JSON_NEW_ARRAY();

	// Add endpoints to JSON array
	for(unsigned int i = 0; i < sizeof(api_request)/sizeof(api_request[0]); i++)
		JSON_REF_STR_IN_ARRAY(endpoints, api_request[i].uri);

	// Add endpoints to JSON object
	JSON_ADD_ITEM_TO_OBJECT(json, "endpoints", endpoints);

	// Send response
	JSON_SEND_OBJECT(json);
}
