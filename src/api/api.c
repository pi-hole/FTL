/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API routes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
// struct mg_connection
#include "civetweb/civetweb.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
#include "shmem.h"
// exit_code
#include "signals.h"

// defined in dnsmasq/dnsmasq.h
extern volatile char FTL_terminate;

static int api_ftl_endpoints(struct ftl_conn *api);

static struct {
	const char *uri;
	const char *parameters;
	int (*func)(struct ftl_conn *api);
	const bool opts[2];
} api_request[] = {
	// URI                                      ARGUMENTS                     FUNCTION                               OPTIONS
	// Note: The order of appearance matters here, more specific URIs have to
	// appear *before* less specific URIs: 1. "/a/b/c", 2. "/a/b", 3. "/a"
	{ "/api/dns/blocking",                      "",                           api_dns_blocking,                      { false, false } },
	{ "/api/dns/cache",                         "",                           api_dns_cache,                         { false, false } },
	{ "/api/dns/port",                          "",                           api_dns_port,                          { false, false } },
	{ "/api/dns/entries",                       "",                           api_dns_entries,                       { false, false } },
	{ "/api/clients",                           "/{client}",                  api_list,                              { false, false } },
	{ "/api/domains",                           "/{type}/{kind}/{domain}",    api_list,                              { false, false } },
	{ "/api/groups",                            "/{name}",                    api_list,                              { false, false } },
	{ "/api/lists",                             "/{list}",                    api_list,                              { false, false } },
	{ "/api/ftl/client",                        "",                           api_ftl_client,                        { false, false } },
	{ "/api/ftl/logs/dns",                      "",                           api_ftl_logs_dns,                      { false, false } },
	{ "/api/ftl/sysinfo",                       "",                           api_ftl_sysinfo,                       { false, false } },
	{ "/api/ftl/dbinfo",                        "",                           api_ftl_dbinfo,                        { false, false } },
	{ "/api/ftl/endpoints",                     "",                           api_ftl_endpoints,                     { false, false } },
	{ "/api/history/clients",                   "",                           api_history_clients,                   { false, false } },
	{ "/api/history/database/clients",          "",                           api_history_database_clients,          { false, false } },
	{ "/api/history/database",                  "",                           api_history_database,                  { false, false } },
	{ "/api/history",                           "",                           api_history,                           { false, false } },
	{ "/api/queries/suggestions",               "",                           api_queries_suggestions,               { false, false } },
	{ "/api/queries",                           "",                           api_queries,                           { false, false } },
	{ "/api/stats/summary",                     "",                           api_stats_summary,                     { false, false } },
	{ "/api/stats/query_types",                 "",                           api_stats_query_types,                 { false, false } },
	{ "/api/stats/upstreams",                   "",                           api_stats_upstreams,                   { false, false } },
	{ "/api/stats/top_domains",                 "",                           api_stats_top_domains,                 { false, false } },
	{ "/api/stats/top_clients",                 "",                           api_stats_top_clients,                 { false, false } },
	{ "/api/stats/recent_blocked",              "",                           api_stats_recentblocked,               { false, false } },
	{ "/api/stats/database/top_domains",        "",                           api_stats_database_top_items,          { false, true  } },
	{ "/api/stats/database/top_clients",        "",                           api_stats_database_top_items,          { false, false } },
	{ "/api/stats/database/summary",            "",                           api_stats_database_summary,            { false, false } },
	{ "/api/stats/database/query_types",        "",                           api_stats_database_query_types,        { false, false } },
	{ "/api/stats/database/upstreams",          "",                           api_stats_database_upstreams,          { false, false } },
	{ "/api/version",                           "",                           api_version,                           { false, false } },
	{ "/api/auth",                              "",                           api_auth,                              { false, false } },
	{ "/api/config",                            "",                           api_config,                            { false, false } },
	{ "/api/network/gateway",                   "",                           api_network_gateway,                   { false, false } },
	{ "/api/network/interfaces",                "",                           api_network_interfaces,                { false, false } },
	{ "/api/network/devices",                   "",                           api_network_devices,                   { false, false } },
	{ "/api/docs",                              "",                           api_docs,                              { false, false } },
};

int api_handler(struct mg_connection *conn, void *ignored)
{
	// Prepare API info struct
	struct ftl_conn api = {
		conn,
		mg_get_request_info(conn),
		http_method(conn),
		NULL,
		NULL,
		{ false, NULL, NULL, 0u },
		{ false },
		{ false, false }
	};

	// Allocate memory for the payload
	api.payload.raw = calloc(MAX_PAYLOAD_BYTES, sizeof(char));
	if(!api.payload.raw)
	{
		log_crit("Cannot handle API request %s %s: %s",
		         api.request->request_method,
		         api.request->local_uri_raw,
		         strerror(ENOMEM));
	}

	// Read and try to parse payload
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
			log_debug(DEBUG_API, "Sending to %s", api_request[i].uri);
			ret = api_request[i].func(&api);
			log_debug(DEBUG_API, "Done");
			break;
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

	// Free raw payload bytes (always allocated)
	free(api.payload.raw);

	// Restart FTL if requested
	if(api.ftl.restart)
	{
		// Trigger an automatic restart by systemd
		exit_code = RESTART_FTL_CODE;
		FTL_terminate = 1;
	}

	return ret;
}

static int api_ftl_endpoints(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	cJSON *json = JSON_NEW_OBJECT();
	cJSON *endpoints = JSON_NEW_ARRAY();

	// Add endpoints to JSON array
	for(unsigned int i = 0; i < sizeof(api_request)/sizeof(api_request[0]); i++)
	{
		cJSON *endpoint = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(endpoint, "uri", api_request[i].uri);
		JSON_REF_STR_IN_OBJECT(endpoint, "parameters", api_request[i].parameters);
		JSON_ADD_ITEM_TO_ARRAY(endpoints, endpoint);
	}

	// Add endpoints to JSON object
	JSON_ADD_ITEM_TO_OBJECT(json, "endpoints", endpoints);

	// Send response
	JSON_SEND_OBJECT(json);
}
