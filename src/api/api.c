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

static int api_endpoints(struct ftl_conn *api);

static struct {
	const char *uri;
	const char *parameters;
	int (*func)(struct ftl_conn *api);
	struct api_options opts;
	bool require_auth;
	enum http_method methods;
} api_request[] = {
	// URI                                      ARGUMENTS                     FUNCTION                               OPTIONS           AUTH   ALLOWED METHODS
	// Note: The order of appearance matters here, more specific URIs have to
	// appear *before* less specific URIs: 1. "/a/b/c", 2. "/a/b", 3. "/a"
	{ "/api/dns/blocking",                      "",                           api_dns_blocking,                      { false, 0             }, true,  HTTP_GET | HTTP_POST },
	{ "/api/dns/cache",                         "",                           api_dns_cache,                         { false, 0             }, true,  HTTP_GET },
	{ "/api/dns/entries",                       "",                           api_dns_entries,                       { false, 0             }, true,  HTTP_GET },
	{ "/api/dns/entries",                       "/{ip}/{host}",               api_dns_entries,                       { false, 0             }, true,  HTTP_PUT | HTTP_DELETE },
	{ "/api/clients",                           "/{client}",                  api_list,                              { false, 0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/domains",                           "/{type}/{kind}/{domain}",    api_list,                              { false, 0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/groups",                            "/{name}",                    api_list,                              { false, 0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/lists",                             "/{list}",                    api_list,                              { false, 0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/ftl/client",                        "",                           api_ftl_client,                        { false, 0             }, false, HTTP_GET },
	{ "/api/ftl/sysinfo",                       "",                           api_ftl_sysinfo,                       { false, 0             }, true,  HTTP_GET },
	{ "/api/ftl/dbinfo",                        "",                           api_ftl_dbinfo,                        { false, 0             }, true,  HTTP_GET },
	{ "/api/logs/dnsmasq",                      "",                           api_logs,                              { false, FIFO_DNSMASQ  }, true,  HTTP_GET },
	{ "/api/logs/ftl",                          "",                           api_logs,                              { false, FIFO_FTL      }, true,  HTTP_GET },
	{ "/api/logs/http",                         "",                           api_logs,                              { false, FIFO_CIVETWEB }, true,  HTTP_GET },
	{ "/api/logs/ph7",                          "",                           api_logs,                              { false, FIFO_PH7      }, true,  HTTP_GET },
	{ "/api/history/clients",                   "",                           api_history_clients,                   { false, 0             }, true,  HTTP_GET },
	{ "/api/history/database/clients",          "",                           api_history_database_clients,          { false, 0             }, true,  HTTP_GET },
	{ "/api/history/database",                  "",                           api_history_database,                  { false, 0             }, true,  HTTP_GET },
	{ "/api/history",                           "",                           api_history,                           { false, 0             }, true,  HTTP_GET },
	{ "/api/queries/suggestions",               "",                           api_queries_suggestions,               { false, 0             }, true,  HTTP_GET },
	{ "/api/queries",                           "",                           api_queries,                           { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/summary",                     "",                           api_stats_summary,                     { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/query_types",                 "",                           api_stats_query_types,                 { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/upstreams",                   "",                           api_stats_upstreams,                   { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/top_domains",                 "",                           api_stats_top_domains,                 { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/top_clients",                 "",                           api_stats_top_clients,                 { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/recent_blocked",              "",                           api_stats_recentblocked,               { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/database/top_domains",        "",                           api_stats_database_top_items,          { true,  0             }, true,  HTTP_GET },
	{ "/api/stats/database/top_clients",        "",                           api_stats_database_top_items,          { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/database/summary",            "",                           api_stats_database_summary,            { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/database/query_types",        "",                           api_stats_database_query_types,        { false, 0             }, true,  HTTP_GET },
	{ "/api/stats/database/upstreams",          "",                           api_stats_database_upstreams,          { false, 0             }, true,  HTTP_GET },
	{ "/api/version",                           "",                           api_version,                           { false, 0             }, true,  HTTP_GET },
	{ "/api/auth",                              "",                           api_auth,                              { false, 0             }, false, HTTP_GET | HTTP_POST | HTTP_DELETE },
	{ "/api/config",                            "",                           api_config,                            { false, 0             }, true,  HTTP_GET | HTTP_PATCH },
	{ "/api/network/gateway",                   "",                           api_network_gateway,                   { false, 0             }, true,  HTTP_GET },
	{ "/api/network/interfaces",                "",                           api_network_interfaces,                { false, 0             }, true,  HTTP_GET },
	{ "/api/network/devices",                   "",                           api_network_devices,                   { false, 0             }, true,  HTTP_GET },
	{ "/api/endpoints",                         "",                           api_endpoints,                         { false, 0             }, true,  HTTP_GET },
	{ "/api/docs",                              "",                           api_docs,                              { false, 0             }, false, HTTP_GET },
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
		{ false, 0 }
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
		// Check if the requested method is allowed
		if(!(api_request[i].methods & api.method))
			continue;

		// Check if the requested URI starts with the API endpoint
		if((api.item = startsWith(api_request[i].uri, &api)) != NULL)
		{
			// Copy options to API struct
			memcpy(&api.opts, &api_request[i].opts, sizeof(api.opts));

			// Verify requesting client is allowed to see this ressource
			if(api_request[i].require_auth && check_client_auth(&api) == API_AUTH_UNAUTHORIZED)
				return send_json_unauthorized(&api);

			// Call the API function and get the return code
			log_debug(DEBUG_API, "Sending to %s", api_request[i].uri);
			ret = api_request[i].func(&api);
			log_debug(DEBUG_API, "Done");
			break;
		}

		// Free memory allocated for action path (if allocated)
		if(api.action_path != NULL)
		{
			free(api.action_path);
			api.action_path = NULL;
		}
	}

	// Free JSON-parsed payload memory (if allocated)
	if(api.payload.json != NULL)
	{
		cJSON_Delete(api.payload.json);
		api.payload.json = NULL;
	}

	// Free raw payload bytes (always allocated)
	free(api.payload.raw);
	api.payload.raw = NULL;

	if(ret == 0)
	{
		// not found or invalid request
		ret = send_json_error(&api, 404,
		                      "not_found",
		                      "Not found",
		                      api.request->local_uri_raw);
	}

	// Restart FTL if requested
	if(api.ftl.restart)
	{
		// Trigger an automatic restart by systemd
		exit_code = RESTART_FTL_CODE;
		FTL_terminate = 1;
	}

	return ret;
}

static int api_endpoints(struct ftl_conn *api)
{
	cJSON *get = JSON_NEW_ARRAY();
	cJSON *post = JSON_NEW_ARRAY();
	cJSON *put = JSON_NEW_ARRAY();
	cJSON *patch = JSON_NEW_ARRAY();
	cJSON *delete = JSON_NEW_ARRAY();

	// Add endpoints to JSON array
	for(unsigned int i = 0; i < sizeof(api_request)/sizeof(api_request[0]); i++)
	{
		for(enum http_method method = HTTP_GET; method <= HTTP_DELETE; method <<= 1)
		{
			if(!(api_request[i].methods & method))
				continue;
			cJSON *endpoint = JSON_NEW_OBJECT();
			JSON_REF_STR_IN_OBJECT(endpoint, "uri", api_request[i].uri);
			JSON_REF_STR_IN_OBJECT(endpoint, "parameters", api_request[i].parameters);

			// Add endpoint to the correct array
			switch(method)
			{
				case HTTP_UNKNOWN:
					cJSON_Delete(endpoint);
					break;
				case HTTP_GET:
					JSON_ADD_ITEM_TO_ARRAY(get, endpoint);
					break;
				case HTTP_POST:
					JSON_ADD_ITEM_TO_ARRAY(post, endpoint);
					break;
				case HTTP_PUT:
					JSON_ADD_ITEM_TO_ARRAY(put, endpoint);
					break;
				case HTTP_PATCH:
					JSON_ADD_ITEM_TO_ARRAY(patch, endpoint);
					break;
				case HTTP_DELETE:
					JSON_ADD_ITEM_TO_ARRAY(delete, endpoint);
					break;
				default:
					break;
			}
		}
	}

	// Add endpoints to JSON object
	cJSON *endpoints = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(endpoints, "get", get);
	JSON_ADD_ITEM_TO_OBJECT(endpoints, "post", post);
	JSON_ADD_ITEM_TO_OBJECT(endpoints, "put", put);
	JSON_ADD_ITEM_TO_OBJECT(endpoints, "patch", patch);
	JSON_ADD_ITEM_TO_OBJECT(endpoints, "delete", delete);
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "endpoints", endpoints);

	// Send response
	JSON_SEND_OBJECT(json);
}
