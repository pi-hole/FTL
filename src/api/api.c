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
#include "webserver/civetweb/civetweb.h"
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
	// URI                                      ARGUMENTS                     FUNCTION                               OPTIONS                          AUTH   ALLOWED METHODS
	//                                                                                                               domains  json   fifo
	// Note: The order of appearance matters here, more specific URIs have to
	// appear *before* less specific URIs: 1. "/a/b/c", 2. "/a/b", 3. "/a"
	{ "/api/dns/blocking",                      "",                           api_dns_blocking,                      { false, true,  0             }, true,  HTTP_GET | HTTP_POST },
	{ "/api/clients",                           "/{client}",                  api_list,                              { false, true,  0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/domains",                           "/{type}/{kind}/{domain}",    api_list,                              { false, true,  0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/search",                            "/{domain}",                  api_search,                            { false, true,  0             }, true,  HTTP_GET },
	{ "/api/groups",                            "/{name}",                    api_list,                              { false, true,  0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/lists",                             "/{list}",                    api_list,                              { false, true,  0             }, true,  HTTP_GET | HTTP_POST | HTTP_PUT | HTTP_DELETE },
	{ "/api/info/client",                       "",                           api_info_client,                       { false, true,  0             }, false, HTTP_GET },
	{ "/api/info/system",                       "",                           api_info_system,                       { false, true,  0             }, true,  HTTP_GET },
	{ "/api/info/database",                     "",                           api_info_database,                     { false, true,  0             }, true,  HTTP_GET },
	{ "/api/info/sensors",                      "",                           api_info_sensors,                      { false, true,  0             }, true,  HTTP_GET },
	{ "/api/info/host",                         "",                           api_info_host,                         { false, true,  0             }, true,  HTTP_GET },
	{ "/api/info/ftl",                          "",                           api_info_ftl,                          { false, true,  0             }, true,  HTTP_GET },
	{ "/api/info/version",                      "",                           api_info_version,                      { false, true,  0             }, true,  HTTP_GET },
	{ "/api/info/messages",                     "/{message_id}",              api_info_messages,                     { false, true,  0             }, true,  HTTP_DELETE },
	{ "/api/info/messages",                     "",                           api_info_messages,                     { false, true,  0             }, true,  HTTP_GET },
	{ "/api/info/cache",                        "",                           api_info_cache,                        { false, true,  0             }, true,  HTTP_GET },
	{ "/api/logs/dnsmasq",                      "",                           api_logs,                              { false, true,  FIFO_DNSMASQ  }, true,  HTTP_GET },
	{ "/api/logs/ftl",                          "",                           api_logs,                              { false, true,  FIFO_FTL      }, true,  HTTP_GET },
	{ "/api/logs/http",                         "",                           api_logs,                              { false, true,  FIFO_CIVETWEB }, true,  HTTP_GET },
	{ "/api/logs/ph7",                          "",                           api_logs,                              { false, true,  FIFO_PH7      }, true,  HTTP_GET },
	{ "/api/history/clients",                   "",                           api_history_clients,                   { false, true,  0             }, true,  HTTP_GET },
	{ "/api/history/database/clients",          "",                           api_history_database_clients,          { false, true,  0             }, true,  HTTP_GET },
	{ "/api/history/database",                  "",                           api_history_database,                  { false, true,  0             }, true,  HTTP_GET },
	{ "/api/history",                           "",                           api_history,                           { false, true,  0             }, true,  HTTP_GET },
	{ "/api/queries/suggestions",               "",                           api_queries_suggestions,               { false, true,  0             }, true,  HTTP_GET },
	{ "/api/queries",                           "",                           api_queries,                           { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/summary",                     "",                           api_stats_summary,                     { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/query_types",                 "",                           api_stats_query_types,                 { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/upstreams",                   "",                           api_stats_upstreams,                   { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/top_domains",                 "",                           api_stats_top_domains,                 { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/top_clients",                 "",                           api_stats_top_clients,                 { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/recent_blocked",              "",                           api_stats_recentblocked,               { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/database/top_domains",        "",                           api_stats_database_top_items,          { true,  true,  0             }, true,  HTTP_GET },
	{ "/api/stats/database/top_clients",        "",                           api_stats_database_top_items,          { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/database/summary",            "",                           api_stats_database_summary,            { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/database/query_types",        "",                           api_stats_database_query_types,        { false, true,  0             }, true,  HTTP_GET },
	{ "/api/stats/database/upstreams",          "",                           api_stats_database_upstreams,          { false, true,  0             }, true,  HTTP_GET },
	{ "/api/auth",                              "",                           api_auth,                              { false, true,  0             }, false, HTTP_GET | HTTP_POST | HTTP_DELETE },
	{ "/api/config",                            "",                           api_config,                            { false, true,  0             }, true,  HTTP_GET | HTTP_PATCH },
	{ "/api/config",                            "/{element}",                 api_config,                            { false, true,  0             }, true,  HTTP_GET | HTTP_PATCH },
	{ "/api/config",                            "/{element}/{value}",         api_config,                            { false, true,  0             }, true,  HTTP_DELETE | HTTP_PUT },
	{ "/api/network/gateway",                   "",                           api_network_gateway,                   { false, true,  0             }, true,  HTTP_GET },
	{ "/api/network/interfaces",                "",                           api_network_interfaces,                { false, true,  0             }, true,  HTTP_GET },
	{ "/api/network/devices",                   "",                           api_network_devices,                   { false, true,  0             }, true,  HTTP_GET },
	{ "/api/endpoints",                         "",                           api_endpoints,                         { false, true,  0             }, true,  HTTP_GET },
	{ "/api/teleporter",                        "",                           api_teleporter,                        { false, false, 0             }, true,  HTTP_GET | HTTP_POST },
	{ "/api/dhcp/leases",                       "",                           api_dhcp_leases_GET,                   { false, true,  0             }, true,  HTTP_GET },
	{ "/api/dhcp/leases",                       "/{hwaddr}/{ip}/{clid}",      api_dhcp_leases_DELETE,                { false, true,  0             }, true,  HTTP_DELETE },
	{ "/api/action/gravity",                    "",                           api_action_gravity,                    { false, true,  0             }, true,  HTTP_POST },
	{ "/api/action/reboot",                     "",                           api_action_reboot,                     { false, true,  0             }, true,  HTTP_POST },
	{ "/api/action/poweroff",                   "",                           api_action_poweroff,                   { false, true,  0             }, true,  HTTP_POST },
	{ "/api/docs",                              "",                           api_docs,                              { false, true,  0             }, false, HTTP_GET },
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
		{ false, NULL, NULL, NULL, 0u },
		{ false },
		{ false, false, 0 }
	};

	log_debug(DEBUG_API, "Requested API URI: %s %s ? %s (Content-Type %s)",
	          api.request->request_method,
	          api.request->local_uri_raw,
	          api.request->query_string,
	          mg_get_header(conn, "Content-Type"));

	int ret = 0;

	// Loop over all API endpoints and check if the requested URI matches
	bool unauthorized = false;
	enum http_method allowed_methods = 0;
	for(unsigned int i = 0; i < ArraySize(api_request); i++)
	{
		// Check if the requested method is allowed
		if(!(api_request[i].methods & api.method) && api.method != HTTP_OPTIONS)
			continue;

		// Check if the requested URI starts with the API endpoint
		if((api.item = startsWith(api_request[i].uri, &api)) != NULL)
		{

			// Copy options to API struct
			memcpy(&api.opts, &api_request[i].opts, sizeof(api.opts));

			// If this is an OPTIONS request, we add the supported
			// options of this endpoint and continue
			if(api.method == HTTP_OPTIONS)
			{
				allowed_methods |= api_request[i].methods;
				continue;
			}

			if(api_request[i].opts.parse_json)
			{
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
			}

			// Verify requesting client is allowed to see this ressource
			if(api_request[i].require_auth && check_client_auth(&api) == API_AUTH_UNAUTHORIZED)
			{
				unauthorized = true;
				break;
			}

			// Call the API function and get the return code
			log_debug(DEBUG_API, "Sending to %s", api_request[i].uri);
			ret = api_request[i].func(&api);
			log_debug(DEBUG_API, "Done");
			break;
		}
	}

	// Free memory allocated for action path (if allocated)
	if(api.action_path != NULL)
	{
		free(api.action_path);
		api.action_path = NULL;
	}

	// Free JSON-parsed payload memory (if allocated)
	if(api.payload.json != NULL)
	{
		cJSON_Delete(api.payload.json);
		api.payload.json = NULL;
	}

	// Free raw payload bytes
	if(api.payload.raw != NULL)
	{
		free(api.payload.raw);
		api.payload.raw = NULL;
	}

	// Check if we need to return with unauthorized payload
	if(unauthorized)
	{
		// Return with unauthorized payload
		// Do this only after having cleaned up above
		return send_json_unauthorized(&api);
	}

	// The HTTP OPTIONS method requests permitted communication options for
	// a given URL or server. We no not implement the wildcard OPTIONS method
	// but instead return the allowed methods for the requested endpoint
	// in the Allow header.
	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
	if(api.method == HTTP_OPTIONS)
	{
		// Send Allow header
		mg_printf(conn, "HTTP/1.1 204 No Content\r\n"
		                "Allow: ");

		// Loop over all possible methods
		unsigned int m = 0;
		for(enum http_method j = HTTP_GET; j < HTTP_OPTIONS; j <<= 1)
		{
			// Check if this method is allowed for this endpoint
			if(allowed_methods & j)
				mg_printf(conn, "%s%s", m++ > 0 ? ", " : "", get_http_method_str(j));
		}

		// Finish header and send empty body
		mg_printf(conn, "\r\n"
		                "Content-Length: 0\r\n"
		                "Connection: close\r\n\r\n");
		return 204;
	}

	// Check if we need to return with not found payload
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
	for(unsigned int i = 0; i < ArraySize(api_request); i++)
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
				case HTTP_UNKNOWN: // fall through
				case HTTP_OPTIONS:
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
