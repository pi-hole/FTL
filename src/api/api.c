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
// struct config
#include "config/config.h"

static int api_endpoints(struct ftl_conn *api);

static struct {
	const char *uri;
	const char *parameters;
	int (*func)(struct ftl_conn *api);
	struct api_options opts;
	bool require_auth;
	enum http_method methods;
} api_request[] = {
	// URI                                      ARGUMENTS                     FUNCTION                               OPTIONS                                        AUTH   ALLOWED METHODS
	//                                                                                                               flags             fifo ID
	// Note: The order of appearance matters here, more specific URIs have to
	// appear *before* less specific URIs: 1. "/a/b/c", 2. "/a/b", 3. "/a"
	{ "/api/auth/sessions",                     "",                           api_auth_sessions,                     { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/auth/session",                      "/{id}",                      api_auth_session_delete,               { API_PARSE_JSON, 0                         }, true,  HTTP_DELETE },
	{ "/api/auth/app",                          "",                           generateAppPw,                         { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/auth/totp",                         "",                           generateTOTP,                          { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/auth",                              "",                           api_auth,                              { API_PARSE_JSON, 0                         }, false, HTTP_GET | HTTP_POST | HTTP_DELETE },
	{ "/api/dns/blocking",                      "",                           api_dns_blocking,                      { API_PARSE_JSON, 0                         }, true,  HTTP_GET | HTTP_POST },
	{ "/api/clients/_suggestions",              "",                           api_client_suggestions,                { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/clients",                           "/{client}",                  api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_GET | HTTP_PUT | HTTP_DELETE },
	{ "/api/clients",                           "",                           api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/clients:batchDelete",               "",                           api_list,                              { API_PARSE_JSON | API_BATCHDELETE, 0       }, true,  HTTP_POST },
	{ "/api/domains",                           "/{type}/{kind}/{domain}",    api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_GET | HTTP_PUT | HTTP_DELETE },
	{ "/api/domains",                           "/{type}/{kind}",             api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/domains:batchDelete",               "",                           api_list,                              { API_PARSE_JSON | API_BATCHDELETE, 0       }, true,  HTTP_POST },
	{ "/api/search",                            "/{domain}",                  api_search,                            { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/groups",                            "/{name}",                    api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_GET | HTTP_PUT | HTTP_DELETE },
	{ "/api/groups",                            "",                           api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/groups:batchDelete",                "",                           api_list,                              { API_PARSE_JSON | API_BATCHDELETE, 0       }, true,  HTTP_POST },
	{ "/api/lists",                             "/{list}",                    api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_GET | HTTP_PUT | HTTP_DELETE },
	{ "/api/lists",                             "",                           api_list,                              { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/lists:batchDelete",                 "",                           api_list,                              { API_PARSE_JSON | API_BATCHDELETE, 0       }, true,  HTTP_POST },
	{ "/api/info/client",                       "",                           api_info_client,                       { API_PARSE_JSON, 0                         }, false, HTTP_GET },
	{ "/api/info/login",                        "",                           api_info_login,                        { API_PARSE_JSON, 0                         }, false, HTTP_GET },
	{ "/api/info/system",                       "",                           api_info_system,                       { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/database",                     "",                           api_info_database,                     { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/sensors",                      "",                           api_info_sensors,                      { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/host",                         "",                           api_info_host,                         { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/ftl",                          "",                           api_info_ftl,                          { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/version",                      "",                           api_info_version,                      { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/messages/count",               "",                           api_info_messages_count,               { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/messages",                     "/{message_id}",              api_info_messages,                     { API_PARSE_JSON, 0                         }, true,  HTTP_DELETE },
	{ "/api/info/messages",                     "",                           api_info_messages,                     { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/info/metrics",                      "",                           api_info_metrics,                      { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/logs/dnsmasq",                      "",                           api_logs,                              { API_PARSE_JSON, FIFO_DNSMASQ              }, true,  HTTP_GET },
	{ "/api/logs/ftl",                          "",                           api_logs,                              { API_PARSE_JSON, FIFO_FTL                  }, true,  HTTP_GET },
	{ "/api/logs/webserver",                    "",                           api_logs,                              { API_PARSE_JSON, FIFO_WEBSERVER            }, true,  HTTP_GET },
	{ "/api/history/clients",                   "",                           api_history_clients,                   { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/history/database/clients",          "",                           api_history_database_clients,          { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/history/database",                  "",                           api_history_database,                  { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/history",                           "",                           api_history,                           { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/queries/suggestions",               "",                           api_queries_suggestions,               { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/queries",                           "",                           api_queries,                           { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/summary",                     "",                           api_stats_summary,                     { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/query_types",                 "",                           api_stats_query_types,                 { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/upstreams",                   "",                           api_stats_upstreams,                   { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/top_domains",                 "",                           api_stats_top_domains,                 { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/top_clients",                 "",                           api_stats_top_clients,                 { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/recent_blocked",              "",                           api_stats_recentblocked,               { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/database/top_domains",        "",                           api_stats_database_top_items,          { API_DOMAINS | API_PARSE_JSON, 0           }, true,  HTTP_GET },
	{ "/api/stats/database/top_clients",        "",                           api_stats_database_top_items,          { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/database/summary",            "",                           api_stats_database_summary,            { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/database/query_types",        "",                           api_stats_database_query_types,        { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/stats/database/upstreams",          "",                           api_stats_database_upstreams,          { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/config",                            "",                           api_config,                            { API_PARSE_JSON, 0                         }, true,  HTTP_GET | HTTP_PATCH },
	{ "/api/config",                            "/{element}",                 api_config,                            { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/config",                            "/{element}/{value}",         api_config,                            { API_PARSE_JSON, 0                         }, true,  HTTP_DELETE | HTTP_PUT },
	{ "/api/network/gateway",                   "",                           api_network_gateway,                   { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/network/interfaces",                "",                           api_network_interfaces,                { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/network/devices",                   "",                           api_network_devices,                   { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/network/devices",                   "/{device_id}",               api_network_devices,                   { API_PARSE_JSON, 0                         }, true,  HTTP_DELETE },
	{ "/api/endpoints",                         "",                           api_endpoints,                         { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/teleporter",                        "",                           api_teleporter,                        { API_FLAG_NONE, 0                          }, true,  HTTP_GET | HTTP_POST },
	{ "/api/dhcp/leases",                       "",                           api_dhcp_leases_GET,                   { API_PARSE_JSON, 0                         }, true,  HTTP_GET },
	{ "/api/dhcp/leases",                       "/{ip}",                      api_dhcp_leases_DELETE,                { API_PARSE_JSON, 0                         }, true,  HTTP_DELETE },
	{ "/api/action/gravity",                    "",                           api_action_gravity,                    { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/action/restartdns",                 "",                           api_action_restartDNS,                 { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/action/flush/logs",                 "",                           api_action_flush_logs,                 { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/action/flush/arp",                  "",                           api_action_flush_arp,                  { API_PARSE_JSON, 0                         }, true,  HTTP_POST },
	{ "/api/docs",                              "",                           api_docs,                              { API_PARSE_JSON, 0                         }, false, HTTP_GET },
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
		API_AUTH_UNAUTHORIZED,
		double_time(),
		{ false, NULL, NULL, NULL, 0u },
		{ false },
		{ API_FLAG_NONE, 0 }
	};

	log_debug(DEBUG_API, "Requested API URI: %s -> %s %s ? %s (Content-Type %s)",
	          api.request->remote_addr,
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

			if(api_request[i].opts.flags & API_PARSE_JSON)
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

			// Verify requesting client is allowed to see this resource
			if(api_request[i].func == api_search)
			{
				// Handle /api/search special as it may be allowed for local users due to webserver.api.searchAPIauth
				if(!config.webserver.api.searchAPIauth.v.b && is_local_api_user(api.request->remote_addr))
				{
					// Local users does not need to authenticate when searchAPIauth is false
					;
				}
				else if(api_request[i].require_auth && check_client_auth(&api, true) == API_AUTH_UNAUTHORIZED)
				{
					// Users need to authenticate but authentication failed
					unauthorized = true;
					break;
				}
			}
			else if(api_request[i].require_auth && check_client_auth(&api, true) == API_AUTH_UNAUTHORIZED)
			{
				unauthorized = true;
				break;
			}

			// Call the API function and get the return code
			log_debug(DEBUG_API, "Processing %s %s in %s",
			          api.request->request_method,
			          api.request->local_uri_raw,
			          api_request[i].uri);
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
		log_info("Restarting FTL due to API config change");
		exit_code = RESTART_FTL_CODE;
		// Send SIGTERM to FTL
		kill(main_pid(), SIGTERM);
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
