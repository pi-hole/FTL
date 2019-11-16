/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  HTTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
#include "http.h"
#include "../config.h"
#include "../log.h"
#include "json_macros.h"

// Server context handle
static struct mg_context *ctx = NULL;

int send_http(struct mg_connection *conn, const char *mime_type,
              const char *additional_headers, const char *msg)
{
	mg_send_http_ok(conn, mime_type, additional_headers, strlen(msg));
	return mg_write(conn, msg, strlen(msg));
}

int send_http_code(struct mg_connection *conn, int code,
                     const char *additional_headers, const char *msg)
{
	// Payload will be sent with text/plain encoding due to
	// the first line being "Error <code>>" by definition
	return mg_send_http_error(conn, code, "%s", msg);
}

int send_http_error(struct mg_connection *conn)
{
	return mg_send_http_error(conn, 500, "Internal server error");
}

static bool startsWith(const char *path, const char *pattern)
{
	return strncmp(path, pattern, strlen(pattern)) == 0;
}

void __attribute__ ((format (gnu_printf, 3, 4))) http_send(struct mg_connection *conn, bool chunk, const char *format, ...)
{
	char *buffer;
	va_list args;
	va_start(args, format);
	int len = vasprintf(&buffer, format, args);
	va_end(args);
	if(len > 0)
	{
		if(!chunk)
		{
			// Send 200 HTTP header with content size
			mg_send_http_ok(conn, "application/json", NULL, len);
		}
		if(chunk && mg_send_chunk(conn, buffer, len) < 0)
		{
			logg("WARNING: Chunked HTTP writing returned error %s "
			     "(%i, length %i)", strerror(errno), errno, len);
		}
		else if(!chunk && mg_write(conn, buffer, len) < 0)
		{
			logg("WARNING: Regular HTTP writing returned error %s "
			     "(%i, length %i)", strerror(errno), errno, len);
		}
		free(buffer);
	}
}

// Print passed string directly
static int print_simple(struct mg_connection *conn, void *input)
{
	return send_http(conn, "text/plain", NULL, input);
}

static int api_handler(struct mg_connection *conn, void *ignored)
{
	const struct mg_request_info *request = mg_get_request_info(conn);
	// HTTP response
	int ret = 0;
	if(config.debug & DEBUG_API)
	{
		logg("Received request for %s (method %s)",
		     request->local_uri, request->request_method);
	}
	/******************************** api/dns ********************************/
	if(startsWith(request->local_uri, "/api/dns/status"))
	{
		ret = api_dns_status(conn);
	}
	else if(startsWith(request->local_uri, "/api/dns/whitelist/exact"))
	{
		ret = api_dns_somelist(conn, true, true);
	}
	else if(startsWith(request->local_uri, "/api/dns/whitelist/regex"))
	{
		ret = api_dns_somelist(conn, false, true);
	}
	else if(startsWith(request->local_uri, "/api/dns/blacklist/exact"))
	{
		ret = api_dns_somelist(conn, true, false);
	}
	else if(startsWith(request->local_uri, "/api/dns/blacklist/regex"))
	{
		ret = api_dns_somelist(conn, false, false);
	}
	/******************************** api/ftl ****************************/
	else if(startsWith("/api/ftl/clientIP", request->local_uri))
	{
		ret = api_ftl_clientIP(conn);
	}
	/******************************** api/stats **************************/
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
	/******************************** api/version ****************************/
	else if(startsWith("/api/version", request->local_uri))
	{
		ret = api_version(conn);
	}
	/******************************** api/auth ****************************/
	else if(startsWith("/api/auth", request->local_uri))
	{
		ret = api_auth(conn);
	}
	else if(startsWith("/api/auth/salt", request->local_uri))
	{
		ret = api_auth_salt(conn);
	}
	/******************************** api/settings ****************************/
	else if(startsWith("/api/settings/web", request->local_uri))
	{
		ret = api_settings_web(conn);
	}
	else if(startsWith("/api/settings/ftldb", request->local_uri))
	{
		ret = api_settings_ftldb(conn);
	}
	/******************************** not found ******************************/
/*	else
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "status", "requested path is not available");
		JSON_OBJ_REF_STR(json, "path", request->local_uri);
		JSON_SENT_OBJECT(json);
	}*/
	return ret;
}

void http_init(void)
{
	logg("Initializing HTTP server on port %s", httpsettings.port);

	/* Initialize the library */
	unsigned int features = MG_FEATURES_FILES |
				MG_FEATURES_IPV6 |
				MG_FEATURES_CACHE |
				MG_FEATURES_STATS;
	if(mg_init_library(features) == 0)
	{
		logg("Initializing HTTP library failed!");
		return;
	}

	// Prepare options for HTTP server (NULL-terminated list)
	const char *options[] = {
		"document_root", httpsettings.webroot,
		"listening_ports", httpsettings.port,
		"decode_url", "no",
		"num_threads", "4",
		NULL
	};

	/* Start the server */
	if((ctx = mg_start(NULL, NULL, options)) == NULL)
	{
		logg("Initializing HTTP library failed!");
		return;
	}

	/* Add simple demonstration callbacks */
	mg_set_request_handler(ctx, "/ping", print_simple, (char*)"pong\n");
	mg_set_request_handler(ctx, "/api", api_handler, NULL);
}

void http_terminate(void)
{
	/* Stop the server */
	mg_stop(ctx);

	/* Un-initialize the library */
	mg_exit_library();
}

bool http_get_cookie_int(struct mg_connection *conn, const char *cookieName, int *i)
{
	// Maximum cookie length is 4KB
	char cookieValue[4096];
	const char *cookie = mg_get_header(conn, "Cookie");
	if(mg_get_cookie(cookie, cookieName, cookieValue, sizeof(cookieValue)) > 0)
	{
		*i = atoi(cookieValue);
		return true;
	}
	return false;
}

bool http_get_cookie_str(struct mg_connection *conn, const char *cookieName, char *str, size_t str_size)
{
	const char *cookie = mg_get_header(conn, "Cookie");
	if(mg_get_cookie(cookie, cookieName, str, str_size) > 0)
	{
		return true;
	}
	return false;
}

int http_method(struct mg_connection *conn)
{
	const struct mg_request_info *request = mg_get_request_info(conn);
	if(strcmp(request->request_method, "GET") == 0)
	{
		return HTTP_GET;
	}
	else if(strcmp(request->request_method, "DELETE") == 0)
	{
		return HTTP_DELETE;
	}
	else if(strcmp(request->request_method, "POST") == 0)
	{
		return HTTP_POST;
	}
	else
	{
		return HTTP_UNKNOWN;
	}
}