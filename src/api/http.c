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

int send_http(struct mg_connection *conn, const char *mime_type, const char *msg)
{
	mg_send_http_ok(conn, mime_type, strlen(msg));
	return mg_write(conn, msg, strlen(msg));
}

int send_http_error(struct mg_connection *conn)
{
	return mg_send_http_error(conn, 500, "Internal server error");
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
			mg_send_http_ok(conn, "application/json", len);
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
	return send_http(conn, "text/plain", input);
}

static int api_handler(struct mg_connection *conn, void *ignored)
{
	const struct mg_request_info *request = mg_get_request_info(conn);
	// HTTP response
	int ret = 0;
	/******************************** api/dns ********************************/
	if(strcasecmp("/api/dns/status", request->local_uri) == 0)
	{
		ret = api_dns_status(conn);
	}
	else if(strcasecmp("/api/dns/whitelist", request->local_uri) == 0)
	{
		ret = api_dns_whitelist(conn);
	}
	else if(strcasecmp("/api/dns/whitelist/exact", request->local_uri) == 0)
	{
		ret = api_dns_whitelist_exact(conn);
	}
	else if(strcasecmp("/api/dns/whitelist/regex", request->local_uri) == 0)
	{
		ret = api_dns_whitelist_regex(conn);
	}
	else if(strcasecmp("/api/dns/blacklist", request->local_uri) == 0)
	{
		ret = api_dns_blacklist(conn);
	}
	else if(strcasecmp("/api/dns/blacklist/exact", request->local_uri) == 0)
	{
		ret = api_dns_blacklist_exact(conn);
	}
	else if(strcasecmp("/api/dns/blacklist/regex", request->local_uri) == 0 ||
	        strcasecmp("/api/dns/regexlist",       request->local_uri) == 0)
	{
		ret = api_dns_blacklist_regex(conn);
	}
	/******************************** api/ftl ****************************/
	else if(strcasecmp("/api/ftl/version", request->local_uri) == 0)
	{
		ret = api_ftl_version(conn);
	}
	else if(strcasecmp("/api/ftl/db", request->local_uri) == 0)
	{
		ret = api_ftl_db(conn);
	}
	else if(strcasecmp("/api/ftl/clientIP", request->local_uri) == 0)
	{
		ret = api_ftl_clientIP(conn);
	}
	/******************************** api/stats **************************/
	else if(strcasecmp("/api/stats/summary", request->local_uri) == 0)
	{
		ret = api_stats_summary(conn);
	}
	else if(strcasecmp("/api/stats/overTime/history", request->local_uri) == 0)
	{
		ret = api_stats_overTime_history(conn);
	}
	else if(strcasecmp("/api/stats/overTime/clients", request->local_uri) == 0)
	{
		ret = api_stats_overTime_clients(conn);
	}
	else if(strcasecmp("/api/stats/query_types", request->local_uri) == 0)
	{
		ret = api_stats_query_types(conn);
	}
	else if(strcasecmp("/api/stats/upstreams", request->local_uri) == 0)
	{
		ret = api_stats_upstreams(conn);
	}
	else if(strcasecmp("/api/stats/top_domains", request->local_uri) == 0)
	{
		ret = api_stats_top_domains(false, conn);
	}
	else if(strcasecmp("/api/stats/top_blocked", request->local_uri) == 0)
	{
		ret = api_stats_top_domains(true, conn);
	}
	else if(strcasecmp("/api/stats/top_clients", request->local_uri) == 0)
	{
		ret = api_stats_top_clients(false, conn);
	}
	else if(strcasecmp("/api/stats/top_blocked_clients", request->local_uri) == 0)
	{
		ret = api_stats_top_clients(true, conn);
	}
	else if(strcasecmp("/api/stats/history", request->local_uri) == 0)
	{
		ret = api_stats_history(conn);
	}
	else if(strcasecmp("/api/stats/recent_blocked", request->local_uri) == 0)
	{
		ret = api_stats_recentblocked(conn);
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