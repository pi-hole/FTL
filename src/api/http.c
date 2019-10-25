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

// Server context handle
static struct mg_context *ctx = NULL;

static int send_http(struct mg_connection *conn, const char *mime_type, const char *msg)
{
	mg_send_http_ok(conn, mime_type, strlen(msg));
	return mg_write(conn, msg, strlen(msg));
	return 200;
}
/*
static int send_http_chunked_simulator(struct mg_connection *conn, const char *mime_type, const char *msg)
{
	mg_send_http_ok(conn, mime_type, -1);
	// Send bytes one after another
	for(unsigned int i = 0; i < strlen(msg); i++)
	{
		char msgpart[2] = { 0 };
		msgpart[0] = msg[i];
		mg_send_chunk(conn, msgpart, strlen(msgpart));
	}
	return 200;
}

static int send_http_error(struct mg_connection *conn)
{
	return mg_send_http_error(conn, 500, "Internal server error");
}
*/
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
/*
// Print passed string as JSON
static int print_json(struct mg_connection *conn, void *input)
{
	// Create JSON object
	cJSON *json = cJSON_CreateObject();

	// Add string to created object
	if(cJSON_AddStringToObject(json, "message", (const char*)input) == NULL)
	{
		cJSON_Delete(json);
		send_http_error(conn);
		return 500;
	}

	const struct mg_request_info *request = mg_get_request_info(conn);

	// Add URL-decoded URI (relative) to created object
	if(cJSON_AddStringToObject(json, "uri", request->local_uri) == NULL)
	{
		cJSON_Delete(json);
		send_http_error(conn);
		return 500;
	}

	// Add URL-decoded URI (relative) to created object
	if(cJSON_AddStringToObject(json, "client", request->remote_addr) == NULL)
	{
		cJSON_Delete(json);
		send_http_error(conn);
		return 500;
	}

	// Generate string to be sent to the client
	const char* msg = cJSON_PrintUnformatted(json);
	if(msg == NULL)
	{
		cJSON_Delete(json);
		send_http_error(conn);
		return 500;
	}

	// Send JSON string
	if(strcmp(request->local_uri, "/api/chunk_test") == 0)
		send_http_chunked_simulator(conn, "application/json", msg);
	else
		send_http(conn, "application/json", msg);

	// Free JSON ressources
	cJSON_Delete(json);

	// HTTP status code to return
	return 200;
}
*/
// Print passed string directly
static int print_simple(struct mg_connection *conn, void *input)
{
	return send_http(conn, "text/plain", input);
}

static int api_handler(struct mg_connection *conn, void *ignored)
{
	
	//mg_send_chunk(conn, "{", 2);
	const struct mg_request_info *request = mg_get_request_info(conn);
	/******************************** api/dns ********************************/
	if(strcasecmp("/api/dns/status",request->local_uri) == 0)
	{
		api_dns_status(conn);
	}
	/******************************** api/ftl ****************************/
	else if(strcasecmp("/api/ftl/version",request->local_uri) == 0)
	{
		api_ftl_version(conn);
	}
	else if(strcasecmp("/api/ftl/db",request->local_uri) == 0)
	{
		api_ftl_db(conn);
	}
	/******************************** api/summary ****************************/
	else if(strcasecmp("/api/stats/summary",request->local_uri) == 0)
	{
		api_stats_summary(conn);
	}
	// mg_send_http_ok(conn, "application/json", -1);
	//mg_send_chunk(conn, "}", 2);
	return 200;
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
//	mg_set_request_handler(ctx, "/json_test", print_json, (char*)"Greetings from FTL!");
	mg_set_request_handler(ctx, "/api", api_handler, NULL);
}

void http_terminate(void)
{
	/* Stop the server */
	mg_stop(ctx);

	/* Un-initialize the library */
	mg_exit_library();
}