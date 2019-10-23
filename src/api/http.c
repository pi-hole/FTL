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
#include "http.h"
#include "../config.h"
#include "../log.h"
#include "../civetweb/civetweb.h"
#include "../cJSON/cJSON.h"

// Server context handle
static struct mg_context *ctx = NULL;

// Print passed string as JSON
static int print_json(struct mg_connection *conn, void *input)
{
	// Create JSON object
	cJSON *json = cJSON_CreateObject();

	// Add string to created object
	if(cJSON_AddStringToObject(json, "message", (const char*)input) == NULL)
	{
		cJSON_Delete(json);
		return 500;
	}

	// Generate string to be sent to the client
	const char* msg = cJSON_PrintUnformatted(json);
	if(msg == NULL)
	{
		cJSON_Delete(json);
		return 500;
	}

	// Send string
	unsigned long len = strlen(msg);
	mg_printf(conn,
	          "HTTP/1.1 200 OK\r\n"
	          "Content-Length: %lu\r\n"
	          "Content-Type: text/plain\r\n"
	          "Connection: close\r\n\r\n",
	          len);
	mg_write(conn, msg, len);

	// Free JSON ressources
	cJSON_Delete(json);

	// HTTP status code to return
	return 200;
}

// Print passed string directly
static int print_simple(struct mg_connection *conn, void *input)
{
	const char* msg = input;

	// Send string
	unsigned long len = strlen(msg);
	mg_printf(conn,
	          "HTTP/1.1 200 OK\r\n"
	          "Content-Length: %lu\r\n"
	          "Content-Type: text/plain\r\n"
	          "Connection: close\r\n\r\n",
	          len);
	mg_write(conn, msg, len);

	// HTTP status code to return
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
	mg_set_request_handler(ctx, "/test/ftl", print_json, (char*)"Greetings from FTL!");
}

void http_terminate(void)
{
	/* Stop the server */
	mg_stop(ctx);

	/* Un-initialize the library */
	mg_exit_library();
}