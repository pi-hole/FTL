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
#include "../api/routes.h"
// send_http()
#include "http-common.h"
// struct httpsettings
#include "../config.h"
#include "../log.h"
#include "webserver.h"
// ph7_handler
#include "ph7.h"

// Server context handle
static struct mg_context *ctx = NULL;

// Print passed string directly
static int print_simple(struct mg_connection *conn, void *input)
{
	return send_http(conn, "text/plain", input);
}

static int log_http_message(const struct mg_connection *conn, const char *message)
{
	logg("HTTP info: %s", message);
	return 1;
}

static int log_http_access(const struct mg_connection *conn, const char *message)
{
	// Only log when in API debugging mode
	if(config.debug & DEBUG_API)
		logg("HTTP access: %s", message);

	return 1;
}

void http_init(void)
{
	logg("Initializing HTTP server on port %s", httpsettings.port);

	/* Initialize the library */
	unsigned int features = MG_FEATURES_FILES |
//	                        MG_FEATURES_CGI |
	                        MG_FEATURES_IPV6 |
	                        MG_FEATURES_CACHE |
	                        MG_FEATURES_STATS;
	if(mg_init_library(features) == 0)
	{
		logg("Initializing HTTP library failed!");
		return;
	}

	// Prepare options for HTTP server (NULL-terminated list)
	// Note about the additional headers:
	// - "Content-Security-Policy: [...]"
	//   'unsafe-inline' is both required by Chart.js styling some elements directly, and
	//   index.html containing some inlined Javascript code.
	// - "X-Frame-Options: SAMEORIGIN"
	//   The page can only be displayed in a frame on the same origin as the page itself.
	// - "X-Xss-Protection: 1; mode=block"
	//   Enables XSS filtering. Rather than sanitizing the page, the browser will prevent
	//   rendering of the page if an attack is detected.
	// - "X-Content-Type-Options: nosniff"
	//   Marker used by the server to indicate that the MIME types advertised in the
	//   Content-Type headers should not be changed and be followed. This allows to
	//   opt-out of MIME type sniffing, or, in other words, it is a way to say that the
	//   webmasters knew what they were doing. Site security testers usually expect this
	//   header to be set.
	// - "Referrer-Policy: same-origin"
	//   A referrer will be sent for same-site origins, but cross-origin requests will
	//   send no referrer information.
	// The latter four headers are set as expected by https://securityheaders.io
	const char *options[] = {
		"document_root", httpsettings.webroot,
		"listening_ports", httpsettings.port,
		"decode_url", "no",
		"num_threads", "4",
		"access_control_list", httpsettings.acl,
		"additional_header", "Content-Security-Policy: default-src 'self' 'unsafe-inline';\r\n"
		                     "X-Frame-Options: SAMEORIGIN\r\n"
		                     "X-Xss-Protection: 1; mode=block\r\n"
		                     "X-Content-Type-Options: nosniff\r\n"
		                     "Referrer-Policy: same-origin",
//		"cgi_interpreter", httpsettings.php_location,
//		"cgi_pattern", "**.php$", // ** allows the files to by anywhere inside the web root
		"index_files", "index.html,index.htm,index.php",
		NULL
	};

	// Configure logging handlers
	struct mg_callbacks callbacks = { NULL };
	callbacks.log_message = log_http_message;
	callbacks.log_access  = log_http_access;

	/* Start the server */
	if((ctx = mg_start(&callbacks, NULL, options)) == NULL)
	{
		logg("ERROR: Initializing HTTP library failed!\n"
		     "       Web interface will not be available!");
		return;
	}

	/* Add simple demonstration callbacks */
	mg_set_request_handler(ctx, "/ping", print_simple, (char*)"pong\n");
	char *api_path = NULL;
	if(asprintf(&api_path, "%sapi", httpsettings.webhome) > 4)
	{
		if(config.debug & DEBUG_API)
		{
			logg("Installing API handler at %s", api_path);
		}
		mg_set_request_handler(ctx, api_path, api_handler, NULL);
		// The request handler URI got duplicated
		free(api_path);
	}

	// Initialize PH7 engine and register PHP request handler
	init_ph7();
	mg_set_request_handler(ctx, "**.php$", ph7_handler, 0);
}

void http_terminate(void)
{
	/* Stop the server */
	mg_stop(ctx);

	/* Un-initialize the library */
	mg_exit_library();

	/* Un-initialize PH7 */
	ph7_terminate();
}
