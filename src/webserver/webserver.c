/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  HTTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../api/api.h"
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

static int redirect_root_handler(struct mg_connection *conn, void *input)
{
	// Get requested host
	const char *host = mg_get_header(conn, "Host");
	size_t host_len = 0;
	if (host != NULL)
	{
		// If the "Host" is an IPv6 address, like [::1], parse until ] is found.
		if (*host == '[')
		{
			char *pos = strchr(host, ']');
			if (!pos)
			{
				// Malformed hostname starts with '[', but no ']' found
				logg("ERROR: Host name format error '[' without ']'");
				return 0;
			}
			/* terminate after ']' */
			host_len = (size_t)(pos + 1 - host);
		}
		else
		{
			char *pos = strchr(host, ':');
			if (pos != NULL)
			{
				// A ':' separates hostname and port number
				host_len = (size_t)(pos - host);
			}
			else
			{
				// Host header only contains the host name iteself
				host_len = strlen(host);
			}
		}
	}

	// API debug logging
	if(config.debug & DEBUG_API)
	{
		logg("Host header: \"%s\", extracted host: \"%.*s\"", host, (int)host_len, host);

		// Get requested URI
		const struct mg_request_info *request = mg_get_request_info(conn);
		const char *uri = request->local_uri;

		logg("URI: %s", uri);
	}

	// 308 Permanent Redirect from http://pi.hole -> http://pi.hole/admin
	if(host != NULL && strncmp(host, "pi.hole", host_len) == 0)
	{
		mg_send_http_redirect(conn, httpsettings.webhome, 308);
		return 1;
	}

	// else: Not redirecting
	return 0;
}

static int log_http_message(const struct mg_connection *conn, const char *message)
{
	logg_web(HTTP_INFO, "HTTP info: %s", message);
	return 1;
}

static int log_http_access(const struct mg_connection *conn, const char *message)
{
	// Only log when in API debugging mode
	if(config.debug & DEBUG_API)
		logg_web(HTTP_INFO, "ACCESS: %s", message);

	return 1;
}

void http_init(void)
{
	logg_web(HTTP_INFO, "Initializing HTTP server on port %s", httpsettings.port);

	/* Initialize the library */
	unsigned int features = MG_FEATURES_FILES |
//	                        MG_FEATURES_CGI |
	                        MG_FEATURES_IPV6 |
	                        MG_FEATURES_CACHE |
	                        MG_FEATURES_STATS;

	if(mg_init_library(features) == 0)
	{
		logg_web(HTTP_INFO, "Initializing HTTP library failed!");
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
		"decode_url", "yes",
		"enable_directory_listing", "no",
		"num_threads", "16",
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
		logg("ERROR: Start of webserver failed!. Web interface will not be available!");
		logg("       Check webroot %s and listening ports %s",
		     httpsettings.webroot, httpsettings.port);
		return;
	}

	// Register API handler
	mg_set_request_handler(ctx, "/api", api_handler, NULL);

	// Register / -> /admin redirect handler
	mg_set_request_handler(ctx, "/$", redirect_root_handler, NULL);

	// Initialize PH7 engine and register PHP request handler
	init_ph7();
	mg_set_request_handler(ctx, "**/$", ph7_handler, NULL);
	mg_set_request_handler(ctx, "**.php$", ph7_handler, NULL);
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
