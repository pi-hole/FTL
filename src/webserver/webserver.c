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
#include "webserver.h"
// api_handler()
#include "../api/api.h"
// send_http()
#include "http-common.h"
// struct config
#include "../config/config.h"
// log_web()
#include "../log.h"
// get_nprocs()
#include <sys/sysinfo.h>
// file_readable()
#include "../files.h"
// generate_certificate()
#include "x509.h"
// allocate_lua(), free_lua(), init_lua(), request_handler()
#include "lua_web.h"

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
				log_err("Host name format error: Found '[' without ']'");
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

	// Get requested URI
	const struct mg_request_info *request = mg_get_request_info(conn);
	const char *uri = request->local_uri_raw;

	// API debug logging
	if(config.debug.api.v.b)
	{
		log_debug(DEBUG_API, "Host header: \"%s\", extracted host: \"%.*s\"", host, (int)host_len, host);

		log_debug(DEBUG_API, "URI: %s", uri);
	}

	// Check if the requested host is the configured (defaulting to pi.hole)
	// Do not redirect if the host is anything else, e.g. localhost or a
	// blocked domain in IP blocking mode
	if(host != NULL && strncmp(host, config.webserver.domain.v.s, host_len) == 0)
	{
		// 308 Permanent Redirect from http://pi.hole -> http://pi.hole/admin
		if(strcmp(uri, "/") == 0)
		{
			mg_send_http_redirect(conn, config.webserver.paths.webhome.v.s, 308);
			return 1;
		}
	}

	// else: Not redirecting
	return 0;
}

static int redirect_lp_handler(struct mg_connection *conn, void *input)
{
	// Get requested URI
	const struct mg_request_info *request = mg_get_request_info(conn);
	const char *uri = request->local_uri_raw;

	// Remove the ".lp" from the URI
	char *pos = strstr(uri, ".lp");
	char *new_uri = calloc(strlen(uri) - 2, sizeof(char));
	// Copy everything from before the ".lp?" to the new URI
	strncpy(new_uri, uri, pos - uri);
	// Copy everything after ".lp" to the new URI
	strcat(new_uri, pos + 3);

	// Send a 301 redirect to the new URI
	log_debug(DEBUG_API, "Redirecting %s ==301==> %s", uri, new_uri);
	mg_send_http_redirect(conn, new_uri, 301);
	free(new_uri);

	return 1;
}

static int log_http_message(const struct mg_connection *conn, const char *message)
{
	log_web("%s", message);
	return 1;
}

static int log_http_access(const struct mg_connection *conn, const char *message)
{
	// Only log when in API debugging mode
	if(!config.debug.api.v.b)
		return 1;

	log_web("ACCESS: %s", message);

	return 1;
}

void http_init(void)
{
	log_web("Initializing HTTP server on port %s", config.webserver.port.v.s);

	/* Initialize the library */
	unsigned int features = MG_FEATURES_FILES |
	                        MG_FEATURES_IPV6 |
	                        MG_FEATURES_CACHE;

#ifdef HAVE_TLS
	features |= MG_FEATURES_TLS;
#endif

	if(mg_init_library(features) == 0)
	{
		log_web("Initializing HTTP library failed!");
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
	char num_threads[3] = { 0 };
	sprintf(num_threads, "%d", get_nprocs() > 8 ? 16 : 2*get_nprocs());
	const char *options[] = {
		// All passed strings are duplicated internally. See also comment below.
		"document_root", config.webserver.paths.webroot.v.s,
		"listening_ports", config.webserver.port.v.s,
		"decode_url", "yes",
		"enable_directory_listing", "no",
		"num_threads", num_threads,
		"additional_header", "Content-Security-Policy: default-src 'self' 'unsafe-inline';\r\n"
		                     "X-Frame-Options: SAMEORIGIN\r\n"
		                     "X-Xss-Protection: 1; mode=block\r\n"
		                     "X-Content-Type-Options: nosniff\r\n"
		                     "Referrer-Policy: same-origin",
		"index_files", "index.html,index.htm,index.lp",
		"enable_auth_domain_check", "no",
		NULL, NULL,
		NULL, NULL, // Leave slots for access control list (ACL) and TLS configuration at the end
		NULL
	};

	// Get index of next free option
	// Note: The first options are always present, so start at the counting
	// from the end of the array.
	unsigned int next_option = ArraySize(options) - 6;

#ifdef HAVE_TLS
	// Add TLS options if configured
	if(config.webserver.tls_cert.v.s != NULL &&
	   strlen(config.webserver.tls_cert.v.s) > 0)
	{
		// Try to generate certificate if not present
		if(!file_readable(config.webserver.tls_cert.v.s) &&
		   !generate_certificate(config.webserver.tls_cert.v.s, false))
		{
			log_err("Generation of SSL/TLS certificate %s failed!",
			        config.webserver.tls_cert.v.s);
		}

		if(file_readable(config.webserver.tls_cert.v.s))
		{
			options[++next_option] = "ssl_certificate";
			options[++next_option] = config.webserver.tls_cert.v.s;
		}
		else
		{
			log_err("Webserver SSL/TLS certificate %s not found or not readable!",
			        config.webserver.tls_cert.v.s);
		}
	}
#endif
	// Add access control list if configured (last two options)
	if(strlen(config.webserver.acl.v.s) > 0)
	{
		options[++next_option] = "access_control_list";
		// Note: The string is duplicated by CivetWeb, so it doesn't matter if
		//       the original string is freed (config changes) after mg_start()
		//       returns below.
		options[++next_option] = config.webserver.acl.v.s;
	}

	// Configure logging handlers
	struct mg_callbacks callbacks = { NULL };
	callbacks.log_message = log_http_message;
	callbacks.log_access  = log_http_access;
	callbacks.init_lua    = init_lua;

	/* Start the server */
	if((ctx = mg_start(&callbacks, NULL, options)) == NULL)
	{
		log_err("Start of webserver failed!. Web interface will not be available!");
		log_err("       Check webroot %s and listening ports %s",
		        config.webserver.paths.webroot.v.s, config.webserver.port.v.s);
		return;
	}

	// Register API handler
	mg_set_request_handler(ctx, "/api", api_handler, NULL);

	// Register / -> /admin redirect handler
	mg_set_request_handler(ctx, "/$", redirect_root_handler, NULL);

	// Register **.lp -> ** redirect handler
	mg_set_request_handler(ctx, "**.lp$", redirect_lp_handler, NULL);

	// Register handler for the rest
	mg_set_request_handler(ctx, "**", request_handler, NULL);

	// Prepare prerequesites for Lua
	allocate_lua();
}

void FTL_rewrite_pattern(char *filename, size_t filename_buf_len,
                         const char *root, const char *uri)
{
	// Construct full path with ".lp" appended
	const size_t filename_lp_len = strlen(filename) + 3;
	char *filename_lp = calloc(filename_lp_len, sizeof(char));
	if(filename_lp == NULL)
	{
		log_err("Failed to allocate memory for Lua pattern!");
		return;
	}
	strncpy(filename_lp, filename, filename_lp_len);
	strncat(filename_lp, ".lp", filename_lp_len);

	// Check if the file exists
	if(!file_readable(filename_lp))
	{
		log_debug(DEBUG_API, "Not rewriting %s ==> %s, no such file",
		          filename, filename_lp);
		free(filename_lp);
		return;
	}

	log_debug(DEBUG_API, "Rewriting %s ==> %s", filename, filename_lp);
	strncpy(filename, filename_lp, filename_buf_len);
	free(filename_lp);
}

void http_terminate(void)
{
	if(!ctx)
		return;

	/* Stop the server */
	mg_stop(ctx);

	/* Un-initialize the library */
	mg_exit_library();

	// Free Lua-related resources
	free_lua();
}
