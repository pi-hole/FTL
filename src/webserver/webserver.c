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
// struct config.http
#include "../config/config.h"
#include "../log.h"
#include "webserver.h"
// get_nprocs()
#include <sys/sysinfo.h>
// file_readable()
#include "../files.h"
// generate_certificate()
#include "x509.h"
// luaL_dostring()
#include "../lua/lauxlib.h"

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

	// API debug logging
	if(config.debug.api.v.b)
	{
		log_debug(DEBUG_API, "Host header: \"%s\", extracted host: \"%.*s\"", host, (int)host_len, host);

		// Get requested URI
		const struct mg_request_info *request = mg_get_request_info(conn);
		const char *uri = request->local_uri_raw;

		log_debug(DEBUG_API, "URI: %s", uri);
	}

	// 308 Permanent Redirect from http://pi.hole -> http://pi.hole/admin
	if(host != NULL && strncmp(host, config.webserver.domain.v.s, host_len) == 0)
	{
		mg_send_http_redirect(conn, config.webserver.paths.webhome.v.s, 308);
		return 1;
	}

	// else: Not redirecting
	return 0;
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


static char *login_uri = NULL;
static int request_handler(struct mg_connection *conn, void *cbdata)
{
	// Fall back to CivetWeb's default handler if login URI is not available
	// (should never happen)
	if(login_uri == NULL)
		return 0;

	/* Handler may access the request info using mg_get_request_info */
	const struct mg_request_info *req_info = mg_get_request_info(conn);
	const char *local_uri = req_info->local_uri_raw + 1u;

	// Build minimal api struct to check authentication
	struct ftl_conn api = { 0 };
	api.conn = conn;
	api.request = req_info;

	// Every page except admin/login.lp requires authentication
	if(strcmp(local_uri, login_uri) != 0)
	{
		// This is not the login page - check if the user is authenticated
		// Check if the user is authenticated
		if(check_client_auth(&api) == API_AUTH_UNAUTHORIZED)
		{
			// User is not authenticated, redirect to login page
			log_web("Authentication required, redirecting to %slogin.lp?target=/%s", config.webserver.paths.webhome.v.s, local_uri);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %slogin.lp?target=/%s\r\n\r\n", config.webserver.paths.webhome.v.s, local_uri);
			return 302;
		}
	}
	else
	{
		// This is the login page - check if the user is already authenticated
		// Check if the user is authenticated
		if(check_client_auth(&api) != API_AUTH_UNAUTHORIZED)
		{
			// User is already authenticated
			char target[256] = { 0 };
			if(GET_VAR("target", target, req_info->query_string) > 0)
			{
				// Redirect to target page
			}
			else
			{
				// Redirect to index page
				strncpy(target, config.webserver.paths.webhome.v.s, sizeof(target) - 10);
				strcat(target, "index.lp");
			}
			// User is already authenticated, redirect to index page
			log_web("User is already authenticated, redirect to %s", target);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", target);
			return 302;
		}
	}

	// No special handling required, fall back to default CivetWeb handler
	return 0;
}

static void init_lua(const struct mg_connection *conn, void *L, unsigned context_flags)
{
	// Set onerror handler to print errors to the log
	if(luaL_dostring(L, "mg.onerror = function(e) mg.cry('Error at ' .. e) end") != LUA_OK)
	{
		log_err("Error setting Lua onerror handler: %s", lua_tostring(L, -1));
		lua_pop(L, 1);
	}
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

	// Register / and *.lp handler
	mg_set_request_handler(ctx, "**/$", request_handler, NULL);
	mg_set_request_handler(ctx, "**.lp$", request_handler, NULL);

	// Build login URI string (webhome + login.lp)
	// Append "login.lp" to webhome string
	const size_t login_uri_len = strlen(config.webserver.paths.webhome.v.s);
	login_uri = calloc(login_uri_len + 10, sizeof(char));
	memcpy(login_uri, config.webserver.paths.webhome.v.s, login_uri_len);
	strcpy(login_uri + login_uri_len, "login.lp");
	login_uri[login_uri_len + 10u] = '\0';

	// Remove initial slash from login_uri
	if(login_uri[0] == '/')
		memmove(login_uri, login_uri + 1, login_uri_len + 9);
}

void http_terminate(void)
{
	if(!ctx)
		return;

	/* Stop the server */
	mg_stop(ctx);

	/* Un-initialize the library */
	mg_exit_library();

	// Free login_uri
	if(login_uri != NULL)
		free(login_uri);
}
