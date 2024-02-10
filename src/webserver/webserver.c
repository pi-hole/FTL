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
#include "webserver/webserver.h"
// api_handler()
#include "api/api.h"
// send_http()
#include "http-common.h"
// struct config
#include "config/config.h"
// log_web()
#include "log.h"
// get_nprocs()
#include <sys/sysinfo.h>
// file_readable()
#include "files.h"
// generate_certificate()
#include "webserver/x509.h"
// allocate_lua(), free_lua(), init_lua(), request_handler()
#include "webserver/lua_web.h"
// log_certificate_domain_mismatch()
#include "database/message-table.h"

// Server context handle
static struct mg_context *ctx = NULL;
static char *error_pages = NULL;

// Private prototypes
static char *append_to_path(char *path, const char *append);

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
				// Host header only contains the host name itself
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
		// 308 Permanent Redirect from http://pi.hole -> http://pi.hole/admin/
		if(strcmp(uri, "/") == 0)
		{
			log_debug(DEBUG_API, "Redirecting / --308--> %s",
			          config.webserver.paths.webhome.v.s);
			mg_send_http_redirect(conn, config.webserver.paths.webhome.v.s, 308);
			return 1;
		}
	}

	// else: Not redirecting
	return 0;
}

static int redirect_admin_handler(struct mg_connection *conn, void *input)
{
	if(config.debug.api.v.b)
	{
		// Get requested URI
		const struct mg_request_info *request = mg_get_request_info(conn);
		const char *uri = request->local_uri_raw;

		log_debug(DEBUG_API, "Redirecting %s --308--> %s",
		          uri, config.webserver.paths.webhome.v.s);
	}

	// 308 Permanent Redirect from /admin -> /admin/
	mg_send_http_redirect(conn, config.webserver.paths.webhome.v.s, 308);
	return 1;
}

static int redirect_lp_handler(struct mg_connection *conn, void *input)
{
	// Get requested URI
	const struct mg_request_info *request = mg_get_request_info(conn);
	const char *uri = request->local_uri_raw;
	const size_t uri_len = strlen(uri);
	const char *query_string = request->query_string;
	const size_t query_len = query_string != NULL ? strlen(query_string) : 0;

	// We allocate uri_len + query_len - 1 bytes, which is enough for the
	// new URI. The calculation is as follows:
	// 1. We are saving three bytes by skipping ".lp" at the end of the URI
	// 2. We are adding one byte for the trailing '\0'
	// 3. We are adding query_len bytes for the query string (if present)
	// 4. We are adding one byte for the '?' between URI and query string
	//    (if present)
	// Total bytes required: uri_len - 3 + query_len + 1 + 1
	char *new_uri = calloc(uri_len + query_len - 1, sizeof(char));

	// Copy everything from before the ".lp" to the new URI to effectively
	// remove it
	strncpy(new_uri, uri, uri_len - 3);

	// Append query string to the new URI if present
	if(query_len > 0)
	{
		strcat(new_uri, "?");
		strcat(new_uri, query_string);
	}

	// Send a 301 redirect to the new URI
	log_debug(DEBUG_API, "Redirecting %s?%s ==301==> %s",
	          uri, query_string, new_uri);
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

void FTL_mbed_debug(void *user_param, int level, const char *file, int line, const char *message)
{
	// Only log when in TLS debugging mode
	if(!config.debug.tls.v.b)
		return;

	(void)user_param;

	// Skip initial pointer in message (like 0x7f73000279e0) if present
	size_t len = strlen(message);
	if(len > 0 && message[0] == '0' && message[1] == 'x')
	{
		message = strstr(message, ": ") + 2;
		len = strlen(message);
	}

	// Truncate trailing newline in message if present
	if(len > 0 && message[len - 1] == '\n')
		len--;

	// Log the message
	log_web("mbedTLS(%s:%d, %d): %.*s", file, line, level, (int)len, message);
}

#define MAXPORTS 8
static struct serverports
{
	bool is_secure;
	bool is_redirect;
	unsigned char protocol; // 1 = IPv4, 2 = IPv4+IPv6, 3 = IPv6
	in_port_t port;
} server_ports[MAXPORTS] = { 0 };
static in_port_t https_port = 0;
static void get_server_ports(void)
{
	if(ctx == NULL)
		return;

	// Loop over all listening ports
	struct mg_server_port mgports[MAXPORTS] = { 0 };
	if(mg_get_server_ports(ctx, MAXPORTS, mgports) > 0)
	{
		// Loop over all ports
		for(unsigned int i = 0; i < MAXPORTS; i++)
		{
			// Stop if no more ports are configured
			if(mgports[i].protocol == 0)
				break;

			// Store port information
			server_ports[i].port = mgports[i].port;
			server_ports[i].is_secure = mgports[i].is_ssl;
			server_ports[i].is_redirect = mgports[i].is_redirect;
			server_ports[i].protocol = mgports[i].protocol;

			// Store HTTPS port if not already set
			if(mgports[i].is_ssl && https_port == 0)
				https_port = mgports[i].port;

			// Print port information
			log_debug(DEBUG_API, "Listening on port %d (HTTP%s, IPv%s)",
			          mgports[i].port, mgports[i].is_ssl ? "S" : "",
			          mgports[i].protocol == 1 ? "4" : (mgports[i].protocol == 3 ? "6" : "4+6"));
		}
	}
}

in_port_t __attribute__((pure)) get_https_port(void)
{
	return https_port;
}

unsigned short get_api_string(char **buf, const bool domain)
{
	// Initialize buffer to empty string
	size_t len = 0;
	// First byte has the length of the first string
	**buf = 0;
	const char *domain_str = domain ? config.webserver.domain.v.s : "localhost";
	size_t api_str_size = strlen(domain_str) + 20;

	// Check if the string is too long for the TXT record
	if(api_str_size > 255)
	{
		log_err("API URL too long for TXT record!");
		return 0;
	}

	// TXT record format:
	//
	// 0                 length of first string (unsigned char n)
	// 1 to (n+1)        first string
	// (n+2)             length of second string (unsigned char m)
	// (n+3) to (n+m+3)  second string
	// ...
	// This is repeated for every port, so the total length is
	// (n+1) + (n+m+3) + (n+m+3) + ...
	//
	// This is implemented in the loop below

	// Loop over all ports
	for(unsigned int i = 0; i < MAXPORTS; i++)
	{
		// Skip ports that are not configured or redirected
		if(server_ports[i].port == 0 || server_ports[i].is_redirect)
			continue;

		// Reallocate additional memory for every port
		if((*buf = realloc(*buf, (i+1)*api_str_size)) == NULL)
		{
			log_err("Failed to reallocate API URL buffer!");
			return 0;
		}
		const size_t bufsz = (i+1)*api_str_size;

		// Append API URL to buffer
		// We add this at buffer + 1 because the first byte is the
		// length of the string, which we don't know yet
		char *api_str = calloc(api_str_size, sizeof(char));
		const ssize_t this_len = snprintf(api_str, bufsz - len - 1, "http%s://%s:%d/api/",
		                                  server_ports[i].is_secure ? "s" : "",
		                                  domain_str, server_ports[i].port);
		// Check if snprintf() failed
		if(this_len < 0)
		{
			log_err("Failed to append API URL to buffer: %s", strerror(errno));
			return 0;
		}

		// Check if snprintf() truncated the string (this should never
		// happen as we allocate enough memory for the domain to fit)
		if((size_t)this_len >= bufsz - len - 1)
		{
			log_err("API URL buffer too small!");
			return 0;
		}

		// Check if this string is already present in the buffer
		if(memmem(*buf, len, api_str, this_len) != NULL)
		{
			// This string is already present, so skip it
			free(api_str);
			log_debug(DEBUG_API, "Skipping duplicate API URL: %s", api_str);
			continue;
		}

		// Append string to buffer (one byte after the current end of
		// the buffer to leave space for the length byte)
		strcpy(*buf + len + 1, api_str);
		free(api_str);

		// Set first byte to the length of the string (see breakdown
		// above)
		(*buf)[len] = (unsigned char)this_len;

		// Increase total length
		len += this_len + 1;
	}

	// Return total length
	return (unsigned short)len;
}

void http_init(void)
{
	// Don't start web server if port is not set
	if(strlen(config.webserver.port.v.s) == 0)
	{
		log_warn("Not starting web server as webserver.port is empty. API will not be available!");
		return;
	}

	/* Initialize the library */
	log_web("Initializing HTTP server on port %s", config.webserver.port.v.s);
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

	// Construct error_pages path
	error_pages = append_to_path(config.webserver.paths.webroot.v.s, config.webserver.paths.webhome.v.s);
	if(error_pages == NULL)
	{
		log_err("Failed to allocate memory for error_pages path!");
		return;
	}

	// Prepare options for HTTP server (NULL-terminated list)
	// Note about the additional headers:
	// - "Content-Security-Policy: [...]"
	//   'unsafe-inline' is both required by Chart.js styling some elements directly, and
	//   index.html containing some inlined Javascript code.
	// - "X-Frame-Options: DENY"
	//   The page can not be displayed in a frame, regardless of the site attempting to do
	//   so.
	// - "X-Xss-Protection: 0"
	//   Disables XSS filtering in browsers that support it. This header is usually
	//   enabled by default in browsers, and is not recommended as it can hurt the
	//   security of the site. (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
	// - "X-Content-Type-Options: nosniff"
	//   Marker used by the server to indicate that the MIME types advertised in the
	//   Content-Type headers should not be changed and be followed. This allows to
	//   opt-out of MIME type sniffing, or, in other words, it is a way to say that the
	//   webmasters knew what they were doing. Site security testers usually expect this
	//   header to be set.
	// - "Referrer-Policy: strict-origin-when-cross-origin"
	//   A referrer will be sent for same-site origins, but cross-origin requests will
	//   send no referrer information.
	// The latter four headers are set as expected by https://securityheaders.io
	char num_threads[3] = { 0 };
	sprintf(num_threads, "%d", get_nprocs() > 8 ? 16 : 2*get_nprocs());
	const char *options[] = {
		"document_root", config.webserver.paths.webroot.v.s,
		"error_pages", error_pages,
		"listening_ports", config.webserver.port.v.s,
		"decode_url", "yes",
		"enable_directory_listing", "no",
		"num_threads", num_threads,
		"authentication_domain", config.webserver.domain.v.s,
		"additional_header", "Content-Security-Policy: default-src 'self' 'unsafe-inline';\r\n"
		                     "X-Frame-Options: DENY\r\n"
		                     "X-XSS-Protection: 0\r\n"
		                     "X-Content-Type-Options: nosniff\r\n"
		                     "Referrer-Policy: strict-origin-when-cross-origin",
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
	if(config.webserver.tls.cert.v.s != NULL &&
	   strlen(config.webserver.tls.cert.v.s) > 0)
	{
		// Try to generate certificate if not present
		if(!file_readable(config.webserver.tls.cert.v.s))
		{
			if(generate_certificate(config.webserver.tls.cert.v.s, false, config.webserver.domain.v.s))
			{
				log_info("Created SSL/TLS certificate for %s at %s",
				         config.webserver.domain.v.s, config.webserver.tls.cert.v.s);
			}
			else
			{
				log_err("Generation of SSL/TLS certificate %s failed!",
				        config.webserver.tls.cert.v.s);
			}
		}

		if(file_readable(config.webserver.tls.cert.v.s))
		{
			if(read_certificate(config.webserver.tls.cert.v.s, config.webserver.domain.v.s, false) != CERT_DOMAIN_MATCH)
			{
				log_certificate_domain_mismatch(config.webserver.tls.cert.v.s, config.webserver.domain.v.s);
			}
			options[++next_option] = "ssl_certificate";
			options[++next_option] = config.webserver.tls.cert.v.s;

			log_info("Using SSL/TLS certificate file %s",
			         config.webserver.tls.cert.v.s);
		}
		else
		{
			log_err("Webserver SSL/TLS certificate %s not found or not readable!",
			        config.webserver.tls.cert.v.s);
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

	// Prepare error handler
	struct mg_error_data error = { 0 };
	char error_buffer[1024] = { 0 };
	error.text_buffer_size = sizeof(error_buffer);
	error.text = error_buffer;

	// Prepare initialization data
	struct mg_init_data init = { 0 };
	init.callbacks = &callbacks;
	init.user_data = NULL;
	init.configuration_options = options;

	/* Start the server */
	if((ctx = mg_start2(&init, &error)) == NULL)
	{
		log_err("Start of webserver failed!. Web interface will not be available!");
		log_err("       Error: %s (error code %u.%u)", error.text, error.code, error.code_sub);
		log_err("       Hint: Check the webserver log at %s", config.files.log.webserver.v.s);
		return;
	}

	// Register API handler
	mg_set_request_handler(ctx, "/api", api_handler, NULL);

	// Register / -> /admin/ redirect handler
	mg_set_request_handler(ctx, "/$", redirect_root_handler, NULL);

	// Register /admin -> /admin/ redirect handler
	if(strlen(config.webserver.paths.webhome.v.s) > 1)
	{
		// Construct webhome_matcher path
		char *webhome_matcher = NULL;
		webhome_matcher = strdup(config.webserver.paths.webhome.v.s);
		webhome_matcher[strlen(webhome_matcher)-1] = '$';
		log_debug(DEBUG_API, "Redirecting %s --308--> %s",
		          webhome_matcher, config.webserver.paths.webhome.v.s);
		// String is internally duplicated during request configuration
		mg_set_request_handler(ctx, webhome_matcher, redirect_admin_handler, NULL);
		free(webhome_matcher);
	}

	// Register **.lp -> ** redirect handler
	mg_set_request_handler(ctx, "**.lp$", redirect_lp_handler, NULL);

	// Register handler for the rest
	mg_set_request_handler(ctx, "**", request_handler, NULL);

	// Prepare prerequisites for Lua
	allocate_lua();

	// Get server ports
	get_server_ports();

	// Restore sessions from database
	init_api();
}

static char *append_to_path(char *path, const char *append)
{
	const size_t path_len = strlen(path);
	const size_t append_len = strlen(append);
	const size_t total_len = path_len + append_len + 1;
	char *new_path = calloc(total_len, sizeof(char));
	if(new_path == NULL)
	{
		log_err("Failed to allocate memory for path!");
		return NULL;
	}
	strncpy(new_path, path, total_len);
	strncat(new_path, append, total_len);
	return new_path;
}

void FTL_rewrite_pattern(char *filename, size_t filename_buf_len)
{
	const bool trailing_slash = filename[strlen(filename) - 1] == '/';
	char *filename_lp = NULL;

	// Try index pages first
	if(trailing_slash)
		// If there is a trailing slash, append "index.lp"
		filename_lp = append_to_path(filename, "index.lp");
	else
		// If there is no trailing slash, append "/index.lp"
		filename_lp = append_to_path(filename, "/index.lp");

	// Check if the file exists. If so, rewrite the filename and return
	if(filename_lp != NULL && file_readable(filename_lp))
	{
		log_debug(DEBUG_API, "Rewriting index page: %s ==> %s", filename, filename_lp);
		strncpy(filename, filename_lp, filename_buf_len);
		free(filename_lp);
		return;
	}
	free(filename_lp);

	// If there is a trailing slash, we are done
	if(trailing_slash)
		return;

	// Try full path with ".lp" appended
	filename_lp = append_to_path(filename, ".lp");
	if(filename_lp == NULL)
	{
		//Failed to allocate memory for filename!");
		return;
	}

	// Check if the file exists. If so, rewrite the filename and return
	if(file_readable(filename_lp))
	{
		log_debug(DEBUG_API, "Rewriting Lua page: %s ==> %s", filename, filename_lp);
		strncpy(filename, filename_lp, filename_buf_len);
		free(filename_lp);
		return;
	}

	// Change last occurrence of "/" to "-" (if any)
	char *last_slash = strrchr(filename_lp, '/');
	if(last_slash != NULL)
	{
		*last_slash = '-';
		if(file_readable(filename_lp))
		{
			log_debug(DEBUG_API, "Rewriting Lua page (settings page): %s ==> %s", filename, filename_lp);
			strncpy(filename, filename_lp, filename_buf_len);
			free(filename_lp);
			return;
		}
	}
	free(filename_lp);
}

void http_terminate(void)
{
	// The server may have never been started
	if(!ctx)
		return;

	/* Stop the server */
	mg_stop(ctx);

	/* Un-initialize the library */
	mg_exit_library();

	// Free Lua-related resources
	free_lua();

	// Free error_pages path
	if(error_pages != NULL)
	{
		free(error_pages);
		error_pages = NULL;
	}
}
