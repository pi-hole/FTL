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
// create_cli_password()
#include "config/password.h"
// thread_names
#include "signals.h"

#include <mbedtls/ssl_ciphersuites.h>

// Server context handle
static struct mg_context *ctx = NULL;
static char *error_pages = NULL;
static char *prefix_webhome = NULL;
static char *api_uri = NULL;
static char *admin_api_uri = NULL;
static char *login_uri = NULL;

// Private prototypes
static char *append_to_path(char *path, const char *append);

/**
 * @brief Constructs various web paths used by the webserver.
 *
 * @return true if all paths are successfully constructed and allocated, false otherwise.
 */
static bool build_webpaths(void)
{
	// Construct error_pages path
	error_pages = append_to_path(config.webserver.paths.webroot.v.s, config.webserver.paths.webhome.v.s);
	log_debug(DEBUG_API, "Error pages path: %s", error_pages);
	if(error_pages == NULL)
	{
		log_err("Failed to allocate memory for error_pages path!");
		return false;
	}

	// Construct prefix_webhome path
	prefix_webhome = append_to_path(config.webserver.paths.prefix.v.s, config.webserver.paths.webhome.v.s);
	log_debug(DEBUG_API, "Prefix webhome path: %s", prefix_webhome);
	if(prefix_webhome == NULL)
	{
		log_err("Failed to allocate memory for prefix_webhome path!");
		return false;
	}

	// Construct api_url path
	api_uri = append_to_path(config.webserver.paths.prefix.v.s, "/api");
	log_debug(DEBUG_API, "API URI path: %s", api_uri);
	if(api_uri == NULL)
	{
		log_err("Failed to allocate memory for api_uri path!");
		return false;
	}

	// Construct admin_api_uri path
	admin_api_uri = append_to_path(prefix_webhome, "api");
	log_debug(DEBUG_API, "Admin API URI path: %s", admin_api_uri);
	if(admin_api_uri == NULL)
	{
		log_err("Failed to allocate memory for admin_api_uri path!");
		return false;
	}

	// Construct login_uri path
	login_uri = append_to_path(config.webserver.paths.webhome.v.s, "login");
	log_debug(DEBUG_API, "Login URI path: %s", login_uri);
	if(login_uri == NULL)
	{
		log_err("Failed to allocate memory for login_uri path!");
		return false;
	}

	return true;
}

char * __attribute__((pure)) get_prefix_webhome(void)
{
	return prefix_webhome;
}

char * __attribute__((pure)) get_api_uri(void)
{
	return api_uri;
}

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
		if(strcmp(uri, "/") == 0 || strcmp(uri, config.webserver.paths.prefix.v.s) == 0)
		{
			log_debug(DEBUG_API, "Redirecting / --308--> %s",
			          prefix_webhome);
			mg_send_http_redirect(conn, prefix_webhome, 308);
			return 1;
		}
	}

	// else: Not redirecting
	log_debug(DEBUG_API, "Not redirecting %s", uri);
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
		          uri, prefix_webhome);
	}

	// 308 Permanent Redirect from [prefix]<webhome without trailing slash> -> [prefix]<webhome>
	mg_send_http_redirect(conn, prefix_webhome, 308);
	return 1;
}

static int redirect_lp_handler(struct mg_connection *conn, void *input)
{
	// Get requested URI
	const struct mg_request_info *request = mg_get_request_info(conn);
	const char *uri = request->local_uri_raw;
	const size_t uri_len = strlen(uri);

	// Check if we are allowed to serve this directory by checking the
	// configuration setting webserver.serve_all and the requested URI to
	// start with something else than config.webserver.paths.webhome. If so,
	// send error 404
	if(!config.webserver.serve_all.v.b &&
	   strncmp(uri, config.webserver.paths.webhome.v.s, strlen(config.webserver.paths.webhome.v.s)) != 0)
	{
		log_debug(DEBUG_WEBSERVER, "Not serving %s, returning 404", uri);
		mg_send_http_error(conn, 404, "Not Found");
		return 404;
	}

	// Get query string
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
	strncat(new_uri, uri, uri_len - 3);

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

/**
 * @brief Redirects an HTTP request to a specified URL with a given status code.
 *
 * This function formats a URL string using a format specifier and redirects
 * the HTTP connection to the specified URL with the provided HTTP status code.
 *
 * @param conn Pointer to the `mg_connection` structure representing the HTTP connection.
 *             Must not be NULL.
 * @param code HTTP status code to use for the redirection (e.g., 301, 302).
 * @param format Format string for the URL to redirect to. Must not be NULL.
 *               Supports standard printf-style formatting.
 * @param ... Additional arguments for the format string.
 *
 * @return The HTTP status code used for the redirection on success, or 0 on failure.
 */
int __attribute__((format(printf, 3, 4), nonnull(1,3)))
ftl_http_redirect(struct mg_connection *conn, const int code, const char *format, ...)
{
	// Determine the size of the formatted string
	va_list args;
	va_start(args, format);
	int size = vsnprintf(NULL, 0, format, args);
	va_end(args);

	char *buffer = calloc(size + 1, sizeof(char));
	if (buffer == NULL) {
		log_err("Memory allocation failed for redirect format!");
		return 0;
	}

	// Format the string
	va_start(args, format);
	vsnprintf(buffer, size + 1, format, args);
	va_end(args);
	// Ensure null termination
	buffer[size] = '\0';

	log_debug(DEBUG_API, "Redirecting to %s", buffer);
	mg_send_http_redirect(conn, buffer, code);
	free(buffer);

	return code;
}

#define MAXPORTS 8
static struct serverports
{
	bool is_secure :1;
	bool is_redirect :1;
	bool is_optional :1;
	bool is_bound :1;
	char addr[INET6_ADDRSTRLEN + 2]; // +2 for square brackets around IPv6 address
	int port;
	int protocol; // 1 = IPv4, 3 = IPv6
} server_ports[MAXPORTS] = { 0 };
static in_port_t https_port = 0;
/**
 * @brief Retrieves and logs the server ports configuration.
 *
 * This function checks if the server context is initialized and then retrieves
 * the configured server ports. It logs the port information and stores the
 * details in the `server_ports` array. It also identifies and stores the first
 * HTTPS port if available.
 *
 * @note If no ports are configured, a warning is logged and the function returns.
 *
 * @param void This function does not take any parameters.
 * @return bool Returns whether the server ports were successfully retrieved
 */
static bool get_server_ports(void)
{
	if(ctx == NULL)
		return false;

	// Loop over all listening ports
	struct mg_server_port mgports[MAXPORTS] = { 0 };
	const int ports = mg_get_server_ports(ctx, MAXPORTS, mgports);

	// Stop if no ports are configured
	if(ports < 1)
	{
		log_warn("No web server ports configured!");
		return false;
	}

	// Loop over all ports
	for(unsigned int i = 0; i < (unsigned int)ports; i++)
	{
		// Stop if no more ports are configured
		if(mgports[i].protocol == 0)
			break;

		// Store port information
		server_ports[i].port = mgports[i].port;
		server_ports[i].is_secure = mgports[i].is_ssl;
		server_ports[i].is_redirect = mgports[i].is_redirect;
		server_ports[i].is_optional = mgports[i].is_optional;
		server_ports[i].is_bound = mgports[i].is_bound;
		// 1 = IPv4, 3 = IPv6 (can also be a combo-socker serving both),
		// the documentation in civetweb.h is wrong
		server_ports[i].protocol = mgports[i].protocol;

		// Convert listening address to string
		if(server_ports[i].protocol == 1)
			inet_ntop(AF_INET, &mgports[i].addr.sa4.sin_addr, server_ports[i].addr, INET_ADDRSTRLEN);
		else if(server_ports[i].protocol == 3)
		{
			char tmp[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &mgports[i].addr.sa6.sin6_addr, tmp, INET6_ADDRSTRLEN);
			// Enclose IPv6 address in square brackets
			snprintf(server_ports[i].addr, sizeof(server_ports[i].addr), "[%s]", tmp);
		}
		else
			log_warn("Unsupported protocol for port %d", mgports[i].port);

		// Store (first) HTTPS port if not already set
		if(mgports[i].is_ssl && https_port == 0)
			https_port = mgports[i].port;

		// Print port information
		if(i == 0)
			log_info("Web server ports:");
		log_info("  - %s:%d (HTTP%s, IPv%s%s%s, %s)",
		         server_ports[i].addr,
		         server_ports[i].port,
		         server_ports[i].is_secure ? "S" : "",
		         server_ports[i].protocol == 1 ? "4" : "6",
		         server_ports[i].is_redirect ? ", redirecting" : "",
		         server_ports[i].is_optional ? ", optional" : "",
		         server_ports[i].is_bound ? "OK" : "NOT bound");

	}

	return true;
}

in_port_t __attribute__((pure)) get_https_port(void)
{
	return https_port;
}

#define MAX_URL_LEN 255
unsigned short get_api_string(char **buf, const bool domain)
{
	// Initialize buffer to empty string
	size_t len = 0;
	// First byte has the length of the first string
	**buf = 0;

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
		const size_t bufsz = (i + 1) * MAX_URL_LEN;
		if((*buf = realloc(*buf, bufsz)) == NULL)
		{
			log_err("Failed to reallocate API URL buffer!");
			return 0;
		}

		// Use appropriate domain
		const char *addr = domain ? config.webserver.domain.v.s : server_ports[i].addr;

		// If we bound to the wildcard address, substitute it with
		// 127.0.0.1
		if(strcmp(addr, "0.0.0.0") == 0)
			addr = "127.0.0.1";
		else if(strcasecmp(addr, "[::]") == 0)
			addr = "[::1]";

		// Append API URL to buffer
		// We add this at buffer + 1 because the first byte is the
		// length of the string, which we don't know yet
		char *api_str = calloc(MAX_URL_LEN, sizeof(char));
		const ssize_t this_len = snprintf(api_str, MAX_URL_LEN, "http%s://%s:%d%s/api/",
		                                  server_ports[i].is_secure ? "s" : "",
		                                  addr, server_ports[i].port,
		                                  config.webserver.paths.prefix.v.s);
		// Check if snprintf() failed
		if(this_len < 0)
		{
			log_err("Failed to append API URL to buffer: %s", strerror(errno));
			free(api_str);
			return 0;
		}

		// Check if snprintf() truncated the string (this should never
		// happen as we allocate enough memory for the domain to fit)
		if((size_t)this_len >= bufsz - len - 1)
		{
			log_err("API URL buffer too small!");
			free(api_str);
			return 0;
		}

		// Check if this string is already present in the buffer
		if(memmem(*buf, len, api_str, this_len) != NULL)
		{
			// This string is already present, so skip it
			log_debug(DEBUG_API, "Skipping duplicate API URL: %s", api_str);
			free(api_str);
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

/**
 * @brief Prints webserver options with optional debug logging.
 *
 * Iterates over the provided array of static webserver options, escapes both keys and values,
 * and logs each option. If debug is enabled, logs with debug level; otherwise, logs as an error.
 *
 * @param debug           If true, use debug logging; otherwise, use error logging.
 * @param idx             The number of option pairs in the static_options array.
 * @param static_options  Array of key-value string pairs (size: idx * 2).
 */
static void print_webserver_opts(const bool debug, const size_t idx, const char **static_options)
{
	for(size_t i = 0; i <= idx; i++)
	{
		char *escaped_key = escape_string(static_options[i * 2]);
		char *escaped_value = escape_string(static_options[i * 2 + 1]);
		if(debug)
		{
			if(i == idx)
			{
				log_debug(DEBUG_WEBSERVER, "Webserver option %zu/%zu: <END OF OPTIONS>", i, idx);
				break;
			}
			log_debug(DEBUG_WEBSERVER, "Webserver option %zu/%zu: %s=%s",
			          i, idx, escaped_key, escaped_value);
		}
		else
		{
			if(i == idx)
			{
				log_err("Webserver option %zu/%zu: <END OF OPTIONS>", i, idx);
				break;
			}
			log_err("Webserver option %zu/%zu: %s=%s",
			        i, idx, escaped_key, escaped_value);
		}
		if(escaped_key != NULL)
			free(escaped_key);
		if(escaped_value != NULL)
			free(escaped_value);
	}
}

void http_init(void)
{
	// Don't start web server if port is not set
	if(strlen(config.webserver.port.v.s) == 0)
	{
		log_warn("Not starting web server as webserver.port is empty. API will not be available!");
		return;
	}

	// Get maximum number of threads for webserver
	char num_threads[16] = { 0 };
	unsigned int threads = config.webserver.threads.v.ui;
	if(threads == 0)
	{
		// For compatibility with older versions, set the number of
		// threads to the default value (50) if it was 0. Before Pi-hole
		// FTL v6.0.4, the number of threads was computed in dependence
		// of the number of CPUs available. This is no longer the case.
		threads = 50;
	}

	snprintf(num_threads, sizeof(num_threads), "%u", threads);

	// Ensure null termination for safety
	num_threads[sizeof(num_threads) - 1] = '\0';

	/* Initialize the library */
	log_web("Initializing HTTP server on ports \"%s\"", config.webserver.port.v.s);
	unsigned int features = MG_FEATURES_FILES |
	                        MG_FEATURES_IPV6 |
	                        MG_FEATURES_CACHE;

#ifdef HAVE_MBEDTLS
	features |= MG_FEATURES_TLS;
#endif

	if(mg_init_library(features) == 0)
	{
		log_web("Initializing HTTP library failed!");
		return;
	}

	if(!build_webpaths())
	{
		log_err("Failed to build web paths, web interface will not be available!");
		return;
	}

	// Construct additional headers
	char *webheaders = strdup("");
	if (webheaders == NULL) {
		log_err("Failed to allocate memory for webheaders!");
		return;
	}
	cJSON *header;
	cJSON_ArrayForEach(header, config.webserver.headers.v.json)
	{
		if(!cJSON_IsString(header))
		{
			log_err("Invalid header in webserver.headers!");
			continue;
		}

		// Get header value
		const char *h = cJSON_GetStringValue(header);

		// Allocate memory for the new header
		char *new_webheaders = realloc(webheaders, strlen(webheaders) + strlen(h) + 3);
		if (new_webheaders == NULL) {
			log_err("Failed to (re)allocate memory for webheaders!");
			free(webheaders);
			return;
		}
		webheaders = new_webheaders;
		strcat(webheaders, h);
		strcat(webheaders, "\r\n");
	}

	// Prepare options for HTTP server (NULL-terminated list)
	const char *static_options[] = {
		"document_root", config.webserver.paths.webroot.v.s,
		"error_pages", error_pages,
		"listening_ports", config.webserver.port.v.s,
		"decode_url", "yes",
		"enable_directory_listing", "no",
		"num_threads", num_threads,
		"authentication_domain", config.webserver.domain.v.s,
		"additional_header", webheaders,
		"index_files", "index.html,index.htm,index.lp",
		"enable_keep_alive", "yes",
		"keep_alive_timeout_ms", "5000",
		NULL, NULL, // Optional slots for TLS configuration
		NULL, NULL, // Optional slots for access control list (ACL)
		NULL, NULL  // Termination of the array
	};
	const size_t opt_size = (ArraySize(static_options) / 2) + cJSON_GetArraySize(config.webserver.advancedOpts.v.json);
	// We allocate two additional slots for ACL and TLS configuration
	// which are added later if configured
	// The last NULL is for the NULL-termination of the array
	char **conf_opts = calloc(opt_size * 2 + 1, sizeof(char*));
	if (conf_opts == NULL) {
		log_err("Failed to allocate memory (%zu slots) for advanced webserver options!", opt_size * 2 + 1);
		free(webheaders);
		return;
	}
	size_t idx = 0;
	while(idx < (ArraySize(static_options) / 2 - 3)) // -3 for the 6 NULL slots above
	{
		conf_opts[idx * 2] = strdup(static_options[idx * 2]);
		conf_opts[idx * 2 + 1] = strdup(static_options[idx * 2 + 1]);
		idx++;
	}

#ifdef HAVE_MBEDTLS
	// Add TLS options if configured

	// TLS is used when webserver.port contains "s" (e.g. "443s")
	const bool tls_used = config.webserver.port.v.s != NULL &&
	                      strchr(config.webserver.port.v.s, 's') != NULL;

	// Check certificate domain if
	// - TLS is used
	// - A certificate is configured
	// - The certificate is readable
	if(tls_used &&
	   config.webserver.tls.cert.v.s != NULL &&
	   strlen(config.webserver.tls.cert.v.s) > 0)
	{
		// Try to generate certificate if not present
		if(!file_readable(config.webserver.tls.cert.v.s))
		{
			if(generate_certificate(config.webserver.tls.cert.v.s, false, config.webserver.domain.v.s, config.webserver.tls.validity.v.ui))
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

		// Check if the certificate is readable (we may have just
		// created it)
		if(file_readable(config.webserver.tls.cert.v.s))
		{
			if(read_certificate(config.webserver.tls.cert.v.s, config.webserver.domain.v.s, false) != CERT_DOMAIN_MATCH)
			{
				log_certificate_domain_mismatch(config.webserver.tls.cert.v.s, config.webserver.domain.v.s);
			}
			conf_opts[idx * 2] = strdup("ssl_certificate");
			conf_opts[idx * 2 + 1] = strdup(config.webserver.tls.cert.v.s);
			idx++;

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
		conf_opts[idx * 2] = strdup("access_control_list");
		// Note: The string is duplicated by CivetWeb, so it doesn't matter if
		//       the original string is freed (config changes) after mg_start()
		//       returns below.
		conf_opts[idx * 2 + 1] = strdup(config.webserver.acl.v.s);
		idx++;
	}

	cJSON *option = NULL;
	cJSON_ArrayForEach(option, config.webserver.advancedOpts.v.json)
	{
		if(!cJSON_IsString(option))
		{
			log_err("Invalid option in webserver.advancedOpts!");
			continue;
		}

		// Get option value
		const char *opt = cJSON_GetStringValue(option);

		// Split option into key and value at the first '='
		char *equal_sign = strchr(opt, '=');
		if(equal_sign == NULL)
		{
			log_err("Invalid option in webserver.advancedOpts: %s (missing '=')", opt);
			continue;
		}

		// Allocate memory for key and value
		size_t key_len = (size_t)(equal_sign - opt);
		char *key = calloc(key_len + 1, sizeof(char));
		if (key == NULL) {
			log_err("Failed to allocate memory for advanced webserver option key!");
			continue;
		}
		strncpy(key, opt, key_len);
		key[key_len] = '\0';

		char *value = strdup(equal_sign + 1);
		if (value == NULL) {
			log_err("Failed to allocate memory for advanced webserver option value!");
			free(key);
			continue;
		}

		// Store key and value in options array (already allocated
		// above)
		conf_opts[idx * 2] = key;
		conf_opts[idx * 2 + 1] = value;
		idx++;
	}

	// Configure logging handlers
	struct mg_callbacks callbacks;
	memset(&callbacks, 0, sizeof(callbacks));
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
	init.configuration_options = (const char**)conf_opts;

	/* Start the server */
	if((ctx = mg_start2(&init, &error)) == NULL || !get_server_ports())
	{
		log_err("Start of webserver failed! Web interface will not be available!");
		print_webserver_opts(false, idx, (const char **)conf_opts);
		log_err("       Error: %s (error code %u.%u)", error.text, error.code, error.code_sub);
		log_err("       Hint: Check the webserver log at %s", config.files.log.webserver.v.s);
		return;
	}

	// Success: Print used options only if in debug mode
	if(config.debug.webserver.v.b)
		print_webserver_opts(true, idx, (const char **)conf_opts);

	// All configuration options have been copied by CivetWeb, so we
	// can free them here
	for(size_t i = 0; i < idx * 2; i++)
	{
		if(conf_opts[i] != NULL)
			free(conf_opts[i]);
	}
	free(conf_opts);
	free(webheaders);
	webheaders = NULL;

	// Register API handler, use "/api" even when a prefix is defined as the
	// prefix should be stripped away by the reverse proxy
	mg_set_request_handler(ctx, "/api", api_handler, NULL);

	if(strcmp(prefix_webhome, "/") == 0)
	{
		log_debug(DEBUG_API, "Not redirecting root since webhome is '%s'",
			  prefix_webhome);
	} else {
		// Redirect requests to / to the webhome path.
		mg_set_request_handler(ctx, "/$", redirect_root_handler, NULL);
	}

	if(strcmp(config.webserver.paths.webhome.v.s, "/") == 0 &&
	   config.dns.blocking.mode.v.blocking_mode == MODE_IP)
	{
		log_warn("Webhome is set to root (/) and IP blocking is enabled. This may result in the Pi-hole web interface to display in places where otherwise ads would show up");
	}

	// Register [prefix]<webhome without trailing slash> -> [<prefix>]<webhome> redirect handler
	if(strlen(config.webserver.paths.webhome.v.s) > 1 && config.webserver.paths.webhome.v.s[strlen(config.webserver.paths.webhome.v.s)-1] == '/')
	{
		// Replace trailing slash with end-of-string marker for matcher
		char *prefix_webhome_matcher = strdup(prefix_webhome);
		prefix_webhome_matcher[strlen(prefix_webhome_matcher)-1] = '$';

		log_debug(DEBUG_API, "Redirecting %s --308--> %s",
		          prefix_webhome, config.webserver.paths.webhome.v.s);
		mg_set_request_handler(ctx, prefix_webhome_matcher, redirect_admin_handler, NULL);
		// prefix_webhome_matcher is internally duplicated during
		// request configuration so it can be freed here
		free(prefix_webhome_matcher);
	}

	// Register **.lp -> ** redirect handler
	mg_set_request_handler(ctx, "**.lp$", redirect_lp_handler, NULL);

	// Register handler for the rest
	mg_set_request_handler(ctx, "**", request_handler, NULL);

	// Prepare prerequisites for Lua
	allocate_lua(login_uri, admin_api_uri, prefix_webhome);

	// Restore sessions from database
	init_api();

	// Create CLI password (if enabled)
	create_cli_password();
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

void FTL_rewrite_pattern(char *filename, unsigned long filename_buf_len)
{
	log_debug(DEBUG_API, "Rewriting filename: %s", filename);
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
		// Failed to allocate memory for filename
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

	// Remove CLI password
	remove_cli_password();

	// Free error_pages path
	if(error_pages != NULL)
		free(error_pages);

	// Free webhome_matcher path
	if(prefix_webhome != NULL)
		free(prefix_webhome);

	// Free api_uri path
	if(api_uri != NULL)
		free(api_uri);

	// Free admin_api_uri path
	if(admin_api_uri != NULL)
		free(admin_api_uri);

	// Free login_uri path
	if(login_uri != NULL)
		free(login_uri);
}

static void restart_http(void)
{
	// Stop the server
	http_terminate();

	// Reinitialize the webserver
	http_init();
}

/**
 * @brief Prints all supported TLS cipher suites by mbedTLS.
 *
 * This function retrieves the list of all available TLS cipher suites
 * supported by the mbedTLS library and prints their names, cipher IDs,
 * and key lengths to the standard output.
 *
 * The output format for each cipher suite is:
 *   - <suite_name> (Cipher ID: <suite_id>, Key length: <bitlen> bits)
 *
 * No parameters are required and no value is returned.
 */
void get_all_supported_ciphersuites(void)
{
	const int *all = mbedtls_ssl_list_ciphersuites();
	printf("Supported TLS cipher suites:\n");
	for (size_t i = 0; all[i] != 0; ++i)
	{
		// Get cipher suite details
		const mbedtls_ssl_ciphersuite_t *suite_info = mbedtls_ssl_ciphersuite_from_id(all[i]);
		const char *suite_name = mbedtls_ssl_ciphersuite_get_name(suite_info);
		const size_t bitlen = mbedtls_ssl_ciphersuite_get_cipher_key_bitlen(suite_info);
		printf("- %s (Cipher ID: %d, Key length: %zu bits)\n", suite_name, all[i], bitlen);
	}
}

void *webserver_thread(void *val)
{
	(void)val;
	// Set thread name
	prctl(PR_SET_NAME, thread_names[WEBSERVER], 0, 0, 0);

	// Initial delay until we check the certificate for the first time
	thread_sleepms(WEBSERVER, 2000);

	while(!killed)
	{
		// Check if the certificate is about to expire soon
		// We check only if HTTPS is enabled (https_port > 0)
		const enum cert_check status = https_port == 0 ?
			CERT_NOT_IN_USE :
			cert_currently_valid(config.webserver.tls.cert.v.s, 2);

		if(status == CERT_EXPIRES_SOON &&
		   config.webserver.tls.validity.v.ui > 0)
		{
			if(is_pihole_certificate(config.webserver.tls.cert.v.s))
			{
				log_info("TLS certificate at %s is about to expire soon, generating new one",
				         config.webserver.tls.cert.v.s);
				generate_certificate(config.webserver.tls.cert.v.s, false,
				             config.webserver.domain.v.s,
				             config.webserver.tls.validity.v.ui);

				log_info("Restarting HTTP server");
				restart_http();

				log_info("Done. The new certificate is valid for %u days",
				         config.webserver.tls.validity.v.ui);
			}
			else
			{
				log_err("TLS certificate at %s is about to expire soon, but it is not a Pi-hole certificate. Please renew it manually!",
				        config.webserver.tls.cert.v.s);
			}
		}

		// Idle for 1 day (24 hours)
		thread_sleepms(WEBSERVER, 86400000);
	}

	log_info("Terminating webserver thread");
	return NULL;
}
