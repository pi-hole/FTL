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
// terminator_start(), terminator_stop()
#include "webserver/terminator.h"
// dotdoh_server_resolve(), base64url_decode(), doh_answer_min_ttl(),
// dotdoh_source_allowed(), dotdoh_doh_enabled()
#include "dotdoh/server.h"
// DNS_MSG_MAX
#include "dotdoh/framing.h"

// Upper bound on the base64url "dns" value of a plaintext DoH GET, matching the
// terminator's native path.
#define DOH_GET_B64_MAX 8192
// allocate_lua(), free_lua(), init_lua(), request_handler()
#include "webserver/lua_web.h"
// log_certificate_domain_mismatch()
#include "database/message-table.h"
// create_cli_password()
#include "config/password.h"
// thread_names
#include "signals.h"

#ifdef HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#endif /* HAVE_TLS */

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
	log_web_debug(DEBUG_API, "Error pages path: %s", error_pages);
	if(error_pages == NULL)
	{
		log_err("Failed to allocate memory for error_pages path!");
		return false;
	}

	// Construct prefix_webhome path
	prefix_webhome = append_to_path(config.webserver.paths.prefix.v.s, config.webserver.paths.webhome.v.s);
	log_web_debug(DEBUG_API, "Prefix webhome path: %s", prefix_webhome);
	if(prefix_webhome == NULL)
	{
		log_err("Failed to allocate memory for prefix_webhome path!");
		return false;
	}

	// Construct api_url path
	api_uri = append_to_path(config.webserver.paths.prefix.v.s, "/api");
	log_web_debug(DEBUG_API, "API URI path: %s", api_uri);
	if(api_uri == NULL)
	{
		log_err("Failed to allocate memory for api_uri path!");
		return false;
	}

	// Construct admin_api_uri path
	admin_api_uri = append_to_path(prefix_webhome, "api");
	log_web_debug(DEBUG_API, "Admin API URI path: %s", admin_api_uri);
	if(admin_api_uri == NULL)
	{
		log_err("Failed to allocate memory for admin_api_uri path!");
		return false;
	}

	// Construct login_uri path
	login_uri = append_to_path(config.webserver.paths.webhome.v.s, "login");
	log_web_debug(DEBUG_API, "Login URI path: %s", login_uri);
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

bool __attribute__((const)) webserver_have_http2(void)
{
#ifdef HAVE_HTTP2
	return true;
#else
	return false;
#endif
}

bool __attribute__((const)) webserver_have_http3(void)
{
#ifdef HAVE_HTTP3
	return true;
#else
	return false;
#endif
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
			const char *pos = strchr(host, ']');
			if (!pos)
			{
				// Malformed hostname starts with '[', but no ']' found
				log_web(LOG_ERR, "Host name format error: Found '[' without ']'");
				return 0;
			}
			/* terminate after ']' */
			host_len = (size_t)(pos + 1 - host);
		}
		else
		{
			const char *pos = strchr(host, ':');
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
		log_web_debug(DEBUG_API, "Host header: \"%s\", extracted host: \"%.*s\"", host, (int)host_len, host);
		log_web_debug(DEBUG_API, "URI: %s", uri);
	}

	// Check if the requested host is the configured domain (defaulting to pi.hole).
	// Do not redirect if the host is anything else, e.g. a blocked domain in
	// IP blocking mode where the browser connects using the blocked hostname.
	// Use an exact-length comparison to prevent a prefix-match false positive
	// (e.g. host "pi" incorrectly matching domain "pi.hole").
	const size_t domain_len = strlen(config.webserver.domain.v.s);
	if(host != NULL && host_len == domain_len &&
	   strncasecmp(host, config.webserver.domain.v.s, host_len) == 0)
	{
		// 308 Permanent Redirect from http://pi.hole -> http://pi.hole/admin/
		if(strcmp(uri, "/") == 0 || strcmp(uri, config.webserver.paths.prefix.v.s) == 0)
		{
			log_web_debug(DEBUG_API, "Redirecting / --308--> %s",
			          prefix_webhome);
			mg_send_http_redirect(conn, prefix_webhome, 308);
			return 1;
		}
	}

	// Host did not match webserver.domain — not redirecting. When deployed
	// behind a reverse proxy, ensure webserver.domain matches the Host header
	// the proxy forwards (configure via WEBSERVER_DOMAIN in pihole.toml).
	log_web_debug(DEBUG_API, "Not redirecting %s (Host: \"%.*s\" != domain: \"%s\")",
	          uri, (int)host_len, host ? host : "", config.webserver.domain.v.s);
	return 0;
}

static int redirect_admin_handler(struct mg_connection *conn, void *input)
{
	if(config.debug.api.v.b)
	{
		// Get requested URI
		const struct mg_request_info *request = mg_get_request_info(conn);
		const char *uri = request->local_uri_raw;

		log_web_debug(DEBUG_API, "Redirecting %s --308--> %s",
		          uri, prefix_webhome);
	}

	// 308 Permanent Redirect from [prefix]<webhome without trailing slash> -> [prefix]<webhome>
	mg_send_http_redirect(conn, prefix_webhome, 308);
	return 1;
}

static int begin_request_handler(struct mg_connection *conn)
{
	// Reject any request whose (URL-decoded) path contains control
	// characters. CivetWeb decodes local_uri_raw in place, so an encoded
	// CR/LF (%0d%0a) arrives here as a literal newline. Several handlers
	// reflect this path into response headers (e.g. the Location header
	// built by redirect_lp_handler), where embedded CR/LF would allow HTTP
	// response header injection / response splitting. Rejecting such requests
	// centrally - before authentication and before any handler runs - closes
	// the whole class of URI-into-header injection. This runs for every
	// request before authentication, so the rejection is logged only at
	// debug level and never echoes the URI: an unauthenticated client can
	// trivially flood such requests, and logging each one at warning level
	// (or logging the URI verbatim) would itself be a log-flooding /
	// log-injection vector.
	const struct mg_request_info *request = mg_get_request_info(conn);
	for(const char *p = request->local_uri_raw; p != NULL && *p != '\0'; p++)
	{
		if((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
		{
			log_web_debug(DEBUG_WEBSERVER, "Rejecting request with control character in URI");
			mg_send_http_error(conn, 400, "Bad Request");
			return 400;
		}
	}

	// Let CivetWeb process the request normally
	return 0;
}

// Serve one DoH request (RFC 8484) forwarded by a trusted reverse proxy. Only
// reached for a connection whose PROXY v2 header authenticated with
// webserver.proxySecret, so ri->remote_addr is the client address the proxy
// announced rather than the proxy itself, and the query is attributed correctly.
static int dns_query_plain(struct mg_connection *conn, const struct mg_request_info *ri)
{
	// Thread-local rather than on the stack: a CivetWeb worker stack cannot
	// carry two 64 KiB buffers. Same reason the terminator does it this way.
	static _Thread_local uint8_t query[DNS_MSG_MAX];
	static _Thread_local uint8_t answer[DNS_MSG_MAX];
	ssize_t qlen = -1;

	// Only GET and POST are DoH methods; anything else gets the same 405 and
	// Allow header as the terminator's native path (RFC 9110 15.5.6)
	const bool is_post = ri->request_method != NULL && strcmp(ri->request_method, "POST") == 0;
	const bool is_get = ri->request_method != NULL && strcmp(ri->request_method, "GET") == 0;
	if(!is_get && !is_post)
	{
		mg_response_header_start(conn, 405);
		mg_response_header_add(conn, "Allow", "GET, POST", -1);
		mg_response_header_add(conn, "Content-Length", "0", -1);
		mg_response_header_send(conn);
		return 405;
	}

	if(!dotdoh_source_allowed(ri->remote_addr))
	{
		mg_send_http_error(conn, 403, "%s", "source not allowed");
		return 403;
	}

	if(is_post)
	{
		// RFC 8484: body media type application/dns-message (trailing ";..." ok).
		const char *ctype = mg_get_header(conn, "Content-Type");
		if(ctype == NULL || strncasecmp(ctype, "application/dns-message",
		                                sizeof("application/dns-message") - 1) != 0)
		{
			mg_send_http_error(conn, 415, "%s", "expected application/dns-message");
			return 415;
		}
		// Reject an oversized or unknown-length body outright rather than
		// truncating it: a partial read would leave bytes in the stream and
		// desync the next request on a keep-alive connection.
		const long long clen = ri->content_length;
		if(clen < 0)
		{
			mg_send_http_error(conn, 411, "%s", "Content-Length required");
			return 411;
		}
		if(clen == 0 || (size_t)clen > sizeof(query))
		{
			mg_send_http_error(conn, 413, "%s", "DoH query too large");
			return 413;
		}
		// mg_read() may return short; loop until the whole body is in.
		size_t got = 0;
		while(got < (size_t)clen)
		{
			const int rd = mg_read(conn, query + got, (size_t)clen - got);
			if(rd <= 0)
				break;
			got += (size_t)rd;
		}
		if(got == (size_t)clen)
			qlen = (ssize_t)got;
	}
	else if(ri->query_string != NULL)
	{
		// RFC 8484: query base64url-encoded in the "dns" parameter.
		char b64[DOH_GET_B64_MAX];
		const int vlen = mg_get_var(ri->query_string, strlen(ri->query_string),
		                            "dns", b64, sizeof(b64));
		if(vlen > 0)
			qlen = base64url_decode(b64, (size_t)vlen, query, sizeof(query));
	}

	if(qlen <= 0)
	{
		mg_send_http_error(conn, 400, "%s", "malformed DoH request");
		return 400;
	}

	const ssize_t alen = dotdoh_server_resolve(ri->remote_addr, NULL, query,
	                                           (size_t)qlen, answer, sizeof(answer));
	if(alen <= 0)
	{
		mg_send_http_error(conn, 502, "%s", "resolver failed");
		return 502;
	}

	// private: the answer depends on the client's groups, so a shared cache
	// must not hand it to anyone else
	mg_printf(conn,
	          "HTTP/1.1 200 OK\r\n"
	          "Content-Type: application/dns-message\r\n"
	          "Content-Length: %zd\r\n"
	          "Cache-Control: private, max-age=%u\r\n"
	          "X-Content-Type-Options: nosniff\r\n"
	          "\r\n",
	          alen, doh_answer_min_ttl(answer, (size_t)alen));
	mg_write(conn, answer, (size_t)alen);
	return 200;
}

// Guard on the CivetWeb /dns-query path. Inbound DoH is normally served natively
// by the front terminator over TLS (HTTP/1.1, HTTP/2, HTTP/3), so a /dns-query
// reaching CivetWeb arrived over a plaintext hop.
//
// `is_ssl` is set here only when a PROXY v2 header authenticated by
// webserver.proxySecret announced that the client spoke TLS to a trusted proxy
// (civetweb rewrites the peer address and TLS status from that header). That is
// the reverse-proxy deployment dns.dohReverseProxy exists for, and because the
// proxy authenticated itself the announced client address is trustworthy - an
// unauthenticated X-Forwarded-For never is, which is why it is not consulted.
//
// Anything else is a genuinely cleartext request: refuse it with 426, or the
// client's "encrypted" queries would leak on the wire.
static int dns_query_guard(struct mg_connection *conn, void *cbdata)
{
	(void)cbdata;
	const struct mg_request_info *ri = mg_get_request_info(conn);
	if(ri == NULL || !ri->is_ssl || !config.dns.dohReverseProxy.v.b)
	{
		mg_send_http_error(conn, 426, "%s", "DoH requires HTTPS");
		return 426;
	}
	if(!dotdoh_doh_enabled())
	{
		mg_send_http_error(conn, 404, "%s", "DoH is disabled");
		return 404;
	}
	return dns_query_plain(conn, ri);
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
		log_web_debug(DEBUG_WEBSERVER, "Not serving %s, returning 404", uri);
		mg_send_http_error(conn, 404, "Not Found");
		return 404;
	}

	// Get query string
	const char *query_string = request->query_string;
	const size_t query_len = query_string != NULL ? strlen(query_string) : 0;

	// The redirect target carries the configured prefix like every other
	// redirect we send
	const char *prefix = config.webserver.paths.prefix.v.s;
	const size_t prefix_len = strlen(prefix);

	// We allocate prefix_len + uri_len + query_len - 1 bytes, which is enough
	// for the new URI. The calculation is as follows:
	// 1. We are adding prefix_len bytes for the prefix
	// 2. We are saving three bytes by skipping ".lp" at the end of the URI
	// 3. We are adding one byte for the trailing '\0'
	// 4. We are adding query_len bytes for the query string (if present)
	// 5. We are adding one byte for the '?' between URI and query string
	//    (if present)
	// Total bytes required: prefix_len + uri_len - 3 + query_len + 1 + 1
	char *new_uri = calloc(prefix_len + uri_len + query_len - 1, sizeof(char));
	if(new_uri == NULL)
	{
		mg_send_http_error(conn, 500, "Internal Server Error");
		return 500;
	}

	// Copy the prefix and everything from before the ".lp" to the new URI to
	// effectively remove it
	strcat(new_uri, prefix);
	strncat(new_uri, uri, uri_len - 3);

	// Append query string to the new URI if present
	if(query_len > 0)
	{
		strcat(new_uri, "?");
		strcat(new_uri, query_string);
	}

	// Send a 301 redirect to the new URI
	log_web_debug(DEBUG_API, "Redirecting %s?%s ==301==> %s",
	          uri, query_string, new_uri);
	mg_send_http_redirect(conn, new_uri, 301);
	free(new_uri);

	return 1;
}

static int log_http_message(const struct mg_connection *conn, const char *message)
{
	// CivetWeb calls this callback through its mg_cry() error channel, so the
	// messages are errors, not informational lines. The severity is what the
	// web interface colors by.
	log_web(LOG_ERR, "%s", message);
	return 1;
}

static int log_http_access(const struct mg_connection *conn, const char *message)
{
	// Only log when in API debugging mode
	if(!config.debug.api.v.b)
		return 1;

	// Never write the access log into the web server's document root. The
	// log line contains attacker-controlled request data (e.g. the
	// User-Agent header) and, if the log file lives inside the webroot, it
	// could be served - and, for a path matching the Lua server-page
	// pattern, executed - by the web server itself. This is a runtime
	// backstop for the config validator (validate_webserver_logfile) that
	// also catches a single config change setting both paths at once.
	const char *logfile = config.files.log.webserver.v.s;
	const char *webroot = config.webserver.paths.webroot.v.s;
	if(logfile != NULL && webroot != NULL && webroot[0] != '\0' &&
	   strncmp(logfile, webroot, strlen(webroot)) == 0)
		return 1;

	// Escape the line before writing it: it contains attacker-controlled
	// data, so logging it verbatim would allow log injection (forged log
	// lines via CR/LF and other control characters).
	char *escaped = escape_string(message);
	if(escaped != NULL)
	{
		log_web(LOG_INFO, "ACCESS: %s", escaped);
		free(escaped);
	}

	return 1;
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

	log_web_debug(DEBUG_API, "Redirecting to %s", buffer);
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
// TLS terminator bookkeeping: the public TLS port it owns and the ephemeral
// loopback backend port CivetWeb serves it on. Both 0 when TLS is off.
static int terminator_port = 0;
static int backend_port = 0;
// The bind address the operator scoped the secure port to ("" = all interfaces),
// so the terminator honours it instead of always binding every interface.
static char terminator_addr[64] = "";
#ifdef HAVE_TLS
// Every public TLS listener parsed out of webserver.port. terminator_port and
// terminator_addr mirror the first one, which is the port the plaintext-port
// mirroring below uses.
static struct terminator_listener tls_listeners[TERMINATOR_MAX_LISTENERS];
static char tls_listener_addrs[TERMINATOR_MAX_LISTENERS][64];
static unsigned n_tls_listeners = 0;
// Index into tls_listeners of the port terminator_port names
static unsigned tls_primary = 0;
#endif
// Whether the terminator actually serves terminator_port. Settled once
// terminator_start() has returned.
static bool terminator_bound = false;

// Read back the ephemeral loopback port CivetWeb bound for the terminator
// backend. Returns false if CivetWeb reports no ports at all.
static bool find_backend_port(void)
{
	if(ctx == NULL)
		return false;

	struct mg_server_port mgports[MAXPORTS] = { 0 };
	const int ports = mg_get_server_ports(ctx, MAXPORTS, mgports);
	if(ports < 1)
	{
		log_web(LOG_WARNING, "No web server ports configured!");
		return false;
	}

	for(int i = 0; i < ports && terminator_port > 0; i++)
		if(mgports[i].protocol == 1 && !mgports[i].is_ssl &&
		   mgports[i].addr.sa4.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
			backend_port = mgports[i].port;

	return true;
}

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
		log_web(LOG_WARNING, "No web server ports configured!");
		return false;
	}

	// Rebuild the table from scratch (http_init may run again on a restart).
	// https_port is only ever assigned below when still 0, so clear it here too;
	// otherwise a stale value from a previous run survives the rebuild.
	memset(server_ports, 0, sizeof(server_ports));
	https_port = 0;

	// Loop over all ports CivetWeb reports. In terminator mode CivetWeb binds the
	// public plaintext port(s) plus an internal loopback backend; the public TLS
	// port lives on the terminator. Hide the backend and mirror each public
	// plaintext port with the terminator's TLS port on the same address.
	log_info("Web server ports:");
	unsigned int n = 0;
	bool mirrored = false;
	for(unsigned int i = 0; i < (unsigned int)ports && n < MAXPORTS; i++)
	{
		// Stop if no more ports are configured
		if(mgports[i].protocol == 0)
			break;

		// Convert listening address to string
		// 1 = IPv4, 3 = IPv6 (can also be a combo-socket serving both),
		// the documentation in civetweb.h is wrong
		char addr[INET6_ADDRSTRLEN + 2] = { 0 };
		if(mgports[i].protocol == 1)
			inet_ntop(AF_INET, &mgports[i].addr.sa4.sin_addr, addr, INET_ADDRSTRLEN);
		else if(mgports[i].protocol == 3)
		{
			char tmp[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &mgports[i].addr.sa6.sin6_addr, tmp, INET6_ADDRSTRLEN);
			// Enclose IPv6 address in square brackets
			snprintf(addr, sizeof(addr), "[%s]", tmp);
		}
		else
		{
			log_web(LOG_WARNING, "Unsupported protocol for port %d", mgports[i].port);
			continue;
		}

		// The loopback plaintext backend the terminator forwards to is internal,
		// do not advertise it
		if(backend_port > 0 && mgports[i].port == backend_port &&
		   strcmp(addr, "127.0.0.1") == 0)
			continue;

		// Store the public port
		strncpy(server_ports[n].addr, addr, sizeof(server_ports[n].addr) - 1);
		server_ports[n].port = mgports[i].port;
		server_ports[n].is_secure = mgports[i].is_ssl;
		server_ports[n].is_redirect = mgports[i].is_redirect;
		server_ports[n].is_optional = mgports[i].is_optional;
		server_ports[n].is_bound = mgports[i].is_bound;
		server_ports[n].protocol = mgports[i].protocol;
		if(mgports[i].is_ssl && https_port == 0)
			https_port = mgports[i].port;
		log_info("  - %s:%d (HTTP%s, IPv%s%s%s, %s)",
		         server_ports[n].addr, server_ports[n].port,
		         server_ports[n].is_secure ? "S" : "",
		         server_ports[n].protocol == 1 ? "4" : "6",
		         server_ports[n].is_redirect ? ", redirecting" : "",
		         server_ports[n].is_optional ? ", optional" : "",
		         server_ports[n].is_bound ? "OK" : "NOT bound");
		n++;

		// Mirror each public plaintext (non-redirect) port with the terminator's
		// TLS port on the same address.
		if(terminator_port > 0 && !mgports[i].is_ssl &&
		   !mgports[i].is_redirect && n < MAXPORTS)
		{
			server_ports[n] = server_ports[n - 1];
			server_ports[n].port = terminator_port;
			server_ports[n].is_secure = true;
			server_ports[n].is_bound = terminator_bound;
			if(https_port == 0 && terminator_bound)
				https_port = (in_port_t)terminator_port;
			log_info("  - %s:%d (HTTPS, IPv%s%s, terminator, %s)",
			         server_ports[n].addr, server_ports[n].port,
			         server_ports[n].protocol == 1 ? "4" : "6",
			         server_ports[n].is_optional ? ", optional" : "",
			         terminator_bound ? "OK" : "NOT bound");
			n++;
			mirrored = true;
		}
	}

	// The terminator serves the public TLS port outside CivetWeb, so it is
	// normally registered by mirroring a public plaintext port above. If there is
	// no plaintext port to mirror - a TLS-only "443s" config, or only a redirect
	// plaintext port ("80r,443s") - register it explicitly here. Otherwise
	// get_server_ports() would report failure (aborting the whole web interface)
	// or leave https_port at 0, which mis-reports the port in /info and skips
	// certificate auto-renewal (letting an FTL-generated cert silently expire).
	if(terminator_port > 0 && !mirrored && n < MAXPORTS)
	{
		memset(&server_ports[n], 0, sizeof(server_ports[n]));
		strncpy(server_ports[n].addr,
		        terminator_addr[0] != '\0' ? terminator_addr : "0.0.0.0",
		        sizeof(server_ports[n].addr) - 1);
		server_ports[n].port = (in_port_t)terminator_port;
		server_ports[n].is_secure = true;
		server_ports[n].is_bound = terminator_bound;
		server_ports[n].protocol = 1;
		if(terminator_bound)
			https_port = (in_port_t)terminator_port;
		log_info("  - %s:%d (HTTPS, terminator, %s)",
		         server_ports[n].addr, server_ports[n].port,
		         terminator_bound ? "OK" : "NOT bound");
		n++;
	}

#ifdef HAVE_TLS
	// The mirroring above only ever advertises the primary TLS port. Register
	// the remaining ones so /info and the web interface report every port the
	// terminator was asked to serve, and whether it could.
	for(unsigned t = 0; t < n_tls_listeners && n < MAXPORTS; t++)
	{
		if(t == tls_primary)
			continue;
		const char *a = tls_listeners[t].addr;
		// An IPv6 literal needs brackets, or "::1" + ":443" reads as "::1:443".
		// A bare entry is dual-stack; report it as IPv6, matching how the
		// terminator binds it (one AF_INET6 socket also serving IPv4).
		const bool v6 = a[0] == '\0' || strchr(a, ':') != NULL;
		memset(&server_ports[n], 0, sizeof(server_ports[n]));
		if(a[0] == '\0')
			strncpy(server_ports[n].addr, "[::]", sizeof(server_ports[n].addr) - 1);
		else if(v6)
			snprintf(server_ports[n].addr, sizeof(server_ports[n].addr), "[%s]", a);
		else
			strncpy(server_ports[n].addr, a, sizeof(server_ports[n].addr) - 1);
		server_ports[n].port = (in_port_t)tls_listeners[t].port;
		server_ports[n].is_secure = true;
		server_ports[n].is_bound = tls_listeners[t].bound;
		server_ports[n].protocol = v6 ? 3 : 1;
		log_info("  - %s:%d (HTTPS, terminator, %s)",
		         server_ports[n].addr, server_ports[n].port,
		         tls_listeners[t].bound ? "OK" : "NOT bound");
		n++;
	}
#endif

	return n > 0;
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
		// Skip ports that are not configured, redirected or not served
		if(server_ports[i].port == 0 || server_ports[i].is_redirect ||
		   !server_ports[i].is_bound)
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

		// Reject the URL if snprintf() truncated it to fit api_str (this_len is
		// the would-be length) or if it does not fit the destination buffer.
		if((size_t)this_len >= MAX_URL_LEN || (size_t)this_len >= bufsz - len - 1)
		{
			log_err("API URL buffer too small!");
			free(api_str);
			return 0;
		}

		// Check if this string is already present in the buffer
		if(memmem(*buf, len, api_str, this_len) != NULL)
		{
			// This string is already present, so skip it
			log_web_debug(DEBUG_API, "Skipping duplicate API URL: %s", api_str);
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

// Whether the embedded web server knows this option in this build. Passing one
// it does not know makes mg_start() fail, which would leave the web interface
// unavailable until the config is corrected on disk. Which options are
// acceptable is not decided here - webserver.advancedOpts cannot be set through
// the API at all, so reaching this code already required access to the host.
static bool webserver_option_known(const char *key)
{
	// Compared the same way CivetWeb compares them, see get_option_index()
	for(const struct mg_option *opt = mg_get_valid_options(); opt->name != NULL; opt++)
		if(strcmp(key, opt->name) == 0)
			return true;

	return false;
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
		const char *key = static_options[i * 2];
		const char *value = static_options[i * 2 + 1];
		// Never log the value of the per-boot backend-auth secret.
		if(key != NULL && strcmp(key, "proxy_protocol_secret") == 0)
			value = "<per-boot secret>";
		char *escaped_key = escape_string(key);
		char *escaped_value = escape_string(value);
		if(debug)
		{
			if(i == idx)
			{
				log_web_debug(DEBUG_WEBSERVER, "Webserver option %zu/%zu: <END OF OPTIONS>", i, idx);
				break;
			}
			log_web_debug(DEBUG_WEBSERVER, "Webserver option %zu/%zu: %s=%s",
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

#ifdef HAVE_TLS
// Append src to dst (buffer size dstsz), keeping dst NUL-terminated. A no-op once
// dst is full, so the length handed to strncat() can never underflow.
static void str_append(char *dst, size_t dstsz, const char *src)
{
	const size_t used = strlen(dst);
	if(used + 1 >= dstsz)
		return;
	strncat(dst, src, dstsz - used - 1);
}

// Whether a bind address covers every interface. Only a bare port does: the
// terminator binds it as one dual-stack socket, so any other entry for the same
// port can only collide with it. "0.0.0.0" and "[::]" are the IPv4 and IPv6
// halves of a port and are bound as two sockets that coexist.
static bool tls_addr_is_wildcard(const char *addr)
{
	return addr[0] == '\0';
}

// Parse one secure webserver.port entry with CivetWeb's syntax, as these never
// reach CivetWeb's own check: "[ipv6]:", "ipv4:" or "+" (none of them for a
// bare port), a port 1-65535, then only the flags 'o', 'r' and 's', each at
// most once, 's' required and 'r' not with it. addr receives the address
// without brackets, or "" for all interfaces.
static bool parse_tls_entry(const char *ent, char addr[64], int *port)
{
	const char *p = ent;
	addr[0] = '\0';
	if(*p == '[' || (*p != '+' && strchr(p, ':') != NULL))
	{
		const bool v6 = *p == '[';
		const char *end = v6 ? strstr(p, "]:") : strchr(p, ':');
		if(end == NULL)
			return false;
		const char *astart = v6 ? p + 1 : p;
		const size_t alen = (size_t)(end - astart);
		if(alen == 0 || alen >= 64)
			return false;
		memcpy(addr, astart, alen);
		addr[alen] = '\0';
		unsigned char tmp[sizeof(struct in6_addr)];
		if(inet_pton(v6 ? AF_INET6 : AF_INET, addr, tmp) != 1)
			return false;
		p = end + (v6 ? 2 : 1);
	}
	else if(*p == '+')
		p++;

	if(!isdigit((unsigned char)*p))
		return false;
	long val = 0;
	for(; isdigit((unsigned char)*p); p++)
		if((val = val * 10 + (*p - '0')) > 65535)
			return false;
	if(val < 1)
		return false;

	bool o = false, r = false, sec = false;
	for(; *p != '\0'; p++)
	{
		bool *flag = *p == 'o' ? &o : *p == 'r' ? &r : *p == 's' ? &sec : NULL;
		if(flag == NULL || *flag)
			return false;
		*flag = true;
	}
	*port = (int)val;
	return sec && !r;
}

// Split the webserver port list for TLS-terminator mode. Secure ("...s") entries
// name public TLS ports the terminator owns, so they are dropped from CivetWeb's
// list and a loopback plaintext backend (ephemeral port, read back after start)
// is appended instead. Every secure entry is collected into tls (capacity
// tls_cap, backed by the caller's tls_addrs storage); returns how many were
// stored, or 0 if none.
static unsigned split_terminator_ports(const char *cfg, char *backend, size_t backend_len,
                                       struct terminator_listener *tls,
                                       char tls_addrs[][64], unsigned tls_cap)
{
	backend[0] = '\0';
	unsigned n_tls = 0;

	char *copy = strdup(cfg);
	if(copy == NULL)
		return 0;

	char *save = NULL;
	for(char *tok = strtok_r(copy, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save))
	{
		// Trim surrounding whitespace, as CivetWeb's option list parser does
		const char *ent = tok;
		while(*ent == ' ' || *ent == '\t')
			ent++;
		for(char *e = tok + strlen(tok); e > ent && (e[-1] == ' ' || e[-1] == '\t'); )
			*--e = '\0';
		if(*ent == '\0')
			continue;

		// A secure entry (carries the 's' flag) is owned by the terminator
		if(strchr(ent, 's') != NULL)
		{
			// Secure entries never reach CivetWeb, so a malformed one ("44s3",
			// "443xs") must be rejected here rather than read as a port
			char addr[64];
			int port = 0;
			if(!parse_tls_entry(ent, addr, &port))
			{
				log_warn("Ignoring malformed TLS entry '%s' in webserver.port", ent);
				continue;
			}

			// Collapse entries that would bind the same socket. The default
			// "443os,[::]:443os" names the dual-stack listener and then its IPv6
			// half, and binding both is simply EADDRINUSE. A bare port therefore
			// supersedes any address-scoped entry for that port, and vice versa;
			// distinct addresses (e.g. "0.0.0.0" and "[::]") each get a socket.
			bool dup = false;
			for(unsigned j = 0; j < n_tls; j++)
			{
				if(tls[j].port != port)
					continue;
				if(tls_addr_is_wildcard(tls[j].addr) || tls_addr_is_wildcard(addr) ||
				   strcmp(tls[j].addr, addr) == 0)
				{
					// Keep the widest of the two, so "[::1]:443s,443s" still ends
					// up serving every interface.
					if(tls_addr_is_wildcard(addr) && !tls_addr_is_wildcard(tls[j].addr))
						tls_addrs[j][0] = '\0';
					dup = true;
					break;
				}
			}
			if(dup)
				continue; // drop from the list handed to CivetWeb

			if(n_tls >= tls_cap)
			{
				log_warn("Cannot serve TLS on '%s': at most %u TLS ports are supported",
				         ent, tls_cap);
				continue; // still drop it, CivetWeb cannot serve it either
			}
			strcpy(tls_addrs[n_tls], addr);
			tls[n_tls].addr = tls_addrs[n_tls];
			tls[n_tls].port = port;
			n_tls++;
			continue; // drop from the list handed to CivetWeb
		}

		// Keep plaintext entries verbatim
		if(backend[0] != '\0')
			str_append(backend, backend_len, ",");
		str_append(backend, backend_len, ent);
	}
	free(copy);

	// Append the loopback plaintext backend CivetWeb serves the terminator on.
	// Port 0 lets the kernel pick a free port; it is read back after mg_start2().
	if(backend[0] != '\0')
		str_append(backend, backend_len, ",");
	str_append(backend, backend_len, "127.0.0.1:0");

	return n_tls;
}
#endif /* HAVE_TLS */

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
	log_web(LOG_INFO, "Initializing HTTP server on ports \"%s\"", config.webserver.port.v.s);
	// No MG_FEATURES_TLS: civetweb is built without TLS (NO_SSL) and only serves
	// plain HTTP/1.1 on the loopback backend; the front terminator does TLS.
	unsigned int features = MG_FEATURES_FILES |
	                        MG_FEATURES_IPV6 |
	                        MG_FEATURES_CACHE;

	if(mg_init_library(features) == 0)
	{
		log_err("Initializing HTTP library failed!");
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

	// TLS is terminated by the in-process front terminator, not CivetWeb: when the
	// port list has a secure port, hand CivetWeb a plaintext loopback backend instead.
	const char *listening_ports = config.webserver.port.v.s;
#ifdef HAVE_TLS
	const bool tls_used = config.webserver.port.v.s != NULL &&
	                      strchr(config.webserver.port.v.s, 's') != NULL;
	char backend_ports[256];
	terminator_port = 0;
	backend_port = 0;
	terminator_addr[0] = '\0';
	tls_primary = 0;
	terminator_bound = false;
	if(tls_used)
	{
		n_tls_listeners = split_terminator_ports(config.webserver.port.v.s,
		                                         backend_ports, sizeof(backend_ports),
		                                         tls_listeners, tls_listener_addrs,
		                                         TERMINATOR_MAX_LISTENERS);
		if(n_tls_listeners > 0)
		{
			terminator_port = tls_listeners[0].port;
			strncpy(terminator_addr, tls_listeners[0].addr, sizeof(terminator_addr) - 1);
			terminator_addr[sizeof(terminator_addr) - 1] = '\0';
		}
		if(terminator_port > 0)
			listening_ports = backend_ports;
		else
			log_err("Could not extract a TLS port from '%s'; the web server will not offer TLS",
			        config.webserver.port.v.s);
	}
#endif

	// Prepare options for HTTP server (NULL-terminated list)
	const char *static_options[] = {
		"document_root", config.webserver.paths.webroot.v.s,
		"error_pages", error_pages,
		"listening_ports", listening_ports,
		"decode_url", "yes",
		"enable_directory_listing", "no",
		"num_threads", num_threads,
		"authentication_domain", config.webserver.domain.v.s,
		"additional_header", webheaders,
		"index_files", "index.html,index.htm,index.lp",
		"enable_keep_alive", "yes",
		"keep_alive_timeout_ms", "5000",
		// Disable Nagle: without it a small TLS response is split across segments
		// and stalls ~40 ms on the client's delayed ACK, which dominates DoH
		// (and UI/API) latency. Responses are normally sent in full, so Nagle
		// buys nothing here.
		"tcp_nodelay", "1",
		// Pi-hole's web interface is built from Lua *pages* (".lp"), which are
		// the only files the embedded web server may evaluate. CivetWeb would
		// otherwise also run standalone ".lua" scripts and expand server-side
		// includes in ".shtml" files, both through patterns that default to
		// being enabled. Pin all three: an empty pattern matches nothing (see
		// match_prefix_strlen(), whose callers all test for a match > 0) and
		// therefore never selects a handler.
		"lua_server_page_pattern", "**.lp$",
		"lua_script_pattern", "",
		"ssi_pattern", "",
		NULL, NULL, // Optional slots for TLS configuration
		NULL, NULL, // Optional slots for access control list (ACL)
		NULL, NULL  // Termination of the array
	};
	const size_t opt_size = (ArraySize(static_options) / 2) + cJSON_GetArraySize(config.webserver.advancedOpts.v.json) + 1; // +1: proxy_protocol_secret
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

#ifdef HAVE_TLS
	// Ensure the TLS certificate exists and matches the configured domain. The
	// terminator (not CivetWeb) uses it; no ssl_certificate option is passed.
	if(tls_used &&
	   config.webserver.tls.cert.v.s != NULL &&
	   strlen(config.webserver.tls.cert.v.s) > 0)
	{
		// Try to generate certificate if not present
		if(!file_readable(config.webserver.tls.cert.v.s))
		{
			if(generate_certificate(config.webserver.tls.cert.v.s, false, config.webserver.domain.v.s, config.webserver.tls.validity.v.ui))
			{
				log_web(LOG_INFO, "Created SSL/TLS certificate for %s at %s",
				         config.webserver.domain.v.s, config.webserver.tls.cert.v.s);
			}
			else
			{
				log_err("Generation of SSL/TLS certificate %s failed!",
				        config.webserver.tls.cert.v.s);
			}
		}

		// Check if the certificate is readable (we may have just created it)
		if(file_readable(config.webserver.tls.cert.v.s))
		{
			if(read_certificate(config.webserver.tls.cert.v.s, config.webserver.domain.v.s, false) != CERT_DOMAIN_MATCH)
			{
				log_certificate_domain_mismatch(config.webserver.tls.cert.v.s, config.webserver.domain.v.s);
			}
		}
		else
		{
			log_err("Webserver SSL/TLS certificate %s not found or not readable!",
			        config.webserver.tls.cert.v.s);
		}
	}
#endif

	// Hand CivetWeb the shared secret authenticating PROXY v2 headers, so it
	// adopts the real client address the header announces. Two independent
	// reasons to install it: our own front terminator reaches this loopback
	// backend behind such a header, and an operator-configured
	// webserver.proxySecret lets an EXTERNAL reverse proxy do the same. The
	// latter deployment has no local TLS port at all, so it must not be gated on
	// the terminator running. Generated here so it exists before mg_start2();
	// terminator_start() reuses the same value.
	const char *cfg_proxy_secret = config.webserver.proxySecret.v.s;
	if(terminator_port > 0 || (cfg_proxy_secret != NULL && cfg_proxy_secret[0] != '\0'))
	{
		char secret_hex[33]; // 2 * 16-byte token + NUL
		if(terminator_proxy_token_hex(secret_hex, sizeof(secret_hex)))
		{
			conf_opts[idx * 2] = strdup("proxy_protocol_secret");
			conf_opts[idx * 2 + 1] = strdup(secret_hex);
			idx++;
		}
		else
			log_err("Terminator: could not derive proxy_protocol_secret; requests will log the loopback address");
	}

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
			log_web(LOG_ERR, "Invalid option in webserver.advancedOpts!");
			continue;
		}

		// Get option value
		const char *opt = cJSON_GetStringValue(option);

		// Split option into key and value at the first '='
		const char *equal_sign = strchr(opt, '=');
		if(equal_sign == NULL)
		{
			log_web(LOG_ERR, "Invalid option in webserver.advancedOpts: %s (missing '=')", opt);
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

		// Skip an option this build does not know rather than letting
		// mg_start() fail over it
		if(!webserver_option_known(key))
		{
			log_web(LOG_WARNING, "Ignoring unknown webserver.advancedOpts option \"%s\"", key);
			free(key);
			continue;
		}

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
	callbacks.begin_request = begin_request_handler;
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
	if((ctx = mg_start2(&init, &error)) == NULL || !find_backend_port())
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

	// Inbound DoH (RFC 8484) is served natively by the front terminator on
	// /dns-query for HTTP/1.1, HTTP/2 and HTTP/3 (see terminator.c). The only
	// CivetWeb registration is a guard that refuses a plaintext /dns-query (426).
	if(config.dns.doh.v.b)
		mg_set_request_handler(ctx, "/dns-query", dns_query_guard, NULL);

	if(strcmp(prefix_webhome, "/") == 0)
	{
		log_web_debug(DEBUG_API, "Not redirecting root since webhome is '%s'",
			  prefix_webhome);
	} else {
		// Redirect requests to / to the webhome path.
		mg_set_request_handler(ctx, "/$", redirect_root_handler, NULL);
	}

	if(strcmp(config.webserver.paths.webhome.v.s, "/") == 0 &&
	   config.dns.blocking.mode.v.blocking_mode == MODE_IP)
	{
		log_web(LOG_WARNING, "Webhome is set to root (/) and IP blocking is enabled. This may result in the Pi-hole web interface to display in places where otherwise ads would show up");
	}

	// Register [prefix]<webhome without trailing slash> -> [<prefix>]<webhome> redirect handler
	if(strlen(config.webserver.paths.webhome.v.s) > 1 && config.webserver.paths.webhome.v.s[strlen(config.webserver.paths.webhome.v.s)-1] == '/')
	{
		// Replace trailing slash with end-of-string marker for matcher
		char *prefix_webhome_matcher = strdup(prefix_webhome);
		prefix_webhome_matcher[strlen(prefix_webhome_matcher)-1] = '$';

		log_web_debug(DEBUG_API, "Redirecting %s --308--> %s",
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

	// Create CLI password (if enabled)
	create_cli_password();

#ifdef HAVE_TLS
	// Start the TLS terminator in front of the (now plaintext) CivetWeb backend
	// on the loopback port find_backend_port() read back.
	if(tls_used && terminator_port > 0)
	{
		if(backend_port <= 0)
			log_err("Could not determine the CivetWeb loopback backend port; TLS will not be available");
		else if(!terminator_start(tls_listeners, n_tls_listeners, backend_port, config.webserver.tls.cert.v.s))
			log_err("Failed to start the TLS terminator on port %d", terminator_port);

		// Advertise the first TLS port that actually came up
		for(unsigned i = 0; i < n_tls_listeners; i++)
		{
			if(!tls_listeners[i].bound)
				continue;
			tls_primary = i;
			terminator_port = tls_listeners[i].port;
			strncpy(terminator_addr, tls_listeners[i].addr, sizeof(terminator_addr) - 1);
			terminator_addr[sizeof(terminator_addr) - 1] = '\0';
			terminator_bound = true;
			break;
		}
	}
#endif

	// Only now does the port table reflect what the terminator really serves
	get_server_ports();
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
	log_web_debug(DEBUG_API, "Rewriting filename: %s", filename);
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
		log_web_debug(DEBUG_API, "Rewriting index page: %s ==> %s", filename, filename_lp);
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
		log_web_debug(DEBUG_API, "Rewriting Lua page: %s ==> %s", filename, filename_lp);
		strncpy(filename, filename_lp, filename_buf_len);
		free(filename_lp);
		return;
	}

	// Change last occurrence of "/" to "-" (if any), but only if it lies
	// beyond the webroot so the rewritten path stays inside of it
	char *last_slash = strrchr(filename_lp, '/');
	if(last_slash != NULL && (size_t)(last_slash - filename_lp) > strlen(config.webserver.paths.webroot.v.s))
	{
		*last_slash = '-';
		if(file_readable(filename_lp))
		{
			log_web_debug(DEBUG_API, "Rewriting Lua page (settings page): %s ==> %s", filename, filename_lp);
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

#ifdef HAVE_TLS
	// Stop the TLS terminator before the backend it forwards to
	terminator_stop();
#endif

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

#ifdef HAVE_TLS
static void restart_http(void)
{
	// Stop the server
	http_terminate();

	// Reinitialize the webserver
	http_init();
}
#endif /* HAVE_TLS */

/**
 * @brief Prints all supported TLS cipher suites by OpenSSL.
 *
 * This function retrieves the list of TLS cipher suites enabled by default in
 * OpenSSL and prints their names, protocol versions, and key lengths to the
 * standard output.
 *
 * The output format for each cipher suite is:
 *   - <suite_name> (Protocol: <version>, Key length: <bitlen> bits)
 *
 * No parameters are required and no value is returned.
 */
void get_all_supported_ciphersuites(void)
{
#ifdef HAVE_TLS
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
	if(ssl_ctx == NULL)
	{
		printf("Unable to create SSL context\n");
		return;
	}

	STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ssl_ctx);
	printf("Supported TLS cipher suites:\n");
	for(int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++)
	{
		// Get cipher suite details
		const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
		int bitlen = 0;
		SSL_CIPHER_get_bits(cipher, &bitlen);
		printf("- %s (Protocol: %s, Key length: %d bits)\n",
		       SSL_CIPHER_get_name(cipher), SSL_CIPHER_get_version(cipher), bitlen);
	}

	SSL_CTX_free(ssl_ctx);
#endif /* HAVE_TLS */
}

#ifdef HAVE_TLS
void *webserver_thread(void *val)
{
	(void)val;
	// Set thread name
	prctl(PR_SET_NAME, thread_names[WEBSERVER], 0, 0, 0);

	// Initialize FTL HTTP server
	http_init();

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
				log_web(LOG_INFO, "TLS certificate at %s is about to expire soon, generating new one",
				         config.webserver.tls.cert.v.s);
				if(generate_certificate(config.webserver.tls.cert.v.s, false,
				             config.webserver.domain.v.s,
				             config.webserver.tls.validity.v.ui))
				{
					log_web(LOG_INFO, "Restarting HTTP server");
					restart_http();

					log_web(LOG_INFO, "Done. The new certificate is valid for %u days",
					         config.webserver.tls.validity.v.ui);
				}
				else
				{
					// Certificate generation failed. Thanks to the atomic
					// write in write_to_file() the existing certificate file
					// is untouched, so keep serving with it instead of
					// restarting into a broken/missing certificate.
					log_err("Failed to renew TLS certificate at %s, keeping the existing one",
					        config.webserver.tls.cert.v.s);
				}
			}
			else
			{
				log_err("TLS certificate at %s is about to expire soon, but it is not a Pi-hole certificate. Please renew it manually!",
				        config.webserver.tls.cert.v.s);
			}
		}

		// Idle for 1 day (24 hours), sleeping in 1-hour intervals
		// so the thread is not permanently marked as idle (#2818)
		for(int h = 0; h < 24 && !killed; h++)
			thread_sleepms(WEBSERVER, 3600000);
	}

	log_web(LOG_INFO, "Terminating webserver thread");
	return NULL;
}
#endif /* HAVE_TLS */
