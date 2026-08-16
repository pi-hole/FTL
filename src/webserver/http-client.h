/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound HTTP(S) downloader
*
*  Public interface of the libcurl-backed downloader behind pihole.download().
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

// Compile-time limits rather than configuration keys: `pihole-FTL lua` never
// reads the config, so a config-backed limit would be zero in exactly the mode
// the tests use.
#define HTTP_DL_MAX_BYTES     (16u * 1024u * 1024u)
#define HTTP_DL_CONNECT_MS    5000L
#define HTTP_DL_TOTAL_MS      60000L
#define HTTP_DL_MAX_REDIRECTS 5L

struct http_result {
	char *body;  // in-memory mode only, NUL-terminated, owned by the caller
	size_t len;  // body bytes received, in both modes
	long status; // final HTTP status, 0 if we never got one
	char err[256];
};

// Fetch url, which may be http://, https://, ftp://, ftps:// or file://. A NULL
// dest streams the body into res->body, otherwise it is written to dest via a
// temporary file that is renamed into place only after the transfer completed.
// A redirect is never allowed to reach file:// or ftp://, nor to leave TLS.
//
// The URL must never be derived from request data: a Lua page can be served
// without authentication, and this issues an arbitrary outbound request.
//
// Returns true on success, false with res->err filled otherwise. Never aborts.
bool http_get(const char *url, const char *dest, struct http_result *res);

// Release whatever *res still owns. Idempotent.
void http_result_free(struct http_result *res);

#endif // HTTP_CLIENT_H
