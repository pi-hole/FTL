/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  HTTP server prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <stdbool.h>
// in_port_t
#include <netinet/in.h>
// struct mg_connection
#include "webserver/civetweb/civetweb.h"

// Hard-coded maximum number of allowed web server threads
#define MAX_WEBTHREADS 64
// Macro to limiting a numeric value to a certain minimum and maximum
#define LIMIT_MIN_MAX(a, b, c) ((a) < (b) ? (b) : (a) > (c) ? (c) : (a))

void http_init(void);
void http_terminate(void);
void *webserver_thread(void *val);
void get_all_supported_ciphersuites(void);

int ftl_http_redirect(struct mg_connection *conn, const int code, const char *format, ...) __attribute__((format(printf, 3, 4), nonnull(1, 3)));
in_port_t get_https_port(void) __attribute__((pure));
unsigned short get_api_string(char **buf, const bool domain);
char *get_prefix_webhome(void) __attribute__((pure));
char *get_api_uri(void) __attribute__((pure));

// Compile-time protocol capabilities of the advanced TLS backend, exposed so
// --version (compiled in core, which lacks the HTTP/2 and HTTP/3 build flags)
// can report them.
bool webserver_have_http2(void) __attribute__((const));
bool webserver_have_http3(void) __attribute__((const));

#endif // WEBSERVER_H
