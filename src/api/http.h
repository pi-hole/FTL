/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  HTTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef HTTP_H
#define HTTP_H

// External components
#include "../civetweb/civetweb.h"
#include "../cJSON/cJSON.h"

// strlen()
#include <string.h>

// FTLfree()
#include "../memory.h"

void http_init(void);
void http_terminate(void);
void http_send(struct mg_connection *conn, bool chunk, const char *format, ...) __attribute__ ((format (gnu_printf, 3, 4)));

int send_http(struct mg_connection *conn, const char *mime_type,
              const char *additional_headers, const char *msg);
int send_http_code(struct mg_connection *conn, const char *mime_type,
                   const char *additional_headers, int code, const char *msg);
int send_http_error(struct mg_connection *conn);

// Cookie routines
bool http_get_cookie_int(struct mg_connection *conn, const char *cookieName, int *i);
bool http_get_cookie_str(struct mg_connection *conn, const char *cookieName, char *str, size_t str_size);

// HTTP macros
#define GET_VAR(variable, destination, source) mg_get_var(source, strlen(source), variable, destination, sizeof(destination))

// Method routines
enum { HTTP_UNKNOWN, HTTP_GET, HTTP_POST, HTTP_DELETE };
int http_method(struct mg_connection *conn);

#endif // HTTP_H