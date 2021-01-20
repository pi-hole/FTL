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

const char* json_formatter(const cJSON *object);

int send_http(struct mg_connection *conn, const char *mime_type, const char *msg);
int send_http_code(struct mg_connection *conn, const char *mime_type, int code, const char *msg);
int send_http_internal_error(struct mg_connection *conn);
int send_json_unauthorized(struct mg_connection *conn);
int send_json_error(struct mg_connection *conn, const int code,
                    const char *key, const char* message,
                    cJSON *data);
int send_json_success(struct mg_connection *conn);

void http_reread_index_html(void);

// Cookie routines
bool http_get_cookie_int(struct mg_connection *conn, const char *cookieName, int *i);
bool http_get_cookie_str(struct mg_connection *conn, const char *cookieName, char *str, size_t str_size);

// HTTP parameter routines
bool get_bool_var(const char *source, const char *var, bool *boolean);
bool get_uint_var(const char *source, const char *var, unsigned int *num);
bool get_int_var(const char *source, const char *var, int *num);
bool http_get_payload(struct mg_connection *conn, char *payload, const size_t size);
cJSON *get_POST_JSON(struct mg_connection *conn);

// HTTP macros
#define GET_VAR(variable, destination, source) mg_get_var(source, strlen(source), variable, destination, sizeof(destination))

// Method routines
enum http_method { HTTP_UNKNOWN, HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_PATCH, HTTP_DELETE };
int http_method(struct mg_connection *conn);

// Utils
const char *startsWith(const char *path, const char *uri) __attribute__((pure));

#endif // HTTP_H
