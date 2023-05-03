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
#include "civetweb/civetweb.h"
#include "webserver/cJSON/cJSON.h"
// enum fifo_logs
#include "enums.h"

// strlen()
#include <string.h>

// API-internal definitions

// Maximum size of received and processed payload: 64 KB
#define MAX_PAYLOAD_BYTES 64*1024
enum http_method {
	HTTP_UNKNOWN = 0,
	HTTP_GET = 1 << 0,
	HTTP_POST = 1 << 1,
	HTTP_PUT = 1 << 2,
	HTTP_PATCH = 1 << 3,
	HTTP_DELETE = 1 << 4,
	HTTP_OPTIONS = 1 << 5,
};

struct api_options {
	bool domains :1;
	bool parse_json :1;
	enum fifo_logs which;
};

struct ftl_conn {
	struct mg_connection *conn;
	const struct mg_request_info *request;
	const enum http_method method;
	char *action_path;
	const char *item;
	int user_id;
	struct {
		bool avail;
		char *raw;
		cJSON *json;
		const char* json_error;
		long unsigned int size;
	} payload;
	struct {
		bool restart;
	} ftl;

	struct api_options opts;
};


char *json_formatter(const cJSON *object);

int send_http(struct ftl_conn *api, const char *mime_type, const char *msg);
int send_http_code(struct ftl_conn *api, const char *mime_type, int code, const char *msg);
int send_http_internal_error(struct ftl_conn *api);
int send_json_unauthorized(struct ftl_conn *api);
int send_json_error(struct ftl_conn *api, const int code,
                    const char *key, const char* message,
                    const char *hint);
int send_json_error_free(struct ftl_conn *api, const int code,
                         const char *key, const char* message,
                         char *hint, bool free_hint);
int send_json_success(struct ftl_conn *api);
const char *get_http_method_str(const enum http_method method) __attribute__((const));

void http_reread_index_html(void);

// Cookie routines
bool http_get_cookie_int(struct ftl_conn *api, const char *cookieName, int *i);
bool http_get_cookie_str(struct ftl_conn *api, const char *cookieName, char *str, size_t str_size);

// HTTP parameter routines
bool get_bool_var(const char *source, const char *var, bool *boolean);
bool get_ulong_var_msg(const char *source, const char *var, unsigned long *num, const char **msg);
bool get_uint_var_msg(const char *source, const char *var, unsigned int *num, const char **msg);
bool get_uint_var(const char *source, const char *var, unsigned int *num);
bool get_int_var_msg(const char *source, const char *var, int *num, const char **msg);
bool get_int_var(const char *source, const char *var, int *num);
bool get_double_var_msg(const char *source, const char *var, double *num, const char **msg);
bool get_double_var(const char *source, const char *var, double *num);

// HTTP macros
#define GET_VAR(variable, destination, source) mg_get_var(source, strlen(source), variable, destination, sizeof(destination))

// Utils
enum http_method __attribute__((pure)) http_method(struct mg_connection *conn);
const char* __attribute__((pure)) startsWith(const char *path, struct ftl_conn *api);
void read_and_parse_payload(struct ftl_conn *api);
char * __attribute__((malloc)) escape_html(const char *string);

#endif // HTTP_H
