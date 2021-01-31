/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Common HTTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "http-common.h"
#include "../config.h"
#include "../log.h"
#include "json_macros.h"
#include <limits.h>

char pi_hole_extra_headers[PIHOLE_HEADERS_MAXLEN] = { 0 };

// Provides a compile-time flag for JSON formatting
// This should never be needed as all modern browsers
// tyoically contain a JSON explorer
const char* json_formatter(const cJSON *object)
{
	if(httpsettings.prettyJSON)
	{
		/* Examplary output:
		{
			"queries in database":	70,
			"database filesize":	49152,
			"SQLite version":	"3.30.1"
		}
		*/
		return cJSON_Print(object);
	}
	else
	{
		/* Exemplary output
		{"queries in database":70,"database filesize":49152,"SQLite version":"3.30.1"}
		*/
		return cJSON_PrintUnformatted(object);
	}
}

int send_http(struct ftl_conn *api, const char *mime_type,
              const char *msg)
{
	mg_send_http_ok(api->conn, mime_type, NULL, strlen(msg));
	return mg_write(api->conn, msg, strlen(msg));
}

int send_http_code(struct ftl_conn *api, const char *mime_type,
                   int code, const char *msg)
{
	// Payload will be sent with text/plain encoding due to
	// the first line being "Error <code>" by definition
	//return mg_send_http_error(conn, code, "%s", msg);
	my_send_http_error_headers(api->conn, code,
	                           mime_type,
	                           strlen(msg));

	return mg_write(api->conn, msg, strlen(msg));
}

int send_json_unauthorized(struct ftl_conn *api)
{
	return send_json_error(api, 401,
                               "unauthorized",
                               "Unauthorized",
                               NULL);
}

int send_json_error(struct ftl_conn *api, const int code,
                    const char *key, const char* message,
                    cJSON *data)
{
	cJSON *json = JSON_NEW_OBJ();
	cJSON *error = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(error, "key", key);
	JSON_OBJ_REF_STR(error, "message", message);

	// Add data if available
	if(data == NULL)
	{
		JSON_OBJ_ADD_NULL(error, "data");
	}
	else
	{
		JSON_OBJ_ADD_ITEM(error, "data", data);
	}
		
	JSON_OBJ_ADD_ITEM(json, "error", error);

	JSON_SEND_OBJECT_CODE(json, code);
}

int send_json_success(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "status", "success");
	JSON_SEND_OBJECT(json);
}

int send_http_internal_error(struct ftl_conn *api)
{
	return mg_send_http_error(api->conn, 500, "Internal server error");
}

bool get_bool_var(const char *source, const char *var, bool *boolean)
{
	char buffer[16] = { 0 };
	if(GET_VAR(var, buffer, source) > 0)
	{
		*boolean = (strcasecmp(buffer, "true") == 0);
		return true;
	}
	return false;
}

static bool get_long_var_msg(const char *source, const char *var, long *num, const char **msg)
{
	char buffer[128] = { 0 };
	if(GET_VAR(var, buffer, source) < 1)
	{
		// Parameter not found
		*msg = NULL;
		return false;
	}

	// Try to get the value
	char *endptr = NULL;
	errno = 0;
	const long val = strtol(buffer, &endptr, 10);

	// Error checking
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
	    (errno != 0 && val == 0))
	{
		*msg = strerror(errno);
		return false;
	}

	if (endptr == buffer)
	{
		*msg = "No digits were found";
		return false;
	}

	// Otherwise: success
	*num = val;
	return true;
}

bool get_int_var_msg(const char *source, const char *var, int *num, const char **msg)
{
	long val = 0;
	if(!get_long_var_msg(source, var, &val, msg))
		return false;

	if(val > (long)INT_MAX)
	{
		*msg = "Specified integer too large, maximum allowed number is "  xstr(INT_MAX);
		return false;
	}

	if(val < (long)INT_MIN)
	{
		*msg = "Specified integer too negative, minimum allowed number is "  xstr(INT_MIN);
		return false;
	}

	*num = (int)val;
	return false;
}

bool get_int_var(const char *source, const char *var, int *num)
{
	const char *msg = NULL;
	return get_int_var_msg(source, var, num, &msg);
}

bool get_uint_var_msg(const char *source, const char *var, unsigned int *num, const char **msg)
{
	long val = 0;
	if(!get_long_var_msg(source, var, &val, msg))
		return false;

	if(val > (long)UINT_MAX)
	{
		*msg = "Specified integer too large, maximum allowed number is "  xstr(UINT_MAX);
		return false;
	}

	if(val < 0)
	{
		*msg = "Specified integer negavtive, this is not allowed";
		return false;
	}

	*num = (unsigned int)val;
	return false;
}

bool get_uint_var(const char *source, const char *var, unsigned int *num)
{
	const char *msg = NULL;
	return get_uint_var_msg(source, var, num, &msg);
}

const char* __attribute__((pure)) startsWith(const char *path, struct ftl_conn *api)
{
	if(strncmp(path, api->request->local_uri, strlen(path)) == 0)
		if(api->request->local_uri[strlen(path)] == '/')
		{
			// Path match with argument after ".../"
			if(api->action_path != NULL)
				free(api->action_path);
			api->action_path = strdup(api->request->local_uri);
			api->action_path[strlen(path)] = '\0';
			return api->request->local_uri + strlen(path) + 1u;
		}
		else if(strlen(path) == strlen(api->request->local_uri))
		{
			// Path match directly, no argument
			if(api->action_path != NULL)
				free(api->action_path);
			api->action_path = strdup(api->request->local_uri);
			return "";
		}
		else
		{
			// Further components in URL, assume this did't match, e.g.
			// /api/domains/regex[123].com
			return NULL;
		}
	else
		// Path does not match
		return NULL;
}

bool http_get_cookie_int(struct ftl_conn *api, const char *cookieName, int *i)
{
	// Maximum cookie length is 4KB
	char cookieValue[4096];
	const char *cookie = mg_get_header(api->conn, "Cookie");
	if(mg_get_cookie(cookie, cookieName, cookieValue, sizeof(cookieValue)) > 0)
	{
		*i = atoi(cookieValue);
		return true;
	}
	return false;
}

bool http_get_cookie_str(struct ftl_conn *api, const char *cookieName, char *str, size_t str_size)
{
	const char *cookie = mg_get_header(api->conn, "Cookie");
	if(mg_get_cookie(cookie, cookieName, str, str_size) > 0)
	{
		return true;
	}
	return false;
}

enum http_method __attribute__((pure)) http_method(struct mg_connection *conn)
{
	const struct mg_request_info *request = mg_get_request_info(conn);
	if(strcmp(request->request_method, "GET") == 0)
		return HTTP_GET;
	else if(strcmp(request->request_method, "DELETE") == 0)
		return HTTP_DELETE;
	else if(strcmp(request->request_method, "PUT") == 0)
		return HTTP_PUT;
	else if(strcmp(request->request_method, "POST") == 0)
		return HTTP_POST;
	else
		return HTTP_UNKNOWN;
}

void read_and_parse_payload(struct ftl_conn *api)
{
	// Try to extract payload from GET request
	if(api->method == HTTP_GET && api->request->query_string != NULL)
	{
		strncpy(api->payload.raw, api->request->query_string, MAX_PAYLOAD_BYTES-1);
		api->payload.avail = true;
	}
	else // POST, PUT
	{
		int data_len = mg_read(api->conn, api->payload.raw, MAX_PAYLOAD_BYTES - 1);
		logg("Received payload with size: %d", data_len);
		if ((data_len < 1) || (data_len >= MAX_PAYLOAD_BYTES))
			return;

		api->payload.raw[data_len] = '\0';
		api->payload.avail = true;

		// Try to parse possibly existing JSON payload
		api->payload.json = cJSON_Parse(api->payload.raw);
	}
}
