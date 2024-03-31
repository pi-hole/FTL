/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Common HTTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "config/config.h"
#include "log.h"
#include "webserver/json_macros.h"
// UINT_MAX
#include <limits.h>
// HUGE_VAL
#include <math.h>

char pi_hole_extra_headers[PIHOLE_HEADERS_MAXLEN] = { 0 };

// Provides a compile-time flag for JSON formatting
// This should never be needed as all modern browsers
// typically contain a JSON explorer
// This string needs to be freed after using it
char *json_formatter(const cJSON *object)
{
	if(config.webserver.api.prettyJSON.v.b)
	{
		/* Exemplary output:
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
	mg_send_http_ok(api->conn, mime_type, strlen(msg));
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
                    const char *hint)
{
	return send_json_error_free(api, code, key, message, (char*)hint, false);
}

int send_json_error_free(struct ftl_conn *api, const int code,
                         const char *key, const char* message,
                         char *hint, bool free_hint)
{
	if(hint != NULL)
		log_warn("API: %s (%s)", message, hint);
	else
		log_warn("API: %s", message);

	cJSON *error = JSON_NEW_OBJECT();
	JSON_REF_STR_IN_OBJECT(error, "key", key);
	JSON_REF_STR_IN_OBJECT(error, "message", message);
	JSON_COPY_STR_TO_OBJECT(error, "hint", hint);
	if(free_hint && hint != NULL)
		free(hint);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "error", error);
	JSON_SEND_OBJECT_CODE(json, code);
}

int send_json_success(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();
	JSON_REF_STR_IN_OBJECT(json, "status", "success");
	JSON_SEND_OBJECT(json);
}

int send_http_internal_error(struct ftl_conn *api)
{
	return mg_send_http_error(api->conn, 500, "Internal server error");
}

bool get_bool_var(const char *source, const char *var, bool *boolean)
{
	if(!source)
		return false;

	char buffer[16] = { 0 };
	const int ret = GET_VAR(var, buffer, source);
	if(ret == -1)
		return false; // Variable not found

	// else:
	if(strcasecmp(buffer, "true") == 0)
	{
		*boolean = true;
		return true;
	}
	else if(strcasecmp(buffer, "false") == 0)
	{
		*boolean = false;
		return true;
	}
	// else: error
	log_warn("Cannot parse parameter %s in query string \"%s\": \"%s\" is neither \"true\" nor \"false\"", var, source, buffer);
	return false;
}

static bool get_int64_var_msg(const char *source, const char *var, int64_t *num, const char **msg)
{
	if(!source)
		return false;

	char buffer[128] = { 0 };
	const int ret = GET_VAR(var, buffer, source);
	if(ret < 1)
	{
		if(ret == -1)
			*msg = NULL; // Variable not found
		else if(ret == -2)
			*msg = "Internal error: destination buffer too small to hold the decoded value";
		else // ret == 0
			*msg = "Parameter empty";
		return false;
	}

	// Try to get the value
	char *endptr = NULL;
	errno = 0;
#if __BITS_PER_LONG == 64
	const int64_t val = strtol(buffer, &endptr, 10);
#else
	const int64_t val = strtoll(buffer, &endptr, 10);
#endif
	// Error checking
	if ((errno == ERANGE && (val == INT64_MAX || val == INT64_MIN)) ||
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

bool get_uint64_var_msg(const char *source, const char *var, uint64_t *num, const char **msg)
{
	if(!source)
		return false;

	char buffer[128] = { 0 };
	const int ret = GET_VAR(var, buffer, source);
	if(ret < 1)
	{
		if(ret == -1)
			*msg = NULL; // Variable not found
		else if(ret == -2)
			*msg = "Internal error: destination buffer too small to hold the decoded value";
		else // ret == 0
			*msg = "Parameter empty";
		return false;
	}

	// Try to get the value
	char *endptr = NULL;
	errno = 0;
#if __BITS_PER_LONG == 64
	const uint64_t val = strtoul(buffer, &endptr, 10);
#else
	const uint64_t val = strtoull(buffer, &endptr, 10);
#endif

	// Error checking
	if ((errno == ERANGE && val == UINT64_MAX) ||
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
	if(!source)
		return false;

	int64_t val = 0;
	if(!get_int64_var_msg(source, var, &val, msg))
		return false;

	if(val > (int64_t)INT_MAX)
	{
		*msg = "Specified integer too large, maximum allowed number is "  xstr(INT_MAX);
		return false;
	}

	if(val < (int64_t)INT_MIN)
	{
		*msg = "Specified integer too negative, minimum allowed number is "  xstr(INT_MIN);
		return false;
	}

	*num = (int)val;
	return true;
}

bool get_int_var(const char *source, const char *var, int *num)
{
	if(!source)
		return false;

	const char *msg = NULL;
	const bool result = get_int_var_msg(source, var, num, &msg);
	// We don't log an error here if msg == NULL, because it's perfectly valid
	// for a parameter to be missing
	if(!result && msg != NULL)
		log_warn("Cannot parse integer parameter %s in query string \"%s\": %s", var, source, msg);
	return result;
}

bool get_uint_var_msg(const char *source, const char *var, unsigned int *num, const char **msg)
{
	int64_t val = 0;
	if(!get_int64_var_msg(source, var, &val, msg))
		return false;

	if(val > (int64_t)UINT_MAX)
	{
		*msg = "Specified integer too large, maximum allowed number is "  xstr(UINT_MAX);
		return false;
	}

	if(val < 0)
	{
		*msg = "Specified integer negative, this is not allowed";
		return false;
	}

	*num = (unsigned int)val;
	return true;
}

bool get_uint_var(const char *source, const char *var, unsigned int *num)
{
	const char *msg = NULL;
	if(!source)
		return false;
	const bool result = get_uint_var_msg(source, var, num, &msg);
	// We don't log an error here if msg == NULL, because it's perfectly valid
	// for a parameter to be missing
	if(!result && msg != NULL)
		log_warn("Cannot parse unsigned integer parameter %s in query string \"%s\": %s", var, source, msg);
	return result;
}

bool get_double_var_msg(const char *source, const char *var, double *num, const char **msg)
{
	if(!source)
		return false;

	char buffer[128] = { 0 };
	const int ret = GET_VAR(var, buffer, source);
	if(ret < 1)
	{
		if(ret == -1)
			*msg = NULL; // Variable not found
		else if(ret == -2)
			*msg = "Internal error: destination buffer too small to hold the decoded value";
		else // ret == 0
			*msg = "Parameter empty";
		return false;
	}

	// Try to get the value
	char *endptr = NULL;
	errno = 0;
	const double val = strtod(buffer, &endptr);

	// Error checking
	if (errno != 0)
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

bool get_double_var(const char *source, const char *var, double *num)
{
	const char *msg = NULL;
	if(!source)
		return false;
	const bool result = get_double_var_msg(source, var, num, &msg);
	// We don't log an error here if msg == NULL, because it's perfectly valid
	// for a parameter to be missing
	if(!result && msg != NULL)
		log_warn("Cannot parse double parameter %s in query string \"%s\": %s", var, source, msg);
	return result;
}

int get_string_var(const char *source, const char *var, char *dest, size_t dest_len)
{
	if(!source)
		return -1;

	// Allocate a temporary buffer to store the possibly URI-encoded value
	// of the variable. We use the real destination later to store the
	// decoded value. The decoded value will always be shorter than the
	// encoded value, so using the same length is fine.
	char *tempbuf = calloc(dest_len, sizeof(char));
	if(!tempbuf)
	{
		log_err("get_string_var: Out of memory");
		return -1;
	}

	// Extract value of the particular variable
	int len = mg_get_var(source, strlen(source), var, tempbuf, dest_len);

	// Decode the URI component if needed
	if(len > 0)
		len = mg_url_decode(tempbuf, len, dest, dest_len, 0);

	// Free the temporary buffer, if anything was decoded it's now stored in
	// dest
	free(tempbuf);

	// Return the length of the decoded string
	return len;
}

const char* __attribute__((pure)) startsWith(const char *path, struct ftl_conn *api)
{
	// We use local_uri_raw here to get the unescaped URI, see
	// https://github.com/civetweb/civetweb/pull/975
	if(strncmp(path, api->request->local_uri_raw, strlen(path)) == 0)
		if(api->request->local_uri_raw[strlen(path)] == '/')
		{
			// Path match with argument after ".../"
			if(api->action_path != NULL)
				free(api->action_path);
			api->action_path = strdup(api->request->local_uri_raw);
			api->action_path[strlen(path)] = '\0';
			return api->request->local_uri_raw + strlen(path) + 1u;
		}
		else if(strlen(path) == strlen(api->request->local_uri_raw))
		{
			// Path match directly, no argument
			if(api->action_path != NULL)
				free(api->action_path);
			api->action_path = strdup(api->request->local_uri_raw);
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
	else if(strcmp(request->request_method, "PATCH") == 0)
		return HTTP_PATCH;
	else if(strcmp(request->request_method, "OPTIONS") == 0)
		return HTTP_OPTIONS;
	else
		return HTTP_UNKNOWN;
}

const char * __attribute__((const)) get_http_method_str(const enum http_method method)
{
	switch(method)
	{
		case HTTP_GET:
			return "GET";
		case HTTP_DELETE:
			return "DELETE";
		case HTTP_PUT:
			return "PUT";
		case HTTP_POST:
			return "POST";
		case HTTP_PATCH:
			return "PATCH";
		case HTTP_OPTIONS:
			return "OPTIONS";
		case HTTP_UNKNOWN: // fall through
		default:
			return "UNKNOWN";
	}
}

void read_and_parse_payload(struct ftl_conn *api)
{
	// Read payload
	api->payload.size = mg_read(api->conn, api->payload.raw, MAX_PAYLOAD_BYTES - 1);
	if (api->payload.size < 1)
	{
		log_debug(DEBUG_API, "Received no payload");
		return;
	}
	else if (api->payload.size >= MAX_PAYLOAD_BYTES-1)
	{
		// If we reached the upper limit of payload size, we have likely
		// truncated the payload. The only reasonable thing to do here is to
		// discard the payload altogether
		log_warn("API: Received too large payload - DISCARDING");
		return;
	}

	// Debug output of received payload (if enabled)
	log_debug(DEBUG_API, "Received payload with size: %lu", api->payload.size);

	// Terminate string
	api->payload.raw[api->payload.size] = '\0';

	// Set flag to indicate that we have a payload
	api->payload.avail = true;

	// Try to parse possibly existing JSON payload
	api->payload.json = cJSON_ParseWithOpts(api->payload.raw, &api->payload.json_error, 0);
}

// Escape a string to mask HTML special characters, the resulting string is
// always allocated and must be freed (unless NULL is returned)
// See https://www.w3.org/International/questions/qa-escapes#use
char *__attribute__((malloc)) escape_html(const char *string)
{
	// If the string is NULL, return NULL
	if(string == NULL)
		return NULL;

	// Allocate memory for escaped string
	char *escaped = calloc(strlen(string) * 6 + 1, sizeof(char));
	if(!escaped)
		return NULL;

	// Iterate over string and escape special characters
	char *ptr = escaped;
	for(const char *c = string; *c != '\0'; c++)
	{
		switch(*c)
		{
			case '&':
				strcpy(ptr, "&amp;");
				ptr += 5;
				break;
			case '<':
				strcpy(ptr, "&lt;");
				ptr += 4;
				break;
			case '>':
				strcpy(ptr, "&gt;");
				ptr += 4;
				break;
			case '"':
				strcpy(ptr, "&quot;");
				ptr += 6;
				break;
			case '\'':
				strcpy(ptr, "&apos;");
				ptr += 6;
				break;
			default:
				*ptr = *c;
				ptr++;
				break;
		}
	}
	*ptr = '\0';

	return escaped;
}

// Check if the payload is valid JSON, if not send an error response with the
// appropriate status code. If the payload is NULL, send a 400 Bad Request
// response with a hint that no payload was received. If the payload is not
// valid JSON, send a 400 Bad Request response with a hint that the payload is
// invalid JSON.
int check_json_payload(struct ftl_conn *api)
{
	if (api->payload.json == NULL)
	{
		if (api->payload.json_error == NULL)
			return send_json_error(api, 400,
			                       "bad_request",
			                       "No request body data",
			                       NULL);
		else
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid request body data (no valid JSON), error at hint",
			                       api->payload.json_error);
	}

	// All okay
	return 0;
}

// Black magic at work here: We build a JSON array from the group_concat result
// delivered from the database, parse it as valid array and append it as row to
// the data
int parse_groupIDs(struct ftl_conn *api, tablerow *table, cJSON *row)
{
	const size_t buflen = strlen(table->group_ids) + 3u;
	char *group_ids_str = calloc(buflen, sizeof(char));
	if(group_ids_str == NULL)
	{
		return send_json_error(api, 500, // 500 Internal Server Error
		                       "out_of_memory",
		                       "Out of memory",
		                       NULL);
	}
	group_ids_str[0] = '[';
	strcpy(group_ids_str+1u , table->group_ids);
	group_ids_str[buflen-2u] = ']';
	group_ids_str[buflen-1u] = '\0';
	const char *json_error = NULL;
	cJSON *group_ids = cJSON_ParseWithOpts(group_ids_str, &json_error, false);
	free(group_ids_str);
	if(group_ids == NULL)
	{
		// Error parsing group_ids, substitute empty array
		// Note: This should never happen as the database's aggregate
		//       function should always return a valid JSON array
		log_err("Error parsing group_ids, error at: %.20s", json_error);
		JSON_ADD_ITEM_TO_OBJECT(row, "groups", JSON_NEW_ARRAY());
	}
	else
	{
		JSON_ADD_ITEM_TO_OBJECT(row, "groups", group_ids);
	}

	// Success
	return 0;
}

// Escape a string to mask JSON special characters, the resulting string is
// always allocated and must be freed (unless NULL is returned)
// See https://tools.ietf.org/html/rfc8259#section-7
char *__attribute__((malloc)) escape_json(const char *string)
{
	// If the string is NULL, return NULL
	if(string == NULL)
		return NULL;

	// Create a cJSON object (reference, no copy) from the string string
	cJSON *json = cJSON_CreateStringReference(string);
	if(json == NULL)
		return NULL;

	// Get the string representation of the cJSON object. This allocates
	// memory for the string which needs to be free'd later on
	char *namep = cJSON_PrintUnformatted(json);

	// Free cJSON object
	cJSON_Delete(json);

	// Return the JSON escaped string
	return namep;
}
