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
#include "http-common.h"
#include "../config.h"
#include "../log.h"
#include "json_macros.h"

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

int send_http(struct mg_connection *conn, const char *mime_type,
              const char *msg)
{
	mg_send_http_ok(conn, mime_type, NULL, strlen(msg));
	return mg_write(conn, msg, strlen(msg));
}

int send_http_code(struct mg_connection *conn, const char *mime_type,
                   int code, const char *msg)
{
	// Payload will be sent with text/plain encoding due to
	// the first line being "Error <code>" by definition
	//return mg_send_http_error(conn, code, "%s", msg);
	my_send_http_error_headers(conn, code,
	                           mime_type,
	                           strlen(msg));

	return mg_write(conn, msg, strlen(msg));
}

int send_json_unauthorized(struct mg_connection *conn)
{
	return send_json_error(conn, 401,
                               "unauthorized",
                               "Unauthorized",
                               NULL);
}

int send_json_error(struct mg_connection *conn, const int code,
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

int send_json_success(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "status", "success");
	JSON_SEND_OBJECT(json);
}

int send_http_internal_error(struct mg_connection *conn)
{
	return mg_send_http_error(conn, 500, "Internal server error");
}

bool get_bool_var(const char *source, const char *var)
{
	char buffer[16] = { 0 };
	if(GET_VAR(var, buffer, source))
	{
		return (strstr(buffer, "true") != NULL);
	}
	return false;
}

int get_int_var(const char *source, const char *var)
{
	int num = -1;
	char buffer[16] = { 0 };
	if(GET_VAR(var, buffer, source) &&
	   sscanf(buffer, "%d", &num) == 1)
	{
		return num;
	}

	return -1;
}

bool __attribute__((pure)) startsWith(const char *path, const char *uri)
{
	// We subtract 1 to include the trailing slash in webhome
	unsigned int webhome_length = strlen(httpsettings.webhome)-1u;
	unsigned int uri_length = strlen(uri);
	if(uri_length > webhome_length)
	{
		// Compare strings while skipping any possible webhome
		// Note: this is not an issue here as the API callback
		// doesn't even get called when the path does not start in
		// what is configured by httpsettings.webhome.
		// In other words: This strips the webhome such that any
		// request will look like "/api/dns/status" even when the
		// webhome is configured to something like "/admin"
		return strncmp(path, uri+webhome_length, strlen(path)) == 0;
	}
	else
	{
		return false;
	}
}

bool http_get_cookie_int(struct mg_connection *conn, const char *cookieName, int *i)
{
	// Maximum cookie length is 4KB
	char cookieValue[4096];
	const char *cookie = mg_get_header(conn, "Cookie");
	if(mg_get_cookie(cookie, cookieName, cookieValue, sizeof(cookieValue)) > 0)
	{
		*i = atoi(cookieValue);
		return true;
	}
	return false;
}

bool http_get_cookie_str(struct mg_connection *conn, const char *cookieName, char *str, size_t str_size)
{
	const char *cookie = mg_get_header(conn, "Cookie");
	if(mg_get_cookie(cookie, cookieName, str, str_size) > 0)
	{
		return true;
	}
	return false;
}

int http_method(struct mg_connection *conn)
{
	const struct mg_request_info *request = mg_get_request_info(conn);
	if(strcmp(request->request_method, "GET") == 0)
	{
		return HTTP_GET;
	}
	else if(strcmp(request->request_method, "DELETE") == 0)
	{
		return HTTP_DELETE;
	}
	else if(strcmp(request->request_method, "POST") == 0)
	{
		return HTTP_POST;
	}
	else
	{
		return HTTP_UNKNOWN;
	}
}
