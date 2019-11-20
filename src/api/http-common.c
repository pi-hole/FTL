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
#include "routes.h"
#include "http-common.h"
#include "../config.h"
#include "../log.h"
#include "../cJSON/cJSON.h"
#include "json_macros.h"

// Server context handle
static struct mg_context *ctx = NULL;

int send_http(struct mg_connection *conn, const char *mime_type,
              const char *additional_headers, const char *msg)
{
	mg_send_http_ok(conn, mime_type, additional_headers, strlen(msg));
	return mg_write(conn, msg, strlen(msg));
}

int send_http_code(struct mg_connection *conn, const char *mime_type,
                   const char *additional_headers, int code, const char *msg)
{
	// Payload will be sent with text/plain encoding due to
	// the first line being "Error <code>" by definition
	//return mg_send_http_error(conn, code, "%s", msg);
	my_send_http_error_headers(conn, code, mime_type,
	                           additional_headers, strlen(msg));
	return mg_write(conn, msg, strlen(msg));
}

int send_json_unauthorized(struct mg_connection *conn,
                           char *additional_headers)
{
	return send_json_error(conn, 401,
                               "unauthorized",
                               "Unauthorized",
                               NULL, additional_headers);
}

int send_json_error(struct mg_connection *conn, const int code,
                    const char *key, const char* message,
                    cJSON *data, char *additional_headers)
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

	// Send additional headers if supplied
	if(additional_headers == NULL)
	{
		JSON_SENT_OBJECT_CODE(json, code);
	}
	else
	{
		JSON_SENT_OBJECT_AND_HEADERS_CODE(json, code, additional_headers);
	}
}

int send_json_success(struct mg_connection *conn,
                      char * additional_headers)
{
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "status", "success");
	JSON_SENT_OBJECT_AND_HEADERS(json, additional_headers);
}

int send_http_error(struct mg_connection *conn)
{
	return mg_send_http_error(conn, 500, "Internal server error");
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

void __attribute__ ((format (gnu_printf, 3, 4))) http_send(struct mg_connection *conn, bool chunk, const char *format, ...)
{
	char *buffer;
	va_list args;
	va_start(args, format);
	int len = vasprintf(&buffer, format, args);
	va_end(args);
	if(len > 0)
	{
		if(!chunk)
		{
			// Send 200 HTTP header with content size
			mg_send_http_ok(conn, "application/json", NULL, len);
		}
		if(chunk && mg_send_chunk(conn, buffer, len) < 0)
		{
			logg("WARNING: Chunked HTTP writing returned error %s "
			     "(%i, length %i)", strerror(errno), errno, len);
		}
		else if(!chunk && mg_write(conn, buffer, len) < 0)
		{
			logg("WARNING: Regular HTTP writing returned error %s "
			     "(%i, length %i)", strerror(errno), errno, len);
		}
		free(buffer);
	}
}

// Print passed string directly
static int print_simple(struct mg_connection *conn, void *input)
{
	return send_http(conn, "text/plain", NULL, input);
}

static char *indexfile_content = NULL;
static void read_indexfile(void)
{
	char *index_path = NULL;
	if(asprintf(&index_path, "%s%sindex.html", httpsettings.webroot, httpsettings.webhome) < 0)
	{
		logg("read_indexfile(): Memory error (1)");
		return;
	}
	char *base_tag = NULL;
	if(asprintf(&base_tag, "<base href='%s'>", httpsettings.webhome) < 0)
	{
		logg("read_indexfile(): Memory error (2)");
	}
	unsigned int base_tag_length = strlen(base_tag);

	FILE *indexfile = fopen(index_path, "r");
	if(indexfile == NULL)
	{
		logg("ERROR: Cannot open \"%s\"", index_path);
		free(index_path);
		return;
	}

	// Get file size by seeking the EOF
	fseek(indexfile, 0, SEEK_END);
	size_t fsize = ftell(indexfile);

	// Go back to the beginning
	fseek(indexfile, 0, SEEK_SET);

	// Allocate memory for the index file
	indexfile_content = calloc(fsize + base_tag_length + 1, sizeof(char));
	if(indexfile_content == NULL)
	{
		logg("read_indexfile(): Memory error (3)");
		free(index_path);
		free(base_tag);
	}

	// Read entire file into buffer
	if(fread(indexfile_content, sizeof(char), fsize, indexfile) != fsize)
	{
		logg("WARNING: Filesize of \"%s\" changed during reading.", index_path);
	}

	// Close file handle
	fclose(indexfile);

	// Zero-terminate string
	indexfile_content[fsize] = '\0';

	// Find "<head>"
	char *head_ptr = strstr(indexfile_content, "<head>");
	if(head_ptr == NULL)
	{
		logg("ERROR: No <head> tag found in \"%s\"", index_path);
		free(index_path);
		free(base_tag);
		return;
	}

	// Advance beyond the <head> tag
	head_ptr += 6u; // 6u == strlen("<head>");

	// Make space for <base> tag to be inserted
	memmove(head_ptr + base_tag_length, head_ptr, base_tag_length);

	// Insert <base> tag into new space
	memcpy(head_ptr, base_tag, base_tag_length);

	// Free memory
	free(index_path);
	free(base_tag);
}

static int index_handler(struct mg_connection *conn, void *ignored)
{
	const struct mg_request_info *request = mg_get_request_info(conn);

	if(strstr(request->local_uri, ".") > strstr(request->local_uri, "/"))
	{
		// Found file extension, process as usual
		return 0;
	}
	if(config.debug & DEBUG_API)
		logg("Received request for %s -> rerouting to index.html", request->local_uri);

	// Plain request found, we serve the index.html file we have in memory
	if(indexfile_content != NULL)
	{
		mg_send_http_ok(conn, "text/html", NULL, strlen(indexfile_content));
		mg_write(conn, indexfile_content, strlen(indexfile_content));
		return 200;
	}
	else
	{
		logg("ERROR: index.html not available, responding with Error 500.");
		send_http_error(conn);
		return 500;
	}
	
}

static int log_http_message(const struct mg_connection *conn, const char *message)
{
	logg("HTTP info: %s", message);
	return 1;
}

static int log_http_access(const struct mg_connection *conn, const char *message)
{
	// Only log when in API debugging mode
	if(config.debug & DEBUG_API)
		logg("HTTP access: %s", message);

	return 1;
}

void http_init(void)
{
	logg("Initializing HTTP server on port %s", httpsettings.port);

	/* Initialize the library */
	unsigned int features = MG_FEATURES_FILES |
				MG_FEATURES_IPV6 |
				MG_FEATURES_CACHE |
				MG_FEATURES_STATS;
	if(mg_init_library(features) == 0)
	{
		logg("Initializing HTTP library failed!");
		return;
	}

	// Prepare options for HTTP server (NULL-terminated list)
	const char *options[] = {
		"document_root", httpsettings.webroot,
		"listening_ports", httpsettings.port,
		"decode_url", "no",
		"num_threads", "4",
		"access_control_list", httpsettings.acl,
		NULL
	};

	// Configure logging handler
	struct mg_callbacks callbacks = {NULL};
	callbacks.log_message = log_http_message;

	// We log all access to pihole-FTL.log when in API debugging mode
	callbacks.log_access = log_http_access;

	/* Start the server */
	if((ctx = mg_start(&callbacks, NULL, options)) == NULL)
	{
		logg("ERROR: Initializing HTTP library failed!");
		return;
	}

	/* Add simple demonstration callbacks */
	mg_set_request_handler(ctx, "/ping", print_simple, (char*)"pong\n");
	char *api_path = NULL;
	if(asprintf(&api_path, "%sapi", httpsettings.webhome) > 4)
	{
		if(config.debug & DEBUG_API)
		{
			logg("Installing API handler at %s", api_path);
		}
		mg_set_request_handler(ctx, api_path, api_handler, NULL);
		// The request handler URI got duplicated
		free(api_path);
	}

	read_indexfile();
	mg_set_request_handler(ctx, httpsettings.webhome, index_handler, NULL);
}

void http_terminate(void)
{
	/* Stop the server */
	mg_stop(ctx);

	// Release memory for the index.html file
	free(indexfile_content);

	/* Un-initialize the library */
	mg_exit_library();
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