/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Lua-related webserver routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/lua_web.h"
#include "api/api.h"

// luaL_dostring()
#include "lua/lauxlib.h"
// struct config
#include "config/config.h"
// log_web()
#include "log.h"

// directory_exists()
#include "files.h"

static char *login_uri = NULL, *admin_api_uri = NULL;
void allocate_lua(void)
{
	// Build login URI string (webhome + login)
	// Append "login" to webhome string
	const size_t login_uri_len = strlen(config.webserver.paths.webhome.v.s);
	login_uri = calloc(login_uri_len + 6, sizeof(char));
	memcpy(login_uri, config.webserver.paths.webhome.v.s, login_uri_len);
	strcpy(login_uri + login_uri_len, "login");
	login_uri[login_uri_len + 5u] = '\0';
	log_debug(DEBUG_API, "Login URI: %s", login_uri);

	// Build "wrong" API URI string (webhome + api)
	// Append "api" to webhome string
	const size_t admin_api_uri_len = strlen(config.webserver.paths.webhome.v.s);
	admin_api_uri = calloc(admin_api_uri_len + 4, sizeof(char));
	memcpy(admin_api_uri, config.webserver.paths.webhome.v.s, admin_api_uri_len);
	strcpy(admin_api_uri + admin_api_uri_len, "api");
	admin_api_uri[admin_api_uri_len + 3u] = '\0';
	log_debug(DEBUG_API, "Admin API URI: %s", admin_api_uri);
}

void free_lua(void)
{
	// Free login_uri
	if(login_uri != NULL)
		free(login_uri);

	// Free admin_api_uri
	if(admin_api_uri != NULL)
		free(admin_api_uri);
}

void init_lua(const struct mg_connection *conn, void *L, unsigned context_flags)
{
	// Set onerror handler to print errors to the log
	if(luaL_dostring(L, "mg.onerror = function(e) mg.cry('Error at ' .. e) end") != LUA_OK)
	{
		log_err("Error setting Lua onerror handler: %s", lua_tostring(L, -1));
		lua_pop(L, 1);
	}
}

int request_handler(struct mg_connection *conn, void *cbdata)
{
	// Fall back to CivetWeb's default handler if login URI is not available
	// (should never happen)
	if(login_uri == NULL || admin_api_uri == NULL)
		return 0;

	/* Handler may access the request info using mg_get_request_info */
	const struct mg_request_info *req_info = mg_get_request_info(conn);
	const size_t uri_raw_len = strlen(req_info->local_uri_raw);

	// Build minimal api struct to check authentication
	struct ftl_conn api = { 0 };
	api.conn = conn;
	api.request = req_info;
	api.now = double_time();

	// Check if the request is for the API under /admin/api
	// (it is posted at /api)
	if(strncmp(req_info->local_uri_raw, admin_api_uri, strlen(admin_api_uri)) == 0)
	{
		const size_t hint_len = 38 + strlen(admin_api_uri) + 2*strlen(config.webserver.domain.v.s);
		char *hint = calloc(hint_len, sizeof(char));
		snprintf(hint, hint_len, "The API is hosted at %s/api, not %s%s",
		         config.webserver.domain.v.s, config.webserver.domain.v.s, admin_api_uri);
		hint[hint_len - 1u] = '\0';
		// not found or invalid request
		return send_json_error_free(&api, 400,
		                            "bad_request",
		                            "Bad request",
		                            hint,
		                            true);
	}

	// Check if last part of the URI contains a dot (is a file)
	const char *last_dot = strrchr(req_info->local_uri_raw, '.');
	const char *last_slash = strrchr(req_info->local_uri_raw, '/');
	const bool no_dot = (last_dot == NULL || last_slash > last_dot);

	// Check if the request is for the login page
	const bool login = (strcmp(req_info->local_uri_raw, login_uri) == 0);

	// Check if the request is for a LUA page (every XYZ.lp has already been
	// rewritten at this point to XYZ)
	if(!no_dot)
	{
		// Not a LUA page - fall back to CivetWeb's default handler
		return 0;
	}

	// Every LUA page except admin/login requires authentication
	const int authorized = check_client_auth(&api, false) != API_AUTH_UNAUTHORIZED;
	if(!login)
	{
		// This is not the login page - check if the user is authenticated
		// Check if the user is authenticated
		if(!authorized)
		{
			// Append query string to target
			char *target = NULL;
			if(req_info->query_string != NULL)
			{
				target = calloc(uri_raw_len + strlen(req_info->query_string) + 2u, sizeof(char));
				strcpy(target, req_info->local_uri_raw);
				strcat(target, "?");
				strcat(target, req_info->query_string);
			}
			else
			{
				target = strdup(req_info->local_uri_raw);
			}
			if(target == NULL)
			{
				log_err("Error allocating memory for redirection target");
				return send_json_error(&api, 500,
				                       "internal_error",
				                       "Internal server error",
				                       "Cannot allocate memory for redirection target");
			}

			// Encode target string
			const size_t encoded_target_len = strlen(target) * 3u + 1u;
			char *encoded_target = calloc(encoded_target_len, sizeof(char));
			if(encoded_target == NULL)
			{
				log_err("Error allocating memory for encoded redirection target");
				return send_json_error(&api, 500,
				                       "internal_error",
				                       "Internal server error",
				                       "Cannot allocate memory for encoded redirection target");
			}

			// Encode target string
			mg_url_encode(target, encoded_target, encoded_target_len);
			free(target);

			// User is not authenticated, redirect to login page
			log_web("Authentication required, redirecting to %slogin?target=%s", config.webserver.paths.webhome.v.s, encoded_target);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %slogin?target=%s\r\n\r\n", config.webserver.paths.webhome.v.s, encoded_target);
			free(encoded_target);
			return 302;
		}
	}
	else
	{
		// This is the login page - check if the user is already authenticated
		// Check if the user is authenticated
		if(authorized)
		{
			// User is already authenticated, redirect to index page
			log_web("User is already authenticated, redirecting to %s", config.webserver.paths.webhome.v.s);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", config.webserver.paths.webhome.v.s);
			return 302;
		}
	}

	// No special handling required, fall back to default CivetWeb handler
	return 0;
}
