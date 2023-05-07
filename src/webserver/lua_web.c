/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Lua-related webserver routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "lua_web.h"
#include "../api/api.h"

// luaL_dostring()
#include "../lua/lauxlib.h"
// struct config
#include "../config/config.h"
// log_web()
#include "../log.h"

static char *login_uri = NULL, *admin_api_uri = NULL;
void allocate_lua(void)
{
	// Build login URI string (webhome + login.lp)
	// Append "login.lp" to webhome string
	const size_t login_uri_len = strlen(config.webserver.paths.webhome.v.s);
	login_uri = calloc(login_uri_len + 10, sizeof(char));
	memcpy(login_uri, config.webserver.paths.webhome.v.s, login_uri_len);
	strcpy(login_uri + login_uri_len, "login.lp");
	login_uri[login_uri_len + 10u] = '\0';

	// Build "wrong" API URI string (webhome + api)
	// Append "api" to webhome string
	const size_t admin_api_uri_len = strlen(config.webserver.paths.webhome.v.s);
	admin_api_uri = calloc(admin_api_uri_len + 4, sizeof(char));
	memcpy(admin_api_uri, config.webserver.paths.webhome.v.s, admin_api_uri_len);
	strcpy(admin_api_uri + admin_api_uri_len, "api");
	admin_api_uri[admin_api_uri_len + 4u] = '\0';
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

	// Build minimal api struct to check authentication
	struct ftl_conn api = { 0 };
	api.conn = conn;
	api.request = req_info;

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

	// Every page except admin/login.lp requires authentication
	if(strcmp(req_info->local_uri_raw, login_uri) != 0)
	{
		// This is not the login page - check if the user is authenticated
		// Check if the user is authenticated
		if(check_client_auth(&api) == API_AUTH_UNAUTHORIZED)
		{
			// Append query string to target
			char *target = NULL;
			if(req_info->query_string != NULL)
			{
				target = calloc(strlen(req_info->local_uri_raw) + strlen(req_info->query_string) + 2u, sizeof(char));
				strcpy(target, req_info->local_uri_raw);
				strcat(target, "?");
				strcat(target, req_info->query_string);
			}
			else
			{
				target = strdup(req_info->local_uri_raw);
			}
			// Encode target string
			const size_t encoded_target_len = strlen(target) * 3u + 1u;
			char *encoded_target = calloc(encoded_target_len, sizeof(char));
			mg_url_encode(target, encoded_target, encoded_target_len);

			// User is not authenticated, redirect to login page
			log_web("Authentication required, redirecting to %slogin.lp?target=%s", config.webserver.paths.webhome.v.s, encoded_target);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %slogin.lp?target=%s\r\n\r\n", config.webserver.paths.webhome.v.s, encoded_target);
			free(target);
			return 302;
		}
	}
	else
	{
		// This is the login page - check if the user is already authenticated
		// Check if the user is authenticated
		if(check_client_auth(&api) != API_AUTH_UNAUTHORIZED)
		{
			// User is already authenticated, redirect to index page
			log_web("User is already authenticated, redirecting to %sindex.lp", config.webserver.paths.webhome.v.s);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %sindex.lp\r\n\r\n", config.webserver.paths.webhome.v.s);
			return 302;
		}
	}

	// No special handling required, fall back to default CivetWeb handler
	return 0;
}
