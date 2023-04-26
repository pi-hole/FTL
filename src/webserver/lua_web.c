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

static char *login_uri = NULL;
void allocate_lua(void)
{
	// Build login URI string (webhome + login.lp)
	// Append "login.lp" to webhome string
	const size_t login_uri_len = strlen(config.webserver.paths.webhome.v.s);
	login_uri = calloc(login_uri_len + 10, sizeof(char));
	memcpy(login_uri, config.webserver.paths.webhome.v.s, login_uri_len);
	strcpy(login_uri + login_uri_len, "login.lp");
	login_uri[login_uri_len + 10u] = '\0';

	// Remove initial slash from login_uri
	if(login_uri[0] == '/')
		memmove(login_uri, login_uri + 1, login_uri_len + 9);
}

void free_lua(void)
{
	// Free login_uri
	if(login_uri != NULL)
		free(login_uri);
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
	if(login_uri == NULL)
		return 0;

	/* Handler may access the request info using mg_get_request_info */
	const struct mg_request_info *req_info = mg_get_request_info(conn);
	const char *local_uri = req_info->local_uri_raw + 1u;

	// Build minimal api struct to check authentication
	struct ftl_conn api = { 0 };
	api.conn = conn;
	api.request = req_info;

	// Every page except admin/login.lp requires authentication
	if(strcmp(local_uri, login_uri) != 0)
	{
		// This is not the login page - check if the user is authenticated
		// Check if the user is authenticated
		if(check_client_auth(&api) == API_AUTH_UNAUTHORIZED)
		{
			// User is not authenticated, redirect to login page
			log_web("Authentication required, redirecting to %slogin.lp?target=/%s", config.webserver.paths.webhome.v.s, local_uri);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %slogin.lp?target=/%s\r\n\r\n", config.webserver.paths.webhome.v.s, local_uri);
			return 302;
		}
	}
	else
	{
		// This is the login page - check if the user is already authenticated
		// Check if the user is authenticated
		if(check_client_auth(&api) != API_AUTH_UNAUTHORIZED)
		{
			// User is already authenticated
			char target[256] = { 0 };
			if(GET_VAR("target", target, req_info->query_string) > 0)
			{
				// Redirect to target page
			}
			else
			{
				// Redirect to index page
				strncpy(target, config.webserver.paths.webhome.v.s, sizeof(target) - 10);
				strcat(target, "index.lp");
			}
			// User is already authenticated, redirect to index page
			log_web("User is already authenticated, redirect to %s", target);
			mg_printf(conn, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", target);
			return 302;
		}
	}

	// No special handling required, fall back to default CivetWeb handler
	return 0;
}
