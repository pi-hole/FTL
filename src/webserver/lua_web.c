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
// ftl_http_redirect()
#include "webserver.h"

static char *login_uri = NULL, *admin_api_uri = NULL, *prefix_webhome = NULL;
void allocate_lua(char *login_uri_in, char *admin_api_uri_in, char *prefix_webhome_in)
{
	login_uri = login_uri_in;
	admin_api_uri = admin_api_uri_in;
	prefix_webhome = prefix_webhome_in;
}

void init_lua(const struct mg_connection *conn, void *L, unsigned context_flags)
{
	return;
}

int request_handler(struct mg_connection *conn, void *cbdata)
{
	// Fall back to CivetWeb's default handler if login URI is not available
	// (should never happen)
	if(login_uri == NULL || admin_api_uri == NULL || prefix_webhome == NULL)
		return 0;

	/* Handler may access the request info using mg_get_request_info */
	const struct mg_request_info *req_info = mg_get_request_info(conn);

	// Do not redirect for ACME challenges
	log_debug(DEBUG_API, "Local URI: \"%s\"", req_info->local_uri_raw);
	const char acme_challenge[] = "/.well-known/acme-challenge/";
	const bool is_acme = strncmp(req_info->local_uri_raw, acme_challenge, strlen(acme_challenge)) == 0;
	if(is_acme)
	{
		// ACME challenge - no authentication required
		return 0;
	}

	// Check if we are allowed to serve this directory by checking the
	// configuration setting webserver.serve_all and the requested URI to
	// start with something else than config.webserver.paths.webhome. If so,
	// send error 404
	if(!config.webserver.serve_all.v.b &&
	   strncmp(req_info->local_uri_raw, config.webserver.paths.webhome.v.s, strlen(config.webserver.paths.webhome.v.s)) != 0)
	{
		log_debug(DEBUG_WEBSERVER, "Not serving %s, returning 404", req_info->local_uri_raw);
		mg_send_http_error(conn, 404, "Not Found");
		return 404;
	}

	// Build minimal api struct to check authentication
	struct ftl_conn api = { 0 };
	api.conn = conn;
	api.request = req_info;
	api.now = double_time();

	// Check if the request is for the API under <webhome>api
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
		                            hint, true, true);
	}

	// Check if last part of the URI contains a dot (is a file)
	const char *last_dot = strrchr(req_info->local_uri_raw, '.');
	const char *last_slash = strrchr(req_info->local_uri_raw, '/');
	const bool no_dot = (last_dot == NULL || last_slash > last_dot);

	// Check if the request is for the login page
	const bool login = (strcmp(req_info->local_uri_raw, login_uri) == 0);

	// Check if the request is for something in the webhome directory
	const bool in_webhome = (strncmp(req_info->local_uri_raw, prefix_webhome, strlen(prefix_webhome)) == 0);
	log_debug(DEBUG_API, "Request for %s, login: %d, in_webhome: %d, no_dot: %d",
	          req_info->local_uri_raw, login, in_webhome, no_dot);

	// Check if the request is for a LUA page (every XYZ.lp has already been
	// rewritten at this point to XYZ), we also don't enforce authentication
	// for pages outside the webhome directory
	if(!no_dot || !in_webhome)
	{
		// Fall back to CivetWeb's default handler
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
			// User is not authenticated, redirect to login page
			log_web("Authentication required, redirecting to %s%slogin",
			        config.webserver.paths.prefix.v.s, config.webserver.paths.webhome.v.s);
			ftl_http_redirect(conn, 302, "%s%slogin",
			                  config.webserver.paths.prefix.v.s,
			                  config.webserver.paths.webhome.v.s);
			return 302;
		}
	}
	else
	{
		// This is the login page - check if the user is already authenticated
		// Check if the user is authenticated
		if(authorized)
		{
			// User is already authenticated, redirecting to index page
			log_web("User is already authenticated, redirecting to %s%s",
			        config.webserver.paths.prefix.v.s, config.webserver.paths.webhome.v.s);
			ftl_http_redirect(conn, 302, "%s%s",
			                  config.webserver.paths.prefix.v.s,
			                  config.webserver.paths.webhome.v.s);
			return 302;
		}
	}

	// No special handling required, fall back to default CivetWeb handler
	return 0;
}
