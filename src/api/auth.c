/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/auth
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
#include "log.h"
#include "config.h"

static struct {
	bool used;
	time_t valid_until;
	char *remote_addr;
} auth_data[API_MAX_CLIENTS] = {{false, 0, NULL}};

int api_auth(struct mg_connection *conn)
{
	int user_id = -1;
	const struct mg_request_info *request = mg_get_request_info(conn);
	
	// Does the client try to authenticate through a set header?
	const char *xHeader = mg_get_header(conn, "X-Pi-hole-Authenticate");
	if(xHeader != NULL && strlen(xHeader) > 0)
	{
		// TODO: Check hash here
		// Accepted
		for(unsigned int i = 0; i < API_MAX_CLIENTS; i++)
		{
			if(!auth_data[i].used)
			{
				// Found an unused slot
				auth_data[i].used = true;
				auth_data[i].valid_until = time(NULL) + API_SESSION_EXPIRE;
				auth_data[i].remote_addr = strdup(request->remote_addr);

				user_id = i;
				break;
			}
		}

		if(config.debug & DEBUG_API)
		{
			logg("Received X-Pi-hole-Authenticate: %s", xHeader);
			if(user_id > -1)
			{
				char timestr[128];
				get_timestr(timestr, auth_data[user_id].valid_until);
				logg("Registered new user:\n  user_id %i\n  valid_until: %s\n  remote_addr %s",
				      user_id, timestr, auth_data[user_id].remote_addr);
			}
			else
			{
				logg("No free user slots available, not authenticating user");
			}
		}
	}

	// Does the client provide a user_id cookie?
	int num;
	if(http_get_cookie_int(conn, "user_id", &num) && num > -1 && num < API_MAX_CLIENTS)
	{
		if(config.debug & DEBUG_API)
			logg("Read user_id=%i from user-provided cookie", user_id);

		time_t now = time(NULL);
		if(auth_data[num].used &&
			auth_data[num].valid_until >= now &&
			strcmp(auth_data[num].remote_addr, request->remote_addr) == 0)
		{
			// Authenticationm succesful:
			// - We know this client
			// - The session is stil valid
			// - The IP matches the one we've seen earlier
			user_id = num;

			if(config.debug & DEBUG_API)
			{
				char timestr[128];
				get_timestr(timestr, auth_data[user_id].valid_until);
				logg("Recognized known user:\n  user_id %i\n  valid_until: %s\n  remote_addr %s",
					user_id, timestr, auth_data[user_id].remote_addr);
			}
		}
	}

	cJSON *json = JSON_NEW_OBJ();
	if(user_id > -1)
	{
		if(config.debug & DEBUG_API)
			logg("Authentification: OK");

		JSON_OBJ_REF_STR(json, "status", "success");
		// Ten minutes validity
		char *additional_headers = NULL;
		if(asprintf(&additional_headers, "Set-Cookie: user_id=%u; Path=/; Max-Age=%u\r\n", user_id, API_SESSION_EXPIRE) > 0)
		{
			JSON_SENT_OBJECT_AND_HEADERS(json, additional_headers);
		}
		else
		{
			JSON_SENT_OBJECT(json);
		}
	}
	else
	{
		if(config.debug & DEBUG_API)
			logg("Authentification: FAIL");

		JSON_OBJ_REF_STR(json, "key", "unauthorized");
		JSON_OBJ_REF_STR(json, "salt", "unauthorized");
		char *additional_headers = strdup("Set-Cookie: user_id=deleted; Path=/; Max-Age=-1\r\n");
		JSON_SENT_OBJECT_AND_HEADERS_CODE(json, 401, additional_headers);
	}
}