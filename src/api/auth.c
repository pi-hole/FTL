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

int api_auth(struct mg_connection *conn)
{
	bool auth = false;
	
	// Does the client try to authenticate through a set header?
	const char *xHeader = mg_get_header(conn, "X-Pi-hole-Authenticate");
	if(xHeader != NULL && strlen(xHeader) > 0)
	{
		auth = true;

		if(config.debug & DEBUG_API)
			logg("Received X-Pi-hole-Authenticate: %s", xHeader);
	}

	// Does the client provide a user_id cookie?
	int user_id = 0;
	if(http_get_cookie_int(conn, "user_id", &user_id))
	{
		auth = true;

		if(config.debug & DEBUG_API)
			logg("Read user_id=%i from user-provided cookie", user_id);
	}

	cJSON *json = JSON_NEW_OBJ();
	if(auth)
	{
		if(config.debug & DEBUG_API)
			logg("Authentification: OK");

		JSON_OBJ_REF_STR(json, "status", "success");
		// Ten minutes validity
		char *additional_headers = NULL;
		if(asprintf(&additional_headers, "Set-Cookie: user_id=%u; Path=/; Max-Age=%u\r\n", 1, API_SESSION_EXPIRE) > 0)
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
		char *additional_headers = strdup("Set-Cookie: user_id=deleted; Path=/; Max-Age=-1\r\n");
		JSON_SENT_OBJECT_AND_HEADERS_CODE(json, 401, additional_headers);
	}
}