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
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
#include "log.h"
#include "config.h"
// read_setupVarsconf()
#include "setupVars.h"

static struct {
	bool used;
	time_t valid_until;
	char *remote_addr;
} auth_data[API_MAX_CLIENTS] = {{false, 0, NULL}};

// All printable ASCII characters, c.f., https://www.asciitable.com/
// Inspired by https://codereview.stackexchange.com/a/194388
// Randomness: rougly 6 Bit per Byte
#define ASCII_BEG 0x20
#define ASCII_END 0x7E
static void generateRandomString(char *str, size_t size)
{
	for(size_t i = 0u; i < size-1u; i++)
		str[i] = (char) (rand()%(ASCII_END-ASCII_BEG))+ASCII_BEG;

	str[size-1] = '\0';
}

// Can we validate this client?
// Returns -1 if not authenticated or expired
// Returns >= 0 for any valid authentication
#define LOCALHOSTv4 "127.0.0.1"
#define LOCALHOSTv6 "::1"
int check_client_auth(struct mg_connection *conn)
{
	int user_id = -1;
	const struct mg_request_info *request = mg_get_request_info(conn);

	// Is the user requesting from localhost?
	if(!httpsettings.api_auth_for_localhost && (strcmp(request->remote_addr, LOCALHOSTv4) == 0 ||
	                                            strcmp(request->remote_addr, LOCALHOSTv6) == 0))
		return API_MAX_CLIENTS;

	// FIXME: Generally assume authorization for now while we are working on the dashboard!
	return API_MAX_CLIENTS;

	// Does the client provide a user_id cookie?
	int num;
	if(http_get_cookie_int(conn, "user_id", &num) && num > -1 && num < API_MAX_CLIENTS)
	{
		if(config.debug & DEBUG_API)
			logg("API: Read user_id=%i from user-provided cookie", num);

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

			// Update timestamp of this client to extend
			// the validity of their API authentication
			auth_data[num].valid_until = now + httpsettings.session_timeout;

			// Update user cookie
			char *buffer = NULL;
			if(asprintf(&buffer,
				"Set-Cookie: user_id=%u; Path=/; Max-Age=%u\r\n",
				num, httpsettings.session_timeout) < 0)
			{
				return send_json_error(conn, 500, "internal_error", "Internal server error", NULL);
			}
			my_set_cookie_header(conn, buffer);
			free(buffer);

			if(config.debug & DEBUG_API)
			{
				char timestr[128];
				get_timestr(timestr, auth_data[user_id].valid_until);
				logg("API: Recognized known user: user_id %i valid_until: %s remote_addr %s",
					user_id, timestr, auth_data[user_id].remote_addr);
			}
		}
		else if(config.debug & DEBUG_API)
			logg("API Authentification: FAIL (cookie invalid/expired)");
	}
	else if(config.debug & DEBUG_API)
		logg("API Authentification: FAIL (no cookie provided)");

	return user_id;
}

static __attribute__((malloc)) char *get_password_hash(void)
{
	// Try to obtain password from setupVars.conf
	const char* password = read_setupVarsconf("WEBPASSWORD");

	// If the value was not set (or we couldn't open the file for reading),
	// we hand an empty string back to the caller
	if(password == NULL || (password != NULL && strlen(password) == 0u))
	{
		password = "";
	}

	char *hash = strdup(password);

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	return hash;
}

int api_auth(struct mg_connection *conn)
{
	int user_id = -1;
	char *password_hash = get_password_hash();
	const struct mg_request_info *request = mg_get_request_info(conn);
	
	// Does the client try to authenticate through a set header or is there no password on this machine?
	const char *xHeader = mg_get_header(conn, "X-Pi-hole-Authenticate");
	const bool header_set = (xHeader != NULL && strlen(xHeader) > 0);
	const bool empty_password = (strlen(password_hash) == 0u);
	if(header_set || empty_password )
	{
		const bool hash_match = (strcmp(xHeader, password_hash) == 0);
		if(hash_match || empty_password)
		{
			// Accepted
			time_t now = time(NULL);
			for(unsigned int i = 0; i < API_MAX_CLIENTS; i++)
			{
				// Expired slow, mark as unused
				if(auth_data[i].used &&
				   auth_data[i].valid_until < now)
				{
					if(config.debug & DEBUG_API)
					{
						logg("API: Session of client %u (%s) expired, freeing...",
						     i, auth_data[i].remote_addr);
					}
					auth_data[i].used = false;
					auth_data[i].valid_until = 0;
					free(auth_data[i].remote_addr);
					auth_data[i].remote_addr = NULL;
				}

				// Found unused authentication slot (might have been freed before)
				if(!auth_data[i].used)
				{
					auth_data[i].used = true;
					auth_data[i].valid_until = now + httpsettings.session_timeout;
					auth_data[i].remote_addr = strdup(request->remote_addr);

					user_id = i;
					break;
				}
			}

			if(config.debug & DEBUG_API && user_id > -1)
			{
				char timestr[128];
				get_timestr(timestr, auth_data[user_id].valid_until);
				logg("API: Registered new user: user_id %i valid_until: %s remote_addr %s",
				user_id, timestr, auth_data[user_id].remote_addr);
			}
			if(user_id == -1)
			{
				logg("WARNING: No free API slots available, not authenticating user");
			}
		}
		else if(config.debug & DEBUG_API)
		{
			logg("API: Password mismatch. User=%s, setupVars=%s", xHeader, password_hash);
		}

	}
	free(password_hash);
	password_hash = NULL;

	// Did the client authenticate before and we can validate this?
	if(user_id < 0)
		user_id = check_client_auth(conn);

	int method = http_method(conn);
	if(user_id == API_MAX_CLIENTS)
	{
		if(config.debug & DEBUG_API)
			logg("API Authentification: OK, localhost does not need auth.");
		// We still have to send a cookie for the web interface to be happy
		char *buffer = NULL;
		if(asprintf(&buffer,
		            "Set-Cookie: user_id=%u; Path=/; Max-Age=%u\r\n",
		            API_MAX_CLIENTS, API_SESSION_EXPIRE) < 0)
		{
			return send_json_error(conn, 500, "internal_error", "Internal server error", NULL);
		}
		my_set_cookie_header(conn, buffer);
		free(buffer);
	}
	if(user_id > -1 && method == HTTP_GET)
	{
		if(config.debug & DEBUG_API)
			logg("API Authentification: OK, registered new client");

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "status", "success");
		// Ten minutes validity
		char *buffer = NULL;
		if(asprintf(&buffer,
		            "Set-Cookie: user_id=%u; Path=/; Max-Age=%u\r\n",
		            user_id, API_SESSION_EXPIRE) < 0)
		{
			return send_json_error(conn, 500, "internal_error", "Internal server error", NULL);
		}
		my_set_cookie_header(conn, buffer);
		free(buffer);
	
		return send_json_success(conn);
	}
	else if(user_id > -1 && method == HTTP_DELETE)
	{
		if(config.debug & DEBUG_API)
			logg("API Authentification: OK, requested to revoke");

		// Revoke client authentication. This slot can be used by a new client, afterwards.
		auth_data[user_id].used = false;
		auth_data[user_id].valid_until = 0;
		free(auth_data[user_id].remote_addr);
		auth_data[user_id].remote_addr = NULL;

		const char *buffer = "Set-Cookie: user_id=deleted; Path=/; Max-Age=-1\r\n";
		my_set_cookie_header(conn, buffer);
		return send_json_success(conn);
	}
	else
	{
		const char *buffer = "Set-Cookie: user_id=deleted; Path=/; Max-Age=-1\r\n";
		my_set_cookie_header(conn, buffer);
		return send_json_unauthorized(conn);
	}
}

int api_auth_salt(struct mg_connection *conn)
{
	// Generate some salt ((0x7E-0x20)/256*8*44 = 129.25 Bit)
	char salt[45];
	generateRandomString(salt, sizeof(salt));
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "salt", salt);
	JSON_SEND_OBJECT(json);
}