/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/auth
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
#include "../log.h"
#include "../config.h"
// read_setupVarsconf()
#include "../setupVars.h"

// crypto library
#include <nettle/sha2.h>
#include <nettle/base64.h>

// How many bits should the SID use?
#define SID_BITSIZE 128
#define SID_SIZE BASE64_ENCODE_RAW_LENGTH(SID_BITSIZE/8) + 1
static struct {
	bool used;
	time_t valid_until;
	char *remote_addr;
	char sid[SID_SIZE];
} auth_data[API_MAX_CLIENTS] = {{false, 0, NULL, {0}}};

static struct {
	char challenge[2*SHA256_DIGEST_SIZE + 1];
	char response[2*SHA256_DIGEST_SIZE + 1];
	time_t valid_until;
} challenges[API_MAX_CHALLENGES] = {{{0}, {0}, 0}};

// Convert RAW data into hex representation
// Two hexadecimal digits are generated for each input byte.
static void sha256_hex(uint8_t *data, char *buffer)
{
	for (unsigned int i = 0; i < SHA256_DIGEST_SIZE; i++)
	{
		sprintf(buffer, "%02x", data[i]);
		buffer += 2;
	}
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

	// Does the client provide a session cookie?
	char sid[SID_SIZE];
	bool sid_avail = http_get_cookie_str(conn, "sid", sid, SID_SIZE);

	// If not, does the client provide a session ID via GET?
	if(!sid_avail && request->query_string != NULL)
	{
		sid_avail = GET_VAR("forward", sid, request->query_string) > 0;
		sid[SID_SIZE-1] = '\0';
	}

	if(sid_avail)
	{
		time_t now = time(NULL);
		if(config.debug & DEBUG_API)
			logg("API: Read sid=%s", sid);

		for(unsigned int i = 0; i < API_MAX_CLIENTS; i++)
		{
			if(auth_data[i].used &&
			   auth_data[i].valid_until >= now &&
			   strcmp(auth_data[i].remote_addr, request->remote_addr) == 0 &&
			   strcmp(auth_data[i].sid, sid) == 0)
			{
				user_id = i;
				break;
			}
		}
		if(user_id > -1)
		{
			// Authentication succesful:
			// - We know this client
			// - The session is (still) valid
			// - The IP matches the one we know for this SID

			// Update timestamp of this client to extend
			// the validity of their API authentication
			auth_data[user_id].valid_until = now + httpsettings.session_timeout;

			// Update user cookie
			if(snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers),
			            "Set-Cookie: sid=%s; Path=/; Max-Age=%u\r\n",
			            auth_data[user_id].sid, httpsettings.session_timeout) < 0)
			{
				return send_json_error(conn, 500, "internal_error", "Internal server error", NULL);
			}

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

// Check received response
static bool check_response(const char *response)
{
	// Loop over all responses and try to validate response
	time_t now = time(NULL);
	for(unsigned int i = 0; i < API_MAX_CHALLENGES; i++)
	{
		// Skip expired entries
		if(challenges[i].valid_until < now)
			continue;

		if(strcasecmp(challenges[i].response, response) == 0)
		{
			// This challange-response has been used
			// Invalidate to prevent replay attacks
			challenges[i].valid_until = 0;
			return true;
		}
	}

	// If transmitted challenge wasn't found -> this is an invalid auth request
	return false;
}

static int send_api_auth_status(struct mg_connection *conn, const int user_id, const int method)
{
	if(user_id == API_MAX_CLIENTS)
	{
		if(config.debug & DEBUG_API)
			logg("API Authentification: OK (localhost does not need auth)");

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "status", "success");
		JSON_OBJ_ADD_NULL(json, "sid");
		JSON_SEND_OBJECT(json);
	}
	if(user_id > -1 && method == HTTP_GET)
	{
		if(config.debug & DEBUG_API)
			logg("API Authentification: OK");

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "status", "success");
		JSON_OBJ_REF_STR(json, "sid", auth_data[user_id].sid);

		// Ten minutes validity
		if(snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers),
		            "Set-Cookie: sid=%s; Path=/; Max-Age=%u\r\n",
		            auth_data[user_id].sid, API_SESSION_EXPIRE) < 0)
		{
			return send_json_error(conn, 500, "internal_error", "Internal server error", NULL);
		}

		JSON_SEND_OBJECT(json);
	}
	else if(user_id > -1 && method == HTTP_DELETE)
	{
		if(config.debug & DEBUG_API)
			logg("API Authentification: Revoking");

		// Revoke client authentication. This slot can be used by a new client, afterwards.
		auth_data[user_id].used = false;
		auth_data[user_id].valid_until = 0;
		free(auth_data[user_id].remote_addr);
		auth_data[user_id].remote_addr = NULL;
		// We leave the old SID, it will be replaced next time the slot is used

		strncpy(pi_hole_extra_headers, "Set-Cookie: sid=deleted; Path=/; Max-Age=-1\r\n", sizeof(pi_hole_extra_headers));
		return send_json_success(conn);
	}
	else
	{
		strncpy(pi_hole_extra_headers, "Set-Cookie: sid=deleted; Path=/; Max-Age=-1\r\n", sizeof(pi_hole_extra_headers));
		return send_json_unauthorized(conn);
	}
}

static void generateChallenge(const unsigned int idx, const time_t now)
{
	uint8_t raw_challenge[SHA256_DIGEST_SIZE];
	for(unsigned i = 0; i < SHA256_DIGEST_SIZE; i+= 2)
	{
		const int rval = rand();
		raw_challenge[i] = rval & 0xFF;
		raw_challenge[i+1] = (rval >> 8) & 0xFF;
	}
	sha256_hex(raw_challenge, challenges[idx].challenge);
	challenges[idx].valid_until = now + API_CHALLENGE_TIMEOUT;
}

static void generateResponse(const unsigned int idx)
{
	uint8_t raw_response[SHA256_DIGEST_SIZE];
	struct sha256_ctx ctx;
	sha256_init(&ctx);

	// Add challenge in hex representation
	sha256_update(&ctx,
	              sizeof(challenges[idx].challenge)-1,
	              (uint8_t*)challenges[idx].challenge);

	// Add separator
	sha256_update(&ctx, 1, (uint8_t*)":");

	// Get and add password hash from setupVars.conf
	char *password_hash = get_password_hash();
	sha256_update(&ctx,
			strlen(password_hash),
			(uint8_t*)password_hash);
	free(password_hash);
	password_hash = NULL;

	sha256_digest(&ctx, SHA256_DIGEST_SIZE, raw_response);
	sha256_hex(raw_response, challenges[idx].response);
}

int api_auth(struct mg_connection *conn)
{
	// Check HTTP method
	const enum http_method method = http_method(conn);
	if(method != HTTP_GET)
		return 0; // error 404

	// Did the client authenticate before and we can validate this?
	int user_id = check_client_auth(conn);
	return send_api_auth_status(conn, user_id, HTTP_GET);
}

static void generateSID(char *sid)
{
	uint8_t raw_sid[SID_SIZE];
	for(unsigned i = 0; i < (SID_BITSIZE/8); i+= 2)
	{
		const int rval = rand();
		raw_sid[i] = rval & 0xFF;
		raw_sid[i+1] = (rval >> 8) & 0xFF;
	}
	base64_encode_raw(sid, SID_BITSIZE/8, raw_sid);
	sid[SID_SIZE-1] = '\0';
}

// Login action
int api_auth_login(struct mg_connection *conn)
{
	// Check HTTP method
	const enum http_method method = http_method(conn);
	if(method != HTTP_GET)
		return 0; // error 404

	int user_id = -1;
	char *password_hash = get_password_hash();
	const struct mg_request_info *request = mg_get_request_info(conn);

	char response[256] = { 0 };
	const bool reponse_set = request->query_string != NULL && GET_VAR("response", response, request->query_string) > 0;
	const bool empty_password = (strlen(password_hash) == 0u);
	if(reponse_set || empty_password )
	{
		// - Client tries to authenticate using a challenge response, or
		// - There no password on this machine
		if(check_response(response) || empty_password)
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
					generateSID(auth_data[i].sid);

					user_id = i;
					break;
				}
			}

			// Debug logging
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
			logg("API: Response incorrect. Response=%s, setupVars=%s", response, password_hash);
		}

		// Free allocated memory
		free(password_hash);
		password_hash = NULL;
		return send_api_auth_status(conn, user_id, HTTP_GET);
	}
	else
	{
		// Client wants to get a challenge
		// Generate a challenge
		unsigned int i;
		const time_t now = time(NULL);

		// Get an empty/expired slot
		for(i = 0; i < API_MAX_CHALLENGES; i++)
			if(challenges[i].valid_until < now)
				break;

		// If there are no empty/expired slots, then find the oldest challenge
		// and replace it
		if(i == API_MAX_CHALLENGES)
		{
			unsigned int minidx = 0;
			time_t minval = now;
			for(i = 0; i < API_MAX_CHALLENGES; i++)
			{
				if(challenges[i].valid_until < minval)
				{
					minval = challenges[i].valid_until;
					minidx = i;
				}
			}
			i = minidx;
		}

		// Generate and store new challenge
		generateChallenge(i, now);

		// Compute and store expected response for this challenge (SHA-256)
		generateResponse(i);

		// Free allocated memory
		free(password_hash);
		password_hash = NULL;

		// Return to user
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "challenge", challenges[i].challenge);
		JSON_OBJ_ADD_NUMBER(json, "valid_until", challenges[i].valid_until);
		JSON_SEND_OBJECT(json);
	}
}

int api_auth_logout(struct mg_connection *conn)
{
	// Check HTTP method
	const enum http_method method = http_method(conn);
	if(method != HTTP_DELETE)
		return 0; // error 404

	// Did the client authenticate before and we can validate this?
	int user_id = check_client_auth(conn);
	return send_api_auth_status(conn, user_id, HTTP_DELETE);
}
