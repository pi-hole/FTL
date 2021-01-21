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
#include <nettle/version.h>

// On 2017-08-27 (after v3.3, before v3.4), nettle changed the type of
// destination from uint_8t* to char* in all base64 and base16 functions
// (armor-signedness branch). This is a breaking change as this is a change in
// signedness causing issues when compiling FTL against older versions of
// nettle. We create this constant here to have a conversion if necessary.
// See https://github.com/gnutls/nettle/commit/f2da403135e2b2f641cf0f8219ad5b72083b7dfd
#if NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR < 4
#define NETTLE_SIGN (uint8_t*)
#else
#define NETTLE_SIGN
#endif

// How many bits should the SID use?
#define SID_BITSIZE 128
#define SID_SIZE BASE64_ENCODE_RAW_LENGTH(SID_BITSIZE/8) + 1

// Use SameSite=Strict as defense against some classes of cross-site request
// forgery (CSRF) attacks. This ensures the session cookie will only be sent in
// a first-party (i.e., Pi-hole) context and NOT be sent along with requests
// initiated by third party websites.
#define FTL_SET_COOKIE "Set-Cookie: sid=%s; SameSite=Strict; Path=/; Max-Age=%u\r\n"
#define FTL_DELETE_COOKIE "Set-Cookie: sid=deleted; SameSite=Strict; Path=/; Max-Age=-1\r\n"

static struct {
	bool used;
	time_t valid_until;
	char remote_addr[48]; // Large enough for IPv4 and IPv6 addresses, hard-coded in civetweb.h as mg_request_info.remote_addr
	char sid[SID_SIZE];
} auth_data[API_MAX_CLIENTS] = {{false, 0, {0}, {0}}};

#define CHALLENGE_SIZE (2*SHA256_DIGEST_SIZE)
static struct {
	char challenge[CHALLENGE_SIZE + 1];
	char response[CHALLENGE_SIZE + 1];
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
int check_client_auth(struct ftl_conn *api)
{
	// Is the user requesting from localhost?
	if(!httpsettings.api_auth_for_localhost && (strcmp(api->request->remote_addr, LOCALHOSTv4) == 0 ||
	                                            strcmp(api->request->remote_addr, LOCALHOSTv6) == 0))
	{
		return API_AUTH_LOCALHOST;
	}

	// Check if there is a password hash
	char *password_hash = get_password_hash();
	const bool empty_password = (strlen(password_hash) == 0u);
	free(password_hash);
	if(empty_password)
		return API_AUTH_EMPTYPASS;

	// Does the client provide a session cookie?
	char sid[SID_SIZE];
	const char *sid_source = "cookie";
	bool sid_avail = http_get_cookie_str(api, "sid", sid, SID_SIZE);

	// If not, does the client provide a session ID via GET/POST?
	if(!sid_avail && api->payload.avail)
	{
		// Try to extract SID from form-encoded payload
		if(GET_VAR("sid", sid, api->payload.raw) > 0)
		{
			// "+" may have been replaced by " ", undo this here
			for(unsigned int i = 0; i < SID_SIZE; i++)
				if(sid[i] == ' ')
					sid[i] = '+';

			// Zero terminate
			sid[SID_SIZE-1] = '\0';
			sid_source = "payload (form-data)";
			sid_avail = true;
		}
		// Try to extract SID from root of a possibly included JSON payload
		else if(api->payload.json != NULL)
		{
			cJSON *sid_obj = cJSON_GetObjectItem(api->payload.json, "sid");
			if(cJSON_IsString(sid_obj))
			{
				strncpy(sid, sid_obj->valuestring, SID_SIZE - 1u);
				sid[SID_SIZE-1] = '\0';
				sid_source = "payload (JSON)";
				sid_avail = true;
			}
		}
	}

	if(!sid_avail)
	{
		if(config.debug & DEBUG_API)
			logg("API Authentification: FAIL (no SID provided)");

		return API_AUTH_UNAUTHORIZED;
	}

	// else: Analyze SID
	int user_id = API_AUTH_UNAUTHORIZED;
	const time_t now = time(NULL);
	if(config.debug & DEBUG_API)
		logg("API: Read sid=\"%s\" from %s", sid, sid_source);

	for(unsigned int i = 0; i < API_MAX_CLIENTS; i++)
	{
		if(auth_data[i].used &&
		   auth_data[i].valid_until >= now &&
		   strcmp(auth_data[i].remote_addr, api->request->remote_addr) == 0 &&
		   strcmp(auth_data[i].sid, sid) == 0)
		{
			user_id = i;
			break;
		}
	}
	if(user_id > API_AUTH_UNAUTHORIZED)
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
				FTL_SET_COOKIE,
				auth_data[user_id].sid, httpsettings.session_timeout) < 0)
		{
			return send_json_error(api, 500, "internal_error", "Internal server error", NULL);
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
		logg("API Authentification: FAIL (SID invalid/expired)");

	return user_id;
}

// Check received response
static bool check_response(const char *response, const time_t now)
{
	// Loop over all responses and try to validate response
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

static int get_session_object(struct ftl_conn *api, cJSON *json, const int user_id, const time_t now)
{
	// Authentication not needed
	if(user_id == API_AUTH_LOCALHOST || user_id == API_AUTH_EMPTYPASS)
	{
		cJSON *session = JSON_NEW_OBJ();
		JSON_OBJ_ADD_BOOL(session, "valid", true);
		JSON_OBJ_ADD_NULL(session, "sid");
		JSON_OBJ_ADD_NULL(session, "validity");
		JSON_OBJ_ADD_ITEM(json, "session", session);
		return 0;
	}

	// Valid session
	if(user_id > API_AUTH_UNAUTHORIZED && auth_data[user_id].used)
	{
		cJSON *session = JSON_NEW_OBJ();
		JSON_OBJ_ADD_BOOL(session, "valid", true);
		JSON_OBJ_REF_STR(session, "sid", auth_data[user_id].sid);
		JSON_OBJ_ADD_NUMBER(session, "validity", auth_data[user_id].valid_until - now);
		JSON_OBJ_ADD_ITEM(json, "session", session);
		return 0;
	}

	// No valid session
	cJSON *session = JSON_NEW_OBJ();
	JSON_OBJ_ADD_BOOL(session, "valid", false);
	JSON_OBJ_ADD_NULL(session, "sid");
	JSON_OBJ_ADD_NULL(session, "validity");
	JSON_OBJ_ADD_ITEM(json, "session", session);
	return 0;
}

static void delete_session(const int user_id)
{
	// Skip if nothing to be done here
	if(user_id < 0)
		return;

	auth_data[user_id].used = false;
	auth_data[user_id].valid_until = 0;
	memset(auth_data[user_id].sid, 0, sizeof(auth_data[user_id].sid));
	memset(auth_data[user_id].remote_addr, 0, sizeof(auth_data[user_id].remote_addr));
}

static int send_api_auth_status(struct ftl_conn *api, const int user_id, const time_t now)
{
	if(user_id == API_AUTH_LOCALHOST)
	{
		if(config.debug & DEBUG_API)
			logg("API Auth status: OK (localhost does not need auth)");

		cJSON *json = JSON_NEW_OBJ();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT(json);
	}

	if(user_id == API_AUTH_EMPTYPASS)
	{
		if(config.debug & DEBUG_API)
			logg("API Auth status: OK (empty password)");

		cJSON *json = JSON_NEW_OBJ();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT(json);
	}

	if(user_id > API_AUTH_UNAUTHORIZED && (api->method == HTTP_GET || api->method == HTTP_POST))
	{
		if(config.debug & DEBUG_API)
			logg("API Auth status: OK");

		// Ten minutes validity
		if(snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers),
		            FTL_SET_COOKIE,
		            auth_data[user_id].sid, API_SESSION_EXPIRE) < 0)
		{
			return send_json_error(api, 500, "internal_error", "Internal server error", NULL);
		}

		cJSON *json = JSON_NEW_OBJ();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT(json);
	}
	else if(user_id > API_AUTH_UNAUTHORIZED && api->method == HTTP_DELETE)
	{
		if(config.debug & DEBUG_API)
			logg("API Auth status: Logout, asking to delete cookie");

		// Revoke client authentication. This slot can be used by a new client afterwards.
		delete_session(user_id);

		strncpy(pi_hole_extra_headers, FTL_DELETE_COOKIE, sizeof(pi_hole_extra_headers));
		cJSON *json = JSON_NEW_OBJ();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT_CODE(json, 410); // 410 Gone
	}
	else
	{
		if(config.debug & DEBUG_API)
			logg("API Auth status: Invalid, asking to delete cookie");

		strncpy(pi_hole_extra_headers, FTL_DELETE_COOKIE, sizeof(pi_hole_extra_headers));
		cJSON *json = JSON_NEW_OBJ();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT_CODE(json, 401); // 401 Unauthorized
	}
}

static void generateChallenge(const unsigned int idx, const time_t now)
{
	uint8_t raw_challenge[SHA256_DIGEST_SIZE];
	for(unsigned i = 0; i < SHA256_DIGEST_SIZE; i+= 4)
	{
		const long rval = random();
		raw_challenge[i] = rval & 0xFF;
		raw_challenge[i+1] = (rval >> 8) & 0xFF;
		raw_challenge[i+2] = (rval >> 16) & 0xFF;
		raw_challenge[i+3] = (rval >> 24) & 0xFF;
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

static void generateSID(char *sid)
{
	uint8_t raw_sid[SID_SIZE];
	for(unsigned i = 0; i < (SID_BITSIZE/8); i+= 4)
	{
		const long rval = random();
		raw_sid[i] = rval & 0xFF;
		raw_sid[i+1] = (rval >> 8) & 0xFF;
		raw_sid[i+2] = (rval >> 16) & 0xFF;
		raw_sid[i+3] = (rval >> 24) & 0xFF;
	}
	base64_encode_raw(NETTLE_SIGN sid, SID_BITSIZE/8, raw_sid);
	sid[SID_SIZE-1] = '\0';
}

// api/auth
//  GET: Check authentication and obtain a challenge
//  POST: Login
//  DELETE: Logout
int api_auth(struct ftl_conn *api)
{
	// Check HTTP method
	const time_t now = time(NULL);

	char *password_hash = get_password_hash();
	const bool empty_password = (strlen(password_hash) == 0u);

	int user_id = API_AUTH_UNAUTHORIZED;

	bool reponse_set = false;
	char response[256] = { 0 };

	// Did the client authenticate before and we can validate this?
	user_id = check_client_auth(api);

	// If this is a valid session, we can exit early at this point
	if(user_id != API_AUTH_UNAUTHORIZED)
		return send_api_auth_status(api, user_id, now);

	// Login attempt, extract response
	if(api->method == HTTP_POST)
	{
		// Try to extract response from payload
		int len = 0;
		if((len = GET_VAR("response", response, api->payload.raw)) != CHALLENGE_SIZE)
		{
			const char *message = len < 0 ? "No response found" : "Invalid response length";
			if(config.debug & DEBUG_API)
				logg("API auth error: %s", message);
			return send_json_error(api, 400,
			                      "bad_request",
			                      message,
			                      NULL);
		}
		reponse_set = true;
	}

	// Logout attempt
	if(api->method == HTTP_DELETE)
	{
		if(config.debug & DEBUG_API)
			logg("API Auth: User with ID %i wants to log out", user_id);
		return send_api_auth_status(api, user_id, now);
	}

	// Login attempt and/or auth check
	if(reponse_set || empty_password)
	{
		// - Client tries to authenticate using a challenge response, or
		// - There no password on this machine
		const bool response_correct = check_response(response, now);
		if(response_correct || empty_password)
		{
			// Accepted
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
					delete_session(user_id);
				}

				// Found unused authentication slot (might have been freed before)
				if(!auth_data[i].used)
				{
					auth_data[i].used = true;
					auth_data[i].valid_until = now + httpsettings.session_timeout;
					strncpy(auth_data[i].remote_addr, api->request->remote_addr, sizeof(auth_data[i].remote_addr));
					auth_data[i].remote_addr[sizeof(auth_data[i].remote_addr)-1] = '\0';
					generateSID(auth_data[i].sid);

					user_id = i;
					break;
				}
			}

			// Debug logging
			if(config.debug & DEBUG_API && user_id > API_AUTH_UNAUTHORIZED)
			{
				char timestr[128];
				get_timestr(timestr, auth_data[user_id].valid_until);
				logg("API: Registered new user: user_id %i valid_until: %s remote_addr %s (accepted due to %s)",
				     user_id, timestr, auth_data[user_id].remote_addr,
				     response_correct ? "correct response" : "empty password");
			}
			if(user_id == API_AUTH_UNAUTHORIZED)
			{
				logg("WARNING: No free API seats available, not authenticating client");
			}
		}
		else if(config.debug & DEBUG_API)
		{
			logg("API: Response incorrect. Response=%s, setupVars=%s", response, password_hash);
		}

		// Free allocated memory
		free(password_hash);
		password_hash = NULL;
		return send_api_auth_status(api, user_id, now);
	}
	else
	{
		// Client wants to get a challenge
		// Generate a challenge
		unsigned int i;

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

		if(config.debug & DEBUG_API)
		{
			logg("API: Sending challenge=%s", challenges[i].challenge);
		}

		// Return to user
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "challenge", challenges[i].challenge);
		get_session_object(api, json, -1, now);
		JSON_SEND_OBJECT(json);
	}
}
