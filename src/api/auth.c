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
#include "api/auth.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
#include "log.h"
#include "config/config.h"
// get_password_hash()
#include "config/setupVars.h"
// (un)lock_shm()
#include "shmem.h"
// getrandom()
#include "daemon.h"
// sha256_raw_to_hex()
#include "config/password.h"
// database session functions
#include "database/session-table.h"
// FTLDBerror()
#include "database/common.h"

static uint16_t max_sessions = 0;
static struct session *auth_data = NULL;

static void add_request_info(struct ftl_conn *api, const char *csrf)
{
	// Copy CSRF token into request
	if(csrf != NULL)
		strncpy((char*)api->request->csrf_token, csrf, sizeof(api->request->csrf_token) - 1);

	// Store that this client is authenticated
	// We use memset() with the size of an int here to avoid a
	// compiler warning about modifying a variable in a const struct
	memset((int*)&api->request->is_authenticated, 1, sizeof(api->request->is_authenticated));
}

void init_api(void)
{
	// Restore sessions from database
	max_sessions = config.webserver.api.max_sessions.v.u16;
	auth_data = calloc(max_sessions, sizeof(struct session));
	if(auth_data == NULL)
	{
		log_crit("Could not allocate memory for API sessions, check config value of webserver.api.max_sessions");
		exit(EXIT_FAILURE);
	}

	if(!FTLDBerror())
		restore_db_sessions(auth_data, max_sessions);
}

void free_api(void)
{
	if(auth_data == NULL)
		return;

	// Store sessions in database
	backup_db_sessions(auth_data, max_sessions);
	max_sessions = 0;
	free(auth_data);
	auth_data = NULL;
}

// Can we validate this client?
// Returns -1 if not authenticated or expired
// Returns >= 0 for any valid authentication
int check_client_auth(struct ftl_conn *api, const bool is_api)
{
	// When the pwhash is unset, authentication is disabled
	if(config.webserver.api.pwhash.v.s[0] == '\0')
	{
		api->message = "no password set";
		add_request_info(api, NULL);
		return API_AUTH_EMPTYPASS;
	}

	// Does the client provide a session ID?
	char sid[SID_SIZE];
	const char *sid_source = "-";
	// Try to extract SID from cookie
	bool sid_avail = false;

	// If not, does the client provide a session ID via GET/POST?
	if(api->payload.avail)
	{
		// Try to extract SID from form-encoded payload
		if(GET_VAR("sid", sid, api->payload.raw) > 0)
		{
			// "+" may have been replaced by " ", undo this here
			for(unsigned int i = 0; i < SID_SIZE; i++)
				if(sid[i] == ' ')
					sid[i] = '+';

			// Zero terminate SID string
			sid[SID_SIZE-1] = '\0';
			// Mention source of SID
			sid_source = "payload (form-data)";
			// Mark SID as available
			sid_avail = true;
		}
		// Try to extract SID from root of a possibly included JSON payload
		else if(api->payload.json != NULL)
		{
			const cJSON *sid_obj = cJSON_GetObjectItem(api->payload.json, "sid");
			if(cJSON_IsString(sid_obj))
			{
				// Copy SID string
				strncpy(sid, sid_obj->valuestring, SID_SIZE - 1u);
				// Zero terminate SID string
				sid[SID_SIZE-1] = '\0';
				// Mention source of SID
				sid_source = "payload (JSON)";
				// Mark SID as available
				sid_avail = true;
			}
		}
	}

	// If not, does the client provide a session ID via HEADER?
	if(!sid_avail)
	{
		const char *sid_header = NULL;
		// Try to extract SID from header
		if((sid_header = mg_get_header(api->conn, "sid")) != NULL ||
		   (sid_header = mg_get_header(api->conn, "X-FTL-SID")) != NULL)
		{
			// Copy SID string
			strncpy(sid, sid_header, SID_SIZE - 1u);
			// Zero terminate SID string
			sid[SID_SIZE-1] = '\0';
			// Mention source of SID
			sid_source = "header";
			// Mark SID as available
			sid_avail = true;
		}
	}

	// If not, does the client provide a session ID via COOKIE?
	bool cookie_auth = false;
	if(!sid_avail)
	{
		cookie_auth = http_get_cookie_str(api, "sid", sid, SID_SIZE);
		if(cookie_auth)
		{
			// Mention source of SID
			sid_source = "cookie";
			// Mark SID as available
			sid_avail = true;
		}
	}

	// If not, does the client provide a session ID via URI?
	if(!sid_avail && api->request->query_string && GET_VAR("sid", sid, api->request->query_string) > 0)
	{
		// "+" may have been replaced by " ", undo this here
		for(unsigned int i = 0; i < SID_SIZE; i++)
			if(sid[i] == ' ')
				sid[i] = '+';

		// Zero terminate SID string
		sid[SID_SIZE-1] = '\0';
		// Mention source of SID
		sid_source = "URI";
		// Mark SID as available
		sid_avail = true;
	}

	if(!sid_avail)
	{
		api->message = "no SID provided";
		log_debug(DEBUG_API, "API Authentication: FAIL (%s)", api->message);
		return API_AUTH_UNAUTHORIZED;
	}

	// else: Analyze SID
	int user_id = API_AUTH_UNAUTHORIZED;
	const time_t now = time(NULL);
	log_debug(DEBUG_API, "Read sid=\"%s\" from %s", sid, sid_source);

	// If the SID has been sent through a cookie, we require a CSRF token in
	// the header to be sent along with the request for any API requests
	char csrf[SID_SIZE];
	const bool need_csrf = cookie_auth && is_api;
	if(need_csrf)
	{
		const char *csrf_header = NULL;
		// Try to extract CSRF token from header
		if((csrf_header = mg_get_header(api->conn, "X-CSRF-TOKEN")) != NULL)
		{
			// Copy CSRF string
			strncpy(csrf, csrf_header, SID_SIZE - 1u);
			// Zero terminate CSRF string
			csrf[SID_SIZE-1] = '\0';
		}
		else
		{
			api->message = "Cookie authentication without CSRF token";
			log_debug(DEBUG_API, "API Authentication: FAIL (%s)", api->message);
			return API_AUTH_UNAUTHORIZED;
		}
	}

	bool expired = false;
	for(unsigned int i = 0; i < max_sessions; i++)
	{
		if(auth_data[i].used &&
		   strcmp(auth_data[i].sid, sid) == 0)
		{
			// Check if session is known but expired
			if(auth_data[i].valid_until < now)
				expired = true;

			// Check CSRF if authentiating via cookie
			if(need_csrf && strcmp(auth_data[i].csrf, csrf) != 0)
			{
				api->message = "CSRF token mismatch";
				log_debug(DEBUG_API, "API Authentication: FAIL (%s, received \"%s\", expected \"%s\")",
				          api->message, csrf, auth_data[i].csrf);
				return API_AUTH_UNAUTHORIZED;
			}
			user_id = i;
			break;
		}
	}
	if(user_id > API_AUTH_UNAUTHORIZED)
	{
		// Authentication successful: valid session

		// Update timestamp of this client to extend
		// the validity of their API authentication
		auth_data[user_id].valid_until = now + config.webserver.session.timeout.v.ui;

		// Set strict_tls permanently to false if the client connected via HTTP
		auth_data[user_id].tls.mixed |= api->request->is_ssl != auth_data[user_id].tls.login;

		// Update user cookie
		if(snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers),
		            FTL_SET_COOKIE,
		            auth_data[user_id].sid, config.webserver.session.timeout.v.ui) < 0)
		{
			return send_json_error(api, 500, "internal_error", "Internal server error", NULL);
		}

		// Add CSRF token to request
		add_request_info(api, auth_data[user_id].csrf);

		// Debug logging
		if(config.debug.api.v.b)
		{
			char timestr[TIMESTR_SIZE];
			get_timestr(timestr, auth_data[user_id].valid_until, false, false);
			log_debug(DEBUG_API, "Recognized known user: user_id %i, valid_until: %s, remote_addr %s (%s at login)",
			          user_id, timestr, api->request->remote_addr, auth_data[user_id].remote_addr);
		}
	}
	else
	{
		api->message = expired ? "session expired" : "session unknown";
		log_debug(DEBUG_API, "API Authentication: FAIL (%s)", api->message);
		return API_AUTH_UNAUTHORIZED;
	}

	api->user_id = user_id;
	api->session = &auth_data[user_id];

	api->message = "correct password";
	return user_id;
}

static int get_all_sessions(struct ftl_conn *api, cJSON *json)
{
	const time_t now = time(NULL);
	cJSON *sessions = JSON_NEW_ARRAY();
	for(int i = 0; i < max_sessions; i++)
	{
		if(!auth_data[i].used)
			continue;
		cJSON *session = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(session, "id", i);
		JSON_ADD_BOOL_TO_OBJECT(session, "current_session", i == api->user_id);
		JSON_ADD_BOOL_TO_OBJECT(session, "valid", auth_data[i].valid_until >= now);
		cJSON *tls = JSON_NEW_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(tls, "login", auth_data[i].tls.login);
		JSON_ADD_BOOL_TO_OBJECT(tls, "mixed", auth_data[i].tls.mixed);
		JSON_ADD_ITEM_TO_OBJECT(session, "tls", tls);
		JSON_ADD_NUMBER_TO_OBJECT(session, "login_at", auth_data[i].login_at);
		JSON_ADD_NUMBER_TO_OBJECT(session, "last_active", auth_data[i].valid_until - config.webserver.session.timeout.v.ui);
		JSON_ADD_NUMBER_TO_OBJECT(session, "valid_until", auth_data[i].valid_until);
		JSON_REF_STR_IN_OBJECT(session, "remote_addr", auth_data[i].remote_addr);
		if(auth_data[i].user_agent[0] != '\0')
			JSON_REF_STR_IN_OBJECT(session, "user_agent", auth_data[i].user_agent);
		else
			JSON_ADD_NULL_TO_OBJECT(session, "user_agent");
		if(auth_data[i].x_forwarded_for[0] != '\0')
			JSON_REF_STR_IN_OBJECT(session, "x_forwarded_for", auth_data[i].x_forwarded_for);
		else
			JSON_ADD_NULL_TO_OBJECT(session, "x_forwarded_for");
		JSON_ADD_BOOL_TO_OBJECT(session, "app", auth_data[i].app);
		JSON_ADD_BOOL_TO_OBJECT(session, "cli", auth_data[i].cli);
		JSON_ADD_ITEM_TO_ARRAY(sessions, session);
	}
	JSON_ADD_ITEM_TO_OBJECT(json, "sessions", sessions);
	return 0;
}

static int get_session_object(struct ftl_conn *api, cJSON *json, const int user_id, const time_t now)
{
	cJSON *session = JSON_NEW_OBJECT();

	// Authentication not needed
	if(user_id == API_AUTH_EMPTYPASS)
	{
		JSON_ADD_BOOL_TO_OBJECT(session, "valid", true);
		JSON_ADD_BOOL_TO_OBJECT(session, "totp", strlen(config.webserver.api.totp_secret.v.s) > 0);
		JSON_ADD_NULL_TO_OBJECT(session, "sid");
		JSON_ADD_NUMBER_TO_OBJECT(session, "validity", -1);
		JSON_REF_STR_IN_OBJECT(session, "message", api->message);
		JSON_ADD_ITEM_TO_OBJECT(json, "session", session);
		return 0;
	}

	// Valid session
	if(user_id > API_AUTH_UNAUTHORIZED && auth_data[user_id].used)
	{
		JSON_ADD_BOOL_TO_OBJECT(session, "valid", true);
		JSON_ADD_BOOL_TO_OBJECT(session, "totp", strlen(config.webserver.api.totp_secret.v.s) > 0);
		JSON_REF_STR_IN_OBJECT(session, "sid", auth_data[user_id].sid);
		JSON_REF_STR_IN_OBJECT(session, "csrf", auth_data[user_id].csrf);
		JSON_ADD_NUMBER_TO_OBJECT(session, "validity", auth_data[user_id].valid_until - now);
		JSON_REF_STR_IN_OBJECT(session, "message", api->message);
		JSON_ADD_ITEM_TO_OBJECT(json, "session", session);
		return 0;
	}

	// No valid session
	JSON_ADD_BOOL_TO_OBJECT(session, "valid", false);
	JSON_ADD_BOOL_TO_OBJECT(session, "totp", strlen(config.webserver.api.totp_secret.v.s) > 0);
	JSON_ADD_NULL_TO_OBJECT(session, "sid");
	JSON_ADD_NUMBER_TO_OBJECT(session, "validity", -1);
	JSON_REF_STR_IN_OBJECT(session, "message", api->message);
	JSON_ADD_ITEM_TO_OBJECT(json, "session", session);
	return 0;
}

static bool delete_session(const int user_id)
{
	// Skip if nothing to be done here
	if(user_id < 0 || user_id >= max_sessions)
		return false;

	const bool was_valid = auth_data[user_id].used;

	// Zero out this session (also sets valid to false == 0)
	memset(&auth_data[user_id], 0, sizeof(auth_data[user_id]));

	return was_valid;
}

void delete_all_sessions(void)
{
	// Zero out all sessions without looping
	memset(auth_data, 0, max_sessions*sizeof(*auth_data));
}

static int send_api_auth_status(struct ftl_conn *api, const int user_id, const time_t now)
{
	if(user_id > API_AUTH_UNAUTHORIZED && (api->method == HTTP_GET || api->method == HTTP_POST))
	{
		log_debug(DEBUG_API, "API Auth status: OK");

		// Ten minutes validity
		if(snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers),
		            FTL_SET_COOKIE,
		            auth_data[user_id].sid, config.webserver.session.timeout.d.ui) < 0)
		{
			return send_json_error(api, 500, "internal_error", "Internal server error", NULL);
		}

		cJSON *json = JSON_NEW_OBJECT();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT(json);
	}
	else if(api->method == HTTP_DELETE)
	{
		if(user_id > API_AUTH_UNAUTHORIZED)
		{
			log_debug(DEBUG_API, "API Auth status: Logout, asking to delete cookie");

			strncpy(pi_hole_extra_headers, FTL_DELETE_COOKIE, sizeof(pi_hole_extra_headers));

			// Revoke client authentication. This slot can be used by a new client afterwards.
			const int code = delete_session(user_id) ? 204 : 404;

			// Send empty reply with appropriate HTTP status code
			send_http_code(api, NULL, code, "");
			return code;
		}
		else
		{
			log_debug(DEBUG_API, "API Auth status: Logout, but not authenticated");

			cJSON *json = JSON_NEW_OBJECT();
			get_session_object(api, json, user_id, now);
			JSON_SEND_OBJECT_CODE(json, 401); // 401 Unauthorized
		}
	}
	else if(user_id == API_AUTH_EMPTYPASS)
	{
		log_debug(DEBUG_API, "API Auth status: OK (empty password)");

		cJSON *json = JSON_NEW_OBJECT();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT(json);
	}
	else
	{
		log_debug(DEBUG_API, "API Auth status: Invalid, asking to delete cookie");

		strncpy(pi_hole_extra_headers, FTL_DELETE_COOKIE, sizeof(pi_hole_extra_headers));
		cJSON *json = JSON_NEW_OBJECT();
		get_session_object(api, json, user_id, now);
		JSON_SEND_OBJECT_CODE(json, 401); // 401 Unauthorized
	}
}

static void generateSID(char *sid)
{
	uint8_t raw_sid[SID_SIZE];
	if(!get_secure_randomness(raw_sid, sizeof(raw_sid)))
		return;

	base64_encode_raw(NETTLE_SIGN sid, SID_BITSIZE/8, raw_sid);
	sid[SID_SIZE-1] = '\0';
}

// api/auth
//  GET: Check authentication
//  POST: Login
//  DELETE: Logout
int api_auth(struct ftl_conn *api)
{
	// Check HTTP method
	char *password = NULL;
	const time_t now = time(NULL);
	const bool empty_password = config.webserver.api.pwhash.v.s[0] == '\0';

	if(api->item != NULL && strlen(api->item) > 0)
	{
		// Sub-paths are not allowed
		return 0;
	}

	// Login attempt, check password
	if(api->method == HTTP_POST)
	{
		// Try to extract response from payload
		const int ret = check_json_payload(api);
		if(ret != 0)
			return ret;

		// Check if password is available
		cJSON *json_password;
		if((json_password = cJSON_GetObjectItemCaseSensitive(api->payload.json, "password")) == NULL)
		{
			const char *message = "No password found in JSON payload";
			log_debug(DEBUG_API, "API auth error: %s", message);
			return send_json_error(api, 400,
			                       "bad_request",
			                       message,
			                       NULL);
		}

		// Check password type
		if(!cJSON_IsString(json_password))
		{
			const char *message = "Field password has to be of type 'string'";
			log_debug(DEBUG_API, "API auth error: %s", message);
			return send_json_error(api, 400,
			                       "bad_request",
			                       message,
			                       NULL);
		}

		// password is already null-terminated
		password = json_password->valuestring;
	}

	// Did the client authenticate before and we can validate this?
	int user_id = check_client_auth(api, false);

	// If this is a valid session, we can exit early at this point if no password is supplied
	if(user_id != API_AUTH_UNAUTHORIZED && (password == NULL || strlen(password) == 0))
		return send_api_auth_status(api, user_id, now);

	// Logout attempt
	if(api->method == HTTP_DELETE)
	{
		log_debug(DEBUG_API, "API Auth: User with ID %i wants to log out", user_id);
		return send_api_auth_status(api, user_id, now);
	}

	// If this is not a login attempt, we can exit early at this point
	if(password == NULL && !empty_password)
		return send_api_auth_status(api, user_id, now);

	// else: Login attempt
	// - Client tries to authenticate using a password, or
	// - There no password on this machine
	enum password_result result = PASSWORD_INCORRECT;

	// If there is no password (or empty), check if there is any password at all
	if(empty_password && (password == NULL || strlen(password) == 0))
		result = PASSWORD_CORRECT;
	else
		result = verify_login(password);

	if(result == PASSWORD_CORRECT ||
	   result == APPPASSWORD_CORRECT ||
	   result == CLIPASSWORD_CORRECT)
	{
		// Accepted

		// Zero-out password in memory to avoid leaking it when it is
		// freed at the end of the current API request
		if(password != NULL)
			memset(password, 0, strlen(password));

		// Check possible 2FA token
		// Successful login with empty password does not require 2FA
		if(strlen(config.webserver.api.totp_secret.v.s) > 0 && result == PASSWORD_CORRECT)
		{
			// Get 2FA token from payload
			cJSON *json_totp;
			if((json_totp = cJSON_GetObjectItemCaseSensitive(api->payload.json, "totp")) == NULL)
			{
				const char *message = "No 2FA token found in JSON payload";
				log_debug(DEBUG_API, "API auth error: %s", message);
				return send_json_error(api, 400,
							"bad_request",
							message,
							NULL);
			}

			enum totp_status totp = verifyTOTP(json_totp->valueint);
			if(totp == TOTP_REUSED)
			{
				// 2FA token has been reused
				return send_json_error(api, 401,
				                       "unauthorized",
				                       "Reused 2FA token",
				                       "wait for new token");
			}
			else if(totp == TOTP_RATE_LIMIT)
			{
				// 2FA validation requested too often
				return send_json_error(api, 429,
				                       "rate_limiting",
				                       "Rate-limiting 2FA token requests, try again later",
				                       NULL);
			}
			else if(totp != TOTP_CORRECT)
			{
				// 2FA token is invalid
				return send_json_error(api, 401,
				                       "unauthorized",
				                       "Invalid 2FA token",
				                       NULL);
			}
		}

		// Find unused authentication slot
		for(unsigned int i = 0; i < max_sessions; i++)
		{
			// Expired slow, mark as unused
			if(auth_data[i].used &&
			   auth_data[i].valid_until < now)
			{
				log_debug(DEBUG_API, "API: Session of client %u (%s) expired, freeing...",
				          i, auth_data[i].remote_addr);
				delete_session(i);
			}

			// Found unused authentication slot (might have been freed before)
			if(!auth_data[i].used)
			{
				// Mark as used
				auth_data[i].used = true;
				// Set validitiy to now + timeout
				auth_data[i].login_at = now;
				auth_data[i].valid_until = now + config.webserver.session.timeout.v.ui;
				// Set remote address
				strncpy(auth_data[i].remote_addr, api->request->remote_addr, sizeof(auth_data[i].remote_addr));
				auth_data[i].remote_addr[sizeof(auth_data[i].remote_addr)-1] = '\0';
				// Store user-agent (if available)
				const char *user_agent = mg_get_header(api->conn, "user-agent");
				if(user_agent != NULL)
				{
					strncpy(auth_data[i].user_agent, user_agent, sizeof(auth_data[i].user_agent));
					auth_data[i].user_agent[sizeof(auth_data[i].user_agent)-1] = '\0';
				}
				else
				{
					auth_data[i].user_agent[0] = '\0';
				}
				// Store X-Forwarded-For (if available)
				const char *x_forwarded_for = mg_get_header(api->conn, "X-Forwarded-For");
				if(x_forwarded_for != NULL)
				{
					strncpy(auth_data[i].x_forwarded_for, x_forwarded_for, sizeof(auth_data[i].x_forwarded_for));
					auth_data[i].x_forwarded_for[sizeof(auth_data[i].x_forwarded_for)-1] = '\0';
				}
				else
				{
					auth_data[i].x_forwarded_for[0] = '\0';
				}

				auth_data[i].tls.login = api->request->is_ssl;
				auth_data[i].tls.mixed = false;
				auth_data[i].app = result == APPPASSWORD_CORRECT;
				auth_data[i].cli = result == CLIPASSWORD_CORRECT;

				// Generate new SID and CSRF token
				generateSID(auth_data[i].sid);
				generateSID(auth_data[i].csrf);

				user_id = i;
				break;
			}
		}

		// Debug logging
		if(config.debug.api.v.b && user_id > API_AUTH_UNAUTHORIZED)
		{
			char timestr[TIMESTR_SIZE];
			get_timestr(timestr, auth_data[user_id].valid_until, false, false);
			log_debug(DEBUG_API, "API: Registered new user: user_id %i valid_until: %s remote_addr %s (accepted due to %s)",
					user_id, timestr, auth_data[user_id].remote_addr,
					empty_password ? "empty password" : "correct response");
		}
		if(user_id == API_AUTH_UNAUTHORIZED)
		{
			log_warn("No free API seats available (webserver.api.max_sessions = %u), not authenticating client",
			         max_sessions);

			return send_json_error(api, 429,
			                       "api_seats_exceeded",
			                       "API seats exceeded",
			                       "increase webserver.api.max_sessions");
		}

		api->message = result == APPPASSWORD_CORRECT ? "app-password correct" : "password correct";
	}
	else if(result == PASSWORD_RATE_LIMITED)
	{
		// Rate limited
		return send_json_error(api, 429,
		                       "rate_limiting",
		                       "Rate-limiting login attempts",
		                       NULL);
	}
	else if(result == NO_PASSWORD_SET)
	{
		// No password set
		api->message = "password incorrect";
		log_debug(DEBUG_API, "API: Trying to auth with password but none set: '%s'", password);
	}
	else
	{
		api->message = "password incorrect";
		log_debug(DEBUG_API, "API: Password incorrect: '%s'", password);
	}

	// Free allocated memory
	return send_api_auth_status(api, user_id, now);
}

int api_auth_sessions(struct ftl_conn *api)
{
	// Get session object
	cJSON *json = JSON_NEW_OBJECT();
	get_all_sessions(api, json);
	JSON_SEND_OBJECT(json);
}

int api_auth_session_delete(struct ftl_conn *api)
{
	// Get user ID
	int uid;
	if(sscanf(api->item, "%i", &uid) != 1)
		return send_json_error(api, 400, "bad_request", "Missing or invalid session ID", NULL);

	// Check if session ID is valid
	if(uid <= API_AUTH_UNAUTHORIZED || uid >= max_sessions)
		return send_json_error(api, 400, "bad_request", "Session ID out of bounds", NULL);

	// Check if session is used
	if(!auth_data[uid].used)
		return send_json_error(api, 400, "bad_request", "Session ID not in use", NULL);

	// Delete session
	const int code = delete_session(uid) ? 204 : 404;

	// Send empty reply with appropriate HTTP status code
	send_http_code(api, "application/json; charset=utf-8", code, "");
	return code;
}
