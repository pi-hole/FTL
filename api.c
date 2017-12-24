/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  General API commands
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
#include "cJSON.h"

void sendAPIResponse(int sock, char type, char http_code) {
	sendAPIResponseWithCookie(sock, type, http_code, NULL);
}

void sendAPIResponseWithCookie(int sock, char type, char http_code, const long *session) {
	char *http_status;

	switch(http_code) {
		default:
		case OK:
			http_status = "200 OK";
			break;
		case BAD_REQUEST:
			http_status = "400 Bad Request";
			break;
		case INTERNAL_ERROR:
			http_status = "500 Internal Server Error";
			break;
		case NOT_FOUND:
			http_status = "404 Not Found";
			break;
		case UNAUTHORIZED:
			http_status = "401 Unauthorized";
			break;
	}

	// Send header only for full HTTP requests
	if(type == APIH)
	{
		if(session == NULL) {
			// No cookie to send
			ssend(sock,
			      "HTTP/1.0 %s\nServer: FTL\nCache-Control: no-cache\nAccess-Control-Allow-Origin: *\n"
					      "Content-Type: application/json\n\n{", http_status);
		}
		else {
			// Send cookie
			ssend(sock,
			      "HTTP/1.0 %s\nServer: FTL\nCache-Control: no-cache\nAccess-Control-Allow-Origin: *\n"
					      "Set-Cookie: FTL_SESSION=%ld\nContent-Type: application/json\n\n{", http_status, *session);
		}
	}
}

// session will have the client's valid session written to, if it's not unauthorized
enum Auth authenticate(char *with_headers, char *payload, long *session) {
	// First figure out if the client has authenticated before.
	char *sessionStr;
	AuthData *auth = NULL;

	// Find the cookie header (will contain a long int value)
	if(strstr(with_headers, "Cookie: ") != NULL && (sessionStr = strstr(with_headers, "FTL_SESSION=")) != NULL) {
		// Find the start of the cookie (strtol will stop once it gets to a non-numeric character)
		sessionStr += 12;

		// Convert to int
		*session = strtol(sessionStr, NULL, 10);

		if(errno == ERANGE) {
			logg("Failed to decode the authentication cookie");
			return AUTH_UNAUTHORIZED;
		}

		int i;
		for(i = 0; i < authLength; i++) {
			if(authData[i].valid && authData[i].session == *session) {
				auth = &authData[i];
				time_t currentTime = time(NULL);

				// Check to see if the session had expired (24 minutes)
				if(currentTime > auth->lastQueryTime + 1440) {
					authData[i].valid = false;
					return AUTH_UNAUTHORIZED;
				}

				auth->lastQueryTime = currentTime;
			}
		}

		// auth will be null if we didn't find a matching session
		if(auth == NULL)
			return AUTH_UNAUTHORIZED;
		return AUTH_PREVIOUS;
	}

	// Otherwise, check if they are trying to authenticate
	cJSON *input_root = cJSON_Parse(payload);
	cJSON *password_json = cJSON_GetObjectItemCaseSensitive(input_root, "password");

	if(!cJSON_IsString(password_json)) {
		cJSON_Delete(input_root);
		return AUTH_UNAUTHORIZED;
	}

	char *password = password_json->valuestring;

	// todo: use real password
	if(strcmp(password, "password") == 0) {
		auth = malloc(sizeof(AuthData));

		auth->lastQueryTime = time(NULL);

		// Find a unique session number
		while(true) {
			auth->session = random();

			bool unique = true;
			int i;
			for(i = 0; i < authLength; i++) {
				if(authData[i].session == auth->session) {
					unique = false;
					break;
				}
			}

			// Found a unique session number
			if(unique)
				break;
		}

		auth->valid = true;

		// Add to auth storage
		bool found = false;
		int i;
		for(i = 0; i < authLength; i++) {
			if(!authData[i].valid) {
				// Found an invalid auth we can reuse
				found = true;
				authData[i] = *auth;
				break;
			}
		}

		if(!found) {
			// Couldn't reuse any existing auth structures
			memory_check(AUTHDATA);
			authData[authLength] = *auth;
			authLength++;
		}

		*session = auth->session;
		free(auth);
		cJSON_Delete(input_root);

		return AUTH_NEW;
	}

	cJSON_Delete(input_root);

	return AUTH_UNAUTHORIZED;
}

char* getPayload(char *http_message) {
	char *data_start;
	char *unix_newline = strstr(http_message, "\n\n");
	char *win_newline = strstr(http_message, "\r\n\r\n");

	if(unix_newline != NULL)
		data_start = unix_newline + 2;
	else if(win_newline != NULL)
		data_start = win_newline + 4;
	else
		return NULL;

	if(strlen(data_start) == 0)
		return NULL;

	return data_start;
}

bool matchesRegex(char *regex_expression, char *input) {
	regex_t regex;
	int result;

	result = regcomp(&regex, regex_expression, REG_EXTENDED);

	if(result != 0) {
		logg("Failed to compile regex");
		exit(EXIT_FAILURE);
	}

	result = regexec(&regex, input, 0, NULL, 0);
	regfree(&regex);

	return result == 0;
}

bool isValidDomain(char *domain) {
	char *valid_chars_regex = "^((-|_)*[a-z0-9]((-|_)*[a-z0-9])*(-|_)*)(\\.(-|_)*([a-z0-9]((-|_)*[a-z0-9])*))*$";
	char *total_length_regex = "^.{1,253}$";
	char *label_length_regex = "^[^\\.]{1,63}(\\.[^\\.]{1,63})*$";

	return matchesRegex(valid_chars_regex, domain) &&
			matchesRegex(total_length_regex, domain) &&
			matchesRegex(label_length_regex, domain);
}
