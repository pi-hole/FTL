/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/dns
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "dns.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
// {s,g}et_blockingstatus()
#include "../setupVars.h"
// set_blockingmode_timer()
#include "../timers.h"

int api_dns_status(struct mg_connection *conn)
{
	int method = http_method(conn);
	if(method == HTTP_GET)
	{
		// Return current status
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "status", (get_blockingstatus() ? "active" : "inactive"));
		JSON_SEND_OBJECT(json);
	}
	else if(method == HTTP_POST)
	{
		// Verify requesting client is allowed to access this ressource
		if(check_client_auth(conn) < 0)
		{
			return send_json_unauthorized(conn);
		}

		char buffer[1024];
		int data_len = mg_read(conn, buffer, sizeof(buffer) - 1);
		if ((data_len < 1) || (data_len >= (int)sizeof(buffer))) {
			return send_json_error(conn, 400,
			                       "bad_request", "No request body data",
			                       NULL);
		}
		buffer[data_len] = '\0';

		cJSON *obj = cJSON_Parse(buffer);
		if (obj == NULL) {
			return send_json_error(conn, 400,
			                       "bad_request",
			                       "Invalid request body data",
			                        NULL);
		}

		cJSON *elem1 = cJSON_GetObjectItemCaseSensitive(obj, "status");
		if (!cJSON_IsString(elem1)) {
			cJSON_Delete(obj);
			return send_json_error(conn, 400,
			                       "bad_request",
			                       "No \"action\" string in body data",
			                       NULL);
		}
		const char *action = elem1->valuestring;

		unsigned int delay = -1;
		cJSON *elem2 = cJSON_GetObjectItemCaseSensitive(obj, "time");
		if (cJSON_IsNumber(elem2) && elem2->valuedouble > 0.0)
		{
			delay = elem2->valueint;
		}

		cJSON *json = JSON_NEW_OBJ();
		if(strcmp(action, "active") == 0)
		{
			cJSON_Delete(obj);
			JSON_OBJ_REF_STR(json, "status", "active");
			// If no "time" key was present, we call this subroutine with
			// delay == -1 which will disable all previously set timers
			set_blockingmode_timer(delay, false);
			set_blockingstatus(true);
		}
		else if(strcmp(action, "inactive") == 0)
		{
			cJSON_Delete(obj);
			JSON_OBJ_REF_STR(json, "status", "inactive");
			// If no "time" key was present, we call this subroutine with
			// delay == -1 which will disable all previously set timers
			set_blockingmode_timer(delay, true);
			set_blockingstatus(false);
		}
		else
		{
			cJSON_Delete(obj);
			return send_json_error(conn, 400,
			                       "bad_request",
			                       "Invalid \"action\" requested",
			                       NULL);
		}
		JSON_SEND_OBJECT(json);
	}
	else
	{
		// This results in error 404
		return 0;
	}
}

int api_dns_cacheinfo(struct mg_connection *conn)
{
	// Verify requesting client is allowed to access this ressource
	if(check_client_auth(conn) < 0)
	{
		return send_json_unauthorized(conn);
	}

	cacheinforecord cacheinfo;
	getCacheInformation(&cacheinfo);
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(json, "cache_size", cacheinfo.cache_size);
	JSON_OBJ_ADD_NUMBER(json, "cache_inserted", cacheinfo.cache_inserted);
	JSON_OBJ_ADD_NUMBER(json, "cache_evicted", cacheinfo.cache_live_freed);
	JSON_SEND_OBJECT(json);
}
