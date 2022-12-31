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
#include "api.h"
// {s,g}et_blockingstatus()
#include "../setupVars.h"
// set_blockingmode_timer()
#include "../timers.h"
#include "../shmem.h"
// getCacheInformation()
#include "../cache_info.h"
// config struct
#include "../config/config.h"

static int get_blocking(struct ftl_conn *api)
{
	// Return current status
	cJSON *json = JSON_NEW_OBJECT();
	const bool blocking = get_blockingstatus();
	JSON_ADD_BOOL_TO_OBJECT(json, "blocking", blocking);

	// Get timer information (if applicable)
	int delay;
	bool target_status;
	get_blockingmode_timer(&delay, &target_status);
	if(delay > -1)
	{
		JSON_ADD_NUMBER_TO_OBJECT(json, "timer", delay);
	}
	else
	{
		JSON_ADD_NULL_TO_OBJECT(json, "timer");
	}

	// Send object (HTTP 200 OK)
	JSON_SEND_OBJECT(json);
}

static int set_blocking(struct ftl_conn *api)
{
	// Verify requesting client is allowed to access this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	if (api->payload.json == NULL) {
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request body data (no valid JSON)",
		                       NULL);
	}

	cJSON *elem = cJSON_GetObjectItemCaseSensitive(api->payload.json, "blocking");
	if (!cJSON_IsBool(elem)) {
		return send_json_error(api, 400,
		                       "body_error",
		                       "No \"blocking\" boolean in body data",
		                       NULL);
	}
	const bool target_status = cJSON_IsTrue(elem);

	// Get (optional) timer
	int timer = -1;
	elem = cJSON_GetObjectItemCaseSensitive(api->payload.json, "timer");
	if (cJSON_IsNumber(elem) && elem->valuedouble > 0.0)
		timer = elem->valueint;

	if(target_status == get_blockingstatus())
	{
		// The blocking status does not need to be changed

		// Delete a possibly running timer
		set_blockingmode_timer(-1, true);
	}
	else
	{
		// Activate requested status
		set_blockingstatus(target_status);

		// Start timer (-1 disables all running timers)
		set_blockingmode_timer(timer, !target_status);
	}

	// Return GET property as result of POST/PUT/PATCH action
	// if no error happened above
	return get_blocking(api);
}

int api_dns_blocking(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
	{
		lock_shm();
		const int ret = get_blocking(api);
		unlock_shm();
		return ret;
	}
	else if(api->method == HTTP_POST)
	{
		lock_shm();
		const int ret = set_blocking(api);
		unlock_shm();
		return ret;
	}
	else
	{
		// This results in error 404
		return 0;
	}
}

int api_dns_cache(struct ftl_conn *api)
{
	// Verify requesting client is allowed to access this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	struct cache_info ci = { 0 };
	get_dnsmasq_cache_info(&ci);
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(json, "size", ci.cache_size);
	JSON_ADD_NUMBER_TO_OBJECT(json, "inserted", ci.cache_inserted);
	JSON_ADD_NUMBER_TO_OBJECT(json, "evicted", ci.cache_live_freed);
	cJSON *valid = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(valid, "ipv4", ci.valid.ipv4);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "ipv6", ci.valid.ipv6);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "cname", ci.valid.cname);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "srv", ci.valid.srv);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "ds", ci.valid.ds);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "dnskey", ci.valid.dnskey);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "other", ci.valid.other);
	JSON_ADD_ITEM_TO_OBJECT(json, "valid", valid);
	JSON_ADD_NUMBER_TO_OBJECT(json, "expired", ci.expired);
	JSON_ADD_NUMBER_TO_OBJECT(json, "immortal", ci.immortal);
	JSON_SEND_OBJECT(json);
}

int api_dns_port(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(json, "dns_port", config.dns_port);
	JSON_SEND_OBJECT(json);
}
