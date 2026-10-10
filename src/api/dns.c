/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/dns
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
// {s,g}et_blockingstatus()
#include "config/setupVars.h"
// set_temp_blockingstatus()
#include "timers.h"
#include "shmem.h"
// config struct
#include "config/config.h"

// Location of custom.list
#include "config/dnsmasq_config.h"

#define DOMAIN_VALIDATION_REGEX "^((-|_)*[a-z0-9]((-|_)*[a-z0-9])*(-|_)*)(\\.(-|_)*([a-z0-9]((-|_)*[a-z0-9])*))*$"
#define LABEL_VALIDATION_REGEX "^[^\\.]{1,63}(\\.[^\\.]{1,63})*$"

static int get_blocking(struct ftl_conn *api)
{
	// Return current status
	cJSON *json = JSON_NEW_OBJECT();
	const enum blocking_status blocking = get_blockingstatus();
	const char *status = get_blocking_status_str(blocking);
	JSON_REF_STR_IN_OBJECT(json, "blocking", status);

	// Get timer information (if applicable)
	const double delay = get_temp_blockingstatus_timer();
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
	if(get_blockingstatus() == DNS_FAILED)
	{
		return send_json_error(api, 500,
		                       "dns_failure",
		                       "DNS resolver is not running",
		                       NULL);
	}

	// Check if the payload is valid JSON
	const int ret = check_json_payload(api);
	if(ret != 0)
		return ret;

	cJSON *elem = cJSON_GetObjectItemCaseSensitive(api->payload.json, "blocking");
	if (!cJSON_IsBool(elem))
	{
		return send_json_error(api, 400,
		                       "body_error",
		                       "No \"blocking\" boolean in body data",
		                       NULL);
	}
	const bool target_status = cJSON_IsTrue(elem);

	// Get (optional) timer
	double time = -1;
	elem = cJSON_GetObjectItemCaseSensitive(api->payload.json, "timer");
	if (cJSON_IsNumber(elem) && elem->valuedouble > 0.0)
		time = elem->valuedouble;

	if(time > 0)
	{
		// Once the timer expires, the configured status applies again,
		// so that has to be the opposite of the requested one
		set_temp_blockingstatus(target_status, time);
		if(config.dns.blocking.active.v.b == target_status)
			set_blockingstatus(!target_status);

		log_web_debug(DEBUG_API, "%sd Pi-hole for %f seconds", target_status ? "Enable" : "Disable", time);
	}
	else
	{
		// A status without timer is permanent and ends a temporary one
		if(config.dns.blocking.active.v.b != target_status)
			set_blockingstatus(target_status);
		clear_temp_blockingstatus();

		log_web_debug(DEBUG_API, "%sd Pi-hole", target_status ? "Enable" : "Disable");
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
		lock_config();
		lock_shm();
		const int ret = set_blocking(api);
		unlock_shm();
		unlock_config();
		return ret;
	}
	else
	{
		return send_json_error(api, 405, "method_not_allowed", "Method not allowed", NULL);
	}
}
