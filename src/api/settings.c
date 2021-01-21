/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/settings
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"

int api_settings_web(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "layout", "boxed");
	JSON_OBJ_REF_STR(json, "language", "en");
	JSON_SEND_OBJECT(json);
}