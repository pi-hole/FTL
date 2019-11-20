/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/ftl
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "http-common.h"
#include "routes.h"
#include "json_macros.h"
#include "datastructure.h"
// get_FTL_version()
#include "log.h"
// git constants
#include "version.h"

int api_ftl_clientIP(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const struct mg_request_info *request = mg_get_request_info(conn);
	JSON_OBJ_REF_STR(json,"remote_addr", request->remote_addr);
	JSON_SENT_OBJECT(json);
}
