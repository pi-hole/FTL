/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/version
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
// get_FTL_version()
#include "log.h"
#include "version.h"

int api_version(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();

	cJSON *api = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(api, "branch", "none");
	JSON_OBJ_REF_STR(api, "hash", "none");
	JSON_OBJ_REF_STR(api, "tag", "none");
	JSON_OBJ_ADD_ITEM(json, "api", api);

	FILE* file;
	char coreversion[256] = "N/A";
	char webversion[256]  = "N/A";
	if((file = fopen("/etc/pihole/localversions", "r")) != NULL)
	{
		igr(fscanf(file, "%255s %255s", coreversion, webversion));
		fclose(file);
	}
	char corebranch[256] = "N/A";
	char webbranch[256]  = "N/A";
	if((file = fopen("/etc/pihole/localbranches", "r")) != NULL)
	{
		igr(fscanf(file, "%255s %255s", corebranch, webbranch));
		fclose(file);
	}

	cJSON *web = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(web, "branch", webbranch);
	JSON_OBJ_REF_STR(web, "hash", "none");
	JSON_OBJ_REF_STR(web, "tag", webversion);
	JSON_OBJ_ADD_ITEM(json, "web", web);

	cJSON *core = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(core, "branch", corebranch);
	JSON_OBJ_REF_STR(core, "hash", "none");
	JSON_OBJ_REF_STR(core, "tag", coreversion);
	JSON_OBJ_ADD_ITEM(json, "core", core);

	cJSON *ftl = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(ftl, "branch", GIT_BRANCH);
	JSON_OBJ_REF_STR(ftl, "hash", GIT_HASH);
	char *version = get_FTL_version();
	JSON_OBJ_COPY_STR(ftl, "tag", version);
	JSON_OBJ_ADD_ITEM(json, "ftl", ftl);
	free(version);

	JSON_SENT_OBJECT(json);
}