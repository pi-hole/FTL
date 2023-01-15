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
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
// get_FTL_version()
#include "log.h"
#include "version.h"
// prase_line()
#include "files.h"

#define VERSIONS_FILE "/etc/pihole/versions"

int api_version(struct ftl_conn *api)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *key, *value;
	cJSON *core_local = JSON_NEW_OBJECT();
	cJSON *web_local = JSON_NEW_OBJECT();
	cJSON *ftl_local = JSON_NEW_OBJECT();
	cJSON *core_remote = JSON_NEW_OBJECT();
	cJSON *web_remote = JSON_NEW_OBJECT();
	cJSON *ftl_remote = JSON_NEW_OBJECT();
	cJSON *docker = JSON_NEW_OBJECT();

	FILE *fp = fopen(VERSIONS_FILE, "r");
	if(!fp)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to read " VERSIONS_FILE,
		                       NULL);

	// Loop over KEY=VALUE parts in the versions file
	while((read = getline(&line, &len, fp)) != -1)
	{
		if (parse_line(line, &key, &value))
			continue;

		if(strcmp(key, "CORE_BRANCH") == 0)
			JSON_COPY_STR_TO_OBJECT(core_local, "branch", value);
		else if(strcmp(key, "WEB_BRANCH") == 0)
			JSON_COPY_STR_TO_OBJECT(web_local, "branch", value);
		// Added below from the running FTL binary itself
		//else if(strcmp(key, "FTL_BRANCH") == 0)
		//	JSON_COPY_STR_TO_OBJECT(ftl_local, "branch", value);
		else if(strcmp(key, "CORE_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(core_local, "version", value);
		else if(strcmp(key, "WEB_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(web_local, "version", value);
		// Added below from the running FTL binary itself
		//else if(strcmp(key, "FTL_VERSION") == 0)
		//	JSON_COPY_STR_TO_OBJECT(ftl_local, "version", value);
		else if(strcmp(key, "GITHUB_CORE_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(core_remote, "version", value);
		else if(strcmp(key, "GITHUB_WEB_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(web_remote, "version", value);
		else if(strcmp(key, "GITHUB_FTL_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(ftl_remote, "version", value);
		else if(strcmp(key, "CORE_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(core_local, "hash", value);
		else if(strcmp(key, "WEB_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(web_local, "hash", value);
		else if(strcmp(key, "FTL_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(ftl_local, "hash", value);
		else if(strcmp(key, "GITHUB_CORE_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(core_remote, "hash", value);
		else if(strcmp(key, "GITHUB_WEB_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(web_remote, "hash", value);
		else if(strcmp(key, "GITHUB_FTL_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(ftl_remote, "hash", value);
		else if(strcmp(key, "DOCKER_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(docker, "local", value);
		else if(strcmp(key, "GITHUB_DOCKER_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(docker, "remote", value);
	}

	// Free allocated memory and release file pointer
	free(line);
	fclose(fp);

	// Add remaining properties to ftl object
	JSON_REF_STR_IN_OBJECT(ftl_local, "branch", GIT_BRANCH);
	JSON_REF_STR_IN_OBJECT(ftl_local, "version", get_FTL_version());
	JSON_REF_STR_IN_OBJECT(ftl_local, "date", GIT_DATE);

	cJSON *version = JSON_NEW_OBJECT();

	cJSON *core = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(core, "local", core_local);
	JSON_ADD_ITEM_TO_OBJECT(core, "remote", core_remote);
	JSON_ADD_ITEM_TO_OBJECT(version, "core", core);

	cJSON *web = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(web, "local", web_local);
	JSON_ADD_ITEM_TO_OBJECT(web, "remote", web_remote);
	JSON_ADD_ITEM_TO_OBJECT(version, "web", web);

	cJSON *ftl = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(ftl, "local", ftl_local);
	JSON_ADD_ITEM_TO_OBJECT(ftl, "remote", ftl_remote);
	JSON_ADD_ITEM_TO_OBJECT(version, "ftl", ftl);

	// Add nulls to docker if we didn't find any version
	if(!cJSON_HasObjectItem(docker, "local"))
		JSON_ADD_NULL_TO_OBJECT(docker, "local");
	if(!cJSON_HasObjectItem(docker, "remote"))
		JSON_ADD_NULL_TO_OBJECT(docker, "remote");
	JSON_ADD_ITEM_TO_OBJECT(version, "docker", docker);

	// Send reply
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "version", version);
	JSON_SEND_OBJECT(json);
}