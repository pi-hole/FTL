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
#include "api.h"
#include "datastructure.h"
// get_FTL_db_filesize()
#include "files.h"
// get_FTL_version()
#include "log.h"
// get_sqlite3_version()
#include "database/common.h"
// get_number_of_queries_in_DB()
#include "database/query-table.h"
// git constants
#include "version.h"

int api_ftl_clientIP(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const struct mg_request_info *request = mg_get_request_info(conn);
	JSON_OBJ_REF_STR(json,"remote_addr", request->remote_addr);
	JSON_SENT_OBJECT(json);
}

int api_ftl_version(struct mg_connection *conn)
{
	const char *commit = GIT_HASH;
	const char *branch = GIT_BRANCH;
	const char *tag = GIT_TAG;
	const char *date = GIT_DATE;
	const char *version = get_FTL_version();

	// Extract first 7 characters of the hash
	char hash[8];
	memcpy(hash, commit, 7); hash[7] = 0;

	cJSON *json = JSON_NEW_OBJ();
	if(strlen(tag) > 1) {
		JSON_OBJ_REF_STR(json, "version", version);
	} else {
		char *vDev = NULL;
		if(asprintf(&vDev, "vDev-%s", hash) > 0)
		{
			JSON_OBJ_COPY_STR(json, "version", version);
			// We can free here as the string has
			// been copied into the JSON structure
			free(vDev);
		}
	}
	JSON_OBJ_REF_STR(json, "tag", tag);
	JSON_OBJ_REF_STR(json, "branch", branch);
	JSON_OBJ_REF_STR(json, "hash", hash);
	JSON_OBJ_REF_STR(json, "date", date);
	JSON_SENT_OBJECT(json);
}

int api_ftl_db(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const int queries_in_database = get_number_of_queries_in_DB();
	JSON_OBJ_ADD_NUMBER(json, "queries in database", queries_in_database);
	const int db_filesize = get_FTL_db_filesize();
	JSON_OBJ_ADD_NUMBER(json, "database filesize", db_filesize);
	JSON_OBJ_REF_STR(json, "SQLite version", get_sqlite3_version());
	JSON_SENT_OBJECT(json);
}
