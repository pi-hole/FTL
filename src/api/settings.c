/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/settings
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
// get_FTL_db_filesize()
#include "files.h"
// get_sqlite3_version()
#include "database/common.h"
// get_number_of_queries_in_DB()
#include "database/query-table.h"

int api_settings_web(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "layout", "boxed");
	JSON_OBJ_REF_STR(json, "language", "en");
	JSON_SENT_OBJECT(json);
}

int api_settings_ftldb(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const int db_filesize = get_FTL_db_filesize();
	JSON_OBJ_ADD_NUMBER(json, "filesize", db_filesize);
	const int queries_in_database = get_number_of_queries_in_DB();
	JSON_OBJ_ADD_NUMBER(json, "queries", queries_in_database);
	JSON_OBJ_REF_STR(json, "sqlite_version", get_sqlite3_version());
	JSON_SENT_OBJECT(json);
}