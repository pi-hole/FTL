/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Custom DNS
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
#include "database/gravity-db.h"
#include "webserver/json_macros.h"
#include "events.h"

static int api_customdns_get(struct ftl_conn *api)
{
	sqlite3 *db = gravityDB_get_handle();
	if (!db) return send_json_error(api, 500, "database_error", "Gravity database not available", NULL);

	const char *sql = "SELECT c.id, c.domain, c.ip, c.type, c.ttl, c.comment, group_concat(g.group_id) as groups "
	                  "FROM custom_dns c "
	                  "LEFT JOIN custom_dns_by_group g ON c.id = g.custom_dns_id "
	                  "GROUP BY c.id";

	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) return send_json_error(api, 500, "database_error", sqlite3_errmsg(db), NULL);

	cJSON *rows = JSON_NEW_ARRAY();
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		cJSON *row = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(row, "id", sqlite3_column_int(stmt, 0));
		const char *domain = (const char*)sqlite3_column_text(stmt, 1);
		if(domain) JSON_COPY_STR_TO_OBJECT(row, "domain", domain);
		const char *ip = (const char*)sqlite3_column_text(stmt, 2);
		if(ip) JSON_COPY_STR_TO_OBJECT(row, "ip", ip);
		JSON_ADD_NUMBER_TO_OBJECT(row, "type", sqlite3_column_int(stmt, 3));
		JSON_ADD_NUMBER_TO_OBJECT(row, "ttl", sqlite3_column_int(stmt, 4));
		const char *comment = (const char*)sqlite3_column_text(stmt, 5);
		if (comment) JSON_COPY_STR_TO_OBJECT(row, "comment", comment);

		const char *groups = (const char*)sqlite3_column_text(stmt, 6);
		cJSON *groups_array = JSON_NEW_ARRAY();
		if (groups)
		{
			// Parse comma separated groups
			char *g = strdup(groups);
			char *p = strtok(g, ",");
			while (p) {
				cJSON_AddItemToArray(groups_array, cJSON_CreateNumber(atoi(p)));
				p = strtok(NULL, ",");
			}
			free(g);
		}
		JSON_ADD_ITEM_TO_OBJECT(row, "groups", groups_array);

		JSON_ADD_ITEM_TO_ARRAY(rows, row);
	}
	sqlite3_finalize(stmt);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "data", rows);
	JSON_SEND_OBJECT(json);
}

static int api_customdns_add(struct ftl_conn *api)
{
	sqlite3 *db = gravityDB_get_handle();
	if (!db) return send_json_error(api, 500, "database_error", "Gravity database not available", NULL);

	cJSON *json = api->payload.json;
	if (!json) return send_json_error(api, 400, "bad_request", "Missing JSON payload", NULL);

	const char *domain = cJSON_GetStringValue(cJSON_GetObjectItem(json, "domain"));
	const char *ip = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ip"));
	cJSON *type_item = cJSON_GetObjectItem(json, "type");
	cJSON *ttl_item = cJSON_GetObjectItem(json, "ttl");
	const char *comment = cJSON_GetStringValue(cJSON_GetObjectItem(json, "comment"));
	cJSON *groups = cJSON_GetObjectItem(json, "groups");

	if (!domain || !ip) return send_json_error(api, 400, "bad_request", "Missing domain or ip", NULL);

	int type = cJSON_IsNumber(type_item) ? type_item->valueint : 0;
	int ttl = cJSON_IsNumber(ttl_item) ? ttl_item->valueint : 0;

	sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

	sqlite3_stmt *stmt;
	const char *sql = "INSERT INTO custom_dns (domain, ip, type, ttl, comment) VALUES (?, ?, ?, ?, ?)";
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		return send_json_error(api, 500, "database_error", sqlite3_errmsg(db), NULL);
	}

	sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 3, type);
	sqlite3_bind_int(stmt, 4, ttl);
	if (comment) sqlite3_bind_text(stmt, 5, comment, -1, SQLITE_STATIC);
	else sqlite3_bind_null(stmt, 5);

	if (sqlite3_step(stmt) != SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		return send_json_error(api, 500, "database_error", sqlite3_errmsg(db), NULL);
	}
	sqlite3_finalize(stmt);

	sqlite3_int64 id = sqlite3_last_insert_rowid(db);

	if (cJSON_IsArray(groups) && cJSON_GetArraySize(groups) > 0)
	{
		// Remove the default group added by trigger
		sql = "DELETE FROM custom_dns_by_group WHERE custom_dns_id = ?";
		rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
		if (rc == SQLITE_OK)
		{
			sqlite3_bind_int64(stmt, 1, id);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
		}

		cJSON *g;
		cJSON_ArrayForEach(g, groups)
		{
			if (cJSON_IsNumber(g))
			{
				sql = "INSERT INTO custom_dns_by_group (custom_dns_id, group_id) VALUES (?, ?)";
				rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
				if (rc == SQLITE_OK)
				{
					sqlite3_bind_int64(stmt, 1, id);
					sqlite3_bind_int(stmt, 2, g->valueint);
					sqlite3_step(stmt);
					sqlite3_finalize(stmt);
				}
			}
		}
	}
	// Else: trigger already added group 0

	sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

	// Trigger reload/re-resolve
	// set_event(RELOAD_GRAVITY); // This might be too heavy?
	// Maybe just nothing as it's DB based.

	cJSON *response = JSON_NEW_OBJECT();
	JSON_COPY_STR_TO_OBJECT(response, "status", "success");
	JSON_ADD_NUMBER_TO_OBJECT(response, "id", id);
	JSON_SEND_OBJECT(response);
}

static int api_customdns_delete(struct ftl_conn *api)
{
	sqlite3 *db = gravityDB_get_handle();
	if (!db) return send_json_error(api, 500, "database_error", "Gravity database not available", NULL);

	cJSON *json = api->payload.json;
	if (!json) return send_json_error(api, 400, "bad_request", "Missing JSON payload", NULL);

	cJSON *id_item = cJSON_GetObjectItem(json, "id");
	if (!cJSON_IsNumber(id_item)) return send_json_error(api, 400, "bad_request", "Missing or invalid id", NULL);

	int id = id_item->valueint;

	sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

	sqlite3_stmt *stmt;
	const char *sql = "DELETE FROM custom_dns WHERE id = ?";
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		return send_json_error(api, 500, "database_error", sqlite3_errmsg(db), NULL);
	}
	sqlite3_bind_int(stmt, 1, id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	// Trigger tr_custom_dns_delete handles deletion from custom_dns_by_group

	sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

	cJSON *response = JSON_NEW_OBJECT();
	JSON_COPY_STR_TO_OBJECT(response, "status", "success");
	JSON_SEND_OBJECT(response);
}

int api_customdns(struct ftl_conn *api)
{
	if (api->method == HTTP_GET)
		return api_customdns_get(api);
	else if (api->method == HTTP_POST)
		return api_customdns_add(api);
	else if (api->method == HTTP_DELETE)
		return api_customdns_delete(api);
	
	return send_json_error(api, 405, "method_not_allowed", "Method not allowed", NULL);
}
