/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/{allow,deny}list
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
#include "../database/gravity-db.h"

static int api_list_read(struct mg_connection *conn,
                         const int code,
                         const enum gravity_list_type listtype,
                         const char *argument)
{
	const char *sql_msg = NULL;
	if(!gravityDB_readTable(listtype, argument, &sql_msg))
	{
		cJSON *json = JSON_NEW_OBJ();

		// Add argument (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "argument", argument);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		return send_json_error(conn, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not read domains from database table",
		                       json);
	}

	tablerow row;
	cJSON *items = JSON_NEW_ARRAY();
	while(gravityDB_readTableGetRow(&row, &sql_msg))
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "id", row.id);
		JSON_OBJ_ADD_BOOL(item, "enabled", row.enabled);

		// Special fields
		if(listtype == GRAVITY_GROUPS)
		{
			JSON_OBJ_COPY_STR(item, "name", row.name);
			if(row.description != NULL) {
				JSON_OBJ_COPY_STR(item, "description", row.description);
			} else {
				JSON_OBJ_ADD_NULL(item, "description");
			}
		}
		else if(listtype == GRAVITY_ADLISTS)
		{
			JSON_OBJ_COPY_STR(item, "address", row.address);
			if(row.comment != NULL) {
				JSON_OBJ_COPY_STR(item, "comment", row.comment);
			} else {
				JSON_OBJ_ADD_NULL(item, "comment");
			}
		}
		else // domainlists
		{
			JSON_OBJ_REF_STR(item, "type", row.type);
			JSON_OBJ_COPY_STR(item, "domain", row.domain);
			if(row.comment != NULL) {
				JSON_OBJ_COPY_STR(item, "comment", row.comment);
			} else {
				JSON_OBJ_ADD_NULL(item, "comment");
			}
			if(row.group_ids != NULL) {
				// Black JSON magic at work here:
				// We build a JSON array from the group_concat
				// result delivered SQLite3, parse it as valid
				// array and append it as item to the data
				char group_ids_str[strlen(row.group_ids)+3u];
				group_ids_str[0] = '[';
				strcpy(group_ids_str+1u , row.group_ids);
				group_ids_str[sizeof(group_ids_str)-2u] = ']';
				group_ids_str[sizeof(group_ids_str)-1u] = '\0';
				cJSON * group_ids = cJSON_Parse(group_ids_str);
				JSON_OBJ_ADD_ITEM(item, "group_ids", group_ids);
			} else {
				// Empty group set
				cJSON *group_ids = JSON_NEW_ARRAY();
				JSON_OBJ_ADD_ITEM(item, "group_ids", group_ids);
			}
		}
		
		JSON_OBJ_ADD_NUMBER(item, "date_added", row.date_added);
		JSON_OBJ_ADD_NUMBER(item, "date_modified", row.date_modified);

		JSON_ARRAY_ADD_ITEM(items, item);
	}
	gravityDB_readTableFinalize();

	if(sql_msg == NULL)
	{
		// No error, send domains array
		const char *objname;
		cJSON *json = JSON_NEW_OBJ();
		if(listtype == GRAVITY_GROUPS)
			objname = "groups";
		else if(listtype == GRAVITY_ADLISTS)
			objname = "adlists";
		else // domainlists
			objname = "domains";
		JSON_OBJ_ADD_ITEM(json, objname, items);
		JSON_SEND_OBJECT_CODE(json, code);
	}
	else
	{
		JSON_DELETE(items);
		cJSON *json = JSON_NEW_OBJ();

		// Add argument (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "argument", argument);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		return send_json_error(conn, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not read from gravity database",
		                       json);
	}
}

static int api_list_write(struct mg_connection *conn,
                          const enum gravity_list_type listtype,
                          const enum http_method method,
                          const char *argument)
{
	tablerow row = { 0 };

	// Set argument
	row.argument = argument;

	// Extract payload
	char payload[1024] = { 0 };
	http_get_payload(conn, payload, sizeof(payload));

	cJSON *obj = cJSON_Parse(payload);
	if (obj == NULL) {
		return send_json_error(conn, 400,
		                       "bad_request",
		                       "Invalid request body data",
		                       NULL);
	}

	cJSON *json_enabled = cJSON_GetObjectItemCaseSensitive(obj, "enabled");
	if (!cJSON_IsBool(json_enabled)) {
		cJSON_Delete(obj);
		return send_json_error(conn, 400,
		                       "bad_request",
		                       "No \"enabled\" boolean in body data",
		                       NULL);
	}
	row.enabled = cJSON_IsTrue(json_enabled);

	cJSON *json_comment = cJSON_GetObjectItemCaseSensitive(obj, "comment");
	if(cJSON_IsString(json_comment))
		row.comment = json_comment->valuestring;
	else
		row.comment = NULL;

	cJSON *json_description = cJSON_GetObjectItemCaseSensitive(obj, "description");
	if(cJSON_IsString(json_description))
		row.description = json_description->valuestring;
	else
		row.description = NULL;

	cJSON *json_name = cJSON_GetObjectItemCaseSensitive(obj, "name");
	if(cJSON_IsString(json_name))
		row.name = json_name->valuestring;
	else
		row.name = NULL;

	cJSON *json_oldtype = cJSON_GetObjectItemCaseSensitive(obj, "oldtype");
	if(cJSON_IsString(json_oldtype))
		row.oldtype = json_oldtype->valuestring;
	else
		row.oldtype = NULL;

	// Try to add domain to table
	const char *sql_msg = NULL;
	bool okay = false;
	if(gravityDB_addToTable(listtype, &row, &sql_msg, method))
	{
		cJSON *groups = cJSON_GetObjectItemCaseSensitive(obj, "groups");
		if(groups != NULL)
			okay = gravityDB_edit_groups(listtype, groups, &row, &sql_msg);
	}
	if(!okay)
	{
		// Error adding domain, prepare error object
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(json, "argument", argument);
		JSON_OBJ_ADD_BOOL(json, "enabled", row.enabled);
		if(row.comment != NULL)
			JSON_OBJ_REF_STR(json, "comment", row.comment);
		if(row.description != NULL)
			JSON_OBJ_REF_STR(json, "description", row.description);
		if(row.name != NULL)
			JSON_OBJ_REF_STR(json, "name", row.name);
		if(row.oldtype != NULL)
			JSON_OBJ_REF_STR(json, "oldtype", row.oldtype);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		// Free memory not needed any longer
		cJSON_Delete(obj);

		// Send error reply
		return send_json_error(conn, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not add to gravity database",
		                       json);
	}
	// else: everything is okay

	// Free memory not needed any longer
	cJSON_Delete(obj);

	// Send GET style reply with code 201 Created
	return api_list_read(conn, 201, listtype, argument);
}

static int api_list_remove(struct mg_connection *conn,
                           const enum gravity_list_type listtype,
                           const char *argument)
{
	cJSON *json = JSON_NEW_OBJ(); 
	const char *sql_msg = NULL;
	if(gravityDB_delFromTable(listtype, argument, &sql_msg))
	{
		// Send empty reply with code 204 No Content
		JSON_SEND_OBJECT_CODE(json, 204);
	}
	else
	{
		// Add argument
		JSON_OBJ_REF_STR(json, "argument", argument);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		// Send error reply
		return send_json_error(conn, 400,
		                       "database_error",
		                       "Could not remove domain from database table",
		                       json);
	}
}

int api_list(struct mg_connection *conn)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(conn) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(conn);
	}

	enum gravity_list_type listtype;
	bool can_modify = false;
	const struct mg_request_info *request = mg_get_request_info(conn);
	const char *argument = NULL;
	if((argument = startsWith("/api/group", request->local_uri)) != NULL)
	{
		listtype = GRAVITY_GROUPS;
		can_modify = true;
	}
	else if((argument = startsWith("/api/adlist", request->local_uri)) != NULL)
	{
		listtype = GRAVITY_ADLISTS;
		can_modify = true;
	}
	else if((argument = startsWith("/api/list/allow", request->local_uri)) != NULL)
	{
		if((argument = startsWith("/api/list/allow/exact", request->local_uri)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_ALLOW_EXACT;
			can_modify = true;
		}
		else if((argument = startsWith("/api/list/allow/regex", request->local_uri)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_ALLOW_REGEX;
			can_modify = true;
		}
		else
			listtype = GRAVITY_DOMAINLIST_ALLOW_ALL;
	}
	else if((argument = startsWith("/api/list/deny", request->local_uri)) != NULL)
	{
		if((argument = startsWith("/api/list/deny/exact", request->local_uri)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_DENY_EXACT;
			can_modify = true;
		}
		else if((argument = startsWith("/api/list/deny/regex", request->local_uri)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_DENY_REGEX;
			can_modify = true;
		}
		else
			listtype = GRAVITY_DOMAINLIST_DENY_ALL;
	}
	else
	{
		if((argument = startsWith("/api/list/exact", request->local_uri)) != NULL)
			listtype = GRAVITY_DOMAINLIST_ALL_EXACT;
		else if((argument = startsWith("/api/list/regex", request->local_uri)) != NULL)
			listtype = GRAVITY_DOMAINLIST_ALL_REGEX;
		else
		{
			argument = startsWith("/api/list", request->local_uri);
			listtype = GRAVITY_DOMAINLIST_ALL_ALL;
		}
	}

	const enum http_method method = http_method(conn);
	if(method == HTTP_GET)
	{
		return api_list_read(conn, 200, listtype, argument);
	}
	else if(can_modify && (method == HTTP_POST || method == HTTP_PUT || method == HTTP_PATCH))
	{
		// Add item from list
		return api_list_write(conn, listtype, method, argument);
	}
	else if(can_modify && method == HTTP_DELETE)
	{
		// Delete item from list
		return api_list_remove(conn, listtype, argument);
	}
	else if(!can_modify)
	{
		// This list type cannot be modified (e.g., ALL_ALL)
		return send_json_error(conn, 400,
		                       "bad_request",
		                       "Invalid request: Specify list to modify",
		                       NULL);
	}
	else
	{
		// This results in error 404
		return 0;
	}
}
