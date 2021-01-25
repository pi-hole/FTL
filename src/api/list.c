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
#include "../events.h"
// getNameFromIP()
#include "../database/network-table.h"

static int api_list_read(struct ftl_conn *api,
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

		return send_json_error(api, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not read domains from database table",
		                       json);
	}

	tablerow row;
	cJSON *items = JSON_NEW_ARRAY();
	while(gravityDB_readTableGetRow(&row, &sql_msg))
	{
		cJSON *item = JSON_NEW_OBJ();

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
		else if(listtype == GRAVITY_CLIENTS)
		{
			if(row.ip != NULL)
			{
				JSON_OBJ_COPY_STR(item, "ip", row.ip);
				char *name = getNameFromIP(row.ip);
				if(name != NULL)
				{
					JSON_OBJ_COPY_STR(item, "name", name);
					free(name);
				}
				else
				{
					JSON_OBJ_ADD_NULL(item, "name");
				}
			}
			else
			{
				JSON_OBJ_ADD_NULL(item, "ip");
				JSON_OBJ_ADD_NULL(item, "name");
			}

			if(row.comment != NULL) {
				JSON_OBJ_COPY_STR(item, "comment", row.comment);
			} else {
				JSON_OBJ_ADD_NULL(item, "comment");
			}
		}
		else // domainlists
		{
			JSON_OBJ_COPY_STR(item, "domain", row.domain);
			JSON_OBJ_REF_STR(item, "type", row.type);
			if(row.comment != NULL) {
				JSON_OBJ_COPY_STR(item, "comment", row.comment);
			} else {
				JSON_OBJ_ADD_NULL(item, "comment");
			}
		}

		if(row.group_ids != NULL) {
			// Black magic at work here: We build a JSON array from
			// the group_concat result delivered from the database,
			// parse it as valid array and append it as item to the
			// data
			logg("row.group_ids = %p \"%s\"", row.group_ids, row.group_ids);
			char group_ids_str[strlen(row.group_ids)+3u];
			group_ids_str[0] = '[';
			strcpy(group_ids_str+1u , row.group_ids);
			group_ids_str[sizeof(group_ids_str)-2u] = ']';
			group_ids_str[sizeof(group_ids_str)-1u] = '\0';
			cJSON * group_ids = cJSON_Parse(group_ids_str);
			JSON_OBJ_ADD_ITEM(item, "groups", group_ids);
		} else {
			// Empty group set
			cJSON *group_ids = JSON_NEW_ARRAY();
			JSON_OBJ_ADD_ITEM(item, "groups", group_ids);
		}

		// Clients don't have the enabled property
		if(listtype != GRAVITY_CLIENTS)
			JSON_OBJ_ADD_BOOL(item, "enabled", row.enabled);

		cJSON *database = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(database, "id", row.id);
		JSON_OBJ_ADD_NUMBER(database, "date_added", row.date_added);
		JSON_OBJ_ADD_NUMBER(database, "date_modified", row.date_modified);
		JSON_OBJ_ADD_ITEM(item, "database", database);

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
			objname = "lists";
		else if(listtype == GRAVITY_CLIENTS)
			objname = "clients";
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

		return send_json_error(api, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not read from gravity database",
		                       json);
	}
}

static int api_list_write(struct ftl_conn *api,
                          const enum gravity_list_type listtype,
                          const char *argument,
                          char payload[MAX_PAYLOAD_BYTES])
{
	tablerow row = { 0 };

	// Set argument
	row.argument = argument;

	// Check argument is not empty
	if (api->method == HTTP_PUT && strlen(argument) < 1) {
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Missing argument, check URI",
		                       NULL);
	}

	// Check if valid JSON payload is available
	if (api->payload.json == NULL) {
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request body data",
		                       NULL);
	}

	// Clients don't have the enabled property
	if(listtype != GRAVITY_CLIENTS)
	{
		cJSON *json_enabled = cJSON_GetObjectItemCaseSensitive(api->payload.json, "enabled");
		if (!cJSON_IsBool(json_enabled)) {
			return send_json_error(api, 400,
					"bad_request",
					"No \"enabled\" boolean in body data",
					NULL);
		}
		row.enabled = cJSON_IsTrue(json_enabled);
	}

	cJSON *json_item = cJSON_GetObjectItemCaseSensitive(api->payload.json, "item");
	if(cJSON_IsString(json_item) && strlen(json_item->valuestring) > 0)
		row.item = json_item->valuestring;
	else if(api->method == HTTP_PUT)
		row.item = NULL;
	else
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "No \"item\" string in body data",
		                       NULL);
	}

	cJSON *json_comment = cJSON_GetObjectItemCaseSensitive(api->payload.json, "comment");
	if(cJSON_IsString(json_comment) && strlen(json_comment->valuestring) > 0)
		row.comment = json_comment->valuestring;
	else
		row.comment = NULL;

	cJSON *json_description = cJSON_GetObjectItemCaseSensitive(api->payload.json, "description");
	if(cJSON_IsString(json_description) && strlen(json_description->valuestring) > 0)
		row.description = json_description->valuestring;
	else
		row.description = NULL;

	cJSON *json_oldtype = cJSON_GetObjectItemCaseSensitive(api->payload.json, "oldtype");
	if(cJSON_IsString(json_oldtype) && strlen(json_oldtype->valuestring) > 0)
		row.oldtype = json_oldtype->valuestring;
	else
		row.oldtype = NULL;

	bool okay = true;
	char *regex_msg = NULL;
	if(listtype == GRAVITY_DOMAINLIST_ALLOW_REGEX || listtype == GRAVITY_DOMAINLIST_DENY_REGEX)
	{
		// Test validity of this regex
		regexData regex = { 0 };
		okay = compile_regex(argument, &regex, &regex_msg);
	}

	// Try to add item to table
	const char *sql_msg = NULL;
	if(okay && gravityDB_addToTable(listtype, &row, &sql_msg, api->method))
	{
		if(listtype != GRAVITY_GROUPS)
		{
			cJSON *groups = cJSON_GetObjectItemCaseSensitive(api->payload.json, "groups");
			if(groups != NULL)
				okay = gravityDB_edit_groups(listtype, groups, &row, &sql_msg);
			else
				// The groups array is optional, we still succeed if it
				// is omitted (groups stay as they are)
				okay = true;
		}
		else
		{
			// Groups cannot be assigned to groups
			okay = true;
		}
	}
	if(!okay)
	{
		// Error adding item, prepare error object
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

		// Add regex error (may not be available)
		if (regex_msg != NULL) {
			JSON_OBJ_COPY_STR(json, "regex_msg", regex_msg);
			free(regex_msg);
			regex_msg = NULL;
		} else {
			JSON_OBJ_ADD_NULL(json, "regex_msg");
		}

		// Send error reply
		return send_json_error(api, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not add to gravity database",
		                       json);
	}
	// else: everything is okay

	// Inform the resolver that it needs to reload the domainlists
	set_event(RELOAD_GRAVITY);

	int response_code = 201; // 201 - Created
	if(api->method == HTTP_PUT)
		response_code = 200; // 200 - OK
	// Send GET style reply
	return api_list_read(api, response_code, listtype, argument);
}

static int api_list_remove(struct ftl_conn *api,
                           const enum gravity_list_type listtype,
                           const char *argument)
{
	cJSON *json = JSON_NEW_OBJ(); 
	const char *sql_msg = NULL;
	if(gravityDB_delFromTable(listtype, argument, &sql_msg))
	{
		// Inform the resolver that it needs to reload the domainlists
		set_event(RELOAD_GRAVITY);

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
		return send_json_error(api, 400,
		                       "database_error",
		                       "Could not remove domain from database table",
		                       json);
	}
}

int api_list(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	char payload[MAX_PAYLOAD_BYTES] = { 0 };
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	enum gravity_list_type listtype;
	bool can_modify = false;
	const char *argument = NULL;
	if((argument = startsWith("/api/groups", api)) != NULL)
	{
		listtype = GRAVITY_GROUPS;
		can_modify = true;
	}
	else if((argument = startsWith("/api/lists", api)) != NULL)
	{
		listtype = GRAVITY_ADLISTS;
		can_modify = true;
	}
	else if((argument = startsWith("/api/clients", api)) != NULL)
	{
		listtype = GRAVITY_CLIENTS;
		can_modify = true;
	}
	else if((argument = startsWith("/api/domains/allow", api)) != NULL)
	{
		if((argument = startsWith("/api/domains/allow/exact", api)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_ALLOW_EXACT;
			can_modify = true;
		}
		else if((argument = startsWith("/api/domains/allow/regex", api)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_ALLOW_REGEX;
			can_modify = true;
		}
		else
			listtype = GRAVITY_DOMAINLIST_ALLOW_ALL;
	}
	else if((argument = startsWith("/api/domains/deny", api)) != NULL)
	{
		if((argument = startsWith("/api/domains/deny/exact", api)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_DENY_EXACT;
			can_modify = true;
		}
		else if((argument = startsWith("/api/domains/deny/regex", api)) != NULL)
		{
			listtype = GRAVITY_DOMAINLIST_DENY_REGEX;
			can_modify = true;
		}
		else
			listtype = GRAVITY_DOMAINLIST_DENY_ALL;
	}
	else
	{
		if((argument = startsWith("/api/domains/exact", api)) != NULL)
			listtype = GRAVITY_DOMAINLIST_ALL_EXACT;
		else if((argument = startsWith("/api/domains/regex", api)) != NULL)
			listtype = GRAVITY_DOMAINLIST_ALL_REGEX;
		else
		{
			argument = startsWith("/api/domains", api);
			listtype = GRAVITY_DOMAINLIST_ALL_ALL;
		}
	}

	if(api->method == HTTP_GET)
	{
		// Read list item identified by URI (or read them all)
		return api_list_read(api, 200, listtype, argument);
	}
	else if(can_modify && api->method == HTTP_PUT)
	{
		// Add/update item identified by URI
		return api_list_write(api, listtype, argument, payload);
	}
	else if(can_modify && api->method == HTTP_POST)
	{
		// Add item to list identified by payload
		if(strlen(argument) != 0)
		{
			cJSON *json = JSON_NEW_OBJ();
			JSON_OBJ_REF_STR(json, "uri_param", argument);
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid request: Specify item in payload, not as URI parameter",
			                       json);
		}
		else
			return api_list_write(api, listtype, argument, payload);
	}
	else if(can_modify && api->method == HTTP_DELETE)
	{
		// Delete item from list
		return api_list_remove(api, listtype, argument);
	}
	else if(!can_modify)
	{
		// This list type cannot be modified (e.g., ALL_ALL)
		return send_json_error(api, 400,
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
