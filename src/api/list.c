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
                         const char *item)
{
	const char *sql_msg = NULL;
	if(!gravityDB_readTable(listtype, item, &sql_msg))
	{
		cJSON *json = JSON_NEW_OBJ();

		// Add item (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "item", item);

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

	tablerow table;
	cJSON *rows = JSON_NEW_ARRAY();
	while(gravityDB_readTableGetRow(&table, &sql_msg))
	{
		cJSON *row = JSON_NEW_OBJ();

		// Special fields
		if(listtype == GRAVITY_GROUPS)
		{
			JSON_OBJ_COPY_STR(row, "name", table.name);
			JSON_OBJ_COPY_STR(row, "comment", table.comment);
		}
		else if(listtype == GRAVITY_ADLISTS)
		{
			JSON_OBJ_COPY_STR(row, "address", table.address);
			JSON_OBJ_COPY_STR(row, "comment", table.comment);
		}
		else if(listtype == GRAVITY_CLIENTS)
		{
			char *name = NULL;
			if(table.client != NULL)
			{
				// Try to obtain hostname if this is a valid IP address
				if(isValidIPv4(table.client) || isValidIPv6(table.client))
					name = getNameFromIP(table.client);
			}
			
			JSON_OBJ_COPY_STR(row, "client", table.client);
			JSON_OBJ_COPY_STR(row, "name", name);
			JSON_OBJ_COPY_STR(row, "comment", table.comment);

			// Free allocated memory (if applicable)
			if(name != NULL)
				free(name);
		}
		else // domainlists
		{
			JSON_OBJ_COPY_STR(row, "domain", table.domain);
			JSON_OBJ_REF_STR(row, "type", table.type);
			JSON_OBJ_REF_STR(row, "kind", table.kind);
			JSON_OBJ_COPY_STR(row, "comment", table.comment);
		}

		// Groups don't have the groups property
		if(listtype != GRAVITY_GROUPS)
		{
			if(table.group_ids != NULL) {
				// Black magic at work here: We build a JSON array from
				// the group_concat result delivered from the database,
				// parse it as valid array and append it as row to the
				// data
				char group_ids_str[strlen(table.group_ids)+3u];
				group_ids_str[0] = '[';
				strcpy(group_ids_str+1u , table.group_ids);
				group_ids_str[sizeof(group_ids_str)-2u] = ']';
				group_ids_str[sizeof(group_ids_str)-1u] = '\0';
				cJSON * group_ids = cJSON_Parse(group_ids_str);
				JSON_OBJ_ADD_ITEM(row, "groups", group_ids);
			} else {
				// Empty group set
				cJSON *group_ids = JSON_NEW_ARRAY();
				JSON_OBJ_ADD_ITEM(row, "groups", group_ids);
			}
		}

		// Clients don't have the enabled property
		if(listtype != GRAVITY_CLIENTS)
			JSON_OBJ_ADD_BOOL(row, "enabled", table.enabled);

		// Add read-only database parameters
		JSON_OBJ_ADD_NUMBER(row, "id", table.id);
		JSON_OBJ_ADD_NUMBER(row, "date_added", table.date_added);
		JSON_OBJ_ADD_NUMBER(row, "date_modified", table.date_modified);

		JSON_ARRAY_ADD_ITEM(rows, row);
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
		JSON_OBJ_ADD_ITEM(json, objname, rows);
		JSON_SEND_OBJECT_CODE(json, code);
	}
	else
	{
		JSON_DELETE(rows);
		cJSON *json = JSON_NEW_OBJ();

		// Add item (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "item", item);

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
                          const char *item,
                          char payload[MAX_PAYLOAD_BYTES])
{
	tablerow row = { 0 };

	// Check if valid JSON payload is available
	if (api->payload.json == NULL) {
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request body data (no valid JSON)",
		                       NULL);
	}

	if(api->method == HTTP_POST)
	{
		// Extract domain/name/client/address from payload whe using POST, all
		// others specify it as URI-component
		cJSON *json_domain, *json_name, *json_address, *json_client;
		switch(listtype)
		{
			case GRAVITY_DOMAINLIST_ALLOW_EXACT:
			case GRAVITY_DOMAINLIST_ALLOW_REGEX:
			case GRAVITY_DOMAINLIST_DENY_EXACT:
			case GRAVITY_DOMAINLIST_DENY_REGEX:
				json_domain = cJSON_GetObjectItemCaseSensitive(api->payload.json, "domain");
				if(cJSON_IsString(json_domain) && strlen(json_domain->valuestring) > 0)
				{
					row.item = json_domain->valuestring;
				}
				else
				{
					cJSON *uri = JSON_NEW_OBJ();
					JSON_OBJ_REF_STR(uri, "path", api->action_path);
					JSON_OBJ_REF_STR(uri, "item", item);
					return send_json_error(api, 400,
					                       "uri_error",
					                       "Invalid request: No item \"domain\" in payload",
					                       uri);
				}
				break;

			case GRAVITY_GROUPS:
				json_name = cJSON_GetObjectItemCaseSensitive(api->payload.json, "name");
				if(cJSON_IsString(json_name) && strlen(json_name->valuestring) > 0)
					row.item = json_name->valuestring;
				else
				{
					cJSON *uri = JSON_NEW_OBJ();
					JSON_OBJ_REF_STR(uri, "path", api->action_path);
					JSON_OBJ_REF_STR(uri, "item", item);
					return send_json_error(api, 400,
					                       "uri_error",
					                       "Invalid request: No item \"name\" in payload",
					                       uri);
				}
				break;

			case GRAVITY_CLIENTS:
				json_client = cJSON_GetObjectItemCaseSensitive(api->payload.json, "client");
				if(cJSON_IsString(json_client) && strlen(json_client->valuestring) > 0)
					row.item = json_client->valuestring;
				else
				{
					cJSON *uri = JSON_NEW_OBJ();
					JSON_OBJ_REF_STR(uri, "path", api->action_path);
					JSON_OBJ_REF_STR(uri, "item", item);
					return send_json_error(api, 400,
					                       "uri_error",
					                       "Invalid request: No item \"client\" in payload",
					                       uri);
				}
				break;

			case GRAVITY_ADLISTS:
				json_address = cJSON_GetObjectItemCaseSensitive(api->payload.json, "address");
				if(cJSON_IsString(json_address) && strlen(json_address->valuestring) > 0)
					row.item = json_address->valuestring;
				else
				{
					cJSON *uri = JSON_NEW_OBJ();
					JSON_OBJ_REF_STR(uri, "path", api->action_path);
					JSON_OBJ_REF_STR(uri, "item", item);
					return send_json_error(api, 400,
					                       "uri_error",
					                       "Invalid request: No item \"address\" in payload",
					                       uri);
				}
				break;
			
			// Aggregate types are not handled by this routine
			case GRAVITY_DOMAINLIST_ALL_ALL:
			case GRAVITY_DOMAINLIST_ALL_EXACT:
			case GRAVITY_DOMAINLIST_ALL_REGEX:
			case GRAVITY_DOMAINLIST_ALLOW_ALL:
			case GRAVITY_DOMAINLIST_DENY_ALL:
				return 500;
		}
	}
	else
	{
		// PUT = Use URI item
		row.item = item;
	}
	

	cJSON *json_comment = cJSON_GetObjectItemCaseSensitive(api->payload.json, "comment");
	if(cJSON_IsString(json_comment) && strlen(json_comment->valuestring) > 0)
		row.comment = json_comment->valuestring;
	else
		row.comment = NULL; // Default value

	cJSON *json_oldtype = cJSON_GetObjectItemCaseSensitive(api->payload.json, "oldtype");
	if(cJSON_IsString(json_oldtype) && strlen(json_oldtype->valuestring) > 0)
		row.oldtype = json_oldtype->valuestring;
	else
		row.oldtype = NULL; // Default value

	cJSON *json_oldkind = cJSON_GetObjectItemCaseSensitive(api->payload.json, "oldkind");
	if(cJSON_IsString(json_oldkind) && strlen(json_oldkind->valuestring) > 0)
		row.oldkind = json_oldkind->valuestring;
	else
		row.oldkind = NULL; // Default value

	cJSON *json_enabled = cJSON_GetObjectItemCaseSensitive(api->payload.json, "enabled");
	if (cJSON_IsBool(json_enabled))
		row.enabled = cJSON_IsTrue(json_enabled);
	else
		row.enabled = true; // Default value

	bool okay = true;
	char *regex_msg = NULL;
	if(listtype == GRAVITY_DOMAINLIST_ALLOW_REGEX || listtype == GRAVITY_DOMAINLIST_DENY_REGEX)
	{
		// Test validity of this regex
		regexData regex = { 0 };
		okay = compile_regex(row.domain, &regex, &regex_msg);
	}

	// Try to add item to table
	const char *sql_msg = NULL;
	if(okay && (okay = gravityDB_addToTable(listtype, &row, &sql_msg, api->method)))
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
		JSON_OBJ_REF_STR(json, "item", row.item);
		JSON_OBJ_ADD_BOOL(json, "enabled", row.enabled);
		if(row.comment != NULL)
			JSON_OBJ_REF_STR(json, "comment", row.comment);
		if(row.name != NULL)
			JSON_OBJ_REF_STR(json, "name", row.name);
		if(row.oldtype != NULL)
			JSON_OBJ_REF_STR(json, "oldtype", row.oldtype);

		// Add SQL message (may be NULL = not available)
		const char *errortype = "database_error";
		const char *errormsg  = "Could not add to gravity database";
		JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);

		// Add regex error (may not be available)
		JSON_OBJ_COPY_STR(json, "regex_msg", regex_msg);
		if (regex_msg != NULL) {
			free(regex_msg);
			regex_msg = NULL;
			// Change error type and message
			errortype = "regex_error";
			errormsg = "Regex validation failed";
		} else {
			JSON_OBJ_ADD_NULL(json, "regex_msg");
		}

		// Send error reply
		return send_json_error(api, 400, // 400 Bad Request
		                       errortype,
		                       errormsg,
		                       json);
	}
	// else: everything is okay

	// Inform the resolver that it needs to reload the domainlists
	set_event(RELOAD_GRAVITY);

	int response_code = 201; // 201 - Created
	if(api->method == HTTP_PUT)
		response_code = 200; // 200 - OK
	// Send GET style reply
	return api_list_read(api, response_code, listtype, row.item);
}

static int api_list_remove(struct ftl_conn *api,
                           const enum gravity_list_type listtype,
                           const char *item)
{
	cJSON *json = JSON_NEW_OBJ(); 
	const char *sql_msg = NULL;
	if(gravityDB_delFromTable(listtype, item, &sql_msg))
	{
		// Inform the resolver that it needs to reload the domainlists
		set_event(RELOAD_GRAVITY);

		// Send empty reply with code 204 No Content
		JSON_SEND_OBJECT_CODE(json, 204);
	}
	else
	{
		// Add item
		JSON_OBJ_REF_STR(json, "item", item);

		// Add SQL message (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);

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
	if((api->item = startsWith("/api/groups", api)) != NULL)
	{
		listtype = GRAVITY_GROUPS;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/lists", api)) != NULL)
	{
		listtype = GRAVITY_ADLISTS;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/clients", api)) != NULL)
	{
		listtype = GRAVITY_CLIENTS;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/domains/allow/exact", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_ALLOW_EXACT;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/domains/allow/regex", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_ALLOW_REGEX;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/domains/allow", api)) != NULL)
	{
			listtype = GRAVITY_DOMAINLIST_ALLOW_ALL;
	}
	else if((api->item = startsWith("/api/domains/deny/exact", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_DENY_EXACT;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/domains/deny/regex", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_DENY_REGEX;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/domains/deny", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_DENY_ALL;
	}
	else if((api->item = startsWith("/api/domains/exact", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_ALL_EXACT;
	}
	else if((api->item = startsWith("/api/domains/regex", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_ALL_REGEX;
	}
	else if((api->item = startsWith("/api/domains", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_ALL_ALL;
	}
	else
	{
			cJSON *json = JSON_NEW_OBJ();
			JSON_OBJ_REF_STR(json, "uri", api->request->local_uri);
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid request: Specified endpoint not available",
			                       json);
	}

	if(api->method == HTTP_GET)
	{
		// Read list item identified by URI (or read them all)
		return api_list_read(api, 200, listtype, api->item);
	}
	else if(can_modify && api->method == HTTP_PUT)
	{
		// Add/update item identified by URI
		if(api->item != NULL && strlen(api->item) == 0)
		{
			cJSON *uri = JSON_NEW_OBJ();
			if(api->action_path != NULL)
			JSON_OBJ_REF_STR(uri, "path", api->action_path);
			JSON_OBJ_REF_STR(uri, "item", api->item);
			return send_json_error(api, 400,
			                       "uri_error",
			                       "Invalid request: Specify item in URI",
			                       uri);
		}
		else
			return api_list_write(api, listtype, api->item, payload);
	}
	else if(can_modify && api->method == HTTP_POST)
	{
		// Add item to list identified by payload
		if(api->item != NULL && strlen(api->item) != 0)
		{
			cJSON *uri = JSON_NEW_OBJ();
			JSON_OBJ_REF_STR(uri, "path", api->action_path);
			JSON_OBJ_REF_STR(uri, "item", api->item);
			return send_json_error(api, 400,
			                       "uri_error",
			                       "Invalid request: Specify item in payload, not as URI parameter",
			                       uri);
		}
		else
			return api_list_write(api, listtype, api->item, payload);
	}
	else if(can_modify && api->method == HTTP_DELETE)
	{
		// Delete item from list
		return api_list_remove(api, listtype, api->item);
	}
	else if(!can_modify)
	{
		// This list type cannot be modified (e.g., ALL_ALL)
		cJSON *uri = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(uri, "path", api->action_path);
		JSON_OBJ_REF_STR(uri, "item", api->item);
		return send_json_error(api, 400,
		                       "uri_error",
		                       "Invalid request: Specify list to modify more precisely",
		                       uri);
	}
	else
	{
		// This results in error 404
		return 0;
	}
}
