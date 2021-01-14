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

static int get_list(struct mg_connection *conn,
                    const int code,
                    const enum gravity_list_type listtype,
                    const char *filter)
{
	const char *sql_msg = NULL;
	if(!gravityDB_readTable(listtype, filter, &sql_msg))
	{
		cJSON *json = JSON_NEW_OBJ();

		// Add filter (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "filter", filter);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		return send_json_error(conn, 402, // 402 Request Failed
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
		else // domainlists
			objname = "domains";
		JSON_OBJ_ADD_ITEM(json, objname, items);
		JSON_SEND_OBJECT_CODE(json, code);
	}
	else
	{
		JSON_DELETE(items);
		cJSON *json = JSON_NEW_OBJ();

		// Add filter (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "filter", filter);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		return send_json_error(conn, 402, // 402 Request Failed
		                       "database_error",
		                       "Could not read domains from database table",
		                       json);
	}
}

static int api_list_read(struct mg_connection *conn,
                         const enum gravity_list_type listtype)
{
	// Extract domain from path (option for GET)
	const struct mg_request_info *request = mg_get_request_info(conn);
	char domain_filter[1024] = { 0 };

	// Advance one character to strip "/"
	const char *encoded_uri = strrchr(request->local_uri, '/')+1u;

	// Decode URL (necessary for regular expressions, harmless for domains)
	if(strlen(encoded_uri) != 0 &&
	   strcmp(encoded_uri, "exact") != 0 &&
	   strcmp(encoded_uri, "regex") != 0 &&
	   strcmp(encoded_uri, "allow") != 0 &&
	   strcmp(encoded_uri, "deny") != 0 &&
	   strcmp(encoded_uri, "list") != 0 &&
	   strcmp(encoded_uri, "group") != 0)
		mg_url_decode(encoded_uri, strlen(encoded_uri), domain_filter, sizeof(domain_filter), 0);

	return get_list(conn, 200, listtype, domain_filter);
}

static int api_list_write(struct mg_connection *conn,
                          const enum gravity_list_type listtype,
                          const enum http_method method)
{
	tablerow domain;

	// Extract payload
	char buffer[1024] = { 0 };
	int data_len = mg_read(conn, buffer, sizeof(buffer) - 1);
	if ((data_len < 1) || (data_len >= (int)sizeof(buffer))) {
		return send_json_error(conn, 400,
		                       "bad_request",
		                       "No request body data",
		                       NULL);
	}
	buffer[data_len] = '\0';

	cJSON *obj = cJSON_Parse(buffer);
	if (obj == NULL) {
		return send_json_error(conn, 400,
		                       "bad_request",
		                       "Invalid request body data",
		                       NULL);
	}

	cJSON *elem_domain = cJSON_GetObjectItemCaseSensitive(obj, "domain");
	if (!cJSON_IsString(elem_domain)) {
		cJSON_Delete(obj);
		return send_json_error(conn, 400,
		                "bad_request",
		                "No \"domain\" string in body data",
		                NULL);
	}
	domain.domain = elem_domain->valuestring;

	domain.enabled = true;
	cJSON *elem_enabled = cJSON_GetObjectItemCaseSensitive(obj, "enabled");
	if (cJSON_IsBool(elem_enabled)) {
		domain.enabled = cJSON_IsTrue(elem_enabled);
	}

	domain.comment = NULL;
	cJSON *elem_comment = cJSON_GetObjectItemCaseSensitive(obj, "comment");
	if (cJSON_IsString(elem_comment)) {
		domain.comment = elem_comment->valuestring;
	}

	// Try to add domain to table
	const char *sql_msg = NULL;
	if(gravityDB_addToTable(listtype, domain, &sql_msg, method))
	{
		cJSON_Delete(obj);
		// Send GET style reply with code 201 Created
		return get_list(conn, 201, listtype, domain.domain);
	}
	else
	{
		// Error adding domain, prepare error object
		// Add domain
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(json, "domain", domain.domain);

		// Add enabled boolean
		JSON_OBJ_ADD_BOOL(json, "enabled", domain.enabled);

		// Add comment (may be NULL)
		if (domain.comment != NULL) {
			JSON_OBJ_COPY_STR(json, "comment", domain.comment);
		} else {
			JSON_OBJ_ADD_NULL(json, "comment");
		}

		// Only delete payload object after having extracted the data
		cJSON_Delete(obj);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		// Send error reply
		return send_json_error(conn, 402, // 402 Request Failed
		                       "database_error",
		                       "Could not add domain to gravity database",
		                       json);
	}
}

static int api_list_remove(struct mg_connection *conn,
                                     const enum gravity_list_type listtype)
{
	const struct mg_request_info *request = mg_get_request_info(conn);

	char domain[1024] = { 0 };
	// Advance one character to strip "/"
	const char *encoded_uri = strrchr(request->local_uri, '/')+1u;
	// Decode URL (necessary for regular expressions, harmless for domains)
	mg_url_decode(encoded_uri, strlen(encoded_uri), domain, sizeof(domain)-1u, 0);

	cJSON *json = JSON_NEW_OBJ(); 
	const char *sql_msg = NULL;
	if(gravityDB_delFromTable(listtype, domain, &sql_msg))
	{
		// Send empty reply with code 204 No Content
		JSON_SEND_OBJECT_CODE(json, 204);
	}
	else
	{
		// Add domain
		JSON_OBJ_REF_STR(json, "domain", domain);

		// Add SQL message (may be NULL = not available)
		if (sql_msg != NULL) {
			JSON_OBJ_REF_STR(json, "sql_msg", sql_msg);
		} else {
			JSON_OBJ_ADD_NULL(json, "sql_msg");
		}

		// Send error reply
		return send_json_error(conn, 402,
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
	if(startsWith("/api/group", request->local_uri))
	{
		listtype = GRAVITY_GROUPS;
		can_modify = true;
	}
	else if(startsWith("/api/list/allow", request->local_uri))
	{
		if(startsWith("/api/list/allow/exact", request->local_uri))
		{
			listtype = GRAVITY_DOMAINLIST_ALLOW_EXACT;
			can_modify = true;
		}
		else if(startsWith("/api/list/allow/regex", request->local_uri))
		{
			listtype = GRAVITY_DOMAINLIST_ALLOW_REGEX;
			can_modify = true;
		}
		else
			listtype = GRAVITY_DOMAINLIST_ALLOW_ALL;
	}
	else if(startsWith("/api/list/deny", request->local_uri))
	{
		if(startsWith("/api/list/deny/exact", request->local_uri))
		{
			listtype = GRAVITY_DOMAINLIST_DENY_EXACT;
			can_modify = true;
		}
		else if(startsWith("/api/list/deny/regex", request->local_uri))
		{
			listtype = GRAVITY_DOMAINLIST_DENY_REGEX;
			can_modify = true;
		}
		else
			listtype = GRAVITY_DOMAINLIST_DENY_ALL;
	}
	else
	{
		if(startsWith("/api/list/exact", request->local_uri))
			listtype = GRAVITY_DOMAINLIST_ALL_EXACT;
		else if(startsWith("/api/list/regex", request->local_uri))
			listtype = GRAVITY_DOMAINLIST_ALL_REGEX;
		else
			listtype = GRAVITY_DOMAINLIST_ALL_ALL;
	}

	const enum http_method method = http_method(conn);
	if(method == HTTP_GET)
	{
		return api_list_read(conn, listtype);
	}
	else if(can_modify && (method == HTTP_POST || method == HTTP_PUT || method == HTTP_PATCH))
	{
		// Add item from list
		return api_list_write(conn, listtype, method);
	}
	else if(can_modify && method == HTTP_DELETE)
	{
		// Delete item from list
		return api_list_remove(conn, listtype);
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
