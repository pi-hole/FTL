/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/{white,black}list
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
#include "../database/gravity-db.h"

static int getTableType(bool whitelist, bool exact)
{
	if(whitelist)
		if(exact)
			return GRAVITY_DOMAINLIST_EXACT_WHITELIST;
		else
			return GRAVITY_DOMAINLIST_REGEX_WHITELIST;
	else
		if(exact)
			return GRAVITY_DOMAINLIST_EXACT_BLACKLIST;
		else
			return GRAVITY_DOMAINLIST_REGEX_BLACKLIST;
}

static int get_domainlist(struct mg_connection *conn, const int code, const int type, const char *domain_filter)
{
	const char *sql_msg = NULL;
	if(!gravityDB_readTable(type, domain_filter, &sql_msg))
	{
		cJSON *json = JSON_NEW_OBJ();

		// Add domain_filter (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "domain_filter", domain_filter);

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

	domainrecord domain;
	cJSON *json = JSON_NEW_ARRAY();
	while(gravityDB_readTableGetDomain(&domain, &sql_msg))
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(item, "domain", domain.domain);
		JSON_OBJ_ADD_BOOL(item, "enabled", domain.enabled);
		JSON_OBJ_ADD_NUMBER(item, "date_added", domain.date_added);
		JSON_OBJ_ADD_NUMBER(item, "date_modified", domain.date_modified);
		JSON_OBJ_COPY_STR(item, "comment", domain.comment);
		JSON_ARRAY_ADD_ITEM(json, item);
	}
	gravityDB_readTableFinalize();

	if(sql_msg == NULL)
	{
		// No error, send requested HTTP code
		JSON_SEND_OBJECT_CODE(json, code);
	}
	else
	{
		JSON_DELETE(json);
		json = JSON_NEW_OBJ();

		// Add domain_filter (may be NULL = not available)
		JSON_OBJ_REF_STR(json, "domain_filter", domain_filter);

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

static int api_dns_domainlist_read(struct mg_connection *conn, bool exact, bool whitelist)
{
	// Extract domain from path (option for GET)
	const struct mg_request_info *request = mg_get_request_info(conn);
	char domain_filter[1024];
	// Advance one character to strip "/"
	const char *encoded_uri = strrchr(request->local_uri, '/')+1u;
	// Decode URL (necessary for regular expressions, harmless for domains)
	if(strlen(encoded_uri) != 0 && strcmp(encoded_uri, "exact") != 0 && strcmp(encoded_uri, "regex") != 0)
		mg_url_decode(encoded_uri, strlen(encoded_uri), domain_filter, sizeof(domain_filter), 0);

	const int type = getTableType(whitelist, exact);
		// Send GET style reply with code 200 OK
	return get_domainlist(conn, 200, type, domain_filter);
}

static int api_dns_domainlist_write(struct mg_connection *conn,
                                    bool exact,
                                    bool whitelist,
                                    const enum http_method method)
{
	// Extract payload
	char buffer[1024];
	int data_len = mg_read(conn, buffer, sizeof(buffer) - 1);
	if ((data_len < 1) || (data_len >= (int)sizeof(buffer))) {
		return send_json_error(conn, 400,
                                       "bad_request", "No request body data",
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
	size_t len = strlen(elem_domain->valuestring);
	char domain[len];
	strcpy(domain, elem_domain->valuestring);

	bool enabled = true;
	cJSON *elem_enabled = cJSON_GetObjectItemCaseSensitive(obj, "enabled");
	if (cJSON_IsBool(elem_enabled)) {
		enabled = cJSON_IsTrue(elem_enabled);
	}

	char *comment = NULL;
	cJSON *elem_comment = cJSON_GetObjectItemCaseSensitive(obj, "comment");
	if (cJSON_IsString(elem_comment)) {
		comment = elem_comment->valuestring;
	}

	// Try to add domain to table
	const char *sql_msg = NULL;
	int type = getTableType(whitelist, exact);
	if(gravityDB_addToTable(type, domain, enabled, comment, &sql_msg, method))
	{
		cJSON_Delete(obj);
		// Send GET style reply with code 201 Created
		return get_domainlist(conn, 201, type, domain);
	}
	else
	{
		// Error adding domain, prepare error object
		// Add domain
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(json, "domain", domain);

		// Add enabled boolean
		JSON_OBJ_ADD_BOOL(json, "enabled", enabled);

		// Add comment (may be NULL)
		if (comment != NULL) {
			JSON_OBJ_COPY_STR(json, "comment", comment);
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

static int api_dns_domainlist_remove(struct mg_connection *conn,
                                     bool exact,
                                     bool whitelist)
{
	const struct mg_request_info *request = mg_get_request_info(conn);

	char domain[1024];
	// Advance one character to strip "/"
	const char *encoded_uri = strrchr(request->local_uri, '/')+1u;
	// Decode URL (necessary for regular expressions, harmless for domains)
	mg_url_decode(encoded_uri, strlen(encoded_uri), domain, sizeof(domain)-1u, 0);

	cJSON *json = JSON_NEW_OBJ(); 
	const char *sql_msg = NULL;
	int type = getTableType(whitelist, exact);
	if(gravityDB_delFromTable(type, domain, &sql_msg))
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

int api_dns_domainlist(struct mg_connection *conn, bool exact, bool whitelist)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(conn) < 0)
	{
		return send_json_unauthorized(conn);
	}

	const enum http_method method = http_method(conn);
	if(method == HTTP_GET)
	{
		return api_dns_domainlist_read(conn, exact, whitelist);
	}
	else if(method == HTTP_POST || method == HTTP_PUT || method == HTTP_PATCH)
	{
		// Add domain from exact white-/blacklist when a user sends
		// the request to the general address /api/dns/{white,black}list
		return api_dns_domainlist_write(conn, exact, whitelist, method);
	}
	else if(method == HTTP_DELETE)
	{
		// Delete domain from exact white-/blacklist when a user sends
		// the request to the general address /api/dns/{white,black}list
		return api_dns_domainlist_remove(conn, exact, whitelist);
	}
	else
	{
		// This results in error 404
		return 0;
	}
}
