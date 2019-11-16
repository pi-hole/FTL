/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/dns
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
// counters
#include "shmem.h"
#include "database/gravity-db.h"
#include "log.h"

int api_dns_status(struct mg_connection *conn)
{
	// Send status
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "status", (counters->gravity > 0 ? "enabled" : "disabled"));
	JSON_SENT_OBJECT(json);
}

static int api_dns_somelist_read(struct mg_connection *conn,
                                 bool show_exact, bool show_regex,
                                 bool whitelist)
{
	cJSON *exact = NULL;
	cJSON *regex = NULL;
	const char *domain = NULL;
	int rowid = 0;

	if(show_exact)
	{
		exact = JSON_NEW_ARRAY()
		gravityDB_getTable(whitelist ? EXACT_WHITELIST_TABLE : EXACT_BLACKLIST_TABLE);
		while((domain = gravityDB_getDomain(&rowid)) != NULL)
		{
			JSON_ARRAY_COPY_STR(exact, domain);
		}
		gravityDB_finalizeTable();
	}

	if(show_regex)
	{
		regex = JSON_NEW_ARRAY()
		gravityDB_getTable(whitelist ? REGEX_WHITELIST_TABLE : REGEX_BLACKLIST_TABLE);
		while((domain = gravityDB_getDomain(&rowid)) != NULL)
		{
			JSON_ARRAY_COPY_STR(regex, domain);
		}
		gravityDB_finalizeTable();
	}
	if(show_exact && ! show_regex)
	{
		JSON_SENT_OBJECT(exact);
	}
	else if(!show_exact && show_regex)
	{
		JSON_SENT_OBJECT(regex);
	}
	else
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_ITEM(json, "exact", exact);
		JSON_OBJ_ADD_ITEM(json, "regex", regex);
		JSON_SENT_OBJECT(json);
	}
}

static int api_dns_somelist_POST(struct mg_connection *conn,
                                   bool store_exact,
                                   bool whitelist)
{
	char buffer[1024];
	int data_len = mg_read(conn, buffer, sizeof(buffer) - 1);
	if ((data_len < 1) || (data_len >= (int)sizeof(buffer))) {
		mg_send_http_error(conn, 400, "%s", "No request body data");
		return 400;
	}
	buffer[data_len] = '\0';

	cJSON *obj = cJSON_Parse(buffer);
	if (obj == NULL) {
		mg_send_http_error(conn, 400, "%s", "Invalid request body data");
		return 400;
	}

	cJSON *elem = cJSON_GetObjectItemCaseSensitive(obj, "domain");

	if (!cJSON_IsString(elem)) {
		cJSON_Delete(obj);
		mg_send_http_error(conn, 400, "%s", "No \"domain\" string in body data");
		return 400;
	}
	const char *domain = elem->valuestring;

	const char *table;
	if(whitelist)
		if(store_exact)
			table = "whitelist";
		else
			table = "regex_whitelist";
	else
		if(store_exact)
			table = "blacklist";
		else
			table = "regex_blacklist";

	cJSON *json = JSON_NEW_OBJ();
	if(gravityDB_addToTable(table, domain))
	{
		JSON_OBJ_REF_STR(json, "key", "added");
		JSON_OBJ_COPY_STR(json, "domain", domain);
		cJSON_Delete(obj);
		JSON_SENT_OBJECT(json);
	}
	else
	{
		JSON_OBJ_REF_STR(json, "key", "error");
		JSON_OBJ_COPY_STR(json, "domain", domain);
		cJSON_Delete(obj);
		// Send 500 internal server error
		JSON_SENT_OBJECT_CODE(json, 500);
	}
}

static int api_dns_somelist_DELETE(struct mg_connection *conn,
                                   bool store_exact,
                                   bool whitelist)
{
	const struct mg_request_info *request = mg_get_request_info(conn);

	char domain[1024];
	// Advance one character to strip "/"
	const char *encoded_uri = strrchr(request->local_uri, '/')+1u;
	// Decode URL (necessar for regular expressions, harmless for domains)
	mg_url_decode(encoded_uri, strlen(encoded_uri), domain, sizeof(domain)-1u, 0);

	const char *table;
	if(whitelist)
		if(store_exact)
			table = "whitelist";
		else
			table = "regex_whitelist";
	else
		if(store_exact)
			table = "blacklist";
		else
			table = "regex_blacklist";

	cJSON *json = JSON_NEW_OBJ();
	if(gravityDB_delFromTable(table, domain))
	{
		JSON_OBJ_REF_STR(json, "key", "removed");
		JSON_OBJ_REF_STR(json, "domain", domain);
		JSON_SENT_OBJECT(json);
	}
	else
	{
		JSON_OBJ_REF_STR(json, "key", "error");
		JSON_OBJ_REF_STR(json, "domain", domain);
		// Send 500 internal server error
		JSON_SENT_OBJECT_CODE(json, 500);
	}
}

int api_dns_somelist(struct mg_connection *conn,
                     bool show_exact, bool show_regex,
                     bool whitelist)
{
	int method = http_method(conn);
	if(method == HTTP_GET)
	{
		return api_dns_somelist_read(conn, show_exact, show_regex, whitelist);
	}
	else if(method == HTTP_POST)
	{
		// Add domain from exact white-/blacklist when a user sends
		// the request to the general address /api/dns/{white,black}list
		return api_dns_somelist_POST(conn, show_exact, whitelist);
	}
	else if(method == HTTP_DELETE)
	{
		// Delete domain from exact white-/blacklist when a user sends
		// the request to the general address /api/dns/{white,black}list
		return api_dns_somelist_DELETE(conn, show_exact, whitelist);
	}
	else
	{
		// This results in error 404
		return 0;
	}
}
