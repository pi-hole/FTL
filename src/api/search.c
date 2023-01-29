/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/search
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
#include "database/gravity-db.h"
// match_regex()
#include "regex_r.h"

#define MAX_SEARCH_RESULTS 10000u

static int search_table(struct ftl_conn *api,
                        const enum gravity_list_type listtype,
                        char *ids, const unsigned int N,
                        const bool partial, cJSON* json)
{
	const char *item = api->item;
	if(ids != NULL)
	{
		// Set item to NULL to indicate that we are searching for IDs
		item = NULL;
		// Strip "[" and "]" from ids
		ids[strlen(ids)-1] = '\0';
		ids++;
	}

	// Check domain against lists table
	const char *sql_msg = NULL;
	if(!gravityDB_readTable(listtype, item, &sql_msg, !partial, ids))
	{
		return send_json_error(api, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not read domains from database table",
		                       sql_msg);
	}

	tablerow table;
	unsigned int n = 0u;
	while(gravityDB_readTableGetRow(&table, &sql_msg) && n++ < N)
	{
		cJSON *row = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(row, "domain", table.domain);
		if(table.type != NULL)
			JSON_REF_STR_IN_OBJECT(row, "type", table.type);
		if(table.kind != NULL)
			JSON_REF_STR_IN_OBJECT(row, "kind", table.kind);
		if(table.address != NULL)
			JSON_COPY_STR_TO_OBJECT(row, "address", table.address);
		JSON_COPY_STR_TO_OBJECT(row, "comment", table.comment);
		JSON_ADD_BOOL_TO_OBJECT(row, "enabled", table.enabled);
		// Add read-only database parameters
		JSON_ADD_NUMBER_TO_OBJECT(row, "id", table.id);
		JSON_ADD_NUMBER_TO_OBJECT(row, "date_added", table.date_added);
		JSON_ADD_NUMBER_TO_OBJECT(row, "date_modified", table.date_modified);

		if(table.group_ids != NULL)
		{
			// Black magic at work here: We build a JSON array from
			// the group_concat result delivered from the database,
			// parse it as valid array and append it as row to the
			// data
			const size_t buflen = strlen(table.group_ids)+3u;
			char *group_ids_str = calloc(buflen, sizeof(char));
			group_ids_str[0] = '[';
			strcpy(group_ids_str+1u , table.group_ids);
			group_ids_str[buflen-2u] = ']';
			group_ids_str[buflen-1u] = '\0';
			cJSON * group_ids = cJSON_Parse(group_ids_str);
			free(group_ids_str);
			JSON_ADD_ITEM_TO_OBJECT(row, "groups", group_ids);
		}
		else
		{
			// Empty group set
			cJSON *group_ids = JSON_NEW_ARRAY();
			JSON_ADD_ITEM_TO_OBJECT(row, "groups", group_ids);
		}
		JSON_ADD_ITEM_TO_ARRAY(json, row);
	}
	gravityDB_readTableFinalize();

	return 200;
}

int api_search(struct ftl_conn *api)
{
	int ret = 0;
	if(api->item == NULL || strlen(api->item) == 0)
	{
		// No search term provided
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request: No search term provided",
		                       api->request->local_uri_raw);
	}

	// Parse query string parameters
	bool partial = false;
	unsigned int N = 20u;
	if(api->request->query_string != NULL)
	{
		// Check if we should perform a partial search
		get_bool_var(api->request->query_string, "partial", &partial);
		get_uint_var(api->request->query_string, "N", &N);

		// Check validity of N
		if(N > MAX_SEARCH_RESULTS)
		{
			// Too many results requested
			char hint[100];
			sprintf(hint, "Requested %u number of results but hard upper limit is %u", N, MAX_SEARCH_RESULTS);
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid request: Requested too many results",
			                       hint);
		}
	}

	// Search through all exact domains
	cJSON *domainlist = JSON_NEW_ARRAY();
	ret = search_table(api, GRAVITY_DOMAINLIST_ALL_EXACT, NULL, N, partial, domainlist);
	if(ret != 200)
		return ret;

	// Search through gravity
	cJSON *gravity = JSON_NEW_ARRAY();
	ret = search_table(api, GRAVITY_GRAVITY, NULL, N, partial, gravity);
	if(ret != 200)
		return ret;

	// Search through all regex filters
	cJSON *regex_ids = JSON_NEW_OBJECT();
	check_all_regex(api->item, regex_ids);
	cJSON *deny_ids = cJSON_GetObjectItem(regex_ids, "deny");
	cJSON *allow_ids = cJSON_GetObjectItem(regex_ids, "allow");

	cJSON *allow = JSON_NEW_ARRAY();
	// Get allow regex filters
	char *allow_list = cJSON_PrintUnformatted(allow_ids);
	ret = search_table(api, GRAVITY_DOMAINLIST_ALLOW_REGEX, allow_list, N, false, allow);
	free(allow_list);
	allow_list = NULL;
	if(ret != 200)
		return ret;

	cJSON *deny = JSON_NEW_ARRAY();
	char *deny_list = cJSON_PrintUnformatted(deny_ids);
	ret = search_table(api, GRAVITY_DOMAINLIST_DENY_REGEX, deny_list, N, false, deny);
	free(deny_list);
	deny_list = NULL;
	if(ret != 200)
		return ret;

	// Free intermediate JSON objects containing list of regex IDs
	cJSON_Delete(regex_ids);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "domains", domainlist);
	JSON_ADD_ITEM_TO_OBJECT(json, "gravity", gravity);
	cJSON *regex = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(regex, "allow", allow);
	JSON_ADD_ITEM_TO_OBJECT(regex, "deny", deny);
	JSON_ADD_ITEM_TO_OBJECT(json, "regex", regex);
	JSON_SEND_OBJECT(json);
}
