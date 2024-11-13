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
// parse_groupIDs()
#include "webserver/http-common.h"
#include <idn2.h>

#define MAX_SEARCH_RESULTS 10000u

static int search_table(struct ftl_conn *api, const char *item,
                        const enum gravity_list_type listtype,
                        char *ids, const unsigned int limit,
                        unsigned int *N, const bool partial, cJSON* json)
{
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
	while(gravityDB_readTableGetRow(listtype, &table, &sql_msg))
	{
		if(++(*N) > limit)
			continue;

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

		if(listtype == GRAVITY_GRAVITY || listtype == GRAVITY_ANTIGRAVITY)
		{
			// Add gravity specific parameters
			JSON_REF_STR_IN_OBJECT(row, "type", table.type);
			JSON_ADD_NUMBER_TO_OBJECT(row, "date_updated", table.date_updated);
			JSON_ADD_NUMBER_TO_OBJECT(row, "number", table.number);
			JSON_ADD_NUMBER_TO_OBJECT(row, "invalid_domains", table.invalid_domains);
			JSON_ADD_NUMBER_TO_OBJECT(row, "abp_entries", table.abp_entries);
			JSON_ADD_NUMBER_TO_OBJECT(row, "status", table.status);
		}

		if(table.group_ids != NULL)
		{
			const int ret = parse_groupIDs(api, &table, row);
			if(ret != 0)
				return ret;
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

static int search_gravity(struct ftl_conn *api, const char *punycode, cJSON *array,
                          cJSON **abp_patterns, const unsigned int limit, unsigned int *N,
                          const bool partial, const bool antigravity)
{
	enum gravity_list_type table = antigravity ? GRAVITY_ANTIGRAVITY : GRAVITY_GRAVITY;
	if(partial)
	{
		// Search for partial matches in (anti/)gravity
		const int ret = search_table(api, punycode, table, NULL, limit, N, partial, array);
		if(ret != 200)
			return ret;
	}
	else
	{
		// Search for exact matches in (anti/)gravity
		int ret = search_table(api, punycode, table, NULL, limit, N, false, array);
		if(ret != 200)
			return ret;

		// Search for ABP matches in (anti/)gravity
		*abp_patterns = gen_abp_patterns(punycode, antigravity);
		cJSON *abp_pattern = NULL;
		cJSON_ArrayForEach(abp_pattern, *abp_patterns)
		{
			const char *pattern = cJSON_GetStringValue(abp_pattern);
			if(pattern == NULL)
				continue;
			ret = search_table(api, pattern, table, NULL, limit, N, partial, array);
			if(ret != 200)
				return ret;
		}
	}

	return 200;
}

int api_search(struct ftl_conn *api)
{
	int ret = 0;
	const char *domain = api->item;
	if(domain == NULL || strlen(domain) == 0)
	{
		// No search term provided
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request: No search term provided",
		                       api->request->local_uri_raw);
	}

	// Parse query string parameters
	bool partial = false, debug = false;
	unsigned int limit = 20u;
	if(api->request->query_string != NULL)
	{
		// Check if we should perform a partial search
		get_bool_var(api->request->query_string, "partial", &partial);
		get_bool_var(api->request->query_string, "debug", &debug);
		get_uint_var(api->request->query_string, "N", &limit);

		// Check validity of limit
		if(limit > MAX_SEARCH_RESULTS)
		{
			// Too many results requested
			char hint[100];
			sprintf(hint, "Requested %u number of results but hard upper limit is %u", limit, MAX_SEARCH_RESULTS);
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid request: Requested too many results",
			                       hint);
		}
	}

	// Convert domain to punycode
	// The IDNA document defines internationalized domain names (IDNs) and a
	// mechanism called IDNA for handling them in a standard fashion. IDNs
	// use characters drawn from a large repertoire (Unicode), but IDNA
	// allows the non-ASCII characters to be represented using only the
	// ASCII characters already allowed in so-called host names today.
	// idn2_to_ascii_lz() convert domain name in the locale’s encoding to an
	// ASCII string. The domain name may contain several labels, separated
	// by dots. The output buffer must be deallocated by the caller.
	// Used flags:
	// - IDN2_NFC_INPUT: Input is in Unicode Normalization Form C (NFC)
	// - IDN2_NONTRANSITIONAL: Use Unicode TR46 non-transitional processing
	char *punycode = NULL;
	const int rc = idn2_to_ascii_lz(domain, &punycode, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
	if (rc != IDN2_OK)
	{
		// Invalid domain name
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request: Invalid domain name",
		                       idn2_strerror(rc));
	}

	// Convert punycode domain to lowercase
	for(unsigned int i = 0u; i < strlen(punycode); i++)
		punycode[i] = tolower(punycode[i]);

	// Search through all exact domains
	cJSON *domains = JSON_NEW_ARRAY();
	unsigned int Nexact = 0u;
	ret = search_table(api, punycode, GRAVITY_DOMAINLIST_ALL_EXACT, NULL, limit, &Nexact, partial, domains);
	if(ret != 200)
	{
		free(punycode);
		return ret;
	}

	// Search through gravity
	cJSON *gravity = JSON_NEW_ARRAY();
	cJSON *gravity_patterns = NULL;
	unsigned int Ngravity = 0u;
	ret = search_gravity(api, punycode, gravity, &gravity_patterns, limit, &Ngravity, partial, false);
	if(ret != 200)
	{
		free(punycode);
		return ret;
	}

	// Search through antigravity
	cJSON *antigravity_patterns = NULL;
	unsigned int Nantigravity = 0u;
	ret = search_gravity(api, punycode, gravity, &antigravity_patterns, limit, &Nantigravity, partial, true);
	if(ret != 200)
	{
		free(punycode);
		return ret;
	}

	// Search through all regex filters
	cJSON *regex_ids = JSON_NEW_OBJECT();
	check_all_regex(punycode, regex_ids);
	cJSON *deny_ids = cJSON_GetObjectItem(regex_ids, "deny");
	cJSON *allow_ids = cJSON_GetObjectItem(regex_ids, "allow");

	// Get allow regex filters
	unsigned int Nregex = 0u;
	if(cJSON_GetArraySize(allow_ids) > 0)
	{
		char *allow_list = cJSON_PrintUnformatted(allow_ids);
		ret = search_table(api,punycode, GRAVITY_DOMAINLIST_ALLOW_REGEX, allow_list, limit, &Nregex, false, domains);
		free(allow_list);
		if(ret != 200)
		{
			free(punycode);
			return ret;
		}
	}

	if(cJSON_GetArraySize(deny_ids) > 0)
	{
		char *deny_list = cJSON_PrintUnformatted(deny_ids);
		ret = search_table(api, punycode, GRAVITY_DOMAINLIST_DENY_REGEX, deny_list, limit, &Nregex, false, domains);
		free(deny_list);
		if(ret != 200)
		{
			free(punycode);
			return ret;
		}
	}

	cJSON *search = JSON_NEW_OBJECT();
	// .domains.{}
	JSON_ADD_ITEM_TO_OBJECT(search, "domains", domains);
	// .gravity.{}
	JSON_ADD_ITEM_TO_OBJECT(search, "gravity", gravity);

	// .results.{}
	cJSON *results = JSON_NEW_OBJECT();

	// .results.domains.{}
	cJSON *jdomains = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(jdomains, "exact", Nexact);
	JSON_ADD_NUMBER_TO_OBJECT(jdomains, "regex", Nregex);
	JSON_ADD_ITEM_TO_OBJECT(results, "domains", jdomains);

	// .results.gravity.{}
	cJSON *jgravity = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(jgravity, "allow", Nantigravity);
	JSON_ADD_NUMBER_TO_OBJECT(jgravity, "block", Ngravity);
	JSON_ADD_ITEM_TO_OBJECT(results, "gravity", jgravity);

	// .results.total
	JSON_ADD_NUMBER_TO_OBJECT(results, "total", Nexact+Nregex+Ngravity+Nantigravity);
	JSON_ADD_ITEM_TO_OBJECT(search, "results", results);

	// .parameters.{}
	cJSON *parameters = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(parameters, "N", limit);
	JSON_ADD_BOOL_TO_OBJECT(parameters, "partial", partial);
	JSON_REF_STR_IN_OBJECT(parameters, "domain", api->item);
	JSON_ADD_BOOL_TO_OBJECT(parameters, "debug", debug);
	JSON_ADD_ITEM_TO_OBJECT(search, "parameters", parameters);

	// .debug.{}
	if(debug)
	{
		// Add debug information
		cJSON *abp_pattern = JSON_NEW_OBJECT();
		JSON_ADD_ITEM_TO_OBJECT(abp_pattern, "gravity", gravity_patterns);
		JSON_ADD_ITEM_TO_OBJECT(abp_pattern, "antigravity", antigravity_patterns);
		cJSON *jdebug = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(jdebug, "domain", domain);
		JSON_COPY_STR_TO_OBJECT(jdebug, "punycode", punycode);
		JSON_ADD_ITEM_TO_OBJECT(jdebug, "abp_pattern", abp_pattern);
		JSON_ADD_ITEM_TO_OBJECT(jdebug, "regex_ids", regex_ids);
		JSON_ADD_ITEM_TO_OBJECT(search, "debug", jdebug);
	}
	else
	{
		// Free intermediate JSON objects containing ABP patterns
		cJSON_Delete(gravity_patterns);
		cJSON_Delete(antigravity_patterns);

		// Free intermediate JSON objects containing list of regex IDs
		cJSON_Delete(regex_ids);
	}

	// Free punycode
	free(punycode);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "search", search);
	JSON_SEND_OBJECT(json);
}
