/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/{allow,deny}list
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
#include "database/gravity-db.h"
#include "events.h"
#include "shmem.h"
// getNameFromIP()
#include "database/network-table.h"
// valid_domain()
#include "tools/gravity-parseList.h"
// parse_groupIDs()
#include "webserver/http-common.h"
#include <idn2.h>

static int api_list_read(struct ftl_conn *api,
                         const int code,
                         const enum gravity_list_type listtype,
                         const char *item,
                         cJSON *processed)
{
	const char *sql_msg = NULL;
	if(!gravityDB_readTable(listtype, item, &sql_msg, true, NULL))
	{
		return send_json_error(api, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not read domains from database table",
		                       sql_msg);
	}

	tablerow table = { 0 };
	cJSON *rows = JSON_NEW_ARRAY();
	while(gravityDB_readTableGetRow(listtype, &table, &sql_msg))
	{
		cJSON *row = JSON_NEW_OBJECT();

		// Special fields
		if(listtype == GRAVITY_GROUPS)
		{
			JSON_COPY_STR_TO_OBJECT(row, "name", table.name);
			JSON_COPY_STR_TO_OBJECT(row, "comment", table.comment);
		}
		else if(listtype == GRAVITY_ADLISTS ||
		        listtype == GRAVITY_ADLISTS_BLOCK ||
		        listtype == GRAVITY_ADLISTS_ALLOW)
		{
			JSON_COPY_STR_TO_OBJECT(row, "address", table.address);
			JSON_COPY_STR_TO_OBJECT(row, "comment", table.comment);
		}
		else if(listtype == GRAVITY_CLIENTS)
		{
			char *name = NULL;
			if(table.client != NULL)
			{
				// Try to obtain hostname
				if(isValidIPv4(table.client) || isValidIPv6(table.client))
					name = getNameFromIP(NULL, table.client);
				else if(isMAC(table.client))
					name = getNameFromMAC(table.client);
			}

			JSON_COPY_STR_TO_OBJECT(row, "client", table.client);
			JSON_COPY_STR_TO_OBJECT(row, "name", name);
			JSON_COPY_STR_TO_OBJECT(row, "comment", table.comment);

			// Free allocated memory (if applicable)
			if(name != NULL)
				free(name);
		}
		else // domainlists
		{
			char *unicode = NULL;
			const int rc = idn2_to_unicode_lzlz(table.domain, &unicode, IDN2_NONTRANSITIONAL);
			JSON_COPY_STR_TO_OBJECT(row, "domain", table.domain);
			if(rc == IDN2_OK)
				JSON_COPY_STR_TO_OBJECT(row, "unicode", unicode);
			else
				JSON_COPY_STR_TO_OBJECT(row, "unicode", table.domain);
			JSON_REF_STR_IN_OBJECT(row, "type", table.type);
			JSON_REF_STR_IN_OBJECT(row, "kind", table.kind);
			JSON_COPY_STR_TO_OBJECT(row, "comment", table.comment);
			if(unicode != NULL)
				free(unicode);
		}

		// Groups don't have the groups property
		if(listtype != GRAVITY_GROUPS)
		{
			if(table.group_ids != NULL)
			{
				const int ret = parse_groupIDs(api, &table, row);
				if(ret != 0)
				{
					JSON_DELETE(rows);
					return ret;
				}

			}
			else
			{
				// Empty group set
				cJSON *group_ids = JSON_NEW_ARRAY();
				JSON_ADD_ITEM_TO_OBJECT(row, "groups", group_ids);
			}
		}

		// Clients don't have the enabled property
		if(listtype != GRAVITY_CLIENTS)
			JSON_ADD_BOOL_TO_OBJECT(row, "enabled", table.enabled);

		// Add read-only database parameters
		JSON_ADD_NUMBER_TO_OBJECT(row, "id", table.id);
		JSON_ADD_NUMBER_TO_OBJECT(row, "date_added", table.date_added);
		JSON_ADD_NUMBER_TO_OBJECT(row, "date_modified", table.date_modified);

		// Properties added in https://github.com/pi-hole/pi-hole/pull/3951
		if(listtype == GRAVITY_ADLISTS ||
		   listtype == GRAVITY_ADLISTS_BLOCK ||
		   listtype == GRAVITY_ADLISTS_ALLOW)
		{
			JSON_REF_STR_IN_OBJECT(row, "type", table.type);
			JSON_ADD_NUMBER_TO_OBJECT(row, "date_updated", table.date_updated);
			JSON_ADD_NUMBER_TO_OBJECT(row, "number", table.number);
			JSON_ADD_NUMBER_TO_OBJECT(row, "invalid_domains", table.invalid_domains);
			JSON_ADD_NUMBER_TO_OBJECT(row, "abp_entries", table.abp_entries);
			JSON_ADD_NUMBER_TO_OBJECT(row, "status", table.status);
		}

		JSON_ADD_ITEM_TO_ARRAY(rows, row);
	}
	gravityDB_readTableFinalize();

	if(sql_msg == NULL)
	{
		// No error, send domains array
		const char *objname;
		cJSON *json = JSON_NEW_OBJECT();
		if(listtype == GRAVITY_GROUPS)
			objname = "groups";
		else if(listtype == GRAVITY_ADLISTS ||
		        listtype == GRAVITY_ADLISTS_BLOCK ||
		        listtype == GRAVITY_ADLISTS_ALLOW)
			objname = "lists";
		else if(listtype == GRAVITY_CLIENTS)
			objname = "clients";
		else // domainlists
			objname = "domains";
		JSON_ADD_ITEM_TO_OBJECT(json, objname, rows);

		// Add processed count (if applicable)
		if(processed != NULL)
			JSON_ADD_ITEM_TO_OBJECT(json, "processed", processed);

		JSON_SEND_OBJECT_CODE(json, code);
	}
	else
	{
		JSON_DELETE(rows);
		return send_json_error(api, 400, // 400 Bad Request
		                       "database_error",
		                       "Could not read from gravity database",
		                       sql_msg);
	}
}

static int api_list_write(struct ftl_conn *api,
                          const enum gravity_list_type listtype,
                          const char *item)
{
	tablerow row = { 0 };

	// Check if valid JSON payload is available
	const int json_ret = check_json_payload(api);
	if(json_ret != 0)
		return json_ret;

	bool spaces_allowed = false;
	bool allocated_json = false;
	if(api->method == HTTP_POST)
	{
		// Extract domain/name/client/address from payload when using POST, all
		// others specify it as URI-component
		switch(listtype)
		{
			case GRAVITY_DOMAINLIST_ALLOW_EXACT:
			case GRAVITY_DOMAINLIST_ALLOW_REGEX:
			case GRAVITY_DOMAINLIST_DENY_EXACT:
			case GRAVITY_DOMAINLIST_DENY_REGEX:
			{
				cJSON* json_domain = cJSON_GetObjectItemCaseSensitive(api->payload.json, "domain");
				if(cJSON_IsString(json_domain) && strlen(json_domain->valuestring) > 0)
				{
					row.items = cJSON_CreateArray();
					cJSON_AddItemToArray(row.items, cJSON_CreateStringReference(json_domain->valuestring));
					allocated_json = true;
				}
				else if(cJSON_IsArray(json_domain) && cJSON_GetArraySize(json_domain) > 0)
					row.items = json_domain;
				else
				{
					return send_json_error(api, 400,
					                       "bad_request",
					                       "Invalid request: No valid \"domain\" in payload (must be either string or array)",
					                       NULL);
				}
				break;
			}

			case GRAVITY_GROUPS:
			{
				spaces_allowed = true;
				cJSON *json_name = cJSON_GetObjectItemCaseSensitive(api->payload.json, "name");
				if(cJSON_IsString(json_name) && strlen(json_name->valuestring) > 0)
				{
					row.items = cJSON_CreateArray();
					cJSON_AddItemToArray(row.items, cJSON_CreateStringReference(json_name->valuestring));
					allocated_json = true;
				}
				else if(cJSON_IsArray(json_name) && cJSON_GetArraySize(json_name) > 0)
					row.items = json_name;
				else
				{
					return send_json_error(api, 400,
					                       "bad_request",
					                       "Invalid request: No valid \"name\" in payload (must be either string or array)",
					                       NULL);
				}
				break;
			}

			case GRAVITY_CLIENTS:
			{
				cJSON *json_client = cJSON_GetObjectItemCaseSensitive(api->payload.json, "client");
				if(cJSON_IsString(json_client) && strlen(json_client->valuestring) > 0)
				{
					row.items = cJSON_CreateArray();
					cJSON_AddItemToArray(row.items, cJSON_CreateStringReference(json_client->valuestring));
					allocated_json = true;
				}
				else if(cJSON_IsArray(json_client) && cJSON_GetArraySize(json_client) > 0)
					row.items = json_client;
				else
				{
					return send_json_error(api, 400,
					                       "bad_request",
					                       "Invalid request: No valid \"client\" in payload (must be either string or array)",
					                       NULL);
				}
				break;
			}

			case GRAVITY_ADLISTS:
			case GRAVITY_ADLISTS_BLOCK:
			case GRAVITY_ADLISTS_ALLOW:
			{
				cJSON *json_address = cJSON_GetObjectItemCaseSensitive(api->payload.json, "address");
				if(cJSON_IsString(json_address) && strlen(json_address->valuestring) > 0)
				{
					row.items = cJSON_CreateArray();
					cJSON_AddItemToArray(row.items,  cJSON_CreateStringReference(json_address->valuestring));
					allocated_json = true;
				}
				else if(cJSON_IsArray(json_address) && cJSON_GetArraySize(json_address) > 0)
					row.items = json_address;
				else
				{
					return send_json_error(api, 400,
					                       "bad_request",
					                       "Invalid request: No valid \"address\" in payload (must be either string or array)",
					                       NULL);
				}
				break;
			}

			// Aggregate types (and gravity) are not handled by this routine
			case GRAVITY_DOMAINLIST_ALL_ALL:
			case GRAVITY_DOMAINLIST_ALL_EXACT:
			case GRAVITY_DOMAINLIST_ALL_REGEX:
			case GRAVITY_DOMAINLIST_ALLOW_ALL:
			case GRAVITY_DOMAINLIST_DENY_ALL:
			case GRAVITY_GRAVITY:
			case GRAVITY_ANTIGRAVITY:
				return send_json_error(api, 400, // 400 Bad Request
				                       "bad_request",
				                       "Aggregate types (and gravity) are not handled by this routine",
				                       NULL);
		}
	}
	else
	{
		// PUT = Use URI item
		row.items = cJSON_CreateArray();
		cJSON_AddItemToArray(row.items, cJSON_CreateStringReference(item));
		allocated_json = true;
	}

	cJSON *json_comment = cJSON_GetObjectItemCaseSensitive(api->payload.json, "comment");
	if(cJSON_IsString(json_comment) && strlen(json_comment->valuestring) > 0)
		row.comment = json_comment->valuestring;
	else
		row.comment = NULL; // Default value


	// Check if there is a type field in the payload (only for lists)
	if(listtype == GRAVITY_ADLISTS)
	{
		cJSON *json_type = cJSON_GetObjectItemCaseSensitive(api->payload.json, "type");
		if(cJSON_IsString(json_type) && strlen(json_type->valuestring) > 0)
			row.type_int = strcasecmp(json_type->valuestring, "allow") == 0 ? ADLIST_ALLOW : ADLIST_BLOCK;
		else
		{
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid request: No valid item \"type\" in payload",
			                       NULL);
		}
	}
	else if(listtype == GRAVITY_ADLISTS_BLOCK)
		row.type_int = ADLIST_BLOCK;
	else if(listtype == GRAVITY_ADLISTS_ALLOW)
		row.type_int = ADLIST_ALLOW;
	else
	{
		cJSON *json_type = cJSON_GetObjectItemCaseSensitive(api->payload.json, "type");
		if(cJSON_IsString(json_type) && strlen(json_type->valuestring) > 0)
			row.type = json_type->valuestring;
		else
			row.type = NULL; // Default value
	}

	cJSON *json_kind = cJSON_GetObjectItemCaseSensitive(api->payload.json, "kind");
	if(cJSON_IsString(json_kind) && strlen(json_kind->valuestring) > 0)
		row.kind = json_kind->valuestring;
	else
		row.kind = NULL; // Default value

	cJSON *json_enabled = cJSON_GetObjectItemCaseSensitive(api->payload.json, "enabled");
	if (cJSON_IsBool(json_enabled))
		row.enabled = cJSON_IsTrue(json_enabled);
	else
		row.enabled = true; // Default value

	cJSON *json_name = cJSON_GetObjectItemCaseSensitive(api->payload.json, "name");
	if(cJSON_IsString(json_name) && strlen(json_name->valuestring) > 0)
		row.name = json_name->valuestring;
	else
		row.name = NULL; // Default value

	bool okay = true;
	char *regex_msg = NULL;
	if(listtype == GRAVITY_DOMAINLIST_ALLOW_REGEX || listtype == GRAVITY_DOMAINLIST_DENY_REGEX)
	{
		// Test validity of this regex
		regexData regex = { 0 };
		cJSON *it = NULL;
		cJSON_ArrayForEach(it, row.items)
		{
			// If any element isn't a string, break early
			if(!cJSON_IsString(it))
			{
				okay = false;
				break;
			}

			// Check every array element for its validity
			okay = compile_regex(it->valuestring, &regex, &regex_msg);

			// Free regex after successful compilation
			if(regex.available)
			{
				regfree(&regex.regex);
				free(regex.string);
			}

			// Fail fast if any regex in the passed array is invalid
			if(!okay)
				break;
		}
	}
	else if(!spaces_allowed)
	{
		cJSON *it = NULL;
		cJSON_ArrayForEach(it, row.items)
		{
			// If any element isn't a string, break early
			if(!cJSON_IsString(it))
			{
				okay = false;
				break;
			}

			// Check validity: Spaces are not allowed in any domain/URL
			if(strchr(it->valuestring, ' ') != NULL ||
			   strchr(it->valuestring, '\t') != NULL ||
			   strchr(it->valuestring, '\n') != NULL)
			{
				if(allocated_json)
					cJSON_free(row.items);
				return send_json_error(api, 400, // 400 Bad Request
				                       "bad_request",
				                       "Spaces, newlines and tabs are not allowed in domains and URLs",
				                       it->valuestring);
			}

			if(listtype == GRAVITY_DOMAINLIST_ALLOW_EXACT ||
			   listtype == GRAVITY_DOMAINLIST_DENY_EXACT)
			{
				char *punycode = NULL;
				const int rc = idn2_to_ascii_lz(it->valuestring, &punycode, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
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

				// Validate punycode domain
				// This will reject domains like äöü{{{.com
				// which convert to xn--{{{-pla4gpb.com
				if(!valid_domain(punycode, strlen(punycode), false))
				{
					if(allocated_json)
						cJSON_free(row.items);
					return send_json_error(api, 400, // 400 Bad Request
							"bad_request",
							"Invalid domain",
							it->valuestring);
				}

				// Replace domain with punycode version
				if(!(it->type & cJSON_IsReference))
					free(it->valuestring);
				it->valuestring = punycode;
				// Remove reference flag
				it->type &= ~cJSON_IsReference;
			}
		}
	}

	// Fail fast if any regex in the passed array is invalid
	if(!okay)
	{
		// Send error reply
		if(allocated_json)
			cJSON_free(row.items);
		return send_json_error_free(api, 400, // 400 Bad Request
		                            "regex_error",
		                            "Regex validation failed",
		                            regex_msg, true);
	}

	// Try to add item(s) to table
	const char *sql_msg = NULL;
	cJSON *elem = NULL;
	cJSON *processed = JSON_NEW_OBJECT();
	cJSON *errors = JSON_NEW_ARRAY();
	cJSON *success = JSON_NEW_ARRAY();
	cJSON_AddItemToObject(processed, "errors", errors);
	cJSON_AddItemToObject(processed, "success", success);
	cJSON_ArrayForEach(elem, row.items)
	{
		row.item = elem->valuestring;
		if((okay = gravityDB_addToTable(listtype, &row, &sql_msg, api->method)))
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

		cJSON *details = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(details, "item", row.item);
		if(!okay)
			JSON_COPY_STR_TO_OBJECT(details, "error", sql_msg);
		cJSON_AddItemToArray(okay ? success : errors, details);
	}

	// Inform the resolver that it needs to reload gravity
	set_event(RELOAD_GRAVITY);

	int response_code = 201; // 201 - Created
	if(api->method == HTTP_PUT)
		response_code = 200; // 200 - OK

	// Add "Location" header to response
	if(snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers), "Location: %s/%s", api->action_path, row.item) >= (int)sizeof(pi_hole_extra_headers))
	{
		// This may happen for *extremely* long URLs but is not issue in
		// itself. Merely add a warning to the log file
		log_warn("Could not add Location header to response: URL too long");

		// Truncate location by replacing the last characters with "...\0"
		pi_hole_extra_headers[sizeof(pi_hole_extra_headers)-4] = '.';
		pi_hole_extra_headers[sizeof(pi_hole_extra_headers)-3] = '.';
		pi_hole_extra_headers[sizeof(pi_hole_extra_headers)-2] = '.';
		pi_hole_extra_headers[sizeof(pi_hole_extra_headers)-1] = '\0';
	}

	// Send GET style reply
	const int ret = api_list_read(api, response_code, listtype, row.item, processed);

	// Free allocated memory
	if(allocated_json)
		cJSON_free(row.items);

	return ret;
}

static int api_list_remove(struct ftl_conn *api,
                           const enum gravity_list_type listtype,
                           const char *item)
{
	const char *sql_msg = NULL;
	cJSON *array = api->payload.json;
	bool allocated_json = false;

	// If this is not a :batchDelete call, then the item is specified in the
	// URI, not in the payload. Create a JSON array with the item and use
	// that instead
	const bool isBatchDelete = api->opts.flags & API_BATCHDELETE;

	// If this is a domain callback, we need to translate type/kind into an
	// integer for use in the database
	if(listtype == GRAVITY_DOMAINLIST_ALLOW_EXACT ||
	   listtype == GRAVITY_DOMAINLIST_DENY_EXACT ||
	   listtype == GRAVITY_DOMAINLIST_ALLOW_REGEX ||
	   listtype == GRAVITY_DOMAINLIST_DENY_REGEX ||
	   listtype == GRAVITY_ADLISTS_BLOCK ||
	   listtype == GRAVITY_ADLISTS_ALLOW)
	{
		int type = -1;
		switch (listtype)
		{
			case GRAVITY_DOMAINLIST_ALLOW_EXACT:
				type = 0;
				break;
			case GRAVITY_DOMAINLIST_DENY_EXACT:
				type = 1;
				break;
			case GRAVITY_DOMAINLIST_ALLOW_REGEX:
				type = 2;
				break;
			case GRAVITY_DOMAINLIST_DENY_REGEX:
				type = 3;
				break;
			case GRAVITY_ADLISTS_BLOCK:
				type = ADLIST_BLOCK;
				break;
			case GRAVITY_ADLISTS_ALLOW:
				type = ADLIST_ALLOW;
				break;
			// Not handled herein
			case GRAVITY_GROUPS:
			case GRAVITY_ADLISTS:
			case GRAVITY_CLIENTS:
			case GRAVITY_GRAVITY:
			case GRAVITY_ANTIGRAVITY:
			case GRAVITY_DOMAINLIST_ALLOW_ALL:
			case GRAVITY_DOMAINLIST_DENY_ALL:
			case GRAVITY_DOMAINLIST_ALL_EXACT:
			case GRAVITY_DOMAINLIST_ALL_REGEX:
			case GRAVITY_DOMAINLIST_ALL_ALL:
			default:
				break;
		}

		// Create new JSON array with the item and type:
		// array = [{"item": "example.com", "type": 0}]
		array = cJSON_CreateArray();
		cJSON *obj = cJSON_CreateObject();
		cJSON_AddItemToObject(obj, "item", cJSON_CreateStringReference(item));
		cJSON_AddItemToObject(obj, "type", cJSON_CreateNumber(type));
		cJSON_AddItemToArray(array, obj);
		allocated_json = true;
	}
	else if(isBatchDelete && listtype == GRAVITY_DOMAINLIST_ALL_ALL)
	{
		// Loop over all items and parse type/kind for each item
		cJSON *it = NULL;
		cJSON_ArrayForEach(it, array)
		{
			if(!cJSON_IsObject(it))
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Invalid request: Batch delete requires an array of objects",
				                       NULL);
			}

			// Check if item is a string
			cJSON *json_item = cJSON_GetObjectItemCaseSensitive(it, "item");
			if(!cJSON_IsString(json_item))
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Invalid request: Batch delete requires an array of objects with \"item\" as string",
				                       NULL);
			}

			// Check if type and kind are both present and strings
			cJSON *json_type = cJSON_GetObjectItemCaseSensitive(it, "type");
			cJSON *json_kind = cJSON_GetObjectItemCaseSensitive(it, "kind");
			if(!cJSON_IsString(json_type) || !cJSON_IsString(json_kind))
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Invalid request: Batch delete requires an array of objects with \"type\" and \"kind\" as string",
				                       NULL);
			}

			// Parse type and kind
			// 0 = allow exact
			// 1 = deny exact
			// 2 = allow regex
			// 3 = deny regex
			int type = -1;
			if(strcasecmp(json_type->valuestring, "allow") == 0)
			{
				if(strcasecmp(json_kind->valuestring, "exact") == 0)
					type = 0;
				else if(strcasecmp(json_kind->valuestring, "regex") == 0)
					type = 2;
			}
			else if(strcasecmp(json_type->valuestring, "deny") == 0)
			{
				if(strcasecmp(json_kind->valuestring, "exact") == 0)
					type = 1;
				else if(strcasecmp(json_kind->valuestring, "regex") == 0)
					type = 3;
			}

			// Check if type/kind combination is valid
			if(type == -1)
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Invalid request: Batch delete requires an valid combination of \"type\" and \"kind\" for each object",
				                       NULL);
			}

			// Replace type/kind with integer type
			// array = [{"item": "example.com", "type": 0}]
			cJSON_DeleteItemFromObject(it, "type");
			cJSON_DeleteItemFromObject(it, "kind");
			cJSON_AddNumberToObject(it, "type", type);
		}
	}
	else if(!isBatchDelete)
	{
		// Create array with object (used for clients, groups, lists)
		// array = [{"item": <item>}]
		array = cJSON_CreateArray();
		cJSON *obj = cJSON_CreateObject();
		cJSON_AddItemToObject(obj, "item", cJSON_CreateStringReference(item));
		cJSON_AddItemToArray(array, obj);
		allocated_json = true;
	}

	// Verify that the payload is an array of objects each containing an
	// item
	if(isBatchDelete)
	{
		cJSON *it = NULL;
		cJSON_ArrayForEach(it, array)
		{
			if(!cJSON_IsObject(it))
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Invalid request: Batch delete requires an array of objects",
				                       NULL);
			}

			// Check if item is a string
			cJSON *json_item = cJSON_GetObjectItemCaseSensitive(it, "item");
			if(!cJSON_IsString(json_item))
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Invalid request: Batch delete requires an array of objects with \"item\" as string",
				                       NULL);
			}
		}
	}

	// From here on, we can assume the JSON payload is valid
	unsigned int deleted = 0u;
	if(gravityDB_delFromTable(listtype, array, &deleted, &sql_msg))
	{
		// Inform the resolver that it needs to reload gravity
		set_event(RELOAD_GRAVITY);

		// Free memory allocated above
		if(allocated_json)
			cJSON_free(array);

		// Send empty reply with codes:
		// - 204 No Content (if any items were deleted)
		// - 404 Not Found (if no items were deleted)
		cJSON *json = JSON_NEW_OBJECT();
		JSON_SEND_OBJECT_CODE(json, deleted > 0u ? 204 : 404);
	}
	else
	{
		// Free memory allocated above
		if(allocated_json)
			cJSON_free(array);

		// Send error reply
		return send_json_error(api, 400,
		                       "database_error",
		                       "Could not remove entries from table",
		                       sql_msg);
	}
}

int api_list(struct ftl_conn *api)
{
	enum gravity_list_type listtype;
	bool can_modify = false;
	bool batchDelete = false;
	if((api->item = startsWith("/api/groups", api)) != NULL)
	{
		listtype = GRAVITY_GROUPS;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/groups:batchDelete", api)) != NULL)
	{
		listtype = GRAVITY_GROUPS;
		can_modify = true;
		batchDelete = true;
	}
	else if((api->item = startsWith("/api/lists", api)) != NULL)
	{
		listtype = GRAVITY_ADLISTS;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/lists:batchDelete", api)) != NULL)
	{
		listtype = GRAVITY_ADLISTS;
		can_modify = true;
		batchDelete = true;
	}
	else if((api->item = startsWith("/api/clients", api)) != NULL)
	{
		listtype = GRAVITY_CLIENTS;
		can_modify = true;
	}
	else if((api->item = startsWith("/api/clients:batchDelete", api)) != NULL)
	{
		listtype = GRAVITY_CLIENTS;
		can_modify = true;
		batchDelete = true;
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
	else if((api->item = startsWith("/api/domains:batchDelete", api)) != NULL)
	{
		listtype = GRAVITY_DOMAINLIST_ALL_ALL;
		can_modify = true;
		batchDelete = true;
	}
	else
	{
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid request: Specified endpoint not available",
			                       api->request->local_uri_raw);
	}

	// If this is a request for a list, we check if there is a request
	// parameter narrowing down which kind of list. If so, we modify the
	// list type accordingly
	if(listtype == GRAVITY_ADLISTS && api->request->query_string != NULL)
	{
		// Check if there is a type parameter
		char typestr[16] = { 0 };
		if(get_string_var(api->request->query_string, "type", typestr, sizeof(typestr)) > 0)
		{
			if(strcasecmp(typestr, "allow") == 0)
				listtype = GRAVITY_ADLISTS_ALLOW;
			else if(strcasecmp(typestr, "block") == 0)
				listtype = GRAVITY_ADLISTS_BLOCK;
			else
			{
				// Invalid type parameter
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Invalid request: Invalid type parameter (should be either \"allow\" or \"block\")",
				                       api->request->query_string);
			}
		}
	}

	if(api->method == HTTP_GET)
	{
		// Read list item identified by URI (or read them all)
		// We would not actually need the SHM lock here, however, we do
		// this for simplicity to ensure nobody else is editing the
		// lists while we're doing this here
		lock_shm();
		const int ret = api_list_read(api, 200, listtype, api->item, NULL);
		unlock_shm();
		return ret;
	}
	else if(can_modify && api->method == HTTP_PUT)
	{
		// Add/update item identified by URI
		if(api->item != NULL && strlen(api->item) == 0)
		{
			return send_json_error(api, 400,
			                       "uri_error",
			                       "Invalid request: Specify item in URI",
			                       NULL);
		}
		else
		{
			// We would not actually need the SHM lock here,
			// however, we do this for simplicity to ensure nobody
			// else is editing the lists while we're doing this here
			lock_shm();
			const int ret = api_list_write(api, listtype, api->item);
			unlock_shm();
			return ret;
		}
	}
	else if(can_modify && api->method == HTTP_POST && !batchDelete)
	{
		// Add item to list identified by payload
		if(api->item != NULL && strlen(api->item) != 0)
		{
			return send_json_error(api, 400,
			                       "uri_error",
			                       "Invalid request: Specify item in payload, not as URI parameter",
			                       api->item);
		}
		else
		{
			// We would not actually need the SHM lock here,
			// however, we do this for simplicity to ensure nobody
			// else is editing the lists while we're doing this here
			lock_shm();
			const int ret = api_list_write(api, listtype, api->item);
			unlock_shm();
			return ret;
		}
	}
	else if(can_modify && (api->method == HTTP_DELETE || (api->method == HTTP_POST && batchDelete)))
	{
		// Delete item from list
		// We would not actually need the SHM lock here, however, we do
		// this for simplicity to ensure nobody else is editing the
		// lists while we're doing this here
		lock_shm();
		const int ret = api_list_remove(api, listtype, api->item);
		unlock_shm();
		return ret;
	}
	else if(!can_modify)
	{
		// This list type cannot be modified (e.g., ALL_ALL)
		return send_json_error(api, 400,
		                       "uri_error",
		                       "Invalid request: Specify list to modify more precisely",
		                       api->request->local_uri_raw);
	}
	else
	{
		// This results in error 404
		return 0;
	}
}
