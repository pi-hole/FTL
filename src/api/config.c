/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/ftl
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// struct fifologData
#include "fifo.h"
// sysinfo()
#include <sys/sysinfo.h>
// get_blockingstatus()
#include "setupVars.h"
// counters
#include "shmem.h"
// get_FTL_db_filesize()
#include "files.h"
// get_sqlite3_version()
#include "database/common.h"
// get_number_of_queries_in_DB()
#include "database/query-table.h"
// getgrgid()
#include <grp.h>
// config struct
#include "config/config.h"
// struct clientsData
#include "datastructure.h"
// Routing information and flags
#include <net/route.h>
// Interate through directories
#include <dirent.h>
// INT_MIN, INT_MAX, ...
#include <limits.h>
// writeFTLtoml()
#include "config/toml_writer.h"
// write_dnsmasq_config()
#include "config/dnsmasq_config.h"

// The following functions are used to create the JSON output
// of the /api/config endpoint.

// This function is used to build the object architecture. It is called
// recursively to build the tree of objects.
static cJSON *get_or_create_object(cJSON *parent, const char *path_element)
{
	// Check if this object already exists
	cJSON *object = cJSON_GetObjectItem(parent, path_element);

	// If not, create and append it to the parent
	if(object == NULL)
	{
		object = JSON_NEW_OBJECT();
		JSON_ADD_ITEM_TO_OBJECT(parent, path_element, object);
	}

	// Return the object
	return object;
}

// This function is used to add a property to the JSON output using the
// appropriate type of the config item to add.
static cJSON *addJSONvalue(const enum conf_type conf_type, union conf_value *val)
{
	switch(conf_type)
	{
		case CONF_BOOL:
			return cJSON_CreateBool(val->b);
		case CONF_INT:
			return cJSON_CreateNumber(val->i);
		case CONF_UINT:
		case CONF_ENUM_PRIVACY_LEVEL:
			return cJSON_CreateNumber(val->ui);
		case CONF_LONG:
			return cJSON_CreateNumber(val->l);
		case CONF_ULONG:
			return cJSON_CreateNumber(val->ul);
		case CONF_DOUBLE:
			return cJSON_CreateNumber(val->d);
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
			return val->s ? cJSON_CreateStringReference(val->s) : cJSON_CreateNull();
		case CONF_ENUM_PTR_TYPE:
			return cJSON_CreateStringReference(get_ptr_type_str(val->ptr_type));
		case CONF_ENUM_BUSY_TYPE:
			return cJSON_CreateStringReference(get_busy_reply_str(val->busy_reply));
		case CONF_ENUM_BLOCKING_MODE:
			return cJSON_CreateStringReference(get_blocking_mode_str(val->blocking_mode));
		case CONF_ENUM_REFRESH_HOSTNAMES:
			return cJSON_CreateStringReference(get_refresh_hostnames_str(val->refresh_hostnames));
		case CONF_ENUM_LISTENING_MODE:
			return cJSON_CreateStringReference(get_listening_mode_str(val->listening_mode));
		case CONF_STRUCT_IN_ADDR:
		{
			char addr4[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &val->in_addr, addr4, INET_ADDRSTRLEN);
			return cJSON_CreateString(addr4); // Performs a copy
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			char addr6[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &val->in6_addr, addr6, INET6_ADDRSTRLEN);
			return cJSON_CreateString(addr6); // Performs a copy
		}
		case CONF_JSON_STRING_ARRAY:
		{
			// Return a duplicate to ensure our instance isn't getting freed
			// after returning the reply
			return cJSON_Duplicate(val->json, true);
		}
		default:
			return NULL;
	}
}

static const char *getJSONvalue(struct conf_item *conf_item, cJSON *elem)
{
	if(conf_item == NULL || elem == NULL)
	{
		log_debug(DEBUG_CONFIG, "getJSONvalue(%p, %p) called with invalid arguments, skipping",
		          conf_item, elem);
		return "invalid arguments";
	}
	switch(conf_item->t)
	{
		case CONF_BOOL:
		{
			// Check type
			if(!cJSON_IsBool(elem))
				return "not of type bool";
			// Set item
			conf_item->v.b = elem->valueint;
			log_debug(DEBUG_CONFIG, "Set %s to %s", conf_item->k, conf_item->v.b ? "true" : "false");
			break;
		}
		case CONF_INT:
		{
			// 1. Check it is a number
			// 2. Check the number is within the allowed range for the given data type
			if(!cJSON_IsNumber(elem) ||
			   elem->valuedouble < INT_MIN || elem->valuedouble > INT_MAX)
				return "not of type integer";
			// Set item
			conf_item->v.i = elem->valueint;
			log_debug(DEBUG_CONFIG, "Set %s to %i", conf_item->k, conf_item->v.i);
			break;
		}
		case CONF_UINT:
		{
			// 1. Check it is a number
			// 2. Check the number is within the allowed range for the given data type
			if(!cJSON_IsNumber(elem) ||
			   elem->valuedouble < 0 || elem->valuedouble > UINT_MAX)
				return "not of type unsigned integer";
			// Set item
			conf_item->v.ui = elem->valuedouble;
			log_debug(DEBUG_CONFIG, "Set %s to %u", conf_item->k, conf_item->v.ui);
			break;
		}
		case CONF_LONG:
		{
			// 1. Check it is a number
			// 2. Check the number is within the allowed range for the given data type
			if(!cJSON_IsNumber(elem) ||
			   elem->valuedouble < LONG_MIN || elem->valuedouble > LONG_MAX)
				return "not of type long";
			// Set item
			conf_item->v.l = elem->valuedouble;
			log_debug(DEBUG_CONFIG, "Set %s to %li", conf_item->k, conf_item->v.l);
			break;
		}
		case CONF_ULONG:
		{
			// 1. Check it is a number
			// 2. Check the number is within the allowed range for the given data type
			if(!cJSON_IsNumber(elem) ||
			   elem->valuedouble < 0 || elem->valuedouble > ULONG_MAX)
				return "not of type unsigned long";
			// Set item
			conf_item->v.ul = elem->valuedouble;
			log_debug(DEBUG_CONFIG, "Set %s to %lu", conf_item->k, conf_item->v.ul);
			break;
		}
		case CONF_DOUBLE:
		{
			// Check it is a number
			if(!cJSON_IsNumber(elem))
				return "not of type unsigned long";
			// Set item
			conf_item->v.d = elem->valuedouble;
			log_debug(DEBUG_CONFIG, "Set %s to %f", conf_item->k, conf_item->v.d);
			break;
		}
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
		{
			// Check type
			if(!cJSON_IsString(elem))
				return "not of type string";
			// Free previously allocated memory (if applicable)
			if(conf_item->t == CONF_STRING_ALLOCATED)
				free(conf_item->v.s);
			// Set item
			conf_item->v.s = strdup(elem->valuestring);
			log_debug(DEBUG_CONFIG, "Set %s to \"%s\"", conf_item->k, conf_item->v.s);
			break;
		}
		case CONF_ENUM_PTR_TYPE:
		{
			// Check type
			if(!cJSON_IsString(elem))
				return "not of type string";
			const int ptr_type = get_ptr_type_val(elem->valuestring);
			if(ptr_type == -1)
				return "invalid option";
			// Set item
			conf_item->v.ptr_type = ptr_type;
			log_debug(DEBUG_CONFIG, "Set %s to %d", conf_item->k, conf_item->v.ptr_type);
			break;
		}
		case CONF_ENUM_BUSY_TYPE:
		{
			// Check type
			if(!cJSON_IsString(elem))
				return "not of type string";
			const int busy_reply = get_busy_reply_val(elem->valuestring);
			if(busy_reply == -1)
				return "invalid option";
			// Set item
			conf_item->v.busy_reply = busy_reply;
			log_debug(DEBUG_CONFIG, "Set %s to %d", conf_item->k, conf_item->v.busy_reply);
			break;
		}
		case CONF_ENUM_BLOCKING_MODE:
		{
			// Check type
			if(!cJSON_IsString(elem))
				return "not of type string";
			const int blocking_mode = get_blocking_mode_val(elem->valuestring);
			if(blocking_mode == -1)
				return "invalid option";
			// Set item
			conf_item->v.blocking_mode = blocking_mode;
			log_debug(DEBUG_CONFIG, "Set %s to %d", conf_item->k, conf_item->v.blocking_mode);
			break;
		}
		case CONF_ENUM_REFRESH_HOSTNAMES:
		{
			// Check type
			if(!cJSON_IsString(elem))
				return "not of type string";
			const int refresh_hostnames = get_refresh_hostnames_val(elem->valuestring);
			if(refresh_hostnames == -1)
				return "invalid option";
			// Set item
			conf_item->v.refresh_hostnames = refresh_hostnames;
			log_debug(DEBUG_CONFIG, "Set %s to %d", conf_item->k, conf_item->v.refresh_hostnames );
			break;
		}
		case CONF_ENUM_LISTENING_MODE:
		{
			// Check type
			if(!cJSON_IsString(elem))
				return "not of type string";
			const int listening_mode = get_listening_mode_val(elem->valuestring);
			if(listening_mode == -1)
				return "invalid option";
			// Set item
			conf_item->v.listening_mode = listening_mode;
			log_debug(DEBUG_CONFIG, "Set %s to %d", conf_item->k, conf_item->v.listening_mode);
			break;
		}
		case CONF_ENUM_PRIVACY_LEVEL:
		{
			// Check type
			if(!cJSON_IsNumber(elem))
				return "not of type integer";
			// Check allowed interval
			if(elem->valuedouble < PRIVACY_SHOW_ALL || elem->valuedouble > PRIVACY_MAXIMUM)
				return "not within valid range";
			// Set item
			conf_item->v.i = elem->valueint;
			log_debug(DEBUG_CONFIG, "Set %s to %d", conf_item->k, conf_item->v.i);
			break;
		}
		case CONF_STRUCT_IN_ADDR:
		{
			struct in_addr addr4 = { 0 };
			if(!cJSON_IsString(elem))
				return "not of type string";
			if(!inet_pton(AF_INET, elem->valuestring, &addr4))
				return "not a valid IPv4 address";
			// Set item
			memcpy(&conf_item->v.in_addr, &addr4, sizeof(addr4));
			log_debug(DEBUG_CONFIG, "Set %s to %s", conf_item->k, elem->valuestring);
			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			struct in6_addr addr6 = { 0 };
			if(!cJSON_IsString(elem))
				return "not of type string";
			if(!inet_pton(AF_INET6, elem->valuestring, &addr6))
				return "not a valid IPv6 address";
			// Set item
			memcpy(&conf_item->v.in6_addr, &addr6, sizeof(addr6));
			log_debug(DEBUG_CONFIG, "Set %s to %s", conf_item->k, elem->valuestring);
			break;
		}
		case CONF_JSON_STRING_ARRAY:
		{
			if(!cJSON_IsArray(elem))
				return "not of type array";
			const unsigned int elems = cJSON_GetArraySize(elem);
			for(unsigned int i = 0; i < elems; i++)
			{
				const cJSON *item = cJSON_GetArrayItem(elem, i);
				if(!cJSON_IsString(item))
					return "array has invalid elements";
			}
			// If we reach this point, all elements are valid
			conf_item->v.json = cJSON_Duplicate(elem, true);
		}
	}
	return NULL;
}

static int api_config_get(struct ftl_conn *api)
{
	// Parse query string parameters
	bool detailed = false;
	if(api->request->query_string != NULL)
	{
		// Check if we should return detailed config information
		get_bool_var(api->request->query_string, "detailed", &detailed);
	}

	// Create root JSON object
	cJSON *config_j = JSON_NEW_OBJECT();

	// Iterate over all known config elements and create appropriate JSON
	// objects + items for each of them
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(i);

		// Get path depth
		unsigned int level = config_path_depth(conf_item);

		cJSON *parent = config_j;
		// Parse tree of properties and create JSON objects for each
		// path element if they do not exist yet. We do not create the
		// leaf object itself here (level - 1) as we want to add the
		// actual value of the config item to it.
		for(unsigned int j = 0; j < level - 1; j++)
			parent = get_or_create_object(parent, conf_item->p[j]);

		// Create the config item leaf object
		if(detailed)
		{
			cJSON *leaf = JSON_NEW_OBJECT();
			JSON_REF_STR_IN_OBJECT(leaf, "description", conf_item->h);
			// Create the config item leaf object
			cJSON *val = addJSONvalue(conf_item->t, &conf_item->v);
			if(val == NULL)
			{
				log_warn("Cannot format config item type %s of type %i",
					conf_item->k, conf_item->t);
				continue;
			}
			cJSON *dval = addJSONvalue(conf_item->t, &conf_item->d);
			if(dval == NULL)
			{
				log_warn("Cannot format config item type %s of type %i",
					conf_item->k, conf_item->t);
				continue;
			}
			JSON_ADD_ITEM_TO_OBJECT(leaf, "value", val);
			JSON_ADD_ITEM_TO_OBJECT(leaf, "default", dval);
			JSON_REF_STR_IN_OBJECT(leaf, "allowed", conf_item->a);
			JSON_ADD_ITEM_TO_OBJECT(parent, conf_item->p[level - 1], leaf);
		}
		else
		{
			// Create the config item leaf object
			cJSON *leaf = addJSONvalue(conf_item->t, &conf_item->v);
			if(leaf == NULL)
			{
				log_warn("Cannot format config item type %s of type %i",
					conf_item->k, conf_item->t);
				continue;
			}
			JSON_ADD_ITEM_TO_OBJECT(parent, conf_item->p[level - 1], leaf);
		}
	}

	// Add special item DNS port
	cJSON *dns = get_or_create_object(config_j, "dns");
	JSON_ADD_NUMBER_TO_OBJECT(dns, "port", dns_port);

	// Build and return JSON response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "config", config_j);
	JSON_SEND_OBJECT(json);
}

static int api_config_patch(struct ftl_conn *api)
{
	// Is there a payload with valid JSON data?
	if (api->payload.json == NULL) {
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request body data (no valid JSON)",
		                       NULL);
	}

	// Is there a "config" object at the root of the received JSON payload?
	cJSON *conf = cJSON_GetObjectItem(api->payload.json, "config");
	if (!cJSON_IsObject(conf)) {
		return send_json_error(api, 400,
		                       "body_error",
		                       "No \"config\" object in body data",
		                       NULL);
	}

	// Read all known config items
	bool dnsmasq_changed = false;
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(i);

		// Get path depth
		unsigned int level = config_path_depth(conf_item);

		cJSON *elem = conf;
		// Parse tree of properties and get the individual JSON elements
		for(unsigned int j = 0; j < level; j++)
			elem = cJSON_GetObjectItem(elem, conf_item->p[j]);

		// Check if this element is present - it doesn't have to be!
		if(elem == NULL)
		{
			log_debug(DEBUG_CONFIG, "%s not in JSON payload", conf_item->k);
			continue;
		}

		// Try to set value and report error on failure
		const char *response = getJSONvalue(conf_item, elem);
		if(response != NULL)
		{
			log_err("/api/config: %s invalid: %s", conf_item->k, response);
			continue;
		}

		// If we reach this point, a valid setting was found and changed
		// Check if this item requires a config-rewrite + restart of dnsmasq
		if(conf_item->restart_dnsmasq)
			dnsmasq_changed = true;
	}

	// Reload debug levels
	set_debug_flags();

	// Store changed configuration to disk
	writeFTLtoml(true);

	// Request restart of FTL
	if(dnsmasq_changed)
		if(write_dnsmasq_config(true))
			api->ftl.restart = true;

	// Return full config after possible changes above
	return api_config_get(api);
}

// Endpoint /api/config router
int api_config(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
		return api_config_get(api);

	// POST: Create a new config (not supported)
	// PATCH: Replace parts of the the config with the provided one
	// PUT: Replaces the entire config with the provided one (not supported
	// but PATCH with a full config is the same)
	else if(api->method == HTTP_PATCH)
		return api_config_patch(api);
	else
		return send_json_error(api, 405, "method_error",
		                       "Method not allowed",
		                       "Use GET to retrieve the current config and "
		                       "PATCH to change it (either partially or fully)");
}
