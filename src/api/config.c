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
static cJSON *add_property(const enum conf_type conf_type, union conf_value *val)
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
		case CONF_STRING:
			return val->s ? cJSON_CreateStringReference(val->s) : cJSON_CreateNull();
		case CONF_ENUM_PTR_TYPE:
			return cJSON_CreateStringReference(get_ptr_type_str(val->ptr_type));
		case CONF_ENUM_BUSY_TYPE:
			return cJSON_CreateStringReference(get_busy_reply_str(val->busy_reply));
		case CONF_ENUM_BLOCKING_MODE:
			return cJSON_CreateStringReference(get_blocking_mode_str(val->blocking_mode));
		case CONF_ENUM_REFRESH_HOSTNAMES:
			return cJSON_CreateStringReference(get_refresh_hostnames_str(val->refresh_hostnames));
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
		default:
			return NULL;
	}
}

static int api_config_get(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

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
			cJSON *val = add_property(conf_item->t, &conf_item->v);
			if(val == NULL)
			{
				log_warn("Cannot format config item type %s of type %i",
					conf_item->k, conf_item->t);
				continue;
			}
			cJSON *dval = add_property(conf_item->t, &conf_item->d);
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
			cJSON *leaf = add_property(conf_item->t, &conf_item->v);
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

// Endpoint /api/config router
int api_config(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
		return api_config_get(api);

	// POST: Create a new config (not supported)
	// PATCH: Replace parts of the the config with the provided one
	// PUT: Replaces the entire config with the provided one (not supported
	// but PATCH with a full config is the same)
//	else if(api->method == HTTP_PATCH)
//		return api_config_patch(api);
	else
		return send_json_error(api, 405, "method_error",
		                       "Method not allowed",
		                       "Use GET to retrieve the current config and "
		                       "PATCH to change it (either partially or fully)");
}
