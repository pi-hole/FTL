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
// config struct
#include "config/config.h"
// struct clientsData
#include "datastructure.h"
// INT_MIN, INT_MAX, ...
#include <limits.h>
// writeFTLtoml()
#include "config/toml_writer.h"
// write_dnsmasq_config()
#include "config/dnsmasq_config.h"
// shm_lock()
#include "shmem.h"

static struct {
	const char *name;
	const char *description;
} config_topics[] =
{
	{ "dns", "DNS server settings" },
	{ "dhcp", "DHCP server settings" },
	{ "resolver", "Resolver settings" },
	{ "database", "Database settings" },
	{ "webserver", "Webserver and API settings" },
	{ "files", "File locations" },
	{ "misc", "Miscellaneous settings" },
	{ "debug", "Debug settings" }
};

static struct {
	const char *name;
	struct {
		const char *addr1;
		const char *addr2;
	} v4;
	struct {
		const char *addr1;
		const char *addr2;
	} v6;
} dns_server[] =
{
	{ "Google (ECS, DNSSEC)", { "8.8.8.8", "8.8.4.4" }, { "2001:4860:4860:0:0:0:0:8888", "2001:4860:4860:0:0:0:0:8844" } },
	{ "OpenDNS (ECS, DNSSEC)", { "208.67.222.222", "208.67.220.220" }, {"2620:119:35::35", "2620:119:53::53"} },
	{ "Level3", { "4.2.2.1", "4.2.2.2" }, { NULL, NULL } },
	{ "Comodo", { "8.26.56.26", "8.20.247.20" }, { NULL, NULL} },
	{ "DNS.WATCH (DNSSEC)", { "84.200.69.80", "84.200.70.40" }, { "2001:1608:10:25:0:0:1c04:b12f", "2001:1608:10:25:0:0:9249:d69b" } },
	{ "Quad9 (filtered, DNSSEC)", {"9.9.9.9", "149.112.112.112" }, { "2620:fe::fe", "2620:fe::9" } },
	{ "Quad9 (unfiltered, no DNSSEC)", { "9.9.9.10", "149.112.112.10" }, { "2620:fe::10", "2620:fe::fe:10" } },
	{ "Quad9 (filtered, ECS, DNSSEC)", { "9.9.9.11", "149.112.112.11" }, { "2620:fe::11", "2620:fe::fe:11" } },
	{ "Cloudflare (DNSSEC)", { "1.1.1.1", "1.0.0.1" }, { "2606:4700:4700::1111", "2606:4700:4700::1001" } }
};

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
		case CONF_UINT16:
			return cJSON_CreateNumber(val->u16);
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
		case CONF_UINT16:
		{
			// 1. Check it is a number
			// 2. Check the number is within the allowed range for the given data type
			if(!cJSON_IsNumber(elem) ||
			   elem->valuedouble < 0 || elem->valuedouble > UINT16_MAX)
				return "not of type unsigned integer (16bit)";
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

	// Does the user request only a subset of /config?
	char **requested_path = NULL;
	unsigned int min_level = 0;
	if(api->item != NULL && strlen(api->item) > 0)
	{
		requested_path = gen_config_path(api->item, '/');
		min_level = config_path_depth(requested_path);
	}

	// Iterate over all known config elements and create appropriate JSON
	// objects + items for each of them
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(&config, i);

		// Get path depth
		unsigned int level = config_path_depth(conf_item->p);

		// Subset checking (if requested)
		if(min_level > 0)
		{
			// Skip entry if level is too deep (don't skip arrays here)
			if(min_level > level && conf_item->t != CONF_JSON_STRING_ARRAY)
				continue;
			// Skip entry if level if too deep (add one level for the array itself)
			if(min_level > level+1 && conf_item->t == CONF_JSON_STRING_ARRAY)
				continue;
			// Check equality of paths up to the requested level (if any)
			// Examples:
			//  requested was /config/dnsmasq -> skip all entries that do not start in dnsmasq.
			//  requested was /config/dnsmasq/dhcp -> skip all entries that do not start in dhcp
			//  etc.
			if(!check_paths_equal(conf_item->p, requested_path, min_level - 1))
				continue;
		}

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
			// Create the config item leaf object
			cJSON *leaf = JSON_NEW_OBJECT();

			// Add description
			JSON_REF_STR_IN_OBJECT(leaf, "description", conf_item->h);

			// Add allowed properties (if applicable)
			if(conf_item->a != NULL)
				JSON_ADD_ITEM_TO_OBJECT(leaf, "allowed", conf_item->a);
			else
				JSON_ADD_NULL_TO_OBJECT(leaf, "allowed");

			// Add config item type
			JSON_REF_STR_IN_OBJECT(leaf, "type", get_conf_type_str(conf_item->t));

			// Add current value
			cJSON *val = addJSONvalue(conf_item->t, &conf_item->v);
			if(val == NULL)
			{
				log_warn("Cannot format config item type %s of type %i",
					conf_item->k, conf_item->t);
				continue;
			}
			JSON_ADD_ITEM_TO_OBJECT(leaf, "value", val);

			// Add default value
			cJSON *dval = addJSONvalue(conf_item->t, &conf_item->d);
			if(dval == NULL)
			{
				log_warn("Cannot format config item type %s of type %i",
					conf_item->k, conf_item->t);
				continue;
			}
			JSON_ADD_ITEM_TO_OBJECT(leaf, "default", dval);

			// Add config item flags
			cJSON *flags = JSON_NEW_OBJECT();
			JSON_ADD_BOOL_TO_OBJECT(flags, "restart_dnsmasq", conf_item->f & FLAG_RESTART_DNSMASQ);
			JSON_ADD_BOOL_TO_OBJECT(flags, "advanced", conf_item->f & FLAG_ADVANCED_SETTING);
			JSON_ADD_ITEM_TO_OBJECT(leaf, "flags", flags);

			// Attach leave object to tree of objects
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

	// Release allocated memory
	if(requested_path != NULL)
		free_config_path(requested_path);

	// Build and return JSON response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "config", config_j);
	JSON_SEND_OBJECT(json);
}

static int api_config_patch(struct ftl_conn *api)
{
	// Is there a payload with valid JSON data?
	if (api->payload.json == NULL)
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request body data (no valid JSON)",
		                       NULL);
	}

	// Is there a "config" object at the root of the received JSON payload?
	cJSON *conf = cJSON_GetObjectItem(api->payload.json, "config");
	if (!cJSON_IsObject(conf))
	{
		return send_json_error(api, 400,
		                       "body_error",
		                       "No \"config\" object in body data",
		                       NULL);
	}

	// Read all known config items
	bool dnsmasq_changed = false;
	bool rewrite_custom_list = false;
	struct config conf_copy;
	duplicate_config(&conf_copy);
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(&conf_copy, i);

		// Get path depth
		unsigned int level = config_path_depth(conf_item->p);

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
		if(conf_item->f & FLAG_RESTART_DNSMASQ)
			dnsmasq_changed = true;

		// Check if this item requires a rewrite of the custom.list file
		if(conf_item == &conf_copy.dns.hosts)
			rewrite_custom_list = true;
	}

	// Request restart of FTL
	if(dnsmasq_changed)
	{
		char errbuf[ERRBUF_SIZE] = { 0 };
		if(write_dnsmasq_config(&conf_copy, true, errbuf))
			api->ftl.restart = true;
		else
		{
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid configuration",
			                       errbuf);
		}
	}
	else if(rewrite_custom_list)
	{
		// We need to rewrite the custom.list file but do not need to
		// restart dnsmasq. If dnsmasq is going to be restarted anyway,
		// this is not necessary as the file will be rewritten during
		// the restart
		write_custom_list();
	}

	// Install new configuration
	lock_shm();
	// Backup old config struct (so we can free it)
	struct config old_conf;
	memcpy(&old_conf, &config, sizeof(struct config));
	// Replace old config struct by changed one
	memcpy(&config, &conf_copy, sizeof(struct config));
	// Free old backup struct
	free_config(&old_conf);
	unlock_shm();

	// Store changed configuration to disk
	writeFTLtoml(true);

	// Reload debug levels
	set_debug_flags();

	// Return full config after possible changes above
	return api_config_get(api);
}

// Inspired by https://stackoverflow.com/a/32496721
//static void replace_char(char* str, char find, char replace)
//{
//	for (char *current_pos = strchr(str, find); (current_pos = strchr(str+1, find)) != NULL; *current_pos = replace);
//}

static int api_config_put_delete(struct ftl_conn *api)
{
	if(api->item == NULL || strlen(api->item) == 0)
		return 0;

	char **requested_path = gen_config_path(api->item, '/');
	const unsigned int min_level = config_path_depth(requested_path);

	const char *hint = NULL, *message = NULL;
	if(api->method == HTTP_PUT)
		hint = "Use, e.g., PUT /config/dnsmasq/upstreams/127.0.0.1 to add \"127.0.0.1\" to config.dns.upstreams";
	else
		hint = "Use, e.g., DELETE /config/dnsmasq/upstreams/127.0.0.1 to remove \"127.0.0.1\" from config.dns.upstreams";

	if(min_level < 2)
	{
		// Release allocated memory
		if(requested_path != NULL)
			free_config_path(requested_path);

		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid path depth",
		                       hint);
	}

	char *new_item = requested_path[min_level - 1];

	// Convert path to items, e.g.,
	// dnsmasq/dhcp/active -> dhcp.active
	//char *item = strdup(api->item);
	//replace_char(item, '/', '.');

	// Read all known config items
	bool dnsmasq_changed = false;
	bool rewrite_custom_list = false;
	bool found = false;
	struct config conf_copy;
	duplicate_config(&conf_copy);
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(&conf_copy, i);

		// We support PUT only for adding to string arrays
		if(conf_item->t != CONF_JSON_STRING_ARRAY)
			continue;

		// Get path depth
		const unsigned int level = config_path_depth(conf_item->p);

		// Check equality of paths up to the requested level (if any)
		// Examples:
		//  requested was /config/dnsmasq -> skip all entries that do not start in dnsmasq.
		//  requested was /config/dnsmasq/dhcp -> skip all entries that do not start in dhcp
		//  etc.
		if(!check_paths_equal(conf_item->p, requested_path, max(min_level - 2, level - 1)))
			continue;

		// Check if this is a property where we want to add an item
		if(min_level != level + 1)
			continue;

		// Check if this entry does already exist in the array
		int idx = 0;
		for(; idx < cJSON_GetArraySize(conf_item->v.json); idx++)
		{
			cJSON *elem = cJSON_GetArrayItem(conf_item->v.json, idx);
			if(elem != NULL && elem->valuestring != NULL &&
				strcmp(elem->valuestring, new_item) == 0)
			{
				found = true;
				break;
			}
		}

		if(api->method == HTTP_PUT)
		{
			if(found)
			{
				// Item already present
				message = "Item already present";
				hint = "Uniqueness of items is enforced";
				break;
			}
			else
			{
				// Add new item to array
				JSON_COPY_STR_TO_ARRAY(conf_item->v.json, new_item);
				found = true;
			}
		}
		else
		{
			if(found)
			{
				// Remove item from array
				cJSON_DeleteItemFromArray(conf_item->v.json, idx);
			}
			else
			{
				// Item not found
				message = "Item not found";
				hint = "Can only delete existing items";
				break;
			}
		}

		// If we reach this point, a valid setting was found and changed
		// Check if this item requires a config-rewrite + restart of dnsmasq
		if(conf_item->f & FLAG_RESTART_DNSMASQ)
			dnsmasq_changed = true;

		// Check if this item requires a rewrite of the custom.list file
		if(conf_item == &conf_copy.dns.hosts)
			rewrite_custom_list = true;
		break;
	}

	// Release allocated memory
	if(requested_path != NULL)
		free_config_path(requested_path);

	// Error 404 if not found
	if(!found || message != NULL)
	{
		if(!message)
			message = "No item specified";
		return send_json_error(api, 400,
		                       "bad_request",
		                       message,
		                       hint);
	}

	// We need to build a new config (and carefully test it!) whenever dnsmasq
	// options have changed that need a restart of the resolver
	if(dnsmasq_changed)
	{
		char errbuf[ERRBUF_SIZE] = { 0 };
		// Request restart of FTL
		if(write_dnsmasq_config(&conf_copy, true, errbuf))
			api->ftl.restart = true;
		else
		{
			// The new config did not work
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Invalid configuration",
			                       errbuf);
		}
	}
	else if(rewrite_custom_list)
	{
		// We need to rewrite the custom.list file but do not need to
		// restart dnsmasq. If dnsmasq is going to be restarted anyway,
		// this is not necessary as the file will be rewritten during
		// the restart
		write_custom_list();
	}

	// Install new configuration
	lock_shm();
	// Backup old config struct (so we can free it)
	struct config old_conf;
	memcpy(&old_conf, &config, sizeof(struct config));
	// Replace old config struct by changed one
	memcpy(&config, &conf_copy, sizeof(struct config));
	// Free old backup struct
	free_config(&old_conf);
	unlock_shm();

	// Store changed configuration to disk
	writeFTLtoml(true);

	// Reload debug levels
	set_debug_flags();

	return api->method == HTTP_PUT ? 201 : 204; // 201 - Created or 204 - No content
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
	else if(api->method == HTTP_PUT || api->method == HTTP_DELETE)
		return api_config_put_delete(api);

	return 0;
}

int api_config_topics(struct ftl_conn *api)
{
	cJSON *topics = JSON_NEW_ARRAY();
	for(unsigned int i = 0; i < sizeof(config_topics)/sizeof(*config_topics); i++)
	{
		cJSON *topic = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(topic, "name", config_topics[i].name);
		JSON_REF_STR_IN_OBJECT(topic, "description", config_topics[i].description);
		JSON_ADD_ITEM_TO_ARRAY(topics, topic);
	}

	// Build and return JSON response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "topics", topics);
	JSON_SEND_OBJECT(json);
}

int api_config_server(struct ftl_conn *api)
{
	cJSON *servers = JSON_NEW_ARRAY();
	for(unsigned int i = 0; i < sizeof(dns_server)/sizeof(*dns_server); i++)
	{
		cJSON *server = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(server, "name", dns_server[i].name);

		cJSON *v4 = JSON_NEW_ARRAY();
		if(dns_server[i].v4.addr1 != NULL)
			JSON_REF_STR_IN_ARRAY(v4, dns_server[i].v4.addr1);
		if(dns_server[i].v4.addr2 != NULL)
			JSON_REF_STR_IN_ARRAY(v4, dns_server[i].v4.addr2);
		JSON_ADD_ITEM_TO_OBJECT(server, "v4", v4);

		cJSON *v6 = JSON_NEW_ARRAY();
		if(dns_server[i].v6.addr1 != NULL)
			JSON_REF_STR_IN_ARRAY(v6, dns_server[i].v6.addr1);
		if(dns_server[i].v6.addr2 != NULL)
			JSON_REF_STR_IN_ARRAY(v6, dns_server[i].v6.addr2);
		JSON_ADD_ITEM_TO_OBJECT(server, "v6", v6);

		JSON_ADD_ITEM_TO_ARRAY(servers, server);
	}

	// Build and return JSON response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "server", servers);
	JSON_SEND_OBJECT(json);
}
