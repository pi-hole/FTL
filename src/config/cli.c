/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  CLI config routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "config/cli.h"
#include "config/config.h"
#include "config/toml_helper.h"
#include "config/toml_writer.h"
#include "config/dnsmasq_config.h"
#include "log.h"
#include "datastructure.h"
// toml_table_t
#include "tomlc99/toml.h"
// hash_password()
#include "config/password.h"
// check_capability()
#include "capabilities.h"
// suggest_closest_conf_key()
#include "config/suggest.h"

enum exit_codes {
	OKAY = 0,
	FAIL = 1,
	VALUE_INVALID = 2,
	DNSMASQ_TEST_FAILED = 3,
	KEY_UNKNOWN = 4,
	ENV_VAR_FORCED = 5,
} __attribute__((packed));

// Read a TOML value from a table depending on its type
static bool readStringValue(struct conf_item *conf_item, const char *value, struct config *newconf)
{
	if(conf_item == NULL || value == NULL)
	{
		log_debug(DEBUG_CONFIG, "readStringValue(%p, %p) called with invalid arguments, skipping",
		          conf_item, value);
		return false;
	}
	switch(conf_item->t)
	{
		case CONF_BOOL:
		{
			if(strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0)
				conf_item->v.b = true;
			else if(strcasecmp(value, "false") == 0 || strcasecmp(value, "no") == 0)
				conf_item->v.b = false;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: [ true, false, yes, no ]", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_ALL_DEBUG_BOOL:
		{
			if(strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0)
			{
				set_all_debug(newconf, true);
				conf_item->v.b = true;
				set_debug_flags(newconf);
			}
			else if(strcasecmp(value, "false") == 0 || strcasecmp(value, "no") == 0)
			{
				set_all_debug(newconf, false);
				conf_item->v.b = false;
				set_debug_flags(newconf);
			}
			else
			{
				log_err("Config setting %s is invalid, allowed options are: [ true, false, yes, no ]", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_INT:
		{
			int val;
			if(sscanf(value, "%i", &val) == 1)
				conf_item->v.i = val;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: integer", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_UINT:
		{
			unsigned int val;
			if(sscanf(value, "%u", &val) == 1)
				conf_item->v.ui = val;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: unsigned integer", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_UINT16:
		{
			uint16_t val;
			if(sscanf(value, "%hu", &val) == 1)
				conf_item->v.ui = val;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: unsigned integer (16 bit)", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_LONG:
		{
			long val;
			if(sscanf(value, "%li", &val) == 1)
				conf_item->v.l = val;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: long integer", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_ULONG:
		{
			unsigned long val;
			if(sscanf(value, "%lu", &val) == 1)
				conf_item->v.ul = val;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: unsigned long integer", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_DOUBLE:
		{
			double val;
			if(sscanf(value, "%lf", &val) == 1)
				conf_item->v.d = val;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: double", conf_item->k);
				return false;
			}
			break;
		}
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
		{
			if(conf_item->t == CONF_STRING_ALLOCATED)
					free(conf_item->v.s);
			conf_item->v.s = strdup(value);
			conf_item->t = CONF_STRING_ALLOCATED;
			break;
		}
		case CONF_PASSWORD:
		{
			// Get pointer to pwhash instead of the password by
			// decrementing the pointer by one. This is safe as we
			// know that the pwhash is the immediately preceding
			// item in the struct
			conf_item--;

			// Get password hash as allocated string (an empty string is hashed to an empty string)
			char *pwhash = strlen(value) > 0 ? create_password(value) : strdup("");

			// Verify that the password hash is either valid or empty
			const enum password_result status = verify_password(value, pwhash, false);
			if(status != PASSWORD_CORRECT && status != NO_PASSWORD_SET)
			{
				log_err("Failed to create password hash (verification failed), password remains unchanged");
				free(pwhash);
				return false;
			}

			// Free old password hash if it was allocated
			if(conf_item->t == CONF_STRING_ALLOCATED)
					free(conf_item->v.s);

			// Store new password hash
			conf_item->v.s = pwhash;
			conf_item->t = CONF_STRING_ALLOCATED;
			break;
		}
		case CONF_ENUM_PTR_TYPE:
		{
			const int ptr_type = get_ptr_type_val(value);
			if(ptr_type != -1)
				conf_item->v.ptr_type = ptr_type;
			else
			{
				char *allowed = NULL;
				CONFIG_ITEM_ARRAY(conf_item->a, allowed);
				log_err("Config setting %s is invalid, allowed options are: %s", conf_item->k, allowed);
				free(allowed);
				return false;
			}
			break;
		}
		case CONF_ENUM_BUSY_TYPE:
		{
			const int busy_reply = get_busy_reply_val(value);
			if(busy_reply != -1)
				conf_item->v.busy_reply = busy_reply;
			else
			{
				char *allowed = NULL;
				CONFIG_ITEM_ARRAY(conf_item->a, allowed);
				log_err("Config setting %s is invalid, allowed options are: %s", conf_item->k, allowed);
				free(allowed);
				return false;
			}
			break;
		}
		case CONF_ENUM_BLOCKING_MODE:
		{
			const int blocking_mode = get_blocking_mode_val(value);
			if(blocking_mode != -1)
				conf_item->v.blocking_mode = blocking_mode;
			else
			{
				char *allowed = NULL;
				CONFIG_ITEM_ARRAY(conf_item->a, allowed);
				log_err("Config setting %s is invalid, allowed options are: %s", conf_item->k, allowed);
				free(allowed);
				return false;
			}
			break;
		}
		case CONF_ENUM_REFRESH_HOSTNAMES:
		{
			const int refresh_hostnames = get_refresh_hostnames_val(value);
			if(refresh_hostnames != -1)
				conf_item->v.refresh_hostnames = refresh_hostnames;
			else
			{
				char *allowed = NULL;
				CONFIG_ITEM_ARRAY(conf_item->a, allowed);
				log_err("Config setting %s is invalid, allowed options are: %s", conf_item->k, allowed);
				free(allowed);
				return false;
			}
			break;
		}
		case CONF_ENUM_LISTENING_MODE:
		{
			const int listeningMode = get_listeningMode_val(value);
			if(listeningMode != -1)
				conf_item->v.listeningMode = listeningMode;
			else
			{
				char *allowed = NULL;
				CONFIG_ITEM_ARRAY(conf_item->a, allowed);
				log_err("Config setting %s is invalid, allowed options are: %s", conf_item->k, allowed);
				free(allowed);
				return false;
			}
			break;
		}
		case CONF_ENUM_PRIVACY_LEVEL:
		{
			int val;
			if(sscanf(value, "%i", &val) == 1 && val >= PRIVACY_SHOW_ALL && val <= PRIVACY_MAXIMUM)
				conf_item->v.i = val;
			else
			{
				log_err("Config setting %s is invalid, allowed options are: integer between %d and %d", conf_item->k, PRIVACY_SHOW_ALL, PRIVACY_MAXIMUM);
				return false;
			}
			break;
		}
		case CONF_ENUM_WEB_THEME:
		{
			const int web_theme = get_web_theme_val(value);
			if(web_theme != -1)
				conf_item->v.web_theme = web_theme;
			else
			{
				char *allowed = NULL;
				CONFIG_ITEM_ARRAY(conf_item->a, allowed);
				log_err("Config setting %s is invalid, allowed options are: %s", conf_item->k, allowed);
				free(allowed);
				return false;
			}
			break;
		}
		case CONF_ENUM_TEMP_UNIT:
		{
			const int temp_unit = get_temp_unit_val(value);
			if(temp_unit != -1)
				conf_item->v.temp_unit = temp_unit;
			else
			{
				char *allowed = NULL;
				CONFIG_ITEM_ARRAY(conf_item->a, allowed);
				log_err("Config setting %s is invalid, allowed options are: %s", conf_item->k, allowed);
				free(allowed);
				return false;
			}
			break;
		}
		case CONF_STRUCT_IN_ADDR:
		{
			struct in_addr addr4 = { 0 };
			if(strlen(value) == 0)
			{
				// Special case: empty string -> 0.0.0.0
				conf_item->v.in_addr.s_addr = INADDR_ANY;
			}
			else if(inet_pton(AF_INET, value, &addr4))
				memcpy(&conf_item->v.in_addr, &addr4, sizeof(addr4));
			else
			{
				log_err("Config setting %s is invalid (%s), allowed options are: IPv4 address", conf_item->k, strerror(errno));
				return false;
			}
			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			struct in6_addr addr6 = { 0 };
			if(strlen(value) == 0)
			{
				// Special case: empty string -> ::
				memcpy(&conf_item->v.in6_addr, &in6addr_any, sizeof(in6addr_any));
			}
			else if(inet_pton(AF_INET6, value, &addr6))
				memcpy(&conf_item->v.in6_addr, &addr6, sizeof(addr6));
			else
			{
				log_err("Config setting %s is invalid (%s), allowed options are: IPv6 address", conf_item->k, strerror(errno));
				return false;
			}
			break;
		}
		case CONF_JSON_STRING_ARRAY:
		{
			const char *json_error = NULL;
			cJSON *elem = cJSON_ParseWithOpts(value, &json_error, 0);
			if(elem == NULL)
			{
				log_err("Config setting %s is invalid: not valid JSON, error at: %.20s", conf_item->k, json_error);
				return false;
			}
			if(!cJSON_IsArray(elem))
			{
				log_err("Config setting %s is invalid: not a valid string array (example: [ \"a\", \"b\", \"c\" ])", conf_item->k);
				return false;
			}
			const unsigned int elems = cJSON_GetArraySize(elem);
			for(unsigned int i = 0; i < elems; i++)
			{
				const cJSON *item = cJSON_GetArrayItem(elem, i);
				if(!cJSON_IsString(item))
				{
					log_err("Config setting %s is invalid: element with index %u is not a string", conf_item->k, i);
					cJSON_Delete(elem);
					return false;
				}
			}
			// If we reach this point, all elements are valid
			// Free previously allocated JSON array and replace with new
			cJSON_Delete(conf_item->v.json);
			conf_item->v.json = elem;
			break;
		}
	}

	return true;
}

int set_config_from_CLI(const char *key, const char *value)
{
	// Check if we are either
	// - root, or
	// - pihole with CAP_CHOWN capability on the pihole-FTL binary
	const uid_t euid = geteuid();
	const struct passwd *current_user = getpwuid(euid);
	const bool is_root = euid == 0;
	const bool is_pihole = current_user != NULL && strcmp(current_user->pw_name, "pihole") == 0;
	const bool have_chown_cap = check_capability(CAP_CHOWN);
	if(!is_root && !(is_pihole && have_chown_cap))
	{
		if(is_pihole)
			printf("Permission error: CAP_CHOWN is missing on the binary\n");
		else
			printf("Permission error: User %s is not allowed to edit Pi-hole's config\n", current_user->pw_name);

		printf("Please run this command using sudo\n\n");
		return EXIT_FAILURE;
	}

	// Identify config option
	struct config newconf;
	duplicate_config(&newconf, &config);
	struct conf_item *conf_item = NULL;
	struct conf_item *new_item = NULL;
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to (copied) memory location of this conf_item
		struct conf_item *item = get_conf_item(&newconf, i);

		if(strcmp(item->k, key) != 0)
			continue;

		if(item->f & FLAG_ENV_VAR)
		{
			log_err("Config option %s is read-only (set via environmental variable)", key);
			free_config(&newconf);
			return ENV_VAR_FORCED;
		}

		// This is the config option we are looking for
		new_item = item;

		// Also get pointer to memory location of this conf_item
		conf_item = get_conf_item(&config, i);

		// Break early
		break;
	}

	// Check if we found the config option
	if(new_item == NULL)
	{
		unsigned int N = 0;
		char **matches = suggest_closest_conf_key(false, key, &N);
		log_err("Unknown config option %s, did you mean:", key);
		for(unsigned int i = 0; i < N; i++)
			log_err(" - %s", matches[i]);
		free(matches);

		free_config(&newconf);
		return KEY_UNKNOWN;
	}

	// Parse value
	if(!readStringValue(new_item, value, &newconf))
	{
		free_config(&newconf);
		return VALUE_INVALID;
	}

	// Check if value changed compared to current value
	// Also check if this is the password config item change as this
	// actually changed pwhash behind the scenes
	if(!compare_config_item(conf_item->t, &new_item->v, &conf_item->v) ||
	   conf_item->t == CONF_PASSWORD)
	{
		// Config item changed

		// Validate new value(if validation function is defined)
		if(new_item->c != NULL)
		{
			char errbuf[VALIDATOR_ERRBUF_LEN] = { 0 };
			if(!new_item->c(&new_item->v, new_item->k, errbuf))
			{
				free_config(&newconf);
				log_err("Invalid value: %s", errbuf);
				return 3;
			}
		}

		// Is this a dnsmasq option we need to check?
		if(conf_item->f & FLAG_RESTART_FTL)
		{
			char errbuf[ERRBUF_SIZE] = { 0 };
			if(!write_dnsmasq_config(&newconf, true, errbuf))
			{
				// Test failed
				log_debug(DEBUG_CONFIG, "Config item %s: dnsmasq config test failed", conf_item->k);
				free_config(&newconf);
				return DNSMASQ_TEST_FAILED;
			}
		}
		else if(conf_item == &config.dns.hosts)
		{
			// We need to rewrite the custom.list file but do not
			// need to restart dnsmasq
			write_custom_list();
		}

		// Install new configuration
		replace_config(&newconf);

		// Print value
		writeTOMLvalue(stdout, -1, new_item->t, &new_item->v);
	}
	else
	{
		// No change
		log_debug(DEBUG_CONFIG, "Config item %s: Unchanged", conf_item->k);
		free_config(&newconf);

		// Print value
		writeTOMLvalue(stdout, -1, conf_item->t, &conf_item->v);
	}

	putchar('\n');
	writeFTLtoml(false);
	return OKAY;
}

int get_config_from_CLI(const char *key, const bool quiet)
{
	// Identify config option
	struct conf_item *conf_item = NULL;

	// We first loop over all config options to check if the one we are
	// looking for is an exact match, use partial match otherwise
	bool exactMatch = false;
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *item = get_conf_item(&config, i);

		// Check if item.k is identical with key
		if(strcmp(item->k, key) == 0)
		{
			exactMatch = true;
			break;
		}
	}

	// Loop over all config options again to find the one we are looking for
	// (possibly partial match)
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *item = get_conf_item(&config, i);

		// Check if item.k starts with key
		if(key != NULL &&
		   ((exactMatch && strcmp(item->k, key) != 0) ||
		    (!exactMatch && strncmp(item->k, key, strlen(key)))))
			continue;

		// Skip write-only options
		if(item->f & FLAG_WRITE_ONLY)
			continue;

		// This is the config option we are looking for
		conf_item = item;

		// Print key if this is not an exact match
		if(key == NULL || strcmp(item->k, key) != 0)
			printf("%s = ", item->k);

		// Print value
		if(conf_item-> f & FLAG_WRITE_ONLY)
			puts("<write-only property>");
		else
			writeTOMLvalue(stdout, -1, conf_item->t, &conf_item->v);
		putchar('\n');
	}

	// Check if we found the config option
	if(conf_item == NULL)
	{
		unsigned int N = 0;
		char **matches = suggest_closest_conf_key(false, key, &N);
		log_err("Unknown config option %s, did you mean:", key);
		for(unsigned int i = 0; i < N; i++)
			log_err(" - %s", matches[i]);
		free(matches);

		return KEY_UNKNOWN;
	}

	// Use return status if this is a boolean value
	// and we are in quiet mode
	if(quiet && conf_item != NULL && conf_item->t == CONF_BOOL)
		return conf_item->v.b ? OKAY : FAIL;

	return OKAY;
}
