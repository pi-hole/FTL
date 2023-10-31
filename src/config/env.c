/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Environment-related routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "env.h"
#include "log.h"
#include "config/config.h"
// get_refresh_hostnames_str()
#include "datastructure.h"
//set_and_check_password()
#include "config/password.h"
// cli_tick()
#include "args.h"

struct env_item
{
	bool used;
	char *key;
	char *value;
	struct env_item *next;
};

static struct env_item *env_list = NULL;

void getEnvVars(void)
{
	// Read environment variables only once
	if(env_list != NULL)
		return;

	// Get all environment variables
	for(char **env = environ; *env != NULL; env++)
	{
		// Check if this is a FTLCONF_ variable
		if(strncmp(*env, FTLCONF_PREFIX, sizeof(FTLCONF_PREFIX) - 1) == 0)
		{
			// Split key and value
			char *key = strtok(*env, "=");
			char *value = strtok(NULL, "=");

			// Add to list
			struct env_item *new_item = calloc(1, sizeof(struct env_item));
			new_item->used = false;
			new_item->key = strdup(key);
			new_item->value = strdup(value);
			new_item->next = env_list;
			env_list = new_item;
		}
	}
}

void printFTLenv(void)
{
	// Nothing to print if no env vars are used
	if(env_list == NULL)
		return;

	// Count number of used and unused env vars
	unsigned int used = 0, unused = 0;
	for(struct env_item *item = env_list; item != NULL; item = item->next)
	{
		if(item->used)
			used++;
		else
			unused++;
	}

	log_info("%u FTLCONF environment variable%s found (%u used, %u unused)",
	         used + unused, used + unused == 1 ? "" : "s", used, unused);

	// Iterate over all known FTLCONF environment variables
	for(struct env_item *item = env_list; item != NULL; item = item->next)
	{
		if(item->used)
		{
			log_info("%s %s", cli_tick(), item->key);
			continue;
		}
		// else: print warning
		log_warn("%s %s is unknown", cli_cross(), item->key);
	}
}

static char *getFTLenv(const char *key)
{
	// Iterate over all known FTLCONF environment variables
	for(struct env_item *item = env_list; item != NULL; item = item->next)
	{
		// Check if this is the requested key
		if(strcmp(item->key, key) == 0)
		{
			item->used = true;
			return item->value;
		}
	}

	// Return NULL if the key was not found
	return NULL;
}

void freeEnvVars(void)
{
	// Free all environment variables
	while(env_list != NULL)
	{
		struct env_item *next = env_list->next;
		free(env_list->key);
		free(env_list->value);
		free(env_list);
		env_list = next;
	}
}

bool readEnvValue(struct conf_item *conf_item, struct config *newconf)
{
	// First check if a environmental variable with the given key exists by
	// iterating over the list of FTLCONF_ variables
	char *envvar = getFTLenv(conf_item->e);

	// Return early if this environment variable does not exist
	if(envvar == NULL)
		return false;

	log_debug(DEBUG_CONFIG, "ENV %s = %s", conf_item->e, envvar);

	switch(conf_item->t)
	{
		case CONF_BOOL:
		{
			if(strcasecmp(envvar, "true") == 0 || strcasecmp(envvar, "yes") == 0)
				conf_item->v.b = true;
			else if(strcasecmp(envvar, "false") == 0 || strcasecmp(envvar, "no") == 0)
				conf_item->v.b = false;
			else
				log_warn("ENV %s is not of type bool", conf_item->e);
			break;
		}
		case CONF_ALL_DEBUG_BOOL:
		{
			if(strcasecmp(envvar, "true") == 0 || strcasecmp(envvar, "yes") == 0)
				set_all_debug(newconf, true);
			else if(strcasecmp(envvar, "false") == 0 || strcasecmp(envvar, "no") == 0)
				set_all_debug(newconf, false);
			else
				log_warn("ENV %s is not of type bool", conf_item->e);
			break;
		}
		case CONF_INT:
		{
			int val = 0;
			if(sscanf(envvar, "%i", &val) == 1)
				conf_item->v.i = val;
			else
				log_warn("ENV %s is not of type integer", conf_item->e);
			break;
		}
		case CONF_UINT:
		{
			unsigned int val = 0;
			if(sscanf(envvar, "%u", &val) == 1)
				conf_item->v.ui = val;
			else
				log_warn("ENV %s is not of type unsigned integer", conf_item->e);
			break;
		}
		case CONF_UINT16:
		{
			unsigned int val = 0;
			if(sscanf(envvar, "%u", &val) == 1 && val <= UINT16_MAX)
				conf_item->v.ui = val;
			else
				log_warn("ENV %s is not of type unsigned integer (16 bit)", conf_item->e);
			break;
		}
		case CONF_LONG:
		{
			long val = 0;
			if(sscanf(envvar, "%li", &val) == 1)
				conf_item->v.l = val;
			else
				log_warn("ENV %s is not of type long", conf_item->e);
			break;
		}
		case CONF_ULONG:
		{
			unsigned long val = 0;
			if(sscanf(envvar, "%lu", &val) == 1)
				conf_item->v.ul = val;
			else
				log_warn("ENV %s is not of type unsigned long", conf_item->e);
			break;
		}
		case CONF_DOUBLE:
		{
			double val = 0;
			if(sscanf(envvar, "%lf", &val) == 1)
				conf_item->v.d = val;
			else
				log_warn("ENV %s is not of type double", conf_item->e);
			break;
		}
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
		{
			if(conf_item->t == CONF_STRING_ALLOCATED)
				free(conf_item->v.s);
			conf_item->v.s = strdup(envvar);
			conf_item->t = CONF_STRING_ALLOCATED;
			break;
		}
		case CONF_ENUM_PTR_TYPE:
		{
			const int ptr_type = get_ptr_type_val(envvar);
			if(ptr_type != -1)
				conf_item->v.ptr_type = ptr_type;
			else
				log_warn("ENV %s is invalid, allowed options are: %s", conf_item->e, conf_item->h);
			break;
		}
		case CONF_ENUM_BUSY_TYPE:
		{
			const int busy_reply = get_busy_reply_val(envvar);
			if(busy_reply != -1)
				conf_item->v.busy_reply = busy_reply;
			else
				log_warn("ENV %s is invalid, allowed options are: %s", conf_item->e, conf_item->h);
			break;
		}
		case CONF_ENUM_BLOCKING_MODE:
		{
			const int blocking_mode = get_blocking_mode_val(envvar);
			if(blocking_mode != -1)
				conf_item->v.blocking_mode = blocking_mode;
			else
				log_warn("ENV %s is invalid, allowed options are: %s", conf_item->e, conf_item->h);
			break;
		}
		case CONF_ENUM_REFRESH_HOSTNAMES:
		{
			const int refresh_hostnames = get_refresh_hostnames_val(envvar);
			if(refresh_hostnames != -1)
				conf_item->v.refresh_hostnames = refresh_hostnames;
			else
				log_warn("ENV %s is invalid, allowed options are: %s", conf_item->e, conf_item->h);
			break;
		}
		case CONF_ENUM_LISTENING_MODE:
		{
			const int listeningMode = get_listeningMode_val(envvar);
			if(listeningMode != -1)
				conf_item->v.listeningMode = listeningMode;
			else
				log_warn("ENV %s is invalid, allowed options are: %s", conf_item->e, conf_item->h);
			break;
		}
		case CONF_ENUM_WEB_THEME:
		{
			const int web_theme = get_web_theme_val(envvar);
			if(web_theme != -1)
				conf_item->v.web_theme = web_theme;
			else
				log_warn("ENV %s is invalid, allowed options are: %s", conf_item->e, conf_item->h);
			break;
		}
		case CONF_ENUM_TEMP_UNIT:
		{
			const int temp_unit = get_temp_unit_val(envvar);
			if(temp_unit != -1)
				conf_item->v.temp_unit = temp_unit;
			else
				log_warn("ENV %s is invalid, allowed options are: %s", conf_item->e, conf_item->h);
			break;
		}
		case CONF_ENUM_PRIVACY_LEVEL:
		{
			int val = 0;
			if(sscanf(envvar, "%i", &val) == 1 && val >= PRIVACY_SHOW_ALL && val <= PRIVACY_MAXIMUM)
				conf_item->v.i = val;
			else
				log_warn("ENV %s is invalid (not of type integer or outside allowed bounds)", conf_item->e);
			break;
		}
		case CONF_STRUCT_IN_ADDR:
		{
			struct in_addr addr4 = { 0 };
			if(strlen(envvar) == 0)
			{
				// Special case: empty string -> 0.0.0.0
				conf_item->v.in_addr.s_addr = INADDR_ANY;
			}
			else if(inet_pton(AF_INET, envvar, &addr4))
				memcpy(&conf_item->v.in_addr, &addr4, sizeof(addr4));
			else
				log_warn("ENV %s is invalid (not of type IPv4 address)", conf_item->e);
			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			struct in6_addr addr6 = { 0 };
			if(strlen(envvar) == 0)
			{
				// Special case: empty string -> ::
				memcpy(&conf_item->v.in6_addr, &in6addr_any, sizeof(in6addr_any));
			}
			else if(inet_pton(AF_INET6, envvar, &addr6))
				memcpy(&conf_item->v.in6_addr, &addr6, sizeof(addr6));
			else
				log_warn("ENV %s is invalid (not of type IPv6 address)", conf_item->e);
			break;
		}
		case CONF_JSON_STRING_ARRAY:
		{
			// Make a copy of envvar as strtok modified the input string
			char *envvar_copy = strdup(envvar);
			// Free previously allocated JSON array
			cJSON_Delete(conf_item->v.json);
			conf_item->v.json = cJSON_CreateArray();
			// Parse envvar array and generate a JSON array (env var
			// arrays are ;-delimited)
			const char delim[] =";";
			const char *elem = strtok(envvar_copy, delim);
			while(elem != NULL)
			{
				// Only import non-empty entries
				if(strlen(elem) > 0)
				{
					// Add string to our JSON array
					cJSON *item = cJSON_CreateString(elem);
					cJSON_AddItemToArray(conf_item->v.json, item);
				}

				// Search for the next element
				elem = strtok(NULL, delim);
			}
			free(envvar_copy);
			break;
		}
		case CONF_PASSWORD:
		{
			if(!set_and_check_password(conf_item, envvar))
			{
				log_warn("ENV %s is invalid", conf_item->e);
				break;
			}
		}
	}

	return true;
}
