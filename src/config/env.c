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
// suggest_closest()
#include "config/suggest.h"
// LINE_MAX
#include <limits.h>
// openFTLtoml()
#include "config/toml_helper.h"
struct env_item
{
	bool used;
	bool valid;
	char *key;
	char *value;
	const char *error;
	const char *allowed;
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
			// Make a copy of the environment variable to avoid
			// modifying the original string
			char *env_copy = strdup(*env);

			// Split key and value using strtok_r
			char *saveptr = NULL;
			char *key = strtok_r(env_copy, "=", &saveptr);

			// Log warning if value is missing
			char *value;
			if(strlen(*env) <= strlen(key) + 1)
			{
				log_warn("Environment variable %s has no value, substituting with empty string", key);
				value = (char*)"";
			}
			else
			{
				// The entire string *after* the key + 1 (for
				// the '=') is the value
				value = *env + strlen(key) + 1;
			}
			log_debug(DEBUG_CONFIG, "ENV \"%s\" = \"%s\"", key, value);

			// Add to list
			struct env_item *new_item = calloc(1, sizeof(struct env_item));
			new_item->used = false;
			new_item->key = strdup(key);
			new_item->value = strdup(value);
			new_item->error = NULL;
			new_item->allowed = NULL;
			new_item->next = env_list;
			env_list = new_item;

			// Free the copy of the environment variable
			free(env_copy);
		}
	}

}

void printFTLenv(void)
{
	// Nothing to print if no env vars are used
	if(env_list == NULL)
		return;

	// Count number of used and ignored env vars
	unsigned int used = 0, invalid = 0, ignored = 0;
	for(struct env_item *item = env_list; item != NULL; item = item->next)
	{
		if(item->used)
			if(item->valid)
				used++;
			else
				invalid++;
		else
			ignored++;
	}

	const unsigned int sum = used + invalid + ignored;
	log_info("%u FTLCONF environment variable%s found (%u used, %u invalid, %u ignored)",
	         sum, sum == 1 ? "" : "s", used, invalid, ignored);

	// Iterate over all known FTLCONF environment variables
	for(struct env_item *item = env_list; item != NULL; item = item->next)
	{
		if(item->used)
		{
			if(item->valid)
				log_info("   %s %s is used", cli_tick(), item->key);
			else
			{
				if(item->error != NULL && item->allowed == NULL)
					log_err("  %s %s is invalid (%s)",
					        cli_cross(), item->key, item->error);
				else if(item->error != NULL && item->allowed != NULL)
					log_err("  %s %s is invalid (%s, allowed options are: %s)",
					        cli_cross(), item->key, item->error, item->allowed);
				else
					log_err("  %s %s is invalid",
					        cli_cross(), item->key);
			}

			continue;
		}
		// else: print warning
		unsigned int N = 0;
		char **matches = suggest_closest_conf_key(true, item->key, &N);

		// Print the closest matches
		log_warn("%s %s is unknown, did you mean any of these?", cli_qst(), item->key);
		for(size_t i = 0; i < N; ++i)
			log_warn("    - %s", matches[i]);
		free(matches);
	}
}

static struct env_item *__attribute__((pure)) getFTLenv(const char *key)
{
	// Iterate over all known FTLCONF environment variables
	for(struct env_item *item = env_list; item != NULL; item = item->next)
	{
		// Check if this is the requested key
		if(strcmp(item->key, key) == 0)
			return item;
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

bool __attribute__((nonnull(1,2,3))) readEnvValue(struct conf_item *conf_item, struct config *newconf, cJSON *forced_vars, bool *reset)
{
	// First check if a environmental variable with the given key exists by
	// iterating over the list of FTLCONF_ variables
	struct env_item *item = getFTLenv(conf_item->e);

	if(item == NULL)
	{
		// Environment variable does not exist

		// Check if this was a forced setting before
		// If so, we revert the config option to default
		for(int i = 0; i < cJSON_GetArraySize(forced_vars); i++)
		{
			const char *forced_var = cJSON_GetArrayItem(forced_vars, i)->valuestring;
			if(strcmp(forced_var, conf_item->k) == 0)
			{
				log_info("Resetting %s to default (not forced anymore)", conf_item->k);

				// Revert to default
				if(conf_item->t == CONF_STRING_ALLOCATED)
				{
					// Free previously allocated string
					free(conf_item->v.s);
					// Make a duplicate of the default value
					conf_item->v.s = strdup(conf_item->d.s);
				}
				else
				{
					// Revert to default value
					memcpy(&conf_item->v, &conf_item->d, sizeof(conf_item->v));
				}

				// Mark this environment variable as reset to
				// default
				if(reset != NULL)
					*reset = true;
				break;
			}
		}

		// Return false as this setting is not forced by an environment
		// variable
		return false;
	}

	// Mark this environment variable as used
	item->used = true;

	// else: We found an environment variable with the given key
	const char *envvar = item != NULL ? item->value : NULL;

	log_debug(DEBUG_CONFIG, "ENV %s = %s", conf_item->e, envvar);

	switch(conf_item->t)
	{
		case CONF_BOOL:
		{
			if(strcasecmp(envvar, "true") == 0 || strcasecmp(envvar, "yes") == 0)
			{
				conf_item->v.b = true;
				item->valid = true;
			}
			else if(strcasecmp(envvar, "false") == 0 || strcasecmp(envvar, "no") == 0)
			{
				conf_item->v.b = false;
				item->valid = true;
			}
			else
			{
				item->error = "not of type bool";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_ALL_DEBUG_BOOL:
		{
			if(strcasecmp(envvar, "true") == 0 || strcasecmp(envvar, "yes") == 0)
			{
				set_all_debug(newconf, true);
				item->valid = true;
			}
			else if(strcasecmp(envvar, "false") == 0 || strcasecmp(envvar, "no") == 0)
			{
				set_all_debug(newconf, false);
				item->valid = true;
			}
			else
			{
				item->error = "not of type bool";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_INT:
		{
			int val = 0;
			if(sscanf(envvar, "%i", &val) == 1)
			{
				conf_item->v.i = val;
				item->valid = true;
			}
			else
			{
				item->error = "not of type integer";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_UINT:
		{
			unsigned int val = 0;
			if(sscanf(envvar, "%u", &val) == 1)
			{
				conf_item->v.ui = val;
				item->valid = true;
			}
			else
			{
				item->error = "not of type unsigned integer";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_UINT16:
		{
			unsigned int val = 0;
			if(sscanf(envvar, "%u", &val) == 1 && val <= UINT16_MAX)
			{
				conf_item->v.ui = val;
				item->valid = true;
			}
			else
			{
				item->error = "not of type unsigned integer (16 bit";
				log_warn("ENV %s is %s)", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_LONG:
		{
			long val = 0;
			if(sscanf(envvar, "%li", &val) == 1)
			{
				conf_item->v.l = val;
				item->valid = true;
			}
			else
			{
				item->error = "not of type long";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_ULONG:
		{
			unsigned long val = 0;
			if(sscanf(envvar, "%lu", &val) == 1)
			{
				conf_item->v.ul = val;
				item->valid = true;
			}
			else
			{
				item->error = "not of type unsigned long";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_DOUBLE:
		{
			double val = 0;
			if(sscanf(envvar, "%lf", &val) == 1)
			{
				conf_item->v.d = val;
				item->valid = true;
			}
			else
			{
				item->error = "not of type double";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
			break;
		}
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
		{
			if(conf_item->t == CONF_STRING_ALLOCATED)
				free(conf_item->v.s);
			conf_item->v.s = strdup(envvar);
			conf_item->t = CONF_STRING_ALLOCATED;
			item->valid = true;
			break;
		}
		case CONF_ENUM_PTR_TYPE:
		{
			const int ptr_type = get_ptr_type_val(envvar);
			if(ptr_type != -1)
			{
				conf_item->v.ptr_type = ptr_type;
				item->valid = true;
			}
			else
			{
				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_BUSY_TYPE:
		{
			const int busy_reply = get_busy_reply_val(envvar);
			if(busy_reply != -1)
			{
				conf_item->v.busy_reply = busy_reply;
				item->valid = true;
			}
			else
			{

				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_BLOCKING_MODE:
		{
			const int blocking_mode = get_blocking_mode_val(envvar);
			if(blocking_mode != -1)
			{
				conf_item->v.blocking_mode = blocking_mode;
				item->valid = true;
			}
			else
			{

				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_REFRESH_HOSTNAMES:
		{
			const int refresh_hostnames = get_refresh_hostnames_val(envvar);
			if(refresh_hostnames != -1)
			{
				conf_item->v.refresh_hostnames = refresh_hostnames;
				item->valid = true;
			}
			else
			{

				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_LISTENING_MODE:
		{
			const int listeningMode = get_listeningMode_val(envvar);
			if(listeningMode != -1)
			{
				conf_item->v.listeningMode = listeningMode;
				item->valid = true;
			}
			else
			{

				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_WEB_THEME:
		{
			const int web_theme = get_web_theme_val(envvar);
			if(web_theme != -1)
			{
				conf_item->v.web_theme = web_theme;
				item->valid = true;
			}
			else
			{

				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_TEMP_UNIT:
		{
			const int temp_unit = get_temp_unit_val(envvar);
			if(temp_unit != -1)
			{
				conf_item->v.temp_unit = temp_unit;
				item->valid = true;
			}
			else
			{

				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_BLOCKING_EDNS_MODE:
		{
			const int edns_mode = get_edns_mode_val(envvar);
			if(edns_mode != -1)
			{
				conf_item->v.edns_mode = edns_mode;
				item->valid = true;
			}
			else
			{

				item->error = "not an allowed option";
				item->allowed = conf_item->h;
				log_warn("ENV %s is %s, allowed options are: %s",
				         conf_item->e, item->error, item->allowed);
				item->valid = false;
			}
			break;
		}
		case CONF_ENUM_PRIVACY_LEVEL:
		{
			int val = 0;
			if(sscanf(envvar, "%i", &val) == 1 && val >= PRIVACY_SHOW_ALL && val <= PRIVACY_MAXIMUM)
			{
				conf_item->v.i = val;
				item->valid = true;
			}
			else
			{
				item->error = "not of type integer or outside allowed bounds";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
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
			{
				memcpy(&conf_item->v.in_addr, &addr4, sizeof(addr4));
				item->valid = true;
			}
			else
			{
				item->error = "not of type IPv4 address";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
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
			{
				memcpy(&conf_item->v.in6_addr, &addr6, sizeof(addr6));
				item->valid = true;
			}
			else
			{
				item->error = "not of type IPv6 address";
				log_warn("ENV %s is %s", conf_item->e, item->error);
				item->valid = false;
			}
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
					cJSON *citem = cJSON_CreateString(elem);
					cJSON_AddItemToArray(conf_item->v.json, citem);
				}

				// Search for the next element
				elem = strtok(NULL, delim);
			}
			free(envvar_copy);
			item->valid = true;
			break;
		}
		case CONF_PASSWORD:
		{
			if(!set_and_check_password(conf_item, envvar))
			{
				log_warn("ENV %s is invalid", conf_item->e);
				item->valid = false;
				break;
			}
			item->valid = true;
			break;
		}
	}

	return true;
}

cJSON *read_forced_vars(const unsigned int version)
{
	// Create cJSON array to store forced variables
	cJSON *env_vars = cJSON_CreateArray();

	// Try to open default config file. Use fallback if not found
	bool locked = false;
	FILE *fp = openFTLtoml("r", version, &locked);
	if(fp == NULL)
	{
		// Return empty cJSON array
		return env_vars;
	}

	// Read file line by line until we get to the end of the file where the
	// statistics are stored, specifically, the line starting with
	// "# X entr{y is,ies are} forced through environment"
	char line[LINE_MAX] = { 0 };
	while(fgets(line, sizeof(line), fp) != NULL)
	{
		// Check if this is the line we are looking for
		if(strncmp(line, "# ", 2) == 0)
		{
			// Check if this is the line we are looking for
			if(strstr(line, "forced through environment:") != NULL)
				break;
		}
	}

	// Read the next lines to extract the variables
	while(fgets(line, sizeof(line), fp) != NULL)
	{
		// Check if this is the line we are looking for
		if(strncmp(line, "#   - ", 6) != 0)
		{
			// We are done, break out of the loop
			break;
		}

		// else: Add the variable to the cJSON array
		// Trim the string (remove leading "#   - " and trailing newline)
		line[strcspn(line, "\n")] = '\0';
		cJSON_AddItemToArray(env_vars, cJSON_CreateString(line + 6));
	}

	// Close file and release exclusive lock
	closeFTLtoml(fp, locked);

	// Return cJSON array
	return env_vars;
}
