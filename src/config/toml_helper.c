/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TOML config writer routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "toml_helper.h"
#include "log.h"
#include "config/config.h"
// get_refresh_hostnames_str()
#include "datastructure.h"
// flock(), LOCK_SH
#include <sys/file.h>

// Open the TOML file for reading or writing
FILE * __attribute((malloc)) __attribute((nonnull(1))) openFTLtoml(const char *mode)
{
	FILE *fp;
	// If reading: first check if there is a local file
	if(strcmp(mode, "r") == 0 &&
	   (fp = fopen("pihole-FTL.toml", mode)) != NULL)
		return fp;

	// No readable local file found, try global file
	fp = fopen(GLOBALTOMLPATH, mode);

	// Return early if opening failed
	if(!fp)
		return NULL;

	// Lock file, may block if the file is currently opened
	if(flock(fileno(fp), LOCK_EX) != 0)
		log_err("Cannot open FTL's config file in exclusive mode: %s", strerror(errno));

	return fp;
}

// Open the TOML file for reading or writing
void closeFTLtoml(FILE *fp)
{
	// Lock file, may block if the file is currently opened
	if(flock(fileno(fp), LOCK_UN) != 0)
		log_err("Cannot release lock on FTL's config file: %s", strerror(errno));

	if(fclose(fp) != 0)
		log_err("Cannot close FTL's config file: %s", strerror(errno));

	return;
}

// Print a string to a TOML file, escaping special characters as necessary
static void printTOMLstring(FILE *fp, const char *s)
{
	// Substitute empty string if pointer is NULL
	if(s == NULL)
		 s = "";

	bool ok = true;
	// Check if string is printable and does not contain any special characters
	for (const char* p = s; *p && ok; p++)
	{
		int ch = *p;
		ok = isprint(ch) && ch != '"' && ch != '\\';
	}

	// If string is printable and does not contain any special characters, we can
	// print it as is without further escaping
	if (ok)
	{
		fprintf(fp, "\"%s\"", s);
		return;
	}

	// Otherwise, we need to escape special characters, this is more work
	int len = strlen(s);
	fprintf(fp, "\"");
	for ( ; len; len--, s++)
	{
		int ch = *s;
		if (isprint(ch) && ch != '"' && ch != '\\')
		{
			putc(ch, fp);
			continue;
		}

		// Escape special characters
		switch (ch) {
			case 0x08: fprintf(fp, "\\b"); continue;
			case 0x09: fprintf(fp, "\\t"); continue;
			case 0x0a: fprintf(fp, "\\n"); continue;
			case 0x0c: fprintf(fp, "\\f"); continue;
			case 0x0d: fprintf(fp, "\\r"); continue;
			case '"':  fprintf(fp, "\\\""); continue;
			case '\\': fprintf(fp, "\\\\"); continue;
			default:   fprintf(fp, "\\0x%02x", ch & 0xff); continue;
		}
	}
	fprintf(fp, "\"");
}

// Indentation (tabs and/or spaces) is allowed but not required, we use it for
// the sake of readability
void indentTOML(FILE *fp, const unsigned int indent)
{
	for (unsigned int i = 0; i < 2*indent; i++)
		fputc(' ', fp);
}

// Write a TOML value to a file depending on its type
void writeTOMLvalue(FILE * fp, const enum conf_type t, union conf_value *v)
{
	switch(t)
	{
		case CONF_BOOL:
			fprintf(fp, "%s", v->b ? "true" : "false");
			break;
		case CONF_INT:
			fprintf(fp, "%i", v->i);
			break;
		case CONF_UINT:
		case CONF_ENUM_PRIVACY_LEVEL:
			fprintf(fp, "%u", v->ui);
			break;
		case CONF_LONG:
			fprintf(fp, "%li", v->l);
			break;
		case CONF_ULONG:
			fprintf(fp, "%lu", v->ul);
			break;
		case CONF_DOUBLE:
			fprintf(fp, "%f", v->d);
			break;
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
			printTOMLstring(fp, v->s);
			break;
		case CONF_ENUM_PTR_TYPE:
			printTOMLstring(fp, get_ptr_type_str(v->ptr_type));
			break;
		case CONF_ENUM_BUSY_TYPE:
			printTOMLstring(fp, get_busy_reply_str(v->busy_reply));
			break;
		case CONF_ENUM_BLOCKING_MODE:
			printTOMLstring(fp, get_blocking_mode_str(v->blocking_mode));
			break;
		case CONF_ENUM_REFRESH_HOSTNAMES:
			printTOMLstring(fp, get_refresh_hostnames_str(v->refresh_hostnames));
			break;
		case CONF_STRUCT_IN_ADDR:
		{
			char addr4[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &v->in_addr, addr4, INET_ADDRSTRLEN);
			printTOMLstring(fp, addr4);
			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			char addr6[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &v->in6_addr, addr6, INET6_ADDRSTRLEN);
			printTOMLstring(fp, addr6);
			break;
		}
		case CONF_JSON_STRING_ARRAY:
		{
			fputs("[ ", fp);
			const unsigned int elems = cJSON_GetArraySize(v->json);
			for(unsigned int i = 0; i < elems; i++)
			{
				cJSON *item = cJSON_GetArrayItem(v->json, i);
				printTOMLstring(fp, item->valuestring);
				// Add a comma if there is one more element to come
				if(item->next)
					fputs(", ", fp);
			}
			fputs(" ]", fp);
			break;
		}
	}
}

// Read a TOML value from a table depending on its type
void readTOMLvalue(struct conf_item *conf_item, const char* key, toml_table_t *toml)
{
	if(conf_item == NULL || key == NULL || toml == NULL)
	{
		log_debug(DEBUG_CONFIG, "readTOMLvalue(%p, %p, %p) called with invalid arguments, skipping",
		          conf_item, key, toml);
		return;
	}
	switch(conf_item->t)
	{
		case CONF_BOOL:
		{
			const toml_datum_t val = toml_bool_in(toml, key);
			if(val.ok)
				conf_item->v.b = val.u.b;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type bool", conf_item->k);
			break;
		}
		case CONF_INT:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok)
				conf_item->v.i = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type integer", conf_item->k);
			break;
		}
		case CONF_UINT:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok && val.u.i >= 0)
				conf_item->v.ui = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type unsigned integer", conf_item->k);
			break;
		}
		case CONF_LONG:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok)
				conf_item->v.l = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type long", conf_item->k);
			break;
		}
		case CONF_ULONG:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok && val.u.i >= 0)
				conf_item->v.ul = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type unsigned long", conf_item->k);
			break;
		}
		case CONF_DOUBLE:
		{
			const toml_datum_t val = toml_double_in(toml, key);
			if(val.ok)
				conf_item->v.d = val.u.d;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type double", conf_item->k);
			break;
		}
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				if(conf_item->t == CONF_STRING_ALLOCATED)
					free(conf_item->v.s);
				conf_item->v.s = val.u.s; // allocated string
				conf_item->t = CONF_STRING_ALLOCATED;
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type string", conf_item->k);
			break;
		}
		case CONF_ENUM_PTR_TYPE:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int ptr_type = get_ptr_type_val(val.u.s);
				if(ptr_type != -1)
					conf_item->v.ptr_type = ptr_type;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type string", conf_item->k);
			break;
		}
		case CONF_ENUM_BUSY_TYPE:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int busy_reply = get_busy_reply_val(val.u.s);
				if(busy_reply != -1)
					conf_item->v.busy_reply = busy_reply;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type string", conf_item->k);
			break;
		}
		case CONF_ENUM_BLOCKING_MODE:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int blocking_mode = get_blocking_mode_val(val.u.s);
				if(blocking_mode != -1)
					conf_item->v.blocking_mode = blocking_mode;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type string", conf_item->k);
			break;
		}
		case CONF_ENUM_REFRESH_HOSTNAMES:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int refresh_hostnames = get_refresh_hostnames_val(val.u.s);
				if(refresh_hostnames != -1)
					conf_item->v.refresh_hostnames = refresh_hostnames;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not of type string", conf_item->k);
			break;
		}
		case CONF_ENUM_PRIVACY_LEVEL:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok && val.u.i >= PRIVACY_SHOW_ALL && val.u.i <= PRIVACY_MAXIMUM)
				conf_item->v.i = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is invalid", conf_item->k);
			break;
		}
		case CONF_STRUCT_IN_ADDR:
		{
			struct in_addr addr4 = { 0 };
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok && inet_pton(AF_INET, val.u.s, &addr4))
				memcpy(&conf_item->v.in_addr, &addr4, sizeof(addr4));
			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			struct in6_addr addr6 = { 0 };
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok && inet_pton(AF_INET6, val.u.s, &addr6))
				memcpy(&conf_item->v.in6_addr, &addr6, sizeof(addr6));
			break;
		}
		case CONF_JSON_STRING_ARRAY:
		{
			// Free previously allocated JSON array
			cJSON_free(conf_item->v.json);
			conf_item->v.json = cJSON_CreateArray();
			// Parse TOML array and generate a JSON array
			const toml_array_t *array = toml_array_in(toml, key);
			if(array != NULL)
			{
				const unsigned int nelem = toml_array_nelem(array);
				for(unsigned int i = 0; i < nelem; i++)
				{
					// Get string from TOML
					const toml_datum_t d = toml_string_at(array, i);
					if(!d.ok)
					{
						log_debug(DEBUG_CONFIG, "%s is an invalid array (found at index %d)", conf_item->k, i);
						break;
					}
					// Add string to our JSON array
					cJSON *item = cJSON_CreateString(d.u.s);
					cJSON_AddItemToArray(conf_item->v.json, item);
				}
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST", conf_item->k);
			break;
		}
	}
}
