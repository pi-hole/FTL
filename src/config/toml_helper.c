/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TOML config writer routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "toml_helper.h"
#include "log.h"
#include "config/config.h"
// get_refresh_hostnames_str()
#include "datastructure.h"
// flock(), LOCK_SH
#include <sys/file.h>
// rotate_files()
#include "files.h"
//set_and_check_password()
#include "config/password.h"
// PATH_MAX
#include <limits.h>
// escape_json()
#include "webserver/http-common.h"

// Open the TOML file for reading or writing
FILE * __attribute((malloc)) __attribute((nonnull(1))) openFTLtoml(const char *mode, const unsigned int version)
{
	// This should not happen, install a safeguard anyway to unveil
	// possible future coding issues early on
	if(mode[0] == 'w' && version != 0)
	{
		log_crit("Writing to version != 0 is not supported in openFTLtoml(%s,%u)",
		         mode, version);
		exit(EXIT_FAILURE);
	}

	// Build filename based on version
	char filename[PATH_MAX] = { 0 };
	if(version == 0)
	{
		// Use global config file
		strncpy(filename, GLOBALTOMLPATH, sizeof(filename));

		// Append ".tmp" if we are writing
		if(mode[0] == 'w')
			strncat(filename, ".tmp", sizeof(filename));
	}
	else
	{
		// Use rotated config file
		snprintf(filename, sizeof(filename), BACKUP_DIR"/pihole.toml.%u", version);
	}

	// Try to open config file
	FILE *fp = fopen(filename, mode);

	// Return early if opening failed
	if(!fp)
	{
		log_info("Config %sfile %s not available: %s",
		         version > 0 ? "backup " : "", filename, strerror(errno));
		return NULL;
	}

	// Lock file, may block if the file is currently opened
	if(flock(fileno(fp), LOCK_EX) != 0)
	{
		const int _e = errno;
		log_err("Cannot open config file %s in exclusive mode: %s",
		        filename, strerror(errno));
		fclose(fp);
		errno = _e;
		return NULL;
	}

	// Log if we are using a backup file
	if(version > 0)
		log_info("Using config backup %s", filename);

	errno = 0;
	return fp;
}

// Open the TOML file for reading or writing
void closeFTLtoml(FILE *fp)
{
	// Release file lock
	if(flock(fileno(fp), LOCK_UN) != 0)
		log_err("Cannot release lock on FTL's config file: %s", strerror(errno));

	// Close file
	if(fclose(fp) != 0)
		log_err("Cannot close FTL's config file: %s", strerror(errno));

	// Chown file if we are root
	if(geteuid() == 0)
	{
		// Get UID and GID of user with name "pihole"
		struct passwd *pwd = getpwnam("pihole");
		if(pwd == NULL)
		{
			log_warn("Cannot get UID and GID of user pihole: %s", strerror(errno));
		}
		else
		{
			const uid_t pihole_uid = pwd->pw_uid;
			const gid_t pihole_gid = pwd->pw_gid;
			// Chown file to pihole user
			if(chown(GLOBALTOMLPATH, pihole_uid, pihole_gid) != 0)
				log_warn("Cannot chown "GLOBALTOMLPATH" to pihole:pihole (%u:%u): %s",
					(unsigned int)pihole_uid, (unsigned int)pihole_gid, strerror(errno));
			else
				log_debug(DEBUG_CONFIG, "Chown-ed "GLOBALTOMLPATH" to pihole:pihole (%u:%u)",
					(unsigned int)pihole_uid, (unsigned int)pihole_gid);
		}
	}
	return;
}

// Print a string to a TOML file, escaping special characters as necessary
static void printTOMLstring(FILE *fp, const char *s, const bool toml)
{
	// Substitute empty string if pointer is NULL
	if(s == NULL)
		 s = "";

	// JSON escape string
	char *escaped = escape_json(s);

	// Print error and return if escaping failed
	if(escaped == NULL)
	{
		log_err("Cannot escape string \"%s\" for TOML output", s);
		return;
	}

	// Print string to file
	if(toml)
	{
		// Print string with quotes
		fputs(escaped, fp);
	}
	else
	{
		// Remove trailing quote before printing
		escaped[strlen(escaped) - 1] = '\0';
		// Print string skipping over the leading quote
		fputs(escaped + 1, fp);
	}

	// Free escaped string
	free(escaped);
}

// Indentation (tabs and/or spaces) is allowed but not required, we use it for
// the sake of readability
void indentTOML(FILE *fp, const unsigned int indent)
{
	for (unsigned int i = 0; i < 2*indent; i++)
		fputc(' ', fp);
}

// measure the length until either the end of the string or to the next space
// (whatever comes first)
static unsigned int __attribute__((pure)) length(const char * p)
{
	const char *p2 = p;
	while(*(++p2) && *p2 != ' ');
	return p2 - p;
}

void print_comment(FILE *fp, const char *str, const char *intro, const unsigned int width, const unsigned int indent)
{
	unsigned int i = 0;
	unsigned int extraspace = 0;
	unsigned int ratac = strlen(intro);

	// Add intro if present
	if(ratac > 0)
	{
		for (unsigned int j = 0; j != 2*indent; ++j)
			fputc(' ', fp);
		fputs("# ", fp);
		fputs(intro, fp);
		extraspace = ratac;
		ratac = 0;
	}
	else
	{
		// Add indentation
		for(unsigned int j = 0; j < 2*indent; ++j)
			fputc(' ', fp);
		if(strlen(intro) + strlen(str) > 0)
			fputs("# ", fp);
		else
			fputc('#', fp);
		for(unsigned int j = 0; j < extraspace; ++j)
			fputc(' ', fp);
	}

	// Print string
	while(str[i] != '\0')
	{
		// Wrap to next line if we already printed too much for this one
		if(ratac >= width-extraspace)
		{
			// If this the first line? If not, add a newline
			if (i > 0)
				fputc('\n', fp);
			// Add intendation
			for (unsigned int j = 0; j != 2*indent; ++j)
				fputc(' ', fp);
			// Start a new line
			fputc('#', fp);
			for(unsigned int j = 0; j < extraspace; ++j)
				fputc(' ', fp);
			ratac = 0;
		}

		// If the text character is a space, we print it right away
		// Print a word - measure the length until either the end of the
		// string or to the next space (whatever comes first) and print this
		// part of the string
		unsigned int len = length(str + i);

		// Print word if we either have enough space to print this word or
		// it is really a long word and we are at the beginning of a line
		if(((ratac + len) <= width-extraspace) || (ratac == 0))
		{
			// Add spaces where needed
			if(str[i] == ' ')
				fputc(' ', fp);

			// Print the next word
			ratac += len;
			while (len--)
			{
				// Print characters until we encounter a space or newline
				if(str[i] != ' ' && str[i] != '\n')
					fputc(str[i], fp);
				// If we encounter a newline, we need to break out of the
				// loop and start a new line
				if(str[i] == '\n')
				{
					i++;
					ratac = 2*width;
					break;
				}
				// Advance to next character
				i++;
			}
		}
		else
		{
			// Mark this line as full
			ratac = width;
		}
	}
	fputc('\n', fp);
}

void print_toml_allowed_values(cJSON *allowed_values, FILE *fp, const unsigned int width, const unsigned int indent)
{
	print_comment(fp, "", "", 85, indent);
	print_comment(fp, "", "Possible values are:", 85, indent);
	if(cJSON_IsArray(allowed_values))
	{
		// Loop over array items
		for(int icnt = 0; icnt < cJSON_GetArraySize(allowed_values); icnt++)
		{
			// Get array item
			const cJSON *jopt = cJSON_GetArrayItem(allowed_values, icnt);
			// Skip if this wasn't possible
			if(!jopt)
				continue;
			// Get item and description
			const cJSON *item = cJSON_GetObjectItem(jopt, "item");
			const cJSON *description = cJSON_GetObjectItem(jopt, "description");
			// Skip if one of them is either NULL or not a string
			if(!cJSON_IsString(item) && !cJSON_IsNumber(item))
				continue;
			if(!cJSON_IsString(description))
				continue;
			if(cJSON_IsString(item))
			{
				// Frame item name in "..."
				const size_t buflen = strlen(item->valuestring) + 3u;
				char *itemname = calloc(buflen, sizeof(char));
				// Leading "
				itemname[0] = '"';
				// Copy string (we already know that the string
				// length is buflen - 3u)
				strncpy(itemname + 1, item->valuestring, buflen - 3u);
				// Trailing "
				itemname[buflen-2] = '"';
				// Print item name
				print_comment(fp, itemname, "  - ", 85, indent);
				free(itemname);
			}
			else if(item->valueint < 100)
			{
				// Integer value
				char itemname[3];
				snprintf(itemname, sizeof(itemname), "%d", item->valueint);
				// Print item name
				print_comment(fp, itemname, "  - ", 85, indent);
			}
			// Print item description
			print_comment(fp, description->valuestring, "      ", 85, indent);
		}
	}
	else if(cJSON_IsString(allowed_values))
	{
		print_comment(fp, allowed_values->valuestring, "    ", 85, indent);
	}
	else
	{
		print_comment(fp, "UNKNOWN, please contact Pi-hole support", "    ", 85, indent);
	}
}

// Write a TOML value to a file depending on its type
void writeTOMLvalue(FILE * fp, const int indent, const enum conf_type t, union conf_value *v)
{
	// Check if this is a TOML or CLI output
	const bool toml = fp != stdout;

	// Print value depending on its type
	switch(t)
	{
		case CONF_BOOL:
		case CONF_ALL_DEBUG_BOOL:
			fprintf(fp, "%s", v->b ? "true" : "false");
			break;
		case CONF_INT:
			fprintf(fp, "%i", v->i);
			break;
		case CONF_UINT:
		case CONF_ENUM_PRIVACY_LEVEL:
			fprintf(fp, "%u", v->ui);
			break;
		case CONF_UINT16:
			fprintf(fp, "%hu", v->u16);
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
			printTOMLstring(fp, v->s, toml);
			break;
		case CONF_ENUM_PTR_TYPE:
			printTOMLstring(fp, get_ptr_type_str(v->ptr_type), toml);
			break;
		case CONF_ENUM_BUSY_TYPE:
			printTOMLstring(fp, get_busy_reply_str(v->busy_reply), toml);
			break;
		case CONF_ENUM_BLOCKING_MODE:
			printTOMLstring(fp, get_blocking_mode_str(v->blocking_mode), toml);
			break;
		case CONF_ENUM_REFRESH_HOSTNAMES:
			printTOMLstring(fp, get_refresh_hostnames_str(v->refresh_hostnames), toml);
			break;
		case CONF_ENUM_LISTENING_MODE:
			printTOMLstring(fp, get_listeningMode_str(v->listeningMode), toml);
			break;
		case CONF_ENUM_WEB_THEME:
			printTOMLstring(fp, get_web_theme_str(v->web_theme), toml);
			break;
		case CONF_ENUM_TEMP_UNIT:
			printTOMLstring(fp, get_temp_unit_str(v->temp_unit), toml);
			break;
		case CONF_STRUCT_IN_ADDR:
		{
			// Special case: 0.0.0.0 -> return empty string
			if(v->in_addr.s_addr == INADDR_ANY)
			{
				printTOMLstring(fp, "", toml);
				break;
			}
			// else: normal address
			char addr4[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &v->in_addr, addr4, INET_ADDRSTRLEN);
			printTOMLstring(fp, addr4, toml);
			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			// Special case: :: -> return empty string
			if(memcmp(&v->in6_addr, &in6addr_any, sizeof(in6addr_any)) == 0)
			{
				printTOMLstring(fp, "", toml);
				break;
			}
			// else: normal address
			char addr6[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &v->in6_addr, addr6, INET6_ADDRSTRLEN);
			printTOMLstring(fp, addr6, toml);
			break;
		}
		case CONF_JSON_STRING_ARRAY:
		{
			// Start the array
			fputc('[', fp);
			const unsigned int elems = cJSON_GetArraySize(v->json);
			if(indent > -1 && elems > 0)
				// If there are elements and we are indenting,
				// add a new line
				fputc('\n', fp);
			else if(elems > 0)
				// If there some elements but we do not indent
				// (on CLI output), add space
				fputc(' ', fp);
			for(unsigned int i = 0; i < elems; i++)
			{
				// Get the element
				cJSON *item = cJSON_GetArrayItem(v->json, i);

				// Skip empty elements
				if(strlen(item->valuestring) == 0)
					continue;

				// Add intendation (if we are indenting)
				if(indent > -1)
					indentTOML(fp, indent + 1);

				// Print the element
				printTOMLstring(fp, item->valuestring, toml);

				// Add a comma if there is one more element to come
				if(item->next)
					fputc(',', fp);

				// Add a space after the comma if we are not indenting
				if(indent < 0)
					fputc(' ', fp);
				// Add a new line (if we are indenting)
				else
					fputc('\n', fp);
			}
			if(indent > -1 && elems > 0)
				indentTOML(fp, indent);
			fputc(']', fp);
			break;
		}
		case CONF_PASSWORD:
		{
			printTOMLstring(fp, PASSWORD_VALUE, toml);
			break;
		}
	}
}

// Read a TOML value from a table depending on its type
void readTOMLvalue(struct conf_item *conf_item, const char* key, toml_table_t *toml, struct config *newconf)
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
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid bool", conf_item->k);
			break;
		}
		case CONF_ALL_DEBUG_BOOL:
		{
			const toml_datum_t val = toml_bool_in(toml, key);
			if(val.ok)
				set_all_debug(newconf, val.u.b);
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid bool", conf_item->k);
			break;
		}
		case CONF_INT:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok)
				conf_item->v.i = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid integer", conf_item->k);
			break;
		}
		case CONF_UINT:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok && val.u.i >= 0)
				conf_item->v.ui = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid unsigned integer", conf_item->k);
			break;
		}
		case CONF_UINT16:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok && val.u.i >= 0 && val.u.i <= UINT16_MAX)
				conf_item->v.ui = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid unsigned integer (16 bit)", conf_item->k);
			break;
		}
		case CONF_LONG:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok)
				conf_item->v.l = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid long integer", conf_item->k);
			break;
		}
		case CONF_ULONG:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok && val.u.i >= 0)
				conf_item->v.ul = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid unsigned long integer", conf_item->k);
			break;
		}
		case CONF_DOUBLE:
		{
			const toml_datum_t val = toml_double_in(toml, key);
			if(val.ok)
				conf_item->v.d = val.u.d;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid double", conf_item->k);
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
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid string", conf_item->k);
			break;
		}
		case CONF_ENUM_PTR_TYPE:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int ptr_type = get_ptr_type_val(val.u.s);
				free(val.u.s);
				if(ptr_type != -1)
					conf_item->v.ptr_type = ptr_type;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid string", conf_item->k);
			break;
		}
		case CONF_ENUM_BUSY_TYPE:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int busy_reply = get_busy_reply_val(val.u.s);
				free(val.u.s);
				if(busy_reply != -1)
					conf_item->v.busy_reply = busy_reply;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid string", conf_item->k);
			break;
		}
		case CONF_ENUM_BLOCKING_MODE:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int blocking_mode = get_blocking_mode_val(val.u.s);
				free(val.u.s);
				if(blocking_mode != -1)
					conf_item->v.blocking_mode = blocking_mode;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a validstring", conf_item->k);
			break;
		}
		case CONF_ENUM_REFRESH_HOSTNAMES:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int refresh_hostnames = get_refresh_hostnames_val(val.u.s);
				free(val.u.s);
				if(refresh_hostnames != -1)
					conf_item->v.refresh_hostnames = refresh_hostnames;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid string", conf_item->k);
			break;
		}
		case CONF_ENUM_LISTENING_MODE:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int listeningMode = get_listeningMode_val(val.u.s);
				free(val.u.s);
				if(listeningMode != -1)
					conf_item->v.listeningMode = listeningMode;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid string", conf_item->k);
			break;
		}
		case CONF_ENUM_WEB_THEME:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int web_theme = get_web_theme_val(val.u.s);
				free(val.u.s);
				if(web_theme != -1)
					conf_item->v.web_theme = web_theme;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid string", conf_item->k);
			break;
		}
		case CONF_ENUM_TEMP_UNIT:
		{
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				const int temp_unit = get_temp_unit_val(val.u.s);
				free(val.u.s);
				if(temp_unit != -1)
					conf_item->v.temp_unit = temp_unit;
				else
					log_warn("Config setting %s is invalid, allowed options are: %s", conf_item->k, conf_item->h);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is not a valid string", conf_item->k);
			break;
		}
		case CONF_ENUM_PRIVACY_LEVEL:
		{
			const toml_datum_t val = toml_int_in(toml, key);
			if(val.ok && val.u.i >= PRIVACY_SHOW_ALL && val.u.i <= PRIVACY_MAXIMUM)
				conf_item->v.i = val.u.i;
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is invalid (not an integer or outside allowed bounds)", conf_item->k);
			break;
		}
		case CONF_STRUCT_IN_ADDR:
		{
			struct in_addr addr4 = { 0 };
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				if(strlen(val.u.s) == 0)
				{
					// Special case: empty string -> 0.0.0.0
					conf_item->v.in_addr.s_addr = INADDR_ANY;
				}
				else if(inet_pton(AF_INET, val.u.s, &addr4))
					memcpy(&conf_item->v.in_addr, &addr4, sizeof(addr4));
				else
					log_warn("Config %s is invalid (not of type IPv4 address)", conf_item->k);
				free(val.u.s);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is invalid (not a valid string of type IPv4 address)", conf_item->k);
			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			struct in6_addr addr6 = { 0 };
			const toml_datum_t val = toml_string_in(toml, key);
			if(val.ok)
			{
				if(strlen(val.u.s) == 0)
				{
					// Special case: empty string -> ::
					memcpy(&conf_item->v.in6_addr, &in6addr_any, sizeof(in6addr_any));
				}
				else if(inet_pton(AF_INET6, val.u.s, &addr6))
					memcpy(&conf_item->v.in6_addr, &addr6, sizeof(addr6));
				else
					log_warn("Config %s is invalid (not of type IPv6 address)", conf_item->k);
				free(val.u.s);
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST or is invalid (not a valid string of type IPv6 address)", conf_item->k);
			break;
		}
		case CONF_JSON_STRING_ARRAY:
		{
			// Free previously allocated JSON array
			cJSON_Delete(conf_item->v.json);
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
						log_warn("Config %s is an invalid array (found at index %u)", conf_item->k, i);
						break;
					}
					// Only import non-empty entries
					if(strlen(d.u.s) > 0)
					{
						// Add string to our JSON array
						cJSON *item = cJSON_CreateString(d.u.s);
						cJSON_AddItemToArray(conf_item->v.json, item);
					}
					free(d.u.s);
				}
			}
			else
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST", conf_item->k);
			break;
		}
		case CONF_PASSWORD:
		{
			// This is ignored, it is only a pseudo-element with no real content
			break;
		}
	}
}
