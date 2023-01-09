/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Configuration interpreting routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "config/config.h"
#include "setupVars.h"

unsigned int setupVarsElements = 0;
char ** setupVarsArray = NULL;

void importsetupVarsConf(void)
{
	// Try to obtain password hash from setupVars.conf
	const char *pwhash = read_setupVarsconf("WEBPASSWORD");
	if(pwhash == NULL)
		pwhash = "";

	// Free previously allocated memory (if applicable)
	if(config.api.pwhash.t == CONF_STRING_ALLOCATED)
		free(config.api.pwhash.v.s);
	config.api.pwhash.v.s = strdup(pwhash);
	config.api.pwhash.t = CONF_STRING_ALLOCATED;

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	// Try to obtain blocking active boolean
	const char *blocking = read_setupVarsconf("BLOCKING_ENABLED");

	if(blocking == NULL || getSetupVarsBool(blocking))
	{
		// Parameter either not present in setupVars.conf
		// or explicitly set to true
		config.dns.blocking.active.v.b = true;
	}
	else
	{
		// Disabled
		config.dns.blocking.active.v.b = false;
	}

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	// Get clients which the user doesn't want to see
	const char *excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");

	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);
		for (unsigned int i = 0; i < setupVarsElements; ++i)
		{
			log_debug(DEBUG_CONFIG, "API_EXCLUDE_CLIENTS: [%d] = %s\n", i, setupVarsArray[i]);
			// Add string to our JSON array
			cJSON *item = cJSON_CreateString(setupVarsArray[i]);
			cJSON_AddItemToArray(config.api.exclude_clients.v.json, item);
		}
	}

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	// Get domains which the user doesn't want to see
	char *excludedomains = read_setupVarsconf("API_EXCLUDE_DOMAINS");

	if(excludedomains != NULL)
	{
		getSetupVarsArray(excludedomains);
		for (unsigned int i = 0; i < setupVarsElements; ++i)
		{
			log_debug(DEBUG_CONFIG, "API_EXCLUDE_DOMAINS: [%d] = %s\n", i, setupVarsArray[i]);
			// Add string to our JSON array
			cJSON *item = cJSON_CreateString(setupVarsArray[i]);
			cJSON_AddItemToArray(config.api.exclude_domains.v.json, item);
		}
	}

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	// Try to obtain temperature hot value
	const char *temp_limit = read_setupVarsconf("TEMPERATURE_LIMIT");

	if(temp_limit != NULL)
	{
		double lim;
		if(sscanf(temp_limit, "%lf", &lim) == 1)
			config.misc.temp_limit.v.d = lim;
	}

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	// Try to obtain boxed-layout boolean
	const char *boxed_layout = read_setupVarsconf("WEBUIBOXEDLAYOUT");
	// If the property is set to false and different than "boxed", the property
	// is disabled. This is consistent with the code in AdminLTE when writing
	// this code
	if(boxed_layout != NULL && strcasecmp(boxed_layout, "boxed") != 0)
		config.http.interface.boxed.v.b = false;

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	// Try to obtain theme string
	const char *web_theme = read_setupVarsconf("WEBTHEME");
	if(web_theme == NULL)
		web_theme = "";

	// Free previously allocated memory (if applicable)
	if(config.http.interface.theme.t == CONF_STRING_ALLOCATED)
		free(config.http.interface.theme.v.s);
	config.http.interface.theme.v.s = strdup(web_theme);
	config.http.interface.theme.t = CONF_STRING_ALLOCATED;

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();
}

char* __attribute__((pure)) find_equals(const char *s)
{
	const char *chars = "=";
	while (*s && (!chars || !strchr(chars, *s)))
		s++;
	return (char*)s;
}

void trim_whitespace(char *string)
{
	// isspace(char*) man page:
	// checks for white-space  characters. In the "C" and "POSIX"
	// locales, these are: space, form-feed ('\f'), newline ('\n'),
	// carriage return ('\r'), horizontal tab ('\t'), and vertical tab
	// ('\v').
	char *original = string, *modified = string;
	// Trim any whitespace characters (see above) at the beginning by increasing the pointer address
	while (isspace((unsigned char)*original))
		original++;
	// Copy the content of original into modified as long as there is something in original
	while ((*modified = *original++) != '\0')
		modified++;
	// Trim any whitespace characters (see above) at the end of the string by overwriting it
	// with the zero character (marking the end of a C string)
	while (modified > string && isspace((unsigned char)*--modified))
		*modified = '\0';
}

// This will hold the read string
// in memory and will serve the space
// we will point to in the rest of the
// process (e.g. setupVarsArray will
// actually point to memory addresses
// which we allocate for this buffer.
char * linebuffer = NULL;
size_t linebuffersize = 0;

char *read_setupVarsconf(const char *key)
{
	FILE *setupVarsfp;
	if((setupVarsfp = fopen(config.files.setupVars.v.s, "r")) == NULL)
	{
		log_warn("Reading setupVars.conf failed: %s", strerror(errno));
		return NULL;
	}

	// Allocate keystr
	char * keystr = calloc(strlen(key)+2, sizeof(char));
	if(keystr == NULL)
	{
		log_warn("read_setupVarsconf(%s) failed: Could not allocate memory for keystr", key);
		fclose(setupVarsfp);
		return NULL;
	}
	sprintf(keystr, "%s=", key);

	errno = 0;
	while(getline(&linebuffer, &linebuffersize, setupVarsfp) != -1)
	{
		// Memory allocation issue
		if(linebuffersize == 0 || linebuffer == NULL)
			continue;

		// Strip (possible) newline
		linebuffer[strcspn(linebuffer, "\n")] = '\0';

		// Skip comment lines
		if(linebuffer[0] == '#' || linebuffer[0] == ';')
			continue;

		// Skip lines with other keys
		if((strstr(linebuffer, keystr)) == NULL)
			continue;

		// otherwise: key found
		fclose(setupVarsfp);
		free(keystr);
		return (find_equals(linebuffer) + 1);
	}

	if(errno == ENOMEM)
		log_warn("read_setupVarsconf(%s) failed: could not allocate memory for getline", key);

	// Key not found -> return NULL
	fclose(setupVarsfp);

	// Freeing keystr, not setting to NULL, since not used outside of this routine
	free(keystr);

	return NULL;
}

// split string in form:
//   abc,def,ghi
// into char ** array:
// setupVarsArray[0] = abc
// setupVarsArray[1] = def
// setupVarsArray[2] = ghi
// setupVarsArray[3] = NULL
void getSetupVarsArray(const char * input)
{
	char * p = strtok((char*)input, ",");

	/* split string and append tokens to 'res' */

	while (p) {
		setupVarsArray = realloc(setupVarsArray, sizeof(char*) * ++setupVarsElements);
		if(setupVarsArray == NULL) return;
		setupVarsArray[setupVarsElements-1] = p;
		p = strtok(NULL, ",");
	}

	/* realloc one extra element for the last NULL */
	setupVarsArray = realloc(setupVarsArray, sizeof(char*) * (setupVarsElements+1));
	if(setupVarsArray == NULL) return;
	setupVarsArray[setupVarsElements] = NULL;
}

void clearSetupVarsArray(void)
{
	setupVarsElements = 0;
	// setting unused pointers to NULL
	// protecting against dangling pointer bugs
	// free only if not already NULL
	if(setupVarsArray != NULL)
	{
		free(setupVarsArray);
		setupVarsArray = NULL;
	}
	if(linebuffer != NULL)
	{
		free(linebuffer);
		linebuffersize = 0;
		linebuffer = NULL;
	}
}

bool __attribute__((pure)) getSetupVarsBool(const char * input)
{
	if((strcmp(input, "true")) == 0)
		return true;
	else
		return false;
}
