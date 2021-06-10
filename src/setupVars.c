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

int setupVarsElements = 0;
char ** setupVarsArray = NULL;

void check_setupVarsconf(void)
{
	FILE *setupVarsfp;
	if((setupVarsfp = fopen(config.files.setupVars, "r")) == NULL)
	{
		log_warn("Opening of setupVars.conf failed: %s Make sure it exists and is readable",
		         strerror(errno));
	}
	else
	{
		fclose(setupVarsfp);
	}
}

char* __attribute__((pure)) find_equals(const char* s)
{
	const char* chars = "=";
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

char * read_setupVarsconf(const char *key)
{
	FILE *setupVarsfp;
	if((setupVarsfp = fopen(config.files.setupVars, "r")) == NULL)
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

/* Example
	char * iface = read_setupVarsconf("API_EXCLUDE_DOMAINS");
	if(iface != NULL)
		logg_str("Interface: ",iface);
	getSetupVarsArray(iface);
	int i;
	for (i = 0; i <= setupVarsElements; ++i)
		printf ("[%d] = %s\n", i, setupVarsArray[i]);
	clearSetupVarsArray();
*/

bool insetupVarsArray(const char * str)
{
	// Check for possible NULL pointer
	// (this is valid input, e.g. if clients[i].name is unspecified)
	if(str == NULL)
		return false;

	// Loop over all entries in setupVarsArray
	for (int i = 0; i < setupVarsElements; ++i)
		if(setupVarsArray[i][0] == '*')
		{
			// Copying strlen-1 chars into buffer of size strlen: OK
			size_t lenght = strlen(setupVarsArray[i]);
			char * domain = calloc(lenght, sizeof(char));
			if(domain == NULL) return false;
			// strncat() NULL-terminates the copied string (strncpy() doesn't!)
			strncat(domain, setupVarsArray[i]+1, lenght-1);

			if(strstr(str, domain) != NULL)
			{
				free(domain);
				return true;
			}
			else
			{
				free(domain);
			}
		}
		else
		{
			if(strcmp(setupVarsArray[i], str) == 0)
				return true;
		}

	// If not found
	return false;
}

bool __attribute__((pure)) getSetupVarsBool(const char * input)
{
	if((strcmp(input, "true")) == 0)
		return true;
	else
		return false;
}

// Global variable showing current blocking status
enum blocking_status blockingstatus = BLOCKING_UNKNOWN;

void check_blocking_status(void)
{
	const char* blocking = read_setupVarsconf("BLOCKING_ENABLED");
	const char* message;

	if(blocking == NULL || getSetupVarsBool(blocking))
	{
		// Parameter either not present in setupVars.conf
		// or explicitly set to true
		blockingstatus = BLOCKING_ENABLED;
		message = "enabled";
		clearSetupVarsArray();
	}
	else
	{
		// Disabled
		blockingstatus = BLOCKING_DISABLED;
		message = "disabled";
	}

	log_info("Blocking status is %s", message);
}

bool __attribute__((pure)) get_blockingstatus(void)
{
	return blockingstatus;
}

void set_blockingstatus(bool enabled)
{
	blockingstatus = enabled;
	raise(SIGHUP);
}

// Source password hash from setupVars.conf
__attribute__((malloc)) char *get_password_hash(void)
{
	// Try to obtain password from setupVars.conf
	const char* password = read_setupVarsconf("WEBPASSWORD");

	// If the value was not set (or we couldn't open the file for reading),
	// we hand an empty string back to the caller
	if(password == NULL || (password != NULL && strlen(password) == 0u))
	{
		password = "";
	}

	char *hash = strdup(password);

	// Free memory, harmless to call if read_setupVarsconf() didn't return a result
	clearSetupVarsArray();

	return hash;
}
