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

char ** setupVarsArray = NULL;

void check_setupVarsconf(void)
{
	FILE *setupVarsfp;
	if((setupVarsfp = fopen(files.setupVars, "r")) == NULL)
	{
		logg("WARN: Opening of setupVars.conf failed!");
		logg("      Make sure it exists and is readable");
		logg("      Message: %s", strerror(errno));
	}
	else
	{
		logg("Successfully accessed setupVars.conf");
		fclose(setupVarsfp);
	}
}

char* find_equals(const char* s)
{
	const char* chars = "=";
	while (*s && (!chars || !strchr(chars, *s)))
		s++;
	return (char*)s;
}

// This will hold the read string
// in memory and will serve the space
// we will point to in the rest of the
// process (e.g. setupVarsArray will
// actually point to memory addresses
// which we allocate for this buffer.
char * linebuffer = NULL;
size_t linebuffersize = 0;

char * read_setupVarsconf(const char * key)
{
	FILE *setupVarsfp;
	if((setupVarsfp = fopen(files.setupVars, "r")) == NULL)
	{
		logg("WARN: Reading setupVars.conf failed: %s", strerror(errno));
		return NULL;
	}

	// Allocate keystr
	char * keystr = calloc(strlen(key)+2, sizeof(char));
	if(keystr == NULL)
	{
		logg("WARN: read_setupVarsconf failed: could not allocate memory for keystr");
		fclose(setupVarsfp);
		return NULL;
	}
	sprintf(keystr, "%s=", key);

	errno = 0;
	while(getline(&linebuffer, &linebuffersize, setupVarsfp) != -1)
	{
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
		logg("WARN: read_setupVarsconf failed: could not allocate memory for getline");

	// Key not found -> return NULL
	fclose(setupVarsfp);

	// Freeing keystr, not setting to NULL, since not used outside of this routine
	free(keystr);

	// Freeing and setting to NULL to prevent a dangling pointer
	if(linebuffer != NULL)
	{
		free(linebuffer);
		linebuffersize = 0;
		linebuffer = NULL;
	}

	return NULL;
}

// split string in form:
//   abc,def,ghi
// into char ** array:
// setupVarsArray[0] = abc
// setupVarsArray[1] = def
// setupVarsArray[2] = ghi
// setupVarsArray[3] = NULL
void getSetupVarsArray(char * input)
{
	char * p = strtok(input, ",");

	/* split string and append tokens to 'res' */

	while (p) {
		setupVarsArray = realloc(setupVarsArray, sizeof(char*) * ++setupVarsElements);
		setupVarsArray[setupVarsElements-1] = p;
		p = strtok(NULL, ",");
	}

	/* realloc one extra element for the last NULL */
	setupVarsArray = realloc(setupVarsArray, sizeof(char*) * (setupVarsElements+1));
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

bool insetupVarsArray(char * str)
{
	int i;
	// Loop over all entries in setupVarsArray
	for (i = 0; i < setupVarsElements; ++i)
		if(setupVarsArray[i][0] == '*')
		{
			// Copying strlen-1 chars into buffer of size strlen: OK
			size_t lenght = strlen(setupVarsArray[i]);
			char * domain = calloc(lenght, sizeof(char));
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
			// Return true only when the ends of the two domains match
			// This allows an exclusion of 'nflxso.net' to not display:
			// occ-2-990-987.1.nflxso.net, occ-0-990-987.1.nflxso.net, etc.
			size_t candidate = strlen(str);
			size_t excluded = strlen(setupVarsArray[i]);
			if (excluded > candidate)
				continue;

			size_t end_pos = candidate - excluded;
			if(strcmp(str + end_pos, setupVarsArray[i]) == 0)
				return true;
		}

	// If not found
	return false;
}

bool getSetupVarsBool(char * input)
{
	if((strcmp(input, "true")) == 0)
		return true;
	else
		return false;
}
