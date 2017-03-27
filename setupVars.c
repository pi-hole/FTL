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
		logg_str("      Message: ", strerror(errno));
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

char * read_setupVarsconf(const char * key)
{
	FILE *setupVarsfp;
	if((setupVarsfp = fopen(files.setupVars, "r")) == NULL)
	{
		logg_str("WARN: Reading setupVars.conf failed: ", strerror(errno));
		return NULL;
	}

	char * keystr = calloc(strlen(key)+2,sizeof(char));
	linebuffer = calloc(1024,sizeof(char));

	sprintf(keystr, "%s=", key);

	while(fgets(linebuffer, 1023, setupVarsfp) != NULL)
	{
		// Strip newline from fgets output
		linebuffer[strlen(linebuffer) - 1] = '\0';

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

	// Key not found -> return NULL
	fclose(setupVarsfp);
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
	free(setupVarsArray);
	free(linebuffer);
	// setting unused pointers to NULL
	// protecting against dangling pointer bugs
	setupVarsArray = NULL;
	linebuffer = NULL;
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
			char * domain = calloc(strlen(setupVarsArray[i]),sizeof(char));
			strncpy(domain,setupVarsArray[i]+1,strlen(setupVarsArray[i])-1);
			if(strstr(str, domain) != NULL)
			{
				free(domain);
				return true;
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

bool getSetupVarsBool(char * input)
{
	if((strcmp(input, "true")) == 0)
		return true;
	else
		return false;
}
