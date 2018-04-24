/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Regular Expressions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include <regex.h>
static regex_t regex;

static void log_regex_error(char *where, int errcode)
{
	// Regex failed for some reason (probably user syntax error)
	// Get error string and log it
	size_t length = regerror(errcode, &regex, NULL, 0);
	char *buffer = calloc(length,sizeof(char));
	(void) regerror (errcode, &regex, buffer, length);
	logg("Error when %s blocking RegEx: %s (%i)", where, buffer, errcode);
	free(buffer);
	free_regex();
}

bool init_regex(char *regexin)
{
	// compile a regular expression into a data structure that
	// can be used with regexec to match against a string
	int errcode = regcomp(&regex, regexin, REG_EXTENDED);
	if(errcode == 0)
	{
		return true;
	}

	// else: failed
	log_regex_error("compiling", errcode);
	return false;
}

bool match_regex(char *input)
{
	// Try to match the compiled regular expression against input
	int errcode = regexec(&regex, input, 0, NULL, 0);
	if (errcode == 0)
	{
		// Match, return true
		return true;
	}
	else if (errcode != REG_NOMATCH)
	{
		// Error, return false afterwards
		log_regex_error("matching", errcode);
	}

	// No match, no error, return false
	return false;
}

void free_regex(void)
{
	// Disable blocking regex checking
	config.blockingregex = false;
	regfree(&regex);
}
