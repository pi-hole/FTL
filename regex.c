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

#define NUM_REGEX 1
static regex_t regex[NUM_REGEX];
static bool regexconfigured[NUM_REGEX] = { false };

static void log_regex_error(char *where, int errcode, int index)
{
	// Regex failed for some reason (probably user syntax error)
	// Get error string and log it
	size_t length = regerror(errcode, &regex[index], NULL, 0);
	char *buffer = calloc(length,sizeof(char));
	(void) regerror (errcode, &regex[index], buffer, length);
	logg("ERROR %s regex %i: %s (%i)", index, where, buffer, errcode);
	free(buffer);
	free_regex();
}

bool init_regex(char *regexin, int index)
{
	// compile regular expressions into data structures that
	// can be used with regexec to match against a string
	if(index > NUM_REGEX)
	{
		logg("ERROR: Increase NUM_REGEX");
		return false;
	}
	int errcode = regcomp(&regex[index], regexin, REG_EXTENDED);
	if(errcode != 0)
	{
		log_regex_error("compiling", errcode, index);
		return false;
	}
	// If we reach this point, then no regex compilation failed
	regexconfigured[index] = true;
	return true;
}

bool match_regex(char *input)
{
	int index;
	bool matched = false;

	timer_start(REGEX_TIMER);
	for(index = 0; index < NUM_REGEX; index++)
	{
		// Only check regex which have been compiled
		if(!regexconfigured[index])
			continue;

		// Try to match the compiled regular expression against input
		int errcode = regexec(&regex[index], input, 0, NULL, 0);
		if (errcode == 0)
		{
			// Match, return true
			matched = true;
			break;
		}
		else if (errcode != REG_NOMATCH)
		{
			// Error, return false afterwards
			log_regex_error("matching", errcode, index);
			break;
		}
	}
	logg("Regex evaluation took %.3f msec", timer_elapsed_msec(REGEX_TIMER));
	// No match, no error, return false
	return matched;
}

void free_regex(void)
{
	// Disable blocking regex checking
	config.blockingregex = false;
	int index;
	for(index = 0; index < NUM_REGEX; index++)
		if(regexconfigured[index])
			regfree(&regex[index]);
}
