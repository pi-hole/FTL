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

static int num_regex;
static regex_t *regex;
static bool *regexconfigured;

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

static bool init_regex(char *regexin, int index)
{
	// compile regular expressions into data structures that
	// can be used with regexec to match against a string
	int errcode = regcomp(&regex[index], regexin, REG_EXTENDED);
	if(errcode != 0)
	{
		log_regex_error("compiling", errcode, index);
		return false;
	}
	return true;
}

bool match_regex(char *input)
{
	int index;
	bool matched = false;

	// Start matching timer
	timer_start(REGEX_TIMER);
	for(index = 0; index < num_regex; index++)
	{
		// Only check regex which have been successfully compiled
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
	for(index = 0; index < num_regex; index++)
		if(regexconfigured[index])
			regfree(&regex[index]);
}

void read_regex_from_file(void)
{
	FILE *fp;
	char *buffer = NULL;
	size_t size = 0;
	int i = 0, errors = 0;

	// Start timer for regex compilation analysis
	timer_start(REGEX_TIMER);

	// Get number of lines in the regex file
	num_regex = countlines(files.regexlist);

	if(num_regex < 0)
	{
		logg("INFO: No Regex file found");
		return;
	}

	if((fp = fopen(files.regexlist, "r")) == NULL) {
		logg("WARN: Cannot access Regex file");
		return;
	}

	// Allocate memory for regex
	regex = calloc(num_regex, sizeof(regex_t));
	regexconfigured = calloc(num_regex, sizeof(bool));

	// Search through file
	// getline reads a string from the specified file up to either a
	// newline character or EOF
	while(getline(&buffer, &size, fp) != -1)
	{
		// Strip potential newline character at the end of line we just read
		if(buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1] = '\0';

		// Compile this regex
		logg("Adding \"%s\" to regex",buffer);
		regexconfigured[i] = init_regex(buffer, i);
		if(!regexconfigured[i]) errors++;
		i++;
	}

	// Free allocated memory
	if(buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
	}

	// Close the file
	fclose(fp);

	logg("Compiled %i Regex filters in %.1f msec (%i errors)", num_regex, timer_elapsed_msec(REGEX_TIMER), errors);
}
