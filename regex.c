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
static whitelistStruct whitelist = { 0, NULL };

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

static bool in_whitelist(char *domain)
{
	bool found = false;
	for(int i=0; i < whitelist.count; i++)
	{
		// strcasecmp() compares two strings ignoring case
		if(strcasecmp(whitelist.domains[i], domain) == 0)
		{
			found = true;
			break;
		}
	}
	return found;
}

static void free_whitelist_domains(void)
{
	for(int i=0; i < whitelist.count; i++)
		free(whitelist.domains[i]);

	whitelist.count = 0;

	free(whitelist.domains);
	whitelist.domains = NULL;
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

	// If a regex filter matched, we additionally compare the domain
	// against all known whitelisted domains to possibly prevent blocking
	// of a specific domain. The logic herein is:
	// If matched, then compare against whitelist
	// If in whitelist, negate matched so this function returns: not-to-be-blocked
	if(matched)
		matched = !in_whitelist(input);

	double elapsed = timer_elapsed_msec(REGEX_TIMER);

	// Only log evaluation times if they are longer than normal
	if(elapsed > 10.0 || debug)
		logg("Regex evaluation took %.3f msec", elapsed);

	// No match, no error, return false
	return matched;
}

void free_regex(void)
{
	// Return early if we don't use any regex
	if(regex == NULL)
		return;

	// Disable blocking regex checking and free regex datastructure
	for(int index = 0; index < num_regex; index++)
		if(regexconfigured[index])
			regfree(&regex[index]);

	// Free array with regex datastructure
	free(regex);
	regex = NULL;
	free(regexconfigured);
	regexconfigured = NULL;

	// Reset counter for number of regex
	num_regex = 0;

	// Must reevaluate regex filters after having reread the regex filter
	// We reset all regex status to unknown to have them being reevaluated
	if(counters.domains > 0)
		validate_access("domains", counters.domains-1, false, __LINE__, __FUNCTION__, __FILE__);
	for(int i=0; i < counters.domains; i++)
	{
		domains[i].regexmatch = REGEX_UNKNOWN;
	}

	// Also free array of whitelisted domains
	free_whitelist_domains();
}

static void read_whitelist_from_file(void)
{
	FILE *fp;
	char *buffer = NULL;
	size_t size = 0;

	// Get number of lines in the regex file
	whitelist.count = countlines(files.whitelist);

	if(whitelist.count < 0)
	{
		logg("INFO: No whitelist file found");
		return;
	}

	if((fp = fopen(files.whitelist, "r")) == NULL) {
		logg("WARN: Cannot access whitelist (%s)",files.whitelist);
		return;
	}

	// Allocate memory for regex
	whitelist.domains = calloc(whitelist.count, sizeof(char*));

	// Search through file
	// getline reads a string from the specified file up to either a
	// newline character or EOF
	for(int i=0; getline(&buffer, &size, fp) != -1; i++)
	{
		// Test if file has changed since we counted the lines therein (unlikely
		// but not impossible). If so, read only as far as we have reserved memory
		if(i >= whitelist.count)
			break;

		// Strip potential newline character at the end of line we just read
		if(buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1] = '\0';

		// Copy this whitelist domain into memory
		whitelist.domains[i] = strdup(buffer);
	}

	// Free allocated memory
	if(buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
	}

	// Close the file
	fclose(fp);
}

void read_regex_from_file(void)
{
	FILE *fp;
	char *buffer = NULL;
	size_t size = 0;
	int errors = 0;

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
	for(int i=0; getline(&buffer, &size, fp) != -1; i++)
	{
		// Strip potential newline character at the end of line we just read
		if(buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1] = '\0';

		// Compile this regex
		regexconfigured[i] = init_regex(buffer, i);
		if(!regexconfigured[i]) errors++;
	}

	// Free allocated memory
	if(buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
	}

	// Close the file
	fclose(fp);

	// Read whitelisted domains from file
	read_whitelist_from_file();

	logg("Compiled %i Regex filters and %i whitelisted domains in %.1f msec (%i errors)", num_regex, whitelist.count, timer_elapsed_msec(REGEX_TIMER), errors);
}
