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
static regex_t *regex = NULL;
static bool *regexconfigured = NULL;
static char **regexbuffer = NULL;
static whitelistStruct whitelist = { 0, NULL };

static void log_regex_error(char *where, int errcode, int index)
{
	// Regex failed for some reason (probably user syntax error)
	// Get error string and log it
	size_t length = regerror(errcode, &regex[index], NULL, 0);
	char *buffer = calloc(length,sizeof(char));
	(void) regerror (errcode, &regex[index], buffer, length);
	logg("ERROR %s regex on line %i: %s (%i)", where, index+1, buffer, errcode);
	free(buffer);
}

static bool init_regex(const char *regexin, int index)
{
	// compile regular expressions into data structures that
	// can be used with regexec to match against a string
	int errcode = regcomp(&regex[index], regexin, REG_EXTENDED);
	if(errcode != 0)
	{
		log_regex_error("compiling", errcode, index);
		return false;
	}

	// Store compiled regex string in buffer if in regex debug mode
	if(config.debug & DEBUG_REGEX)
	{
		regexbuffer[index] = strdup(regexin);
	}
	return true;
}

bool in_whitelist(char *domain)
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

	// Free whitelist domains array only allocated
	if(whitelist.domains != NULL)
	{
		free(whitelist.domains);
		whitelist.domains = NULL;
	}
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

			// Print match message when in regex debug mode
			if(config.debug & DEBUG_REGEX)
				logg("Regex in line %i \"%s\" matches \"%s\"", index+1, regexbuffer[index], input);
			break;
		}
		else if (errcode != REG_NOMATCH)
		{
			// Error, return false afterwards
			log_regex_error("matching", errcode, index);
			break;
		}
	}

	double elapsed = timer_elapsed_msec(REGEX_TIMER);

	// Only log evaluation times if they are longer than normal
	if(elapsed > 10.0)
		logg("WARN: Regex evaluation took %.3f msec", elapsed);

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
	{
		if(regexconfigured[index])
		{
			regfree(&regex[index]);

			// Also free buffered regex strings if in regex debug mode
			if(config.debug & DEBUG_REGEX)
			{
				free(regexbuffer[index]);
				regexbuffer[index] = NULL;
			}
		}
	}

	// Free array with regex datastructure
	free(regex);
	regex = NULL;
	free(regexconfigured);
	regexconfigured = NULL;

	// Reset counter for number of regex
	num_regex = 0;

	// Must reevaluate regex filters after having reread the regex filter
	// We reset all regex status to unknown to have them being reevaluated
	if(counters->domains > 0)
		validate_access("domains", counters->domains-1, false, __LINE__, __FUNCTION__, __FILE__);
	for(int i=0; i < counters->domains; i++)
	{
		domains[i].regexmatch = REGEX_UNKNOWN;
	}

	// Also free array of whitelisted domains
	free_whitelist_domains();
}

void read_whitelist_from_database(void)
{
	// Get number of lines in the whitelist table
	whitelist.count = gravityDB_count(WHITE_LIST);

	if(whitelist.count == 0)
	{
		logg("INFO: No whitelist entries found");
		return;
	}
	else if(whitelist.count == DB_FAILED)
	{
		logg("WARN: Database query failed, assuming there are no whitelist entries");
		whitelist.count = 0;
		return;
	}

	// Allocate memory for array of whitelisted domains
	whitelist.domains = calloc(whitelist.count, sizeof(char*));

	// Connect to whitelist table
	if(!gravityDB_getTable(WHITE_LIST))
	{
		logg("read_whitelist_from_database(): Error getting table from database");
		return;
	}

	// Walk database table
	const char *domain = NULL;
	int i = 0;
	while((domain = gravityDB_getDomain()) != NULL)
	{
		// Avoid buffer overflow if database table changed
		// since we counted its entries
		if(i >= whitelist.count)
			break;

		// Copy this whitelisted domain into memory
		whitelist.domains[i++] = strdup(domain);
	}

	// Finalize statement and close gravity database handle
	gravityDB_finalizeTable();
}

void read_regex_from_database(void)
{
	// Get number of lines in the regex table
	num_regex = gravityDB_count(REGEX_LIST);

	if(num_regex == 0)
	{
		logg("INFO: No regex entries found");
		return;
	}
	else if(num_regex == DB_FAILED)
	{
		logg("WARN: Database query failed, assuming there are no regex entries");
		num_regex = 0;
		return;
	}

	// Allocate memory for regex
	regex = calloc(num_regex, sizeof(regex_t));
	regexconfigured = calloc(num_regex, sizeof(bool));

	// Buffer strings if in regex debug mode
	if(config.debug & DEBUG_REGEX)
		regexbuffer = calloc(num_regex, sizeof(char*));

	// Connect to whitelist table
	if(!gravityDB_getTable(REGEX_LIST))
	{
		logg("read_regex_from_database(): Error getting table from database");
		return;
	}

	// Walk database table
	const char *domain = NULL;
	int i = 0;
	while((domain = gravityDB_getDomain()) != NULL)
	{
		// Avoid buffer overflow if database table changed
		// since we counted its entries
		if(i >= num_regex)
			break;

		// Skip this entry if empty: an empty regex filter would match
		// anything anywhere and hence match (and block) all incoming domains.
		// A user can still achieve this with a filter such as ".*", however
		// empty filters in the regex table are probably not expected to have such
		// an effect and would immediately lead to "blocking the entire Internet"
		if(strlen(domain) < 1)
			continue;

		// Copy this regex domain into memory
		regexconfigured[i] = init_regex(domain, i);

		// Increase counter
		i++;
	}

	// Finalize statement and close gravity database handle
	gravityDB_finalizeTable();
}

void log_regex_whitelist(double time)
{
	logg("Compiled %i Regex filters and %i whitelisted domains in %.1f msec (%i errors)", num_regex, whitelist.count, time);
}
