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
#include "regex_r.h"
#include "timers.h"
#include "memory.h"
#include "log.h"
#include "config.h"
// data getter functions
#include "datastructure.h"
#include <regex.h>
#include "database/gravity-db.h"
// bool startup
#include "main.h"
// add_per_client_regex_client()
#include "shmem.h"

static regex_t *regex[2] = { NULL };
static bool *regex_available[2] = { NULL };
static int *regex_id[2] = { NULL };
static char **regexbuffer[2] = { NULL };

const char *regextype[] = { "blacklist", "whitelist" };

static void log_regex_error(const int errcode, const int index, const unsigned char regexid, const char *regexin)
{
	// Regex failed for some reason (probably user syntax error)
	// Get error string and log it
	const size_t length = regerror(errcode, &regex[regexid][index], NULL, 0);
	char *buffer = calloc(length,sizeof(char));
	(void) regerror (errcode, &regex[regexid][index], buffer, length);
	logg("Warning: Invalid regex %s filter \"%s\": %s (error code %i)", regextype[regexid], regexin, buffer, errcode);
	free(buffer);
}

static bool compile_regex(const char *regexin, const int index, const unsigned char regexid)
{
	// compile regular expressions into data structures that
	// can be used with regexec to match against a string
	int regflags = REG_EXTENDED;
	if(config.regex_ignorecase)
		regflags |= REG_ICASE;
	const int errcode = regcomp(&regex[regexid][index], regexin, regflags);
	if(errcode != 0)
	{
		log_regex_error(errcode, index, regexid, regexin);
		return false;
	}

	// Store compiled regex string in buffer if in regex debug mode
	if(config.debug & DEBUG_REGEX)
	{
		regexbuffer[regexid][index] = strdup(regexin);
	}

	return true;
}

int match_regex(const char *input, const int clientID, const unsigned char regexid)
{
	int match_idx = -1;

	// Start matching timer
	timer_start(REGEX_TIMER);
	for(int index = 0; index < counters->num_regex[regexid]; index++)
	{
		// Only check regex which have been successfully compiled ...
		if(!regex_available[regexid][index])
		{
			if(config.debug & DEBUG_REGEX)
				logg("Regex %s (DB ID %d) \"%s\" is NOT AVAILABLE",
				     regextype[regexid], regex_id[regexid][index],
					 regexbuffer[regexid][index]);

			continue;
		}
		// ... and are enabled for this client
		int regexID = index;
		if(regexid == REGEX_WHITELIST)
			regexID += counters->num_regex[REGEX_BLACKLIST];

		if(!get_per_client_regex(clientID, regexID))
		{
			if(config.debug & DEBUG_REGEX)
			{
				clientsData* client = getClient(clientID, true);
				logg("Regex %s (DB ID %d) \"%s\" NOT ENABLED for client %s",
				     regextype[regexid], regex_id[regexid][index],
				     regexbuffer[regexid][index], getstr(client->ippos));
			}

			continue;
		}

		// Try to match the compiled regular expression against input
		int errcode = regexec(&regex[regexid][index], input, 0, NULL, 0);
		// regexec() returns zero for a successful match or REG_NOMATCH for failure.
		// We are only interested in the matching case here.
		if (errcode == 0)
		{
			// Match, return true
			match_idx = regex_id[regexid][index];

			// Print match message when in regex debug mode
			if(config.debug & DEBUG_REGEX)
			{
				logg("Regex %s (DB ID %i) >> MATCH: \"%s\" vs. \"%s\"",
				     regextype[regexid], regex_id[regexid][index],
				     input, regexbuffer[regexid][index]);
			}
			break;
		}

		// Print no match message when in regex debug mode
		if(config.debug & DEBUG_REGEX && match_idx > -1)
		{
			logg("Regex %s (DB ID %i) NO match: \"%s\" vs. \"%s\"",
			     regextype[regexid], regex_id[regexid][index],
				 input, regexbuffer[regexid][index]);
		}
	}

	double elapsed = timer_elapsed_msec(REGEX_TIMER);

	// Only log evaluation times if they are longer than normal
	if(elapsed > 10.0)
		logg("WARN: Regex %s evaluation took %.3f msec", regextype[regexid], elapsed);

	// No match, no error, return false
	return match_idx;
}

static void free_regex(void)
{
	// Reset FTL's DNS cache
	FTL_reset_per_client_domain_data();

	// Return early if we don't use any regex filters
	if(regex[REGEX_WHITELIST] == NULL &&
	   regex[REGEX_BLACKLIST] == NULL)
		return;

	// Reset client configuration
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		reset_per_client_regex(clientID);
	}

	// Free regex datastructure
	for(int regexid = 0; regexid < 2; regexid++)
	{
		for(int index = 0; index < counters->num_regex[regexid]; index++)
		{
			if(!regex_available[regexid][index])
				continue;

			regfree(&regex[regexid][index]);

			// Also free buffered regex strings if in regex debug mode
			if(config.debug & DEBUG_REGEX && regexbuffer[regexid][index] != NULL)
			{
				free(regexbuffer[regexid][index]);
				regexbuffer[regexid][index] = NULL;
			}
		}

		// Free array with regex datastructure
		if(regex[regexid] != NULL)
		{
			free(regex[regexid]);
			regex[regexid] = NULL;
		}

		// Reset counter for number of regex
		counters->num_regex[regexid] = 0;
	}
}

void allocate_regex_client_enabled(clientsData *client, const int clientID)
{
	add_per_client_regex(clientID);

	// Only initialize regex associations when dnsmasq is ready (otherwise, we're still in history reading mode)
	if(!startup)
	{
		gravityDB_get_regex_client_groups(client, counters->num_regex[REGEX_BLACKLIST],
						regex_id[REGEX_BLACKLIST], REGEX_BLACKLIST,
						"vw_regex_blacklist", clientID);
		gravityDB_get_regex_client_groups(client, counters->num_regex[REGEX_WHITELIST],
						regex_id[REGEX_WHITELIST], REGEX_WHITELIST,
						"vw_regex_whitelist", clientID);
	}
}

static void read_regex_table(const unsigned char regexid)
{
	// Get table ID
	unsigned char tableID = (regexid == REGEX_BLACKLIST) ? REGEX_BLACKLIST_TABLE : REGEX_WHITELIST_TABLE;

	// Get number of lines in the regex table
	counters->num_regex[regexid] = gravityDB_count(tableID);

	if(counters->num_regex[regexid] == 0)
	{
		logg("INFO: No regex %s entries found", regextype[regexid]);
		return;
	}
	else if(counters->num_regex[regexid] == DB_FAILED)
	{
		logg("WARN: Database query failed, assuming there are no %s regex entries", regextype[regexid]);
		counters->num_regex[regexid] = 0;
		return;
	}

	// Allocate memory for regex
	regex[regexid] = calloc(counters->num_regex[regexid], sizeof(regex_t));
	regex_id[regexid] = calloc(counters->num_regex[regexid], sizeof(int));
	regex_available[regexid] = calloc(counters->num_regex[regexid], sizeof(bool));

	// Buffer strings if in regex debug mode
	if(config.debug & DEBUG_REGEX)
		regexbuffer[regexid] = calloc(counters->num_regex[regexid], sizeof(char*));

	// Connect to regex table
	if(!gravityDB_getTable(tableID))
	{
		logg("read_regex_from_database(): Error getting %s regex table from database", regextype[regexid]);
		return;
	}

	// Walk database table
	const char *domain = NULL;
	int i = 0, rowid = 0;
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		// Avoid buffer overflow if database table changed
		// since we counted its entries
		if(i >= counters->num_regex[regexid])
			break;

		// Skip this entry if empty: an empty regex filter would match
		// anything anywhere and hence match all incoming domains. A user
		// can still achieve this with a filter such as ".*", however empty
		// filters in the regex table are probably not expected to have such
		// an effect and would immediately lead to "blocking or whitelisting
		// the entire Internet"
		if(strlen(domain) < 1)
			continue;

		// Compile this regex
		if(config.debug & DEBUG_REGEX)
		{
			logg("Compiling %s regex %i (database ID %i): %s", regextype[regexid], i, rowid, domain);
		}
		regex_available[regexid][i] = compile_regex(domain, i, regexid);
		regex_id[regexid][i] = rowid;

		// Increase counter
		i++;
	}

	// Finalize statement and close gravity database handle
	gravityDB_finalizeTable();
}

void read_regex_from_database(void)
{
	// Free regex filters
	// This routine is safe to be called even when there
	// are no regex filters at the moment
	free_regex();

	// Start timer for regex compilation analysis
	timer_start(REGEX_TIMER);

	// Read and compile regex blacklist
	read_regex_table(REGEX_BLACKLIST);

	// Read and compile regex whitelist
	read_regex_table(REGEX_WHITELIST);


	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		clientsData *client = getClient(clientID, true);
		if(client == NULL)
			continue;

		allocate_regex_client_enabled(client, clientID);
	}

	// Print message to FTL's log after reloading regex filters
	logg("Compiled %i whitelist and %i blacklist regex filters in %.1f msec",
	     counters->num_regex[REGEX_WHITELIST], counters->num_regex[REGEX_BLACKLIST],
	     timer_elapsed_msec(REGEX_TIMER));
}
