/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Regular Expressions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Use TRE instead of GNU regex library (compiled into FTL itself)
#define USE_TRE_REGEX

#include "FTL.h"
#include "regex_r.h"
#include "timers.h"
#include "memory.h"
#include "log.h"
#include "config.h"
// data getter functions
#include "datastructure.h"
#include "database/gravity-db.h"
// bool startup
#include "main.h"
// add_per_client_regex_client()
#include "shmem.h"
#include "database/message-table.h"
// init_shmem()
#include "shmem.h"
// read_FTL_config()
#include "config.h"

#ifdef USE_TRE_REGEX
#include "tre-regex/regex.h"
#else
#include <regex.h>
#endif

const char *regextype[REGEX_MAX] = { "blacklist", "whitelist", "CLI" };
static regex_t *regex[REGEX_MAX] = { NULL };
static bool *regex_available[REGEX_MAX] = { NULL };
static int *regex_id[REGEX_MAX] = { NULL };
static char **regexbuffer[REGEX_MAX] = { NULL };

/* Compile regular expressions into data structures that can be used with
   regexec() to match against a string */
static bool compile_regex(const char *regexin, const int index, const enum regex_type regexid, const int dbindex)
{
	// We use the extended RegEx flavor (ERE) and specify that matching should
	// always be case INsensitive
	const int errcode = regcomp(&regex[regexid][index], regexin, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if(errcode != 0)
	{
		// Get error string and log it
		const size_t length = regerror(errcode, &regex[regexid][index], NULL, 0);
		char *buffer = calloc(length, sizeof(char));
		(void) regerror (errcode, &regex[regexid][index], buffer, length);
		logg_regex_warning(regextype[regexid], buffer, dbindex, regexin);
		free(buffer);
		return false;
	}

	// Store compiled regex string in buffer if in regex debug mode
	if(config.debug & DEBUG_REGEX)
	{
		regexbuffer[regexid][index] = strdup(regexin);
	}

	return true;
}

int match_regex(const char *input, const int clientID, const enum regex_type regexid, void *match_params)
{
	int match_idx = -1;
#ifdef USE_TRE_REGEX
	regaparams_t mp = { 0 }; // Setting all costs to zero -> exact matching
	if(match_params != NULL)
		memcpy(&mp, match_params, sizeof(regaparams_t));
	regamatch_t amatch = { 0 }; // This also disables any sub-matching
#endif

	// Loop over all configured regex filters of this type
	for(unsigned int index = 0; index < counters->num_regex[regexid]; index++)
	{
		// Only check regex which have been successfully compiled ...
		if(!regex_available[regexid][index])
		{
			if(config.debug & DEBUG_REGEX)
				logg("Regex %s (%u, DB ID %d) \"%s\" is NOT AVAILABLE",
				     regextype[regexid], index, regex_id[regexid][index],
					 regexbuffer[regexid][index]);

			continue;
		}
		// ... and are enabled for this client
		int regexID = index;
		if(regexid == REGEX_WHITELIST)
			regexID += counters->num_regex[REGEX_BLACKLIST];
		else if(regexid == REGEX_CLI)
			regexID += counters->num_regex[REGEX_BLACKLIST] +
			           counters->num_regex[REGEX_WHITELIST];

		// Only use regular expressions enabled for this client
		// We allow clientID = -1 to get all regex (for testing)
		if(clientID >= 0 && !get_per_client_regex(clientID, regexID))
		{
			if(config.debug & DEBUG_REGEX)
			{
				clientsData* client = getClient(clientID, true);
				if(client != NULL)
				{
					logg("Regex %s (%u, DB ID %d) \"%s\" NOT ENABLED for client %s",
					     regextype[regexid], index, regex_id[regexid][index],
					     regexbuffer[regexid][index], getstr(client->ippos));
				}
			}
			continue;
		}

		// Try to match the compiled regular expression against input
		int errcode;
#ifdef USE_TRE_REGEX
		errcode = tre_regaexec(&regex[regexid][index], input, &amatch, mp, 0);
#else
		errcode = regexec(&regex[regexid][index], input, 0, NULL, 0);
#endif
		// regexec() returns zero for a successful match or REG_NOMATCH for failure.
		// We are only interested in the matching case here.
		if (errcode == 0)
		{
			// Match, return true
			match_idx = regex_id[regexid][index];

			// Print match message when in regex debug mode
			if(config.debug & DEBUG_REGEX)
			{
				// Approximate regex matching mode
				logg("Regex %s (%u, DB ID %i) >> MATCH: \"%s\" vs. \"%s\"",
				     regextype[regexid], index, regex_id[regexid][index],
				     input, regexbuffer[regexid][index]);
#ifdef USE_TRE_REGEX
				if(amatch.cost > 0)
				{
					logg("Regex costs: %i (ins: %i, del: %i sub: %i)",
					     amatch.cost, amatch.num_ins, amatch.num_del, amatch.num_subst);
				}
#endif
			}

			// Always check all regular expressions for clientID = -1
			if(clientID >= 0)
				break;
		}

		// Print no match message when in regex debug mode
		if(config.debug & DEBUG_REGEX && match_idx == -1)
		{
			logg("Regex %s (%u, DB ID %i) NO match: \"%s\" vs. \"%s\"",
			     regextype[regexid], index, regex_id[regexid][index],
			     input, regexbuffer[regexid][index]);
		}
	}

	// No match, no error, return false
	return match_idx;
}

static void free_regex(void)
{
	// Reset FTL's DNS cache
	FTL_reset_per_client_domain_data();

	// Return early if we don't use any regex filters
	if(regex[REGEX_WHITELIST] == NULL &&
	   regex[REGEX_BLACKLIST] == NULL &&
	   regex[REGEX_CLI] == NULL)
		return;

	// Reset client configuration
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		reset_per_client_regex(clientID);
	}

	// Free regex datastructure
	for(unsigned char regexid = 0; regexid < REGEX_MAX; regexid++)
	{
		for(unsigned int index = 0; index < counters->num_regex[regexid]; index++)
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

static void read_regex_table(const enum regex_type regexid)
{
	// Get table ID
	const enum gravity_tables tableID = (regexid == REGEX_BLACKLIST) ? REGEX_BLACKLIST_TABLE : REGEX_WHITELIST_TABLE;

	// Get number of lines in the regex table
	counters->num_regex[regexid] = 0;
	int count = gravityDB_count(tableID);

	if(count == 0)
	{
		logg("INFO: No regex %s entries found", regextype[regexid]);
		return;
	}
	else if(count < 0)
	{
		logg("WARN: Database query failed, assuming there are no %s regex entries", regextype[regexid]);
		return;
	}

	// Store number of regex domains of this type
	counters->num_regex[regexid] = count;

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
		logg("read_regex_from_database(): Error getting %s regex table from database",
		     regextype[regexid]);
		return;
	}

	// Walk database table
	const char *domain = NULL;
	int rowid = 0;
	unsigned int i = 0;
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		// Avoid buffer overflow if database table changed
		// since we counted its entries
		if(i >= counters->num_regex[regexid])
		{
			logg("INFO: read_regex_table(%s) exiting early to avoid overflow.",
			     regexid == REGEX_BLACKLIST ? "black" : "white");
			break;
		}

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
			logg("Compiling %s regex %i (DB ID %i): %s",
			     regextype[regexid], i, rowid, domain);
		}
		regex_available[regexid][i] = compile_regex(domain, i, regexid, rowid);
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
	logg("Compiled %i whitelist and %i blacklist regex filters for %i clients in %.1f msec",
	     counters->num_regex[REGEX_WHITELIST], counters->num_regex[REGEX_BLACKLIST],
	     counters->clients, timer_elapsed_msec(REGEX_TIMER));
}

int regex_test(const char *domainin, const char *regexin)
{
	// Open log file
	silent_log(true, true);
	open_FTL_log(true);

	// Prepare counters and regex memories
	if(!init_shmem())
		return EXIT_FAILURE;
	// Process pihole-FTL.conf to get gravity.db
	read_FTLconf();
	silent_log(true, false);

	// Start actual config after preparation is done
	logg("FTL Regex test:");
	logg("  Domain: \"%s\"", domainin);
	logg("   Regex: \"%s\"", regexin == NULL ? "(from database)" : regexin);

	int match;
	if(regexin == NULL)
	{
		// Read and compile regex lists
		logg("Step 1: Loading & Compiling regex filters from database");
		timer_start(REGEX_TIMER);
		read_regex_table(REGEX_BLACKLIST);
		read_regex_table(REGEX_WHITELIST);
		logg("        Compiled %i black- and %i whitelist regex filters in %.3f msec",
		     counters->num_regex[REGEX_BLACKLIST],
		     counters->num_regex[REGEX_WHITELIST],
		     timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against all loaded regular expressions
		logg("Step 2: Checking domain...");
		timer_start(REGEX_TIMER);
		match = match_regex(domainin, -1, REGEX_BLACKLIST, NULL);
	}
	else
	{
		// Compile CLI regex
		logg("Step 1: Compiling regex filter...");
		counters->num_regex[REGEX_BLACKLIST] = counters->num_regex[REGEX_WHITELIST] = 0;
		counters->num_regex[REGEX_CLI] = 1;

		// Allocate memory for regex
		regex[REGEX_CLI] = calloc(counters->num_regex[REGEX_CLI], sizeof(regex_t));
		regex_id[REGEX_CLI] = calloc(counters->num_regex[REGEX_CLI], sizeof(int));
		regex_available[REGEX_CLI] = calloc(counters->num_regex[REGEX_CLI], sizeof(bool));
		if(config.debug & DEBUG_REGEX)
			regexbuffer[REGEX_CLI] = calloc(counters->num_regex[REGEX_CLI], sizeof(char*));

		// Compile CLI regex
		timer_start(REGEX_TIMER);
		if(compile_regex(regexin, 0, REGEX_CLI, -1))
			regex_available[REGEX_CLI][0] = true;
		else
			return EXIT_FAILURE;
		logg("        Compiled regex filter in %.3f msec", timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against user-provided regular expression
		logg("Step 2: Checking domain...");
		timer_start(REGEX_TIMER);
		match = match_regex(domainin, -1, REGEX_CLI, NULL);
	}

	logg("        Done in %.3f msec\n", timer_elapsed_msec(REGEX_TIMER));
	if(match > -1)
	{
		logg("MATCH");
		return EXIT_SUCCESS;
	}
	else
	{
		logg("NO MATCH");
		return EXIT_FAILURE;
	}
}