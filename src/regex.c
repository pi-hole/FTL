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

static regex_t *regex[2] = { NULL };
static bool *regex_available[2] = { NULL };
static int *regex_id[2] = { NULL };
static char **regexbuffer[2] = { NULL };

const char *regextype[] = { "blacklist", "whitelist" };

/* Compile regular expressions into data structures that can be used with
   regexec() to match against a string */
static bool compile_regex(const char *regexin, const int index, const unsigned char regexid, const int dbindex)
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

int match_regex(const char *input, const int clientID, const unsigned char regexid, void *match_params)
{
	int match_idx = -1;
#ifdef USE_TRE_REGEX
	regaparams_t mp = { 0 };
	if(match_params != NULL)
		memcpy(&mp, match_params, sizeof(regaparams_t));
	regamatch_t amatch = { 0 };
#endif

	// Loop over all configured regex filters of this type
	for(unsigned int index = 0; index < counters->num_regex[regexid]; index++)
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
		int regexID = regexid == REGEX_WHITELIST ? index : index + counters->num_regex[REGEX_BLACKLIST];

		// Only use regular expressions enabled for this client
		// We allow clientID = -1 to get all regex (for testing)
		if(clientID >= 0 && !get_per_client_regex(clientID, regexID))
		{
			if(config.debug & DEBUG_REGEX)
			{
				clientsData* client = getClient(clientID, true);
				if(client != NULL)
				{
					logg("Regex %s (DB ID %d) \"%s\" NOT ENABLED for client %s",
					     regextype[regexid], regex_id[regexid][index],
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
				logg("Regex %s (database ID %i) >> MATCH: \"%s\" vs. \"%s\"",
				     regextype[regexid], regex_id[regexid][index],
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
		if(config.debug & DEBUG_REGEX && match_idx > -1)
		{
			logg("Regex %s (database ID %i) NO match: \"%s\" vs. \"%s\"",
			     regextype[regexid], regex_id[regexid][index],
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
	   regex[REGEX_BLACKLIST] == NULL)
		return;

	// Reset client configuration
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		reset_per_client_regex(clientID);
	}

	// Free regex datastructure
	for(unsigned char regexid = 0; regexid < 2; regexid++)
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

static void read_regex_table(const enum regex_id regexid)
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

int regex_speedtest(void)
{
	// Open log file
	open_FTL_log(true);

	// Prepare counters and regex memories
	if(!init_shmem())
		return EXIT_FAILURE;
	// Process pihole-FTL.conf to get gravity.db
	read_FTLconf();

	// Start actual config after preparation is done
	logg("Starting regex performance test...");

	// Read and compile regex blacklist
	logg("Step 1: Loading & Compiling regex blacklist from database");
	timer_start(REGEX_TIMER);
	read_regex_table(REGEX_BLACKLIST);
	logg("Compiled %i blacklist regex filters", counters->num_regex[REGEX_BLACKLIST]);
	logg("    Total time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));

	// Read and compile regex whitelist
	logg("Step 2: Loading & Compiling regex whitelist from database");
	timer_start(REGEX_TIMER);
	read_regex_table(REGEX_WHITELIST);
	logg("Compiled %i whitelist regex filters", counters->num_regex[REGEX_WHITELIST]);
	logg("    Total time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));


	// Get all domains from gravity table
	logg("Step 3: Reading all gravity domains into memory");
	timer_start(REGEX_TIMER);

	const unsigned int num_gravity = gravityDB_count(GRAVITY_TABLE);
	char **gravity_domains = calloc(num_gravity, sizeof(char*));

	// Connect to vw_gravity table
	if(!gravityDB_getTable(GRAVITY_TABLE))
	{
		logg("regex_speedtest(): Error getting gravity table from database");
		return 0UL;
	}

	const char *domain = NULL;
	unsigned int read_domains = 0;
	while((domain = gravityDB_getDomain(NULL)) != NULL)
	{
		// Avoid buffer overflow if database table changed
		// since we counted its entries
		if(read_domains >= num_gravity)
			break;

		gravity_domains[read_domains++] = strdup(domain);
	}

	// Finalize statement and close gravity database handle
	gravityDB_finalizeTable();
	logg("    Read %u domains", num_gravity);
	logg("    Total time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));

	logg("Step 4: Exactly matching all gravity domains against all loaded regular expressions (blacklist)");
	unsigned long matches = 0UL;
	timer_start(REGEX_TIMER);
	for(unsigned int i = 0; i < read_domains; i++)
	{
		matches += match_regex(gravity_domains[i], -1, REGEX_BLACKLIST, NULL) > -1 ? 1UL:0UL;
	}
	logg("    Total time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
	logg("    (%lu matches)", matches);

	logg("Step 5: Exactly matching all gravity domains against all loaded regular expressions (whitelist)");
	matches = 0UL;
	timer_start(REGEX_TIMER);
	for(unsigned int i = 0; i < read_domains; i++)
	{
		matches += match_regex(gravity_domains[i], -1, REGEX_WHITELIST, NULL) > -1 ? 1UL:0UL;
	}
	logg("    Total time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
	logg("    (%lu matches)", matches);

#ifdef USE_TRE_REGEX
	regaparams_t mp = { 0 };
	mp.cost_del = mp.cost_ins = mp.cost_subst = 1; // Set costs of insert/delete/substitute to one per item
	mp.max_cost = mp.max_err = mp.max_ins = mp.max_del = mp.max_subst = 1; // Allow at most one insertions + deletetions + substitutions
	logg("Step 6: Approximately matching all gravity domains against all loaded regular expressions (blacklist)");
	matches = 0UL;
	timer_start(REGEX_TIMER);
	for(unsigned int i = 0; i < read_domains; i++)
	{
		matches += match_regex(gravity_domains[i], -1, REGEX_BLACKLIST, &mp) > -1 ? 1UL:0UL;
	}
	logg("    Total time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
	logg("    (%lu matches)", matches);

	logg("Step 7: Approximately matching all gravity domains against all loaded regular expressions (whitelist)");
	matches = 0UL;
	timer_start(REGEX_TIMER);
	for(unsigned int i = 0; i < read_domains; i++)
	{
		matches += match_regex(gravity_domains[i], -1, REGEX_WHITELIST, &mp) > -1 ? 1UL:0UL;
	}
	logg("    Total time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
	logg("    (%lu matches)", matches);
#endif // USE_TRE_REGEX

	return EXIT_SUCCESS;
}
