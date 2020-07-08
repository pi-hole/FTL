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
// cli_stuff()
#include "args.h"

const char *regextype[REGEX_MAX] = { "blacklist", "whitelist", "CLI" };

static regex_data *white_regex = NULL;
static regex_data *black_regex = NULL;
static regex_data   *cli_regex = NULL;

regex_data *get_regex_from_type(const enum regex_type regexid);
inline regex_data *get_regex_from_type(const enum regex_type regexid)
{
	switch (regexid)
	{
		case REGEX_BLACKLIST:
			return black_regex;
		case REGEX_WHITELIST:
			return white_regex;
		case REGEX_CLI:
			return cli_regex;
		case REGEX_MAX: // Fall through
		default: // This is not possible
			return NULL;
	}
}

#define FTL_REGEX_SEP ";"
/* Compile regular expressions into data structures that can be used with
   regexec() to match against a string */
static bool compile_regex(const char *regexin, const enum regex_type regexid)
{
	regex_data *regex = get_regex_from_type(regexid);
	int index = counters->num_regex[regexid]++;

	// Extract possible Pi-hole extensions
	char rgxbuf[strlen(regexin) + 1u];
	// Parse special FTL syntax if present
	if(strstr(regexin, FTL_REGEX_SEP) != NULL)
	{
		char *buf = strdup(regexin);
		// Extract regular expression pattern in front of FTL-specific syntax
		char *saveptr = NULL;
		char *part = strtok_r(buf, FTL_REGEX_SEP, &saveptr);
		strncpy(rgxbuf, part, sizeof(rgxbuf));

		// Analyze FTL-specific parts
		while((part = strtok_r(NULL, FTL_REGEX_SEP, &saveptr)) != NULL)
		{
			char extra[5] = { 0 };
			if(sscanf(part, "querytype=%4s", extra))
			{
				for(enum query_types type = TYPE_A; type < TYPE_MAX; type++)
				{
					if(strcasecmp(extra, querytypes[type]) == 0)
					{
						regex[index].query_type = type;
						break;
					}
				}
				if(regex[index].query_type != 0)
					logg("WARNING: Unknown query type: \"%s\"", extra);
			}
			else if(strcasecmp(part, "invert") == 0)
			{
				regex[index].inverted = true;
			}
		}
		free(buf);
	}
	else
	{
		// Copy entire input string into buffer
		strcpy(rgxbuf, regexin);
	}

	// We use the extended RegEx flavor (ERE) and specify that matching should
	// always be case INsensitive
	const int errcode = regcomp(&regex[index].regex, rgxbuf, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if(errcode != 0)
	{
		// Get error string and log it
		const size_t length = regerror(errcode, &regex[index].regex, NULL, 0);
		char *buffer = calloc(length, sizeof(char));
		(void) regerror (errcode, &regex[index].regex, buffer, length);
		logg_regex_warning(regextype[regexid], buffer, regex[index].database_id, regexin);
		free(buffer);
		regex[index].available = false;
		return false;
	}

	// Store compiled regex string in buffer
	regex[index].string = strdup(regexin);
	regex[index].available = true;

	return true;
}

int match_regex(const char *input, const DNSCacheData* dns_cache, const int clientID,
                const enum regex_type regexid, const bool regextest)
{
	int match_idx = -1;
	regex_data *regex = get_regex_from_type(regexid);
#ifdef USE_TRE_REGEX
	regmatch_t match = { 0 }; // This also disables any sub-matching
#endif

	// Loop over all configured regex filters of this type
	for(unsigned int index = 0; index < counters->num_regex[regexid]; index++)
	{
		// Only check regex which have been successfully compiled ...
		if(!regex[index].available)
		{
			if(config.debug & DEBUG_REGEX)
			{
				logg("Regex %s (%u, DB ID %d) \"%s\" is NOT AVAILABLE",
				     regextype[regexid], index, regex[index].database_id,
				     regex[index].string);
			}
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
					     regextype[regexid], index, regex[index].database_id,
					     regex[index].string, getstr(client->ippos));
				}
			}
			continue;
		}

		// Try to match the compiled regular expression against input
#ifdef USE_TRE_REGEX
		int retval = tre_regexec(&regex[index].regex, input, 0, &match, 0);
#else
		int retval = regexec(&regex[index].regex, input, 0, NULL, 0);
#endif
		// regexec() returns REG_OK for a successful match or REG_NOMATCH for failure.
		if ((retval == REG_OK && !regex[index].inverted) ||
		    (retval == REG_NOMATCH && regex[index].inverted))
		{
			// Check possible additional regex settings
			if(dns_cache != NULL)
			{
				// Check query type filtering
				if(regex[index].query_type != 0 && regex[index].query_type != dns_cache->query_type)
				{
					if(config.debug & DEBUG_REGEX)
					{
						logg("Regex %s (%u, DB ID %i) NO match: \"%s\" vs. \"%s\""
						     " (skipped because of query type mismatch)",
						regextype[regexid], index, regex[index].database_id,
						input, regex[index].string);
					}
					continue;
				}
			}

			// Match, return true
			match_idx = regex[index].database_id;

			// Print match message when in regex debug mode
			if(config.debug & DEBUG_REGEX)
			{
				// Approximate regex matching mode
				logg("Regex %s (%u, DB ID %i) >> MATCH: \"%s\" vs. \"%s\"",
				     regextype[regexid], index, regex[index].database_id,
				     input, regex[index].string);
			}

			if(regextest && regexid == REGEX_CLI)
			{
				// CLI provided regular expression
				logg("    %s%s%s matches",
				     cli_bold(), regex[index].string, cli_normal());
			}
			else if(regextest && regexid == REGEX_BLACKLIST)
			{
				// Database-sourced regular expression
				logg("    %s%s%s matches (regex blacklist, DB ID %i)",
				     cli_bold(), regex[index].string, cli_normal(),
				     regex[index].database_id);
			}
			else if(regextest && regexid == REGEX_WHITELIST)
			{
				// Database-sourced regular expression
				logg("    %s%s%s matches (regex whitelist, DB ID %i)",
				     cli_bold(), regex[index].string, cli_normal(),
				     regex[index].database_id);
			}
			else
			{
				// Only check the first match when not in regex-test mode
				break;
			}
		}

		// Print no match message when in regex debug mode
		if(config.debug & DEBUG_REGEX && match_idx == -1)
		{
			logg("Regex %s (%u, DB ID %i) NO match: \"%s\" vs. \"%s\"",
			     regextype[regexid], index, regex[index].database_id,
			     input, regex[index].string);
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
	if(white_regex == NULL &&
	   black_regex == NULL &&
	     cli_regex == NULL)
		return;

	// Reset client configuration
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		reset_per_client_regex(clientID);
	}

	// Free regex datastructure
	// Loop over regex types
	for(unsigned char regexid = 0; regexid < REGEX_MAX; regexid++)
	{
		regex_data *regex = get_regex_from_type(regexid);
		// Loop over entries with this regex type
		for(unsigned int index = 0; index < counters->num_regex[regexid]; index++)
		{
			if(!regex[index].available)
				continue;

			regfree(&regex[index].regex);

			// Also free buffered regex strings
			if(regex[index].string != NULL)
			{
				free(regex[index].string);
				regex[index].string = NULL;
			}
		}

		// Free array with regex datastructure
		if(regex != NULL)
		{
			free(regex);
			regex = NULL;
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
		logg("Blacklist: %p (%i)", black_regex, counters->num_regex[REGEX_BLACKLIST]);
		logg("Whitelist: %p (%i)", white_regex, counters->num_regex[REGEX_WHITELIST]);
		if(counters->num_regex[REGEX_BLACKLIST] > 0)
			gravityDB_get_regex_client_groups(client, counters->num_regex[REGEX_BLACKLIST],
			                                  black_regex, REGEX_BLACKLIST,
			                                  "vw_regex_blacklist", clientID);
		if(counters->num_regex[REGEX_WHITELIST] > 0)
			gravityDB_get_regex_client_groups(client, counters->num_regex[REGEX_WHITELIST],
			                                  white_regex, REGEX_WHITELIST,
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
		return;
	}
	else if(count < 0)
	{
		logg("WARN: Database query failed, assuming there are no %s regex entries", regextype[regexid]);
		return;
	}

	// Allocate memory for regex
	regex_data *regex = NULL;
	if(regexid == REGEX_BLACKLIST)
	{
		black_regex = calloc(count, sizeof(regex_data));
		regex = black_regex;
	}
	else
	{
		white_regex = calloc(count, sizeof(regex_data));
		regex = white_regex;
	}

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
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		// Avoid buffer overflow if database table changed
		// since we counted its entries
		if(counters->num_regex[regexid] >= (unsigned int)count)
		{
			logg("INFO: read_regex_table(%s) exiting early to avoid overflow (%d/%d).",
			     regextype[regexid], counters->num_regex[regexid], count);
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
			     regextype[regexid], counters->num_regex[regexid], rowid, domain);
		}

		compile_regex(domain, regexid);
		regex[counters->num_regex[regexid]-1].database_id = rowid;
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

int regex_test(const bool debug_mode, const bool quiet, const char *domainin, const char *regexin)
{
	// Prepare counters and regex memories
	counters = calloc(1, sizeof(countersStruct));
	// Disable terminal output during config config file parsing
	log_ctrl(false, false);
	// Process pihole-FTL.conf to get gravity.db
	read_FTLconf();

	// Disable all debugging output if not explicitly in debug mode (CLI argument "d")
	if(!debug_mode)
		config.debug = 0;
	// Re-enable terminal output
	log_ctrl(false, !quiet);

	int matchidx = -1;
	if(regexin == NULL)
	{
		// Read and compile regex lists from database
		logg("%s Loading regex filters from database...", cli_info());
		timer_start(REGEX_TIMER);
		log_ctrl(false, true); // Temporarily re-enable terminal output for error logging
		read_regex_table(REGEX_BLACKLIST);
		read_regex_table(REGEX_WHITELIST);
		log_ctrl(false, !quiet); // Re-apply quiet option after compilation
		logg("    Compiled %i black- and %i whitelist regex filters in %.3f msec\n",
		     counters->num_regex[REGEX_BLACKLIST],
		     counters->num_regex[REGEX_WHITELIST],
		     timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against all loaded regular blacklist expressions
		logg("%s Checking domain against blacklist...", cli_info());
		timer_start(REGEX_TIMER);
		int matchidx1 = match_regex(domainin, NULL, -1, REGEX_BLACKLIST, true);
		logg("    Time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against all loaded regular whitelist expressions
		logg("%s Checking domain against whitelist...", cli_info());
		timer_start(REGEX_TIMER);
		int matchidx2 = match_regex(domainin, NULL, -1, REGEX_WHITELIST, true);
		logg("    Time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
		matchidx = MAX(matchidx1, matchidx2);

	}
	else
	{
		// Compile CLI regex
		logg("%s Compiling regex filter...", cli_info());
		cli_regex = calloc(1, sizeof(regex_data));

		// Compile CLI regex
		timer_start(REGEX_TIMER);
		log_ctrl(false, true); // Temporarily re-enable terminal output for error logging
		if(!compile_regex(regexin, REGEX_CLI))
			return EXIT_FAILURE;
		log_ctrl(false, !quiet); // Re-apply quiet option after compilation
		logg("    Compiled regex filter in %.3f msec\n", timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against user-provided regular expression
		logg("Checking domain...");
		timer_start(REGEX_TIMER);
		matchidx = match_regex(domainin, NULL, -1, REGEX_CLI, true);
		if(matchidx == -1)
			logg("    NO MATCH!");
		logg("   Time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
	}

	// Return status 0 = MATCH, 1 = ERROR, 2 = NO MATCH
	return matchidx > -1 ? EXIT_SUCCESS : 2;
}