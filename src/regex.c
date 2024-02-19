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
#include "log.h"
#include "config/config.h"
// data getter functions
#include "datastructure.h"
#include "database/gravity-db.h"
// add_per_client_regex_client()
#include "shmem.h"
#include "database/message-table.h"
// init_shmem()
#include "shmem.h"
// readFTLconf()
#include "config/config.h"
// cli_stuff()
#include "args.h"

const char *regextype[REGEX_MAX] = { "deny", "allow", "CLI" };
// Safety-measure for future extensions
#if TYPE_MAX > 30
#error "Too many query types to be handled by a 32-bit integer"
#endif

static regexData *allow_regex = NULL;
static regexData  *deny_regex = NULL;
static regexData   *cli_regex = NULL;
static unsigned int num_regex[REGEX_MAX] = { 0 };
unsigned int regex_change = 0;
static char regex_msg[REGEX_MSG_LEN] = { 0 };

static inline regexData *get_regex_ptr(const enum regex_type regexid)
{
	switch (regexid)
	{
		case REGEX_DENY:
			return deny_regex;
		case REGEX_ALLOW:
			return allow_regex;
		case REGEX_CLI:
			return cli_regex;
		case REGEX_MAX: // Fall through
		default: // This is not possible
			return NULL;
	}
}

static inline void free_regex_ptr(const enum regex_type regexid)
{
	regexData **regex;
	switch (regexid)
	{
		case REGEX_DENY:
			regex = &deny_regex;
			break;
		case REGEX_ALLOW:
			regex = &allow_regex;
			break;
		case REGEX_CLI:
			regex = &cli_regex;
			break;
		case REGEX_MAX: // Fall through
		default: // This is not possible
			return;
	}

	// Free pointer (if not already NULL)
	if(*regex != NULL)
	{
		free(*regex);
		*regex = NULL;
	}
}

static __attribute__ ((pure)) regexData *get_regex_ptr_from_id(unsigned int regexID)
{
	unsigned int maxi;
	enum regex_type regex_type;
	if(regexID < num_regex[REGEX_DENY])
	{
		// Regex blacklist
		regex_type = REGEX_DENY;
		maxi = num_regex[REGEX_DENY];
	}
	else
	{
		// Subtract regex blacklist
		regexID -= num_regex[REGEX_DENY];

		// Check for regex whitelist
		if(regexID < num_regex[REGEX_ALLOW])
		{
			// Regex whitelist
			regex_type = REGEX_ALLOW;
			maxi = num_regex[REGEX_ALLOW];
		}
		else
		{
			// Subtract regex whitelist
			regexID -= num_regex[REGEX_ALLOW];

			// CLI regex
			regex_type = REGEX_CLI;
			maxi = num_regex[REGEX_CLI];
		}
	}

	regexData *regex = get_regex_ptr(regex_type);
	if(regex != NULL && regexID < maxi)
		return &(regex[regexID]);

	return NULL;
}

unsigned int __attribute__((pure)) get_num_regex(const enum regex_type regexid)
{
	// count number of all available reges
	if(regexid == REGEX_MAX)
	{
		unsigned int num = 0;
		for(unsigned int i = 0; i < REGEX_MAX; i++)
			num += num_regex[i];
		return num;
	}

	// else: specific regex type
	return num_regex[regexid];
}

#define FTL_REGEX_SEP ";"
/* Compile regular expressions into data structures that can be used with
   regexec() to match against a string */
bool compile_regex(const char *regexin, regexData *regex, char **message)
{
	// Extract possible Pi-hole extensions
	char *rgxbuf = calloc(strlen(regexin) + 1u, sizeof(char));
	// Parse special FTL syntax if present
	if(strstr(regexin, FTL_REGEX_SEP) != NULL)
	{
		char *buf = strdup(regexin);
		// Extract regular expression pattern in front of FTL-specific syntax
		char *saveptr = NULL;
		char *part = strtok_r(buf, FTL_REGEX_SEP, &saveptr);
		strncpy(rgxbuf, part, strlen(regexin));

		// Analyze FTL-specific parts
		while((part = strtok_r(NULL, FTL_REGEX_SEP, &saveptr)) != NULL)
		{
			char extra[256] = { 0 };
			// options like
			// - ";querytype=A" (only match type A queries)
			// - ";querytype=!AAAA" (match everything but AAAA queries)
			// - ";querytype=A,AAAA" (match only A and AAAA queries)
			// - ";querytype=!A,AAAA" (match everything but A and AAAA queries)
			if(sscanf(part, "querytype=%63s", extra))
			{
				// Warn if specified more than one querytype option
				if(regex->ext.query_type != 0)
				{
					*message = strdup("Overwriting previous querytype setting (multiple \"querytype=...\" found)");
					free(buf);
					free(rgxbuf);
					return false;
				}

				// Check if the first letter is a "!"
				// This means that the query type matching is inverted
				bool inverted = false;
				if(extra[0] == '!')
				{
					// Set inverted mode (will be applied
					// after parsing all query types)
					inverted = true;

					// Remove the "!" from the string
					memmove(extra, extra+1, strlen(extra));
				}

				// Split input string into individual query types
				char *saveptr2 = NULL;
				char *token = strtok_r(extra, ",", &saveptr2);
				while(token != NULL)
				{
					// Test input string against all implemented query types
					for(enum query_type type = TYPE_A; type < TYPE_MAX; type++)
					{
						// Check for querytype
						const char *qtype = get_query_type_str(type, NULL, NULL);
						if(strcasecmp(token, qtype) == 0)
						{
							regex->ext.query_type ^= 1 << type;
							break;
						}
					}

					// Get next token
					token = strtok_r(NULL, ",", &saveptr2);
				}

				// Check if we found a valid query type
				if(regex->ext.query_type == 0)
				{
					if(asprintf(message, "Unknown querytype \"%s\"", extra) < 1)
							log_err("Memory allocation failed in compile_regex()");
					free(buf);
					free(rgxbuf);
					return false;
				}

				// Invert query types if requested
				if(inverted)
					regex->ext.query_type = ~regex->ext.query_type;

				if(regex->ext.query_type != 0 && config.debug.regex.v.b)
				{
					log_debug(DEBUG_REGEX, "    Hint: This regex matches only specific query types:");
					for(enum query_type type = TYPE_A; type < TYPE_MAX; type++)
					{
						if(regex->ext.query_type & (1 << type))
						{
							const char *qtype = get_query_type_str(type, NULL, NULL);
							log_debug(DEBUG_REGEX, "      - %s", qtype);
						}
					}
				}
			}
			// option: ";invert"
			else if(strcasecmp(part, "invert") == 0)
			{
				regex->ext.inverted = true;

				// Debug output
				log_debug(DEBUG_REGEX, "   This regex will match in inverted mode.");
			}
			// options ";reply=NXDOMAIN", etc.
			else if(sscanf(part, "reply=%255s", extra))
			{
				// Test input string against all implemented reply types
				const char *type = "";
				if(strcasecmp(extra, "NODATA") == 0)
				{
					type = "NODATA";
					regex->ext.reply = REPLY_NODATA;
				}
				else if(strcasecmp(extra, "NXDOMAIN") == 0)
				{
					type = "NXDOMAIN";
					regex->ext.reply = REPLY_NXDOMAIN;
				}
				else if(strcasecmp(extra, "REFUSED") == 0)
				{
					type = "REFUSED";
					regex->ext.reply = REPLY_REFUSED;
				}
				else if(strcasecmp(extra, "IP") == 0)
				{
					type = "IP";
					regex->ext.reply = REPLY_IP;
				}
				else if(inet_pton(AF_INET, extra, &regex->ext.addr4) == 1)
				{
					// Custom IPv4 target
					type = extra;
					regex->ext.reply = REPLY_IP;
					regex->ext.custom_ip4 = true;
				}
				else if(inet_pton(AF_INET6, extra, &regex->ext.addr6) == 1)
				{
					// Custom IPv6 target
					type = extra;
					regex->ext.reply = REPLY_IP;
					regex->ext.custom_ip6 = true;
				}
				else if(strcasecmp(extra, "NONE") == 0)
				{
					type = "NONE";
					regex->ext.reply = REPLY_NONE;
				}
				else if(strncasecmp(extra, "CNAME", 4) == 0)
				{
					type = "CNAME";
					regex->ext.reply = REPLY_CNAME;
					// Check if "CNAME" is followed by a comma and a domain name
					char *comma = strchr(extra, ',');
					if(comma != NULL)
					{
						// Skip comma
						comma++;

						// Copy domain name into buffer
						regex->ext.cname_target = strdup(comma);
						if(regex->ext.cname_target == NULL)
						{
							log_err("Memory allocation failed in compile_regex()");
							free(buf);
							free(rgxbuf);
							return false;
						}
					}
					else
					{
						if(asprintf(message, "Missing domain name for CNAME reply") < 1)
							log_err("Memory allocation failed in compile_regex()");
						free(buf);
						free(rgxbuf);
						return false;
					}
				}
				else
				{
					if(asprintf(message, "Unknown reply type \"%s\"", extra) < 1)
						log_err("Memory allocation failed in compile_regex()");
					free(buf);
					free(rgxbuf);
					return false;
				}

				// Debug output
				if(regex->ext.reply != REPLY_UNKNOWN)
					log_debug(DEBUG_REGEX, "   This regex will result in a custom reply: %s", type);
			}
			else
			{
				if(asprintf(message, "Invalid regex option \"%s\"", part) < 1)
					log_err("Memory allocation failed in compile_regex()");
				free(buf);
				free(rgxbuf);
				return false;
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
	const int errcode = regcomp(&regex->regex, rgxbuf, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if(errcode != 0)
	{
		// Get error string and log it
		(void) regerror (errcode, &regex->regex, regex_msg, sizeof(regex_msg));
		*message = strdup(regex_msg);
		regex->available = false;
		free(rgxbuf);
		return false;
	}

	// Store compiled regex string in buffer
	regex->string = strdup(regexin);
	regex->available = true;

	free(rgxbuf);
	return true;
}

static int match_regex(const char *input, DNSCacheData* dns_cache, const int clientID,
                       const enum regex_type regexid, const bool regextest, cJSON *json)
{
	int match_idx = -1;
#ifdef USE_TRE_REGEX
	regmatch_t match[1] = {{ 0 }}; // This also disables any sub-matching
#endif

	// Check if we need to recompile regex because they were changed in
	// another fork. If this is the case, reload everything (regex
	// themselves as well as per-client enabled/disabled state)
	if(regex_change != counters->regex_change)
	{
		log_info("Reloading externally changed regular expressions");
		read_regex_from_database();
	}

	// Loop over all configured regex filters of this type
	for(unsigned int index = 0; index < num_regex[regexid]; index++)
	{
		regexData *regex = &get_regex_ptr(regexid)[index];
		// Only check regex which have been successfully compiled ...
		if(!regex->available)
		{
			log_debug(DEBUG_REGEX, "Regex %s (%u, DB ID %d) is NOT AVAILABLE (compilation error)",
			          regextype[regexid], index, regex->database_id);
			continue;
		}
		// ... and are enabled for this client
		int regexID = index;
		if(regexid == REGEX_ALLOW)
			regexID += num_regex[REGEX_DENY];
		else if(regexid == REGEX_CLI)
			regexID += num_regex[REGEX_DENY] +
			           num_regex[REGEX_ALLOW];

		// Only use regular expressions enabled for this client
		// We allow clientID = -1 to get all regex (for testing)
		if(clientID >= 0 && !get_per_client_regex(clientID, regexID))
		{
			if(config.debug.regex.v.b)
			{
				clientsData* client = getClient(clientID, true);
				if(client != NULL)
				{
					log_debug(DEBUG_REGEX, "Regex %s (%u, DB ID %d) \"%s\" NOT ENABLED for client %s",
					          regextype[regexid], index, regex->database_id,
					          regex->string, getstr(client->ippos));
				}
			}
			continue;
		}

		// Try to match the compiled regular expression against input
#ifdef USE_TRE_REGEX
		int retval = tre_regexec(&regex->regex, input, 0, match, 0);
#else
		int retval = regexec(&regex->regex, input, 0, NULL, 0);
#endif
		// regexec() returns REG_OK for a successful match or REG_NOMATCH for failure.
		if ((retval == REG_OK && !regex->ext.inverted) ||
		    (retval == REG_NOMATCH && regex->ext.inverted))
		{
			// Check possible additional regex settings
			if(dns_cache != NULL)
			{
				// Check query type filtering
				if(regex->ext.query_type != 0)
				{
					if(!(regex->ext.query_type & (1 << dns_cache->query_type)))
					{
						log_debug(DEBUG_REGEX, "Regex %s (%u, DB ID %i) NO match: \"%s\" vs. \"%s\""
						                       " (skipped because of query type mismatch)",
						          regextype[regexid], index, regex->database_id,
						          input, regex->string);
						continue;
					}
				}
				// Set special reply type if configured for this regex
				if(regex->ext.reply != REPLY_UNKNOWN)
					dns_cache->force_reply = regex->ext.reply;

				// Set CNAME target if configured for this regex
				if(regex->ext.cname_target != NULL)
					dns_cache->cname_target = regex->ext.cname_target;
			}

			// Match, return true
			match_idx = regex->database_id;

			// Print match message when in regex debug mode
			log_debug(DEBUG_REGEX, "Regex %s (%u, DB ID %i) >> MATCH: \"%s\" vs. \"%s\"",
			          regextype[regexid], index, regex->database_id,
			          input, regex->string);

			if(regextest)
			{
				if(regexid == REGEX_CLI)
				{
					// CLI provided regular expression
					log_info("    %s%s%s matches",
					cli_bold(), regex->string, cli_normal());
				}
				else if(regexid == REGEX_DENY)
				{
					// Database-sourced regular expression
					log_info("    %s%s%s matches (regex blacklist, DB ID %i)",
					cli_bold(), regex->string, cli_normal(),
					regex->database_id);
				}
				else if(regexid == REGEX_ALLOW)
				{
					// Database-sourced regular expression
					log_info("    %s%s%s matches (regex whitelist, DB ID %i)",
					cli_bold(), regex->string, cli_normal(),
					regex->database_id);
				}

				// Check query type filtering
				if(regex->ext.query_type != 0)
				{
					log_info("    Hint: This regex matches only specific query types:");
					for(enum query_type type = TYPE_A; type < TYPE_MAX; type++)
					{
						if(regex->ext.query_type & (1 << type))
						{
							const char *qtype = get_query_type_str(type, NULL, NULL);
							log_info("      - %s", qtype);
						}
					}
				}

				// Check inversion
				if(regex->ext.inverted)
				{
					log_info("    Hint: This regex is inverted");
				}

				// Check special reply type
				if(regex->ext.reply != REPLY_UNKNOWN)
				{
					const char *replystr = get_query_reply_str(regex->ext.reply);
					log_info("    Hint: This regex forces reply type %s", replystr);
				}

			}
			else if(json != NULL)
			{
				// Add match to JSON array
				cJSON_AddItemToArray(json, cJSON_CreateNumber(regex->database_id));
			}
			else
			{
				// Only check the first match when not in regex-test mode
				break;
			}
		}

		// Print no match message when in regex debug mode
		if(match_idx == -1)
		{
			log_debug(DEBUG_REGEX, "Regex %s (FTL %u, DB %i) NO match: \"%s\" (input) vs. \"%s\" (regex)",
			          regextype[regexid], index, regex->database_id, input, regex->string);
		}
	}

	// Return match_idx (-1 if there was no match)
	return match_idx;
}

bool in_regex(const char *domain, DNSCacheData *dns_cache, const int clientID, const enum regex_type regexid)
{
	// For performance reasons, the regex evaluations is executed only if the
	// exact whitelist lookup does not deliver a positive match. This is an
	// optimization as the database lookup will most likely hit (a) more domains
	// and (b) will be faster (given a sufficiently large number of regex
	// whitelisting filters).
	const int regex_id = match_regex(domain, dns_cache, clientID, regexid, false, NULL);
	if(regex_id != -1)
	{
		// We found a match
		dns_cache->list_id = regex_id;
		return true;
	}

	return false;
}

// Resolve CNAME targets for regex entries
void resolve_regex_cnames(void)
{
	// Loop over all regex types
	for(enum regex_type regexid = REGEX_DENY; regexid < REGEX_MAX; regexid++)
	{
		// Get pointer to regex data
		regexData *regex = get_regex_ptr(regexid);

		// Skip if no regex of this type are available
		if(regex == NULL)
			continue;

		// Loop over entries with this regex type
		for(unsigned int index = 0; index < num_regex[regexid]; index++)
		{
			if(!regex[index].available)
				continue;

			// Check if this regex has a CNAME target
			if(regex[index].ext.cname_target == NULL)
				continue;

			log_debug(DEBUG_REGEX, "Resolving CNAME target \"%s\" for regex filter %i",
			          regex[index].ext.cname_target, regex[index].database_id);

			// Prepare hints for getaddrinfo()
			struct addrinfo hints;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;

			// Resolve CNAME target to IPv4 address using getaddrinfo()
			struct addrinfo *result;
			if(getaddrinfo(regex[index].ext.cname_target, NULL, &hints, &result) == 0 && result->ai_family == AF_INET)
			{
				regex[index].ext.custom_ip4 = true;
				struct sockaddr_in *addr_in = (void *)result->ai_addr;
				memcpy(&regex[index].ext.addr4, &addr_in->sin_addr, sizeof(regex[index].ext.addr4));
				char buffer[INET_ADDRSTRLEN];
				log_debug(DEBUG_REGEX, "Resolved CNAME target \"%s\" to IPv4 address %s for regex filter %i",
				          regex[index].ext.cname_target, inet_ntop(AF_INET, &regex[index].ext.addr4, buffer, INET_ADDRSTRLEN), regex[index].database_id);
			}

			// Free result
			freeaddrinfo(result);

			// Prepare hints for getaddrinfo()
			hints.ai_family = AF_INET6;

			// Resolve CNAME target to IPv6 address using getaddrinfo()
			if(getaddrinfo(regex[index].ext.cname_target, NULL, &hints, &result) == 0 && result->ai_family == AF_INET6)
			{
				regex[index].ext.custom_ip6 = true;
				struct sockaddr_in6 *addr_in = (void *)(result->ai_addr);
				memcpy(&regex[index].ext.addr6, &addr_in->sin6_addr, sizeof(regex[index].ext.addr6));
				char buffer[INET6_ADDRSTRLEN];
				log_debug(DEBUG_REGEX, "Resolved CNAME target \"%s\" to IPv6 address %s for regex filter %i",
				          regex[index].ext.cname_target, inet_ntop(AF_INET6, &regex[index].ext.addr6, buffer, INET6_ADDRSTRLEN), regex[index].database_id);
			}

			// Free result
			freeaddrinfo(result);
		}
	}
}

void free_regex(void)
{
	// Return early if we don't use any regex filters
	if(allow_regex == NULL &&
	    deny_regex == NULL &&
	     cli_regex == NULL)
	{
		log_debug(DEBUG_DATABASE, "Not using any regex filters, nothing to free or reset");
		return;
	}

	// Reset client configuration
	log_debug(DEBUG_DATABASE, "Resetting per-client regex settings");
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		reset_per_client_regex(clientID);
	}

	// Free regex datastructure
	// Loop over regex types
	for(enum regex_type regexid = REGEX_DENY; regexid < REGEX_MAX; regexid++)
	{
		regexData *regex = get_regex_ptr(regexid);

		// Reset counter for number of regex
		const unsigned int oldcount = num_regex[regexid];
		num_regex[regexid] = 0;

		// Exit early if the regex has already been freed (or has never been used)
		if(regex == NULL)
			continue;

		log_debug(DEBUG_DATABASE, "Going to free %u entries in %s regex struct",
		          oldcount, regextype[regexid]);

		// Loop over entries with this regex type
		for(unsigned int index = 0; index < oldcount; index++)
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

			// Also free buffered CNAME target (if any)
			if(regex[index].ext.cname_target != NULL)
			{
				free(regex[index].ext.cname_target);
				regex[index].ext.cname_target = NULL;
			}
		}

		log_debug(DEBUG_DATABASE, "Loop done, freeing regex pointer (%p)", regex);

		// Free array with regex datastructure
		free_regex_ptr(regexid);
	}
}

// This function does three things:
//   1. Allocate additional memory if required
//   2. Reset all regex to false for this client
//   3. Load regex enabled/disabled state
void reload_per_client_regex(clientsData *client)
{
	// Ensure there is enough memory in the shared memory object
	add_per_client_regex(client->id);

	// Zero-initialize (or wipe previous) regex
	reset_per_client_regex(client->id);

	// Load regex per-group deny regex for this client
	if(num_regex[REGEX_DENY] > 0)
		gravityDB_get_regex_client_groups(client, num_regex[REGEX_DENY],
		                                  deny_regex, REGEX_DENY,
		                                  "vw_regex_blacklist");

	// Load regex per-group allow regex for this client
	if(num_regex[REGEX_ALLOW] > 0)
		gravityDB_get_regex_client_groups(client, num_regex[REGEX_ALLOW],
		                                  allow_regex, REGEX_ALLOW,
		                                  "vw_regex_whitelist");
}

static void read_regex_table(const enum regex_type regexid)
{
	// Get table ID
	const enum gravity_tables tableID = (regexid == REGEX_DENY) ? REGEX_DENY_TABLE : REGEX_ALLOW_TABLE;

	log_debug(DEBUG_DATABASE, "Reading regex %s from database", regextype[regexid]);

	// Get number of lines in the regex table
	num_regex[regexid] = 0;
	int count = gravityDB_count(tableID);

	if(count == 0)
	{
		return;
	}
	else if(count < 0)
	{
		log_warn("Database query failed, assuming there are no %s regex entries", regextype[regexid]);
		return;
	}

	// Allocate memory for regex
	regexData *regex = NULL;
	if(regexid == REGEX_DENY)
	{
		deny_regex = calloc(count, sizeof(regexData));
		regex = deny_regex;
	}
	else
	{
		allow_regex = calloc(count, sizeof(regexData));
		regex = allow_regex;
	}

	// Connect to regex table
	if(!gravityDB_getTable(tableID))
	{
		log_warn("read_regex_from_database(): Error getting %s regex table from database",
		         regextype[regexid]);
		return;
	}

	// Walk database table
	const char *regex_string = NULL;
	int rowid = 0;
	while((regex_string = gravityDB_getDomain(&rowid)) != NULL)
	{
		// Avoid buffer overflow if database table changed
		// since we counted its entries
		if(num_regex[regexid] >= (unsigned int)count)
		{
			log_warn("read_regex_table(%s) exiting early to avoid overflow (%u/%d).",
			         regextype[regexid], num_regex[regexid], count);
			break;
		}

		// Skip this entry if empty: an empty regex filter would match
		// anything anywhere and hence match all incoming regex_strings. A user
		// can still achieve this with a filter such as ".*", however empty
		// filters in the regex table are probably not expected to have such
		// an effect and would immediately lead to "blocking or allowing
		// the entire Internet"
		if(strlen(regex_string) < 1)
			continue;

		// Debug logging
		log_debug(DEBUG_REGEX, "Compiling %s regex %u (DB ID %i): %s",
		          regextype[regexid], num_regex[regexid], rowid, regex_string);

		const int index = num_regex[regexid]++;
		char *message = NULL;

		// Compile this regex
		if(!compile_regex(regex_string, &regex[index], &message) && message != NULL)
		{
			logg_regex_warning(regextype[regexid], message,
			                   regex->database_id, regex_string);
			free(message);
		}

		// Store database ID
		regex[num_regex[regexid]-1].database_id = rowid;

		// Signal other forks that the regex data has changed and should be updated
		regex_change = ++counters->regex_change;
	}

	// Finalize statement and close gravity database handle
	gravityDB_finalizeTable();

	// Debug logging
	log_debug(DEBUG_DATABASE, "Read %u %s regex entries",
	          num_regex[regexid],
	          regextype[regexid]);
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
	read_regex_table(REGEX_DENY);

	// Read and compile regex whitelist
	read_regex_table(REGEX_ALLOW);

	// Loop over all clients and ensure we have enough space and load
	// per-client regex data, not all of the regex read and compiled above
	// will also be used by all clients
	log_debug(DEBUG_DATABASE, "Loading per-client regex data");
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		clientsData *client = getClient(clientID, true);
		// Skip invalid and alias-clients
		if(client == NULL || client->flags.aliasclient)
			continue;

		reload_per_client_regex(client);
	}

	// Print message to FTL's log after reloading regex filters
	log_info("Compiled %u allow and %u deny regex for %i client%s in %.1f msec",
	         num_regex[REGEX_ALLOW], num_regex[REGEX_DENY],
	         counters->clients, counters->clients > 1 ? "s" : "",
	         timer_elapsed_msec(REGEX_TIMER));
}

int regex_test(const bool debug_mode, const bool quiet, const char *domainin, const char *regexin)
{
	// Prepare counters and regex memories
	counters = calloc(1, sizeof(countersStruct));
	// Disable terminal output during config config file parsing
	log_ctrl(false, false);

	// Process pihole-FTL.conf to get gravity.db path
	// Do not overwrite the file after reading it
	readFTLconf(&config, false);

	// Disable all debugging output if not explicitly in debug mode (CLI argument "d")
	if(!debug_mode)
		clear_debug_flags(); // No debug printing wanted
	// Re-enable terminal output
	log_ctrl(false, !quiet);

	int matchidx = -1;
	if(regexin == NULL)
	{
		// Read and compile regex lists from database
		log_info("%s Loading regex filters from database...", cli_info());
		timer_start(REGEX_TIMER);
		log_ctrl(false, true); // Temporarily re-enable terminal output for error logging
		read_regex_table(REGEX_DENY);
		read_regex_table(REGEX_ALLOW);
		log_ctrl(false, !quiet); // Re-apply quiet option after compilation
		log_info("    Compiled %u deny and %u allow regex in %.3f msec\n",
		     num_regex[REGEX_DENY], num_regex[REGEX_ALLOW],
		     timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against all loaded regular deny expressions
		log_info("%s Checking domain against deny regex...", cli_info());
		timer_start(REGEX_TIMER);
		int matchidx1 = match_regex(domainin, NULL, -1, REGEX_DENY, true, NULL);
		log_info("    Time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against all loaded regular allow expressions
		log_info("%s Checking domain against allow regex...", cli_info());
		timer_start(REGEX_TIMER);
		int matchidx2 = match_regex(domainin, NULL, -1, REGEX_ALLOW, true, NULL);
		log_info("    Time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
		matchidx = MAX(matchidx1, matchidx2);

	}
	else
	{
		// Compile CLI regex
		log_info("%s Compiling regex filter...", cli_info());
		regexData regex = { 0 };
		cli_regex = &regex;
		num_regex[REGEX_CLI] = 1;

		// Compile CLI regex
		timer_start(REGEX_TIMER);
		log_ctrl(false, true); // Temporarily re-enable terminal output for error logging
		char *message = NULL;
		if(!compile_regex(regexin, &regex, &message) && message != NULL)
		{
			logg_regex_warning("CLI", message, 0, regexin);
			free(message);
			return 1;
		}
		log_ctrl(false, !quiet); // Re-apply quiet option after compilation
		log_info("    Compiled regex filter in %.3f msec\n", timer_elapsed_msec(REGEX_TIMER));

		// Check user-provided domain against user-provided regular expression
		log_info("Checking domain \"%s\"...", domainin);
		timer_start(REGEX_TIMER);
		matchidx = match_regex(domainin, NULL, -1, REGEX_CLI, true, NULL);
		if(matchidx == -1)
			log_info("    NO MATCH!");
		log_info("   Time: %.3f msec", timer_elapsed_msec(REGEX_TIMER));
	}

	// Return status 0 = MATCH, 1 = ERROR, 2 = NO MATCH
	return matchidx > -1 ? EXIT_SUCCESS : 2;
}

bool check_all_regex(const char *domainin, cJSON *json)
{
	// Check user-provided domain against all loaded regular expressions
	// (deny, allow, and CLI regex)
	cJSON *deny = cJSON_CreateArray();
	int matchidx1 = match_regex(domainin, NULL, -1, REGEX_DENY, false, deny);
	cJSON *allow = cJSON_CreateArray();
	int matchidx2 = match_regex(domainin, NULL, -1, REGEX_ALLOW, false, allow);
	int matchidx = MAX(matchidx1, matchidx2);

	// Add deny and allow regex matches to JSON object
	cJSON_AddItemToObject(json, "deny", deny);
	cJSON_AddItemToObject(json, "allow", allow);

	// Return true if domain matches any regular expression
	return matchidx > -1;
}

// Get internal ID of regex with this database ID
static int __attribute__ ((pure)) regex_id_from_database_id(const int dbID)
{
	// Get number of defined regular expressions
	unsigned int sum_regex = 0;
	for(unsigned int i = 0; i < REGEX_MAX; i++)
		sum_regex += num_regex[i];

	// Find internal ID of regular expression with this database ID
	for(unsigned int i = 0; i < sum_regex; i++)
	{
		regexData *regex = get_regex_ptr_from_id(i);
		if(regex == NULL)
			continue;
		if(regex->database_id == dbID)
			return i;
	}

	return -1;
}

// Return redirection addresses for a given blacklist regex (if specified)
bool regex_get_redirect(const int dbID, struct in_addr *addr4, struct in6_addr *addr6)
{
	// Check dbID for validity, return early if negative
	if(dbID < 0)
		return false;

	// Get internal regex ID from database regex ID
	const int regexID = regex_id_from_database_id(dbID);

	log_debug(DEBUG_REGEX, "Regex: %d (database) -> %d (internal)", dbID, regexID);

	// Check internal regex ID for validity, return early if negative
	if(regexID < 0)
		return false;

	// Get regex from regexID
	regexData *regex = get_regex_ptr_from_id(regexID);
	if(regex == NULL)
		return false;

	bool custom_addr = false;
	// Check for IPv4 redirect
	if(regex->ext.custom_ip4 && addr4 != NULL)
	{
		memcpy(addr4, &(regex->ext.addr4), sizeof(*addr4));
		custom_addr = true;
	}

	// Check for IPv6 redirect
	if(regex->ext.custom_ip6 && addr6 != NULL)
	{
		memcpy(addr6, &(regex->ext.addr6), sizeof(*addr6));
		custom_addr = true;
	}

	return custom_addr;
}
