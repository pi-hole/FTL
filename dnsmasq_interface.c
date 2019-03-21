/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "dnsmasq_interface.h"
#include "shmem.h"
// Prototype of getCacheInformation()
#include "api.h"

void print_flags(unsigned int flags);
void save_reply_type(unsigned int flags, int queryID, struct timeval response);
static unsigned long converttimeval(struct timeval time) __attribute__((const));
static void block_single_domain_regex(char *domain);
static void detect_blocked_IP(unsigned short flags, const char* answer, int queryID);
static void query_externally_blocked(int i, unsigned char status);
static int findQueryID(int id);

unsigned char* pihole_privacylevel = &config.privacylevel;
char flagnames[28][12] = {"F_IMMORTAL ", "F_NAMEP ", "F_REVERSE ", "F_FORWARD ", "F_DHCP ", "F_NEG ", "F_HOSTS ", "F_IPV4 ", "F_IPV6 ", "F_BIGNAME ", "F_NXDOMAIN ", "F_CNAME ", "F_DNSKEY ", "F_CONFIG ", "F_DS ", "F_DNSSECOK ", "F_UPSTREAM ", "F_RRNAME ", "F_SERVER ", "F_QUERY ", "F_NOERR ", "F_AUTH ", "F_DNSSEC ", "F_KEYTAG ", "F_SECSTAT ", "F_NO_RR ", "F_IPSET ", "F_NOEXTRA "};

void _FTL_new_query(unsigned int flags, char *name, struct all_addr *addr, char *types, int id, char type, const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Create new query in data structure
	lock_shm();

	// Get timestamp
	time_t querytimestamp = time(NULL);

	// Save request time
	struct timeval request;
	gettimeofday(&request, 0);

	// Determine query type
	unsigned char querytype = 0;
	if(strcmp(types,"query[A]") == 0)
		querytype = TYPE_A;
	else if(strcmp(types,"query[AAAA]") == 0)
		querytype = TYPE_AAAA;
	else if(strcmp(types,"query[ANY]") == 0)
		querytype = TYPE_ANY;
	else if(strcmp(types,"query[SRV]") == 0)
		querytype = TYPE_SRV;
	else if(strcmp(types,"query[SOA]") == 0)
		querytype = TYPE_SOA;
	else if(strcmp(types,"query[PTR]") == 0)
		querytype = TYPE_PTR;
	else if(strcmp(types,"query[TXT]") == 0)
		querytype = TYPE_TXT;
	else
	{
		// Return early to avoid accessing querytypedata out of bounds
		if(config.debug & DEBUG_QUERIES) logg("Notice: Skipping unknown query type: %s (%i)", types, id);
		unlock_shm();
		return;
	}

	// Skip AAAA queries if user doesn't want to have them analyzed
	if(!config.analyze_AAAA && querytype == TYPE_AAAA)
	{
		if(config.debug & DEBUG_QUERIES) logg("Not analyzing AAAA query");
		unlock_shm();
		return;
	}

	// Ensure we have enough space in the queries struct
	memory_check(QUERIES);
	int queryID = counters->queries;

	// Convert domain to lower case
	char *domain = strdup(name);
	strtolower(domain);

	// If domain is "pi.hole" we skip this query
	if(strcmp(domain, "pi.hole") == 0)
	{
		// free memory already allocated here
		free(domain);
		unlock_shm();
		return;
	}

	// Store plain text domain in buffer for regex validation
	char *domainbuffer = strdup(domain);

	// Get client IP address
	char dest[ADDRSTRLEN];
	inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	char *client = strdup(dest);
	strtolower(client);

	// Check if user wants to skip queries coming from localhost
	if(config.ignore_localhost &&
	   (strcmp(client, "127.0.0.1") == 0 || strcmp(client, "::1") == 0))
	{
		free(domain);
		free(client);
		unlock_shm();
		return;
	}

	// Log new query if in debug mode
	const char *proto = (type == UDP) ? "UDP" : "TCP";
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** new %s %s \"%s\" from %s (ID %i, FTL %i, %s:%i)",
		     proto, types, domain, client, id, queryID, file, line);
	}

	// Update counters
	counters->querytype[querytype-1]++;

	// Update overTime
	unsigned int timeidx = getOverTimeID(querytimestamp);
	overTime[timeidx].querytypedata[querytype-1]++;

	// Skip rest of the analysis if this query is not of type A or AAAA
	// but user wants to see only A and AAAA queries (pre-v4.1 behavior)
	if(config.analyze_only_A_AAAA && querytype != TYPE_A && querytype != TYPE_AAAA)
	{
		// Don't process this query further here, we already counted it
		if(config.debug & DEBUG_QUERIES) logg("Notice: Skipping new query: %s (%i)", types, id);
		free(domain);
		free(domainbuffer);
		free(client);
		unlock_shm();
		return;
	}

	// Go through already knows domains and see if it is one of them
	int domainID = findDomainID(domain);

	// Go through already knows clients and see if it is one of them
	int clientID = findClientID(client, true);

	// Save everything
	validate_access("queries", queryID, false, __LINE__, __FUNCTION__, __FILE__);
	queries[queryID].magic = MAGICBYTE;
	queries[queryID].timestamp = querytimestamp;
	queries[queryID].type = querytype;
	queries[queryID].status = QUERY_UNKNOWN;
	queries[queryID].domainID = domainID;
	queries[queryID].clientID = clientID;
	queries[queryID].timeidx = timeidx;
	// Initialize database rowID with zero, will be set when the query is stored in the long-term DB
	queries[queryID].db = 0;
	queries[queryID].id = id;
	queries[queryID].complete = false;
	queries[queryID].response = converttimeval(request);
	// Initialize reply type
	queries[queryID].reply = REPLY_UNKNOWN;
	// Store DNSSEC result for this domain
	queries[queryID].dnssec = DNSSEC_UNSPECIFIED;

	// Check and apply possible privacy level rules
	// The currently set privacy level (at the time the query is
	// generated) is stored in the queries structure
	get_privacy_level(NULL);
	queries[queryID].privacylevel = config.privacylevel;

	// Increase DNS queries counter
	counters->queries++;
	// Count this query as unknown as long as no reply has
	// been found and analyzed
	counters->unknown++;

	// Update overTime data
	overTime[timeidx].total++;
	// Update overTime data structure with the new client
	clients[clientID].overTime[timeidx]++;

	// Set lastQuery timer and add one query for network table
	clients[clientID].lastQuery = querytimestamp;
	clients[clientID].numQueriesARP++;

	// Try blocking regex if configured
	validate_access("domains", domainID, false, __LINE__, __FUNCTION__, __FILE__);
	if(domains[domainID].regexmatch == REGEX_UNKNOWN && blockingstatus != BLOCKING_DISABLED)
	{
		// For minimal performance impact, we test the regex only when
		// - regex checking is enabled, and
		// - this domain has not already been validated against the regex.
		// This effectively prevents multiple evaluations of the same domain
		//
		// If a regex filter matched, we additionally compare the domain
		// against all known whitelisted domains to possibly prevent blocking
		// of a specific domain. The logic herein is:
		// If matched, then compare against whitelist
		// If in whitelist, negate matched so this function returns: not-to-be-blocked
		if(match_regex(domainbuffer) && !in_whitelist(domainbuffer))
		{
			// We have to block this domain
			block_single_domain_regex(domainbuffer);
			domains[domainID].regexmatch = REGEX_BLOCKED;
		}
		else
		{
			// Explicitly mark as not blocked to skip regex test
			// next time we see this domain
			domains[domainID].regexmatch = REGEX_NOTBLOCKED;
		}
	}

	// Free allocated memory
	free(client);
	free(domain);
	free(domainbuffer);

	// Release thread lock
	unlock_shm();
}

static int findQueryID(int id)
{
	// Loop over all queries - we loop in reverse order (start from the most recent query and
	// continuously walk older queries while trying to find a match. Ideally, we should always
	// find the correct query with zero iterations, but it may happen that queries are processed
	// asynchronously, e.g. for slow upstream relies to a huge amount of requests.
	// We iterate from the most recent query down to at most MAXITER queries in the past to avoid
	// iterating through the entire array of queries
	// MAX(0, a) is used to return 0 in case a is negative (negative array indices are harmful)

	// Validate access only once for the maximum index (all lower will work)
	int until = MAX(0, counters->queries-MAXITER);
	int start = MAX(0, counters->queries-1);
	validate_access("queries", until, false, __LINE__, __FUNCTION__, __FILE__);

	// Check UUIDs of queries
	for(int i = start; i >= until; i--)
		if(queries[i].id == id)
			return i;

	// If not found
	return -1;
}

void _FTL_forwarded(unsigned int flags, char *name, struct all_addr *addr, int id, const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Save that this query got forwarded to an upstream server
	lock_shm();

	// Get forward destination IP address
	char dest[ADDRSTRLEN];
	// If addr == NULL, we will only duplicate an empty string instead of uninitialized memory
	dest[0] = '\0';
	if(addr != NULL)
		inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	// Convert forward to lower case
	char *forward = strdup(dest);
	strtolower(forward);

	// Debug logging
	if(config.debug & DEBUG_QUERIES) logg("**** forwarded %s to %s (ID %i, %s:%i)", name, forward, id, file, line);

	// Save status and forwardID in corresponding query identified by dnsmasq's ID
	int i = findQueryID(id);
	if(i < 0)
	{
		// This may happen e.g. if the original query was a PTR query or "pi.hole"
		// as we ignore them altogether
		free(forward);
		unlock_shm();
		return;
	}

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destinations are coming in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	if(queries[i].complete && queries[i].status != QUERY_CACHE)
	{
		free(forward);
		unlock_shm();
		return;
	}

	// Get ID of forward destination, create new forward destination record
	// if not found in current data structure
	int forwardID = findForwardID(forward, true);
	queries[i].forwardID = forwardID;

	unsigned int timeidx = queries[i].timeidx;

	if(queries[i].status == QUERY_CACHE)
	{
		// Detect if we cached the <CNAME> but need to ask the upstream
		// servers for the actual IPs now, we remove this query from the
		// counters for cache replied queries as we had to forward a
		// request for it. Example:
		// Assume a domain a.com is a CNAME which is cached and has a very
		// long TTL. It point to another domain server.a.com which has an
		// A record but this has a much lower TTL.
		// If you now query a.com and then again after some time, you end
		// up in a situation where dnsmasq can answer the first level of
		// the DNS result (the CNAME) from cache, hence the status of this
		// query is marked as "answered from cache" in FTLDNS. However, for
		// server.a.com wit the much shorter TTL, we still have to forward
		// something and ask the upstream server for the final IP address.
		// This code section acknowledges this by removing one entry from
		// the cached counters as we will re-brand this query as having been
		// forwarded in the following.
		counters->cached--;
		// Also correct overTime data
		overTime[timeidx].cached--;

		// Correct reply timer
		struct timeval response;
		gettimeofday(&response, 0);
		// Reset timer, shift slightly into the past to acknowledge the time
		// FTLDNS needed to look up the CNAME in its cache
		queries[i].response = converttimeval(response) - queries[i].response;
	}
	else
	{
		// Normal forwarded query (status is set below)
		// Query is no longer unknown
		counters->unknown--;
		// Hereby, this query is now fully determined
		queries[i].complete = true;
	}

	// Set query status to forwarded only after the
	// if(queries[i].status == QUERY_CACHE) { ... }
	// from above as otherwise this check will always
	// be negative
	queries[i].status = QUERY_FORWARDED;

	// Update overTime data
	overTime[timeidx].forwarded++;

	// Update counter for forwarded queries
	counters->forwardedqueries++;

	// Release allocated memory
	free(forward);
	unlock_shm();
}

void FTL_dnsmasq_reload(void)
{
	// This function is called by the dnsmasq code on receive of SIGHUP
	// *before* clearing the cache and rereading the lists
	// This is the only hook that is not skipped in PRIVACY_NOSTATS mode

	logg("Received SIGHUP, reloading cache");

	// Called when dnsmasq re-reads its config and hosts files
	// Reset number of blocked domains
	counters->gravity = 0;

	// Inspect 01-pihole.conf to see if Pi-hole blocking is enabled,
	// i.e. if /etc/pihole/gravity.list is sourced as addn-hosts file
	check_blocking_status();

	// Reread pihole-FTL.conf to see which blocking mode the user wants to use
	// It is possible to change the blocking mode here as we anyhow clear the
	// cache and reread all blocking lists
	// Passing NULL to this function means it has to open the config file on
	// its own behalf (on initial reading, the config file is already opened)
	get_blocking_mode(NULL);

	// Reread regex.list
	free_regex();
	read_regex_from_file();

	// Reread pihole-FTL.conf to see which debugging flags are set
	read_debuging_settings(NULL);

	// Print current set of capabilities if requested via debug flag
	if(config.debug & DEBUG_CAPS)
		check_capabilities();
}

void _FTL_reply(unsigned short flags, char *name, struct all_addr *addr, int id, const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Interpret hosts files that have been read by dnsmasq
	lock_shm();
	// Determine returned result if available
	char dest[ADDRSTRLEN]; dest[0] = '\0';
	if(addr)
	{
		inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	}

	// Extract answer (used e.g. for detecting if a local config is a user-defined
	// wildcard blocking entry in form "server=/tobeblocked.com/")
	const char *answer = dest;
	if(flags & F_CNAME)
		answer = "(CNAME)";
	else if((flags & F_NEG) && (flags & F_NXDOMAIN))
		answer = "(NXDOMAIN)";
	else if(flags & F_NEG)
		answer = "(NODATA)";

	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** got reply %s is %s (ID %i, %s:%i)", name, answer, id, file, line);
		print_flags(flags);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Save status in corresponding query identified by dnsmasq's ID
	int i = findQueryID(id);
	if(i < 0)
	{
		// This may happen e.g. if the original query was "pi.hole"
		if(config.debug & DEBUG_QUERIES) logg("FTL_reply(): Query %i has not been found", id);
		unlock_shm();
		return;
	}

	if(queries[i].reply != REPLY_UNKNOWN)
	{
		// Nothing to be done here
		unlock_shm();
		return;
	}

	// Determine if this reply is an exact match for the queried domain
	int domainID = queries[i].domainID;
	validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
	bool isExactMatch = (name != NULL && strcmp(getstr(domains[domainID].domainpos), name) == 0);

	if((flags & F_CONFIG) && isExactMatch && !queries[i].complete)
	{
		// Answered from local configuration, might be a wildcard or user-provided
		// This query is no longer unknown
		counters->unknown--;

		// Get time index
		unsigned int timeidx = queries[i].timeidx;

		if(strcmp(answer, "(NXDOMAIN)") == 0 ||
		   strcmp(answer, "0.0.0.0") == 0 ||
		   strcmp(answer, "::") == 0)
		{
			// Answered from user-defined blocking rules (dnsmasq config files)
			counters->blocked++;
			overTime[timeidx].blocked++;

			validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
			domains[queries[i].domainID].blockedcount++;

			validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);
			clients[queries[i].clientID].blockedcount++;

			queries[i].status = QUERY_WILDCARD;
		}
		else
		{
			// Answered from a custom (user provided) cache file
			counters->cached++;
			overTime[timeidx].cached++;

			queries[i].status = QUERY_CACHE;
		}

		// Save reply type and update individual reply counters
		save_reply_type(flags, i, response);

		// Hereby, this query is now fully determined
		queries[i].complete = true;
	}
	else if((flags & F_FORWARD) && isExactMatch)
	{
		// Only proceed if query is not already known
		// to have been blocked by Quad9
		if(queries[i].reply != QUERY_EXTERNAL_BLOCKED_IP &&
		   queries[i].reply != QUERY_EXTERNAL_BLOCKED_NULL &&
		   queries[i].reply != QUERY_EXTERNAL_BLOCKED_NXRA)
		{
			// Save reply type and update individual reply counters
			save_reply_type(flags, i, response);

			// Detect if returned IP indicates that this query was blocked
			detect_blocked_IP(flags, answer, i);
		}
	}
	else if(flags & F_REVERSE)
	{
		// isExactMatch is not used here as the PTR is special.
		// Example:
		// Question: PTR 8.8.8.8
		// will lead to:
		//   domains[domainID].domain = 8.8.8.8.in-addr.arpa
		// and will return
		//   name = google-public-dns-a.google.com
		// Hence, isExactMatch is always false

		// Save reply type and update individual reply counters
		save_reply_type(flags, i, response);
	}
	else if(isExactMatch && !queries[i].complete)
	{
		logg("*************************** unknown REPLY ***************************");
		print_flags(flags);
	}

	unlock_shm();
}

static void detect_blocked_IP(unsigned short flags, const char* answer, int queryID)
{
	if(flags & F_HOSTS)
	{
		// Skip replies which originated locally. Otherwise, we would
		// count gravity.list blocked queries as externally blocked.
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			logg("Skipping detection of external blocking IP for ID %i as origin is HOSTS", queryID);
		}
		return;
	}
	else if(flags & F_REVERSE)
	{
		// Do not mark responses of PTR requests as externally blocked.
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			logg("Skipping detection of external blocking IP for ID %i as query is PTR", queryID);
		}
		return;
	}

	// If received one of the following IPs as reply, OpenDNS
	// (Cisco Umbrella) blocked this query
	// See https://support.opendns.com/hc/en-us/articles/227986927-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses-
	// for a full list of these IP addresses
	if(flags & F_IPV4 && answer != NULL &&
		(strcmp("146.112.61.104", answer) == 0 ||
		 strcmp("146.112.61.105", answer) == 0 ||
		 strcmp("146.112.61.106", answer) == 0 ||
		 strcmp("146.112.61.107", answer) == 0 ||
		 strcmp("146.112.61.108", answer) == 0 ||
		 strcmp("146.112.61.109", answer) == 0 ||
		 strcmp("146.112.61.110", answer) == 0 ))
	{
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			logg("Upstream responded with known blocking page (IPv4), ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domains[queryID].domainpos), answer);
		}

		// Update status
		query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_IP);
	}

	else if(flags & F_IPV6 && answer != NULL &&
		(strcmp("::ffff:146.112.61.104", answer) == 0 ||
		 strcmp("::ffff:146.112.61.105", answer) == 0 ||
		 strcmp("::ffff:146.112.61.106", answer) == 0 ||
		 strcmp("::ffff:146.112.61.107", answer) == 0 ||
		 strcmp("::ffff:146.112.61.108", answer) == 0 ||
		 strcmp("::ffff:146.112.61.109", answer) == 0 ||
		 strcmp("::ffff:146.112.61.110", answer) == 0 ))
	{
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			logg("Upstream responded with known blocking page (IPv6), ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domains[queryID].domainpos), answer);
		}

		// Update status
		query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_IP);
	}

	// If upstream replied with 0.0.0.0 or ::,
	// we assume that it filtered the reply as
	// nothing is reachable under these addresses
	else if(flags & F_IPV4 && answer != NULL &&
		strcmp("0.0.0.0", answer) == 0)
	{
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			logg("Upstream responded with 0.0.0.0, ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domains[queryID].domainpos), answer);
		}

		// Update status
		query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_NULL);
	}

	else if(flags & F_IPV6 && answer != NULL &&
		strcmp("::", answer) == 0)
	{
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			logg("Upstream responded with ::, ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domains[queryID].domainpos), answer);
		}

		// Update status
		query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_NULL);
	}
}

static void query_externally_blocked(int i, unsigned char status)
{
	// If query is already known to be externally blocked,
	// then we have nothing to do here
	if(queries[i].status == QUERY_EXTERNAL_BLOCKED_IP ||
	   queries[i].status == QUERY_EXTERNAL_BLOCKED_NULL ||
	   queries[i].status == QUERY_EXTERNAL_BLOCKED_NXRA)
		return;

	// Get time index of this query
	unsigned int timeidx = queries[i].timeidx;

	// Correct counters if necessary ...
	if(queries[i].status == QUERY_FORWARDED)
	{
		counters->forwardedqueries--;
		overTime[timeidx].forwarded--;
		validate_access("forwarded", queries[i].forwardID, true, __LINE__, __FUNCTION__, __FILE__);
		forwarded[queries[i].forwardID].count--;
	}
	// ... but as blocked
	counters->blocked++;
	overTime[timeidx].blocked++;
	validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
	domains[queries[i].domainID].blockedcount++;
	validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);
	clients[queries[i].clientID].blockedcount++;

	// Update status
	queries[i].status = status;
}

void _FTL_cache(unsigned int flags, char *name, struct all_addr *addr, char *arg, int id, const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Save that this query got answered from cache
	lock_shm();
	char dest[ADDRSTRLEN]; dest[0] = '\0';
	if(addr)
	{
		inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	}

	// Convert domain to lower case
	char *domain = strdup(name);
	strtolower(domain);

	// If domain is "pi.hole", we skip this query
	if(strcmp(domain, "pi.hole") == 0)
	{
		// free memory already allocated here
		free(domain);
		unlock_shm();
		return;
	}
	free(domain);

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** got cache answer for %s / %s / %s (ID %i, %s:%i)", name, dest, arg, id, file, line);
		print_flags(flags);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	if(((flags & F_HOSTS) && (flags & F_IMMORTAL)) ||
	   ((flags & F_NAMEP) && (flags & F_DHCP)) ||
	   (flags & F_FORWARD) ||
	   (flags & F_REVERSE) ||
	   (flags & F_RRNAME))
	{
		// List data: /etc/pihole/gravity.list, /etc/pihole/black.list, /etc/pihole/local.list, etc.
		// or
		// DHCP server reply
		// or
		// regex blocked query
		// or
		// cached answer to previously forwarded request

		// Determine requesttype
		unsigned char requesttype = 0;
		if(flags & F_HOSTS)
		{
			if(arg != NULL && strstr(arg, "/gravity.list") != NULL)
				requesttype = QUERY_GRAVITY;
			else if(arg != NULL && strstr(arg, "/black.list") != NULL)
				requesttype = QUERY_BLACKLIST;
			else // local.list, hostname.list, /etc/hosts and others
				requesttype = QUERY_CACHE;
		}
		else if((flags & F_NAMEP) && (flags & F_DHCP)) // DHCP server reply
			requesttype = QUERY_CACHE;
		else if(flags & F_FORWARD) // cached answer to previously forwarded request
			requesttype = QUERY_CACHE;
		else if(flags & F_REVERSE) // cached answer to reverse request (PTR)
			requesttype = QUERY_CACHE;
		else if(flags & F_RRNAME) // cached answer to TXT query
			requesttype = QUERY_CACHE;
		else
		{
			logg("*************************** unknown CACHE reply (1) ***************************");
			print_flags(flags);
		}

		int i = findQueryID(id);
		if(i < 0 || queries[i].complete)
		{
			// This may happen e.g. if the original query was a PTR query or "pi.hole"
			// as we ignore them altogether or if the query is already complete
			unlock_shm();
			return;
		}

		// This query is no longer unknown
		counters->unknown--;

		// Get time index
		unsigned int timeidx = queries[i].timeidx;

		int domainID = queries[i].domainID;
		validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);

		int clientID = queries[i].clientID;
		validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);

		// Mark this query as blocked if domain was matched by a regex
		if(domains[domainID].regexmatch == REGEX_BLOCKED)
			requesttype = QUERY_WILDCARD;

		queries[i].status = requesttype;

		// Detect if returned IP indicates that this query was blocked
		detect_blocked_IP(flags, dest, i);

		// Re-read requesttype as detect_blocked_IP() might have changed it
		requesttype = queries[i].status;

		// Handle counters accordingly
		switch(requesttype)
		{
			case QUERY_GRAVITY: // gravity.list
			case QUERY_BLACKLIST: // black.list
			case QUERY_WILDCARD: // regex blocked
				counters->blocked++;
				overTime[timeidx].blocked++;
				domains[domainID].blockedcount++;
				clients[clientID].blockedcount++;
				break;
			case QUERY_CACHE: // cached from one of the lists
				counters->cached++;
				overTime[timeidx].cached++;
				break;
			case QUERY_EXTERNAL_BLOCKED_IP:
			case QUERY_EXTERNAL_BLOCKED_NULL:
			case QUERY_EXTERNAL_BLOCKED_NXRA:
				// everything has already been done
				// in query_externally_blocked()
				break;
		}

		// Save reply type and update individual reply counters
		save_reply_type(flags, i, response);

		// Hereby, this query is now fully determined
		queries[i].complete = true;
	}
	else
	{
		logg("*************************** unknown CACHE reply (2) ***************************");
		print_flags(flags);
	}
	unlock_shm();
}

void _FTL_dnssec(int status, int id, const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Process DNSSEC result for a domain
	lock_shm();
	// Search for corresponding query identified by ID
	int i = findQueryID(id);
	if(i < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
	{
		int domainID = queries[i].domainID;
		validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
		logg("**** got DNSSEC details for %s: %i (ID %i, %s:%i)", getstr(domains[domainID].domainpos), status, id, file, line);
	}

	// Iterate through possible values
	if(status == STAT_SECURE)
		queries[i].dnssec = DNSSEC_SECURE;
	else if(status == STAT_INSECURE)
		queries[i].dnssec = DNSSEC_INSECURE;
	else
		queries[i].dnssec = DNSSEC_BOGUS;

	unlock_shm();
}

void _FTL_upstream_error(unsigned int rcode, int id, const char* file, const int line)
{
	// Process upstream errors
	// Queries with error are those where the RCODE
	// in the DNS header is neither NOERROR nor NXDOMAIN.

	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Process DNSSEC result for a domain
	lock_shm();
	// Search for corresponding query identified by ID
	int i = findQueryID(id);
	if(i < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}
	// Translate dnsmasq's rcode into something we can use
	const char *rcodestr = NULL;
	switch(rcode)
	{
		case SERVFAIL:
			rcodestr = "SERVFAIL";
			queries[i].reply = REPLY_SERVFAIL;
			break;
		case REFUSED:
			rcodestr = "REFUSED";
			queries[i].reply = REPLY_REFUSED;
			break;
		case NOTIMP:
			rcodestr = "NOT IMPLEMENTED";
			queries[i].reply = REPLY_NOTIMP;
			break;
		default:
			rcodestr = "UNKNOWN";
			queries[i].reply = REPLY_OTHER;
			break;
	}

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
	{
		int domainID = queries[i].domainID;
		validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
		logg("**** got error report for %s: %s (ID %i, %s:%i)", getstr(domains[domainID].domainpos), rcodestr, id, file, line);
		if(queries[i].reply == REPLY_OTHER)
		{
			logg("Unknown rcode = %i", rcode);
		}
	}

	unlock_shm();
}

void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const int id, const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Check if RA bit is unset in DNS header and rcode is NXDOMAIN
	// If the response code (rcode) is NXDOMAIN, we may be seeing a response from
	// an externally blocked query. As they are not always accompany a necessary
	// SOA record, they are not getting added to our cache and, therefore,
	// FTL_reply() is never getting called from within the cache routines.
	// Hence, we have to store the necessary information about the NXDOMAIN
	// reply already here.
	if((header4 & 0x80) || rcode != NXDOMAIN)
	{
		// RA bit is set or rcode is not NXDOMAIN
		return;
	}

	lock_shm();

	// Search for corresponding query identified by ID
	int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	if(config.debug & DEBUG_QUERIES)
	{
		int domainID = queries[queryID].domainID;
		validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
		logg("**** %s externally blocked (ID %i, FTL %i, %s:%i)", getstr(domains[domainID].domainpos), id, queryID, file, line);
	}


	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Store query as externally blocked
	query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_NXRA);

	// Store reply type as replied with NXDOMAIN
	save_reply_type(F_NEG | F_NXDOMAIN, queryID, response);

	unlock_shm();
}

void print_flags(unsigned int flags)
{
	// Debug function, listing resolver flags in clear text
	// e.g. "Flags: F_FORWARD F_NEG F_IPV6"

	// Only print flags if corresponding debugging flag is set
	if(!(config.debug & DEBUG_FLAGS))
		return;

	unsigned int i;
	char *flagstr = calloc(256,sizeof(char));
	for(i = 0; i < sizeof(flags)*8; i++)
		if(flags & (1u << i))
			strcat(flagstr, flagnames[i]);
	logg("     Flags: %s", flagstr);
	free(flagstr);
}

void save_reply_type(unsigned int flags, int queryID, struct timeval response)
{
	// Iterate through possible values
	validate_access("queries", queryID, false, __LINE__, __FUNCTION__, __FILE__);
	if(flags & F_NEG)
	{
		if(flags & F_NXDOMAIN)
		{
			// NXDOMAIN
			queries[queryID].reply = REPLY_NXDOMAIN;
			counters->reply_NXDOMAIN++;
		}
		else
		{
			// NODATA(-IPv6)
			queries[queryID].reply = REPLY_NODATA;
			counters->reply_NODATA++;
		}
	}
	else if(flags & F_CNAME)
	{
		// <CNAME>
		queries[queryID].reply = REPLY_CNAME;
		counters->reply_CNAME++;
	}
	else if(flags & F_REVERSE)
	{
		// reserve lookup
		queries[queryID].reply = REPLY_DOMAIN;
		counters->reply_domain++;
	}
	else if(flags & F_RRNAME)
	{
		// TXT query
		queries[queryID].reply = REPLY_RRNAME;
	}
	else
	{
		// Valid IP
		queries[queryID].reply = REPLY_IP;
		counters->reply_IP++;
	}

	// Save response time (relative time)
	queries[queryID].response = converttimeval(response) -
	                            queries[queryID].response;
}

pthread_t telnet_listenthreadv4;
pthread_t telnet_listenthreadv6;
pthread_t socket_listenthread;
pthread_t DBthread;
pthread_t GCthread;
pthread_t DNSclientthread;

void FTL_fork_and_bind_sockets(struct passwd *ent_pw)
{
	if(daemonmode)
		go_daemon();
	else
		savepid();

	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Bind to sockets
	bind_sockets();

	// Start TELNET IPv4 thread
	if(ipv4telnet && pthread_create( &telnet_listenthreadv4, &attr, telnet_listening_thread_IPv4, NULL ) != 0)
	{
		logg("Unable to open IPv4 telnet listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start TELNET IPv6 thread
	if(ipv6telnet &&  pthread_create( &telnet_listenthreadv6, &attr, telnet_listening_thread_IPv6, NULL ) != 0)
	{
		logg("Unable to open IPv6 telnet listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start SOCKET thread
	if(pthread_create( &socket_listenthread, &attr, socket_listening_thread, NULL ) != 0)
	{
		logg("Unable to open Unix socket listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start database thread if database is used
	if(database && pthread_create( &DBthread, &attr, DB_thread, NULL ) != 0)
	{
		logg("Unable to open database thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until garbage collection needs to be done
	if(pthread_create( &GCthread, &attr, GC_thread, NULL ) != 0)
	{
		logg("Unable to open GC thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until host names needs to be resolved
	if(pthread_create( &DNSclientthread, &attr, DNSclient_thread, NULL ) != 0)
	{
		logg("Unable to open DNS client thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Chown files if FTL started as user root but a dnsmasq config option
	// states to run as a different user/group (e.g. "nobody")
	if(ent_pw != NULL && getuid() == 0)
	{
		if(chown(FTLfiles.log, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
			logg("Setting ownership (%i:%i) of %s failed: %s (%i)", ent_pw->pw_uid, ent_pw->pw_gid, FTLfiles.log, strerror(errno), errno);
		if(database && chown(FTLfiles.db, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
			logg("Setting ownership (%i:%i) of %s failed: %s (%i)", ent_pw->pw_uid, ent_pw->pw_gid, FTLfiles.db, strerror(errno), errno);
	}
}

// int cache_inserted, cache_live_freed are defined in dnsmasq/cache.c
void getCacheInformation(int *sock)
{
	ssend(*sock,"cache-size: %i\ncache-live-freed: %i\ncache-inserted: %i\n",
	            daemon->cachesize,
	            daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED],
	            daemon->metrics[METRIC_DNS_CACHE_INSERTED]);
	// cache-size is obvious
	// It means the resolver handled <cache-inserted> names lookups that needed to be sent to
	// upstream severes and that <cache-live-freed> was thrown out of the cache
	// before reaching the end of its time-to-live, to make room for a newer name.
	// For <cache-live-freed>, smaller is better.
	// New queries are always cached. If the cache is full with entries
	// which haven't reached the end of their time-to-live, then the entry
	// which hasn't been looked up for the longest time is evicted.
}

void _FTL_forwarding_failed(struct server *server, const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Save that this query got forwarded to an upstream server
	lock_shm();
	char dest[ADDRSTRLEN];
	if(server->addr.sa.sa_family == AF_INET)
		inet_ntop(AF_INET, &server->addr.in.sin_addr, dest, ADDRSTRLEN);
	else
		inet_ntop(AF_INET6, &server->addr.in6.sin6_addr, dest, ADDRSTRLEN);

	// Convert forward to lower case
	char *forward = strdup(dest);
	strtolower(forward);
	int forwardID = findForwardID(forward, false);

	if(config.debug & DEBUG_QUERIES) logg("**** forwarding to %s (ID %i, %s:%i) failed", dest, forwardID, file, line);

	forwarded[forwardID].failed++;

	free(forward);
	unlock_shm();
	return;
}

static unsigned long __attribute__((const)) converttimeval(struct timeval time)
{
	// Convert time from struct timeval into units
	// of 10*milliseconds
	return time.tv_sec*10000 + time.tv_usec/100;
}

// This subroutine prepares IPv4 and IPv6 addresses for blocking queries depending on the configured blocking mode
static void prepare_blocking_mode(struct all_addr *addr4, struct all_addr *addr6, bool *has_IPv4, bool *has_IPv6)
{
	// Read IPv4 address for host entries from setupVars.conf
	char* const IPv4addr = read_setupVarsconf("IPV4_ADDRESS");
	if((config.blockingmode == MODE_IP || config.blockingmode == MODE_IP_NODATA_AAAA) &&
	   IPv4addr != NULL && strlen(IPv4addr) > 0)
	{
		// Strip off everything at the end of the IP (CIDR might be there)
		char* a=IPv4addr; for(;*a;a++) if(*a == '/') *a = 0;
		// Prepare IPv4 address for records
		if(inet_pton(AF_INET, IPv4addr, addr4) > 0)
			*has_IPv4 = true;
	}
	else
	{
		// Blocking mode will use zero-initialized all_addr struct
		*has_IPv4 = true;
	}
	clearSetupVarsArray(); // will free/invalidate IPv4addr

	// Read IPv6 address for host entries from setupVars.conf
	char* const IPv6addr = read_setupVarsconf("IPV6_ADDRESS");
	if(config.blockingmode == MODE_IP &&
	   IPv6addr != NULL && strlen(IPv6addr) > 0)
	{
		// Strip off everything at the end of the IP (CIDR might be there)
		char* a=IPv6addr; for(;*a;a++) if(*a == '/') *a = 0;
		// Prepare IPv6 address for records
		if(inet_pton(AF_INET6, IPv6addr, addr6) > 0)
			*has_IPv6 = true;
	}
	else if(config.blockingmode == MODE_IP_NODATA_AAAA)
	{
		// Blocking mode will use zero-initialized all_addr struct
		// This is irrelevant, however, as this blocking mode will
		// reply with NODATA to AAAA queries. Still, we need to
		// generate separate IPv4 (IP) and AAAA (NODATA) records
		*has_IPv6 = true;
	}
	else
	{
		// Don't create IPv6 cache entries when we don't need them
		// Also, don't create them if we are in IP blocking mode and
		// strlen(IPv6addr) == 0
		*has_IPv6 = false;
	}
	clearSetupVarsArray(); // will free/invalidate IPv6addr
}

// Prototypes from functions in dnsmasq's source
void add_hosts_entry(struct crec *cache, struct all_addr *addr, int addrlen, unsigned int index, struct crec **rhash, int hashsz);
void rehash(int size);

// This routine adds one domain to the resolver's cache. Depending on the configured blocking mode it may create
// a single entry valid for IPv4 & IPv6 or two entries one for IPv4 and one for IPv6.
// When IPv6 is not available on the machine, we do not add IPv6 cache entries (likewise for IPv4)
static int add_blocked_domain(struct all_addr *addr4, struct all_addr *addr6, bool has_IPv4, bool has_IPv6,
                              char *domain, int len, struct crec **rhash, int hashsz, unsigned int index)
{
	int name_count = 0;
	struct crec *cache4,*cache6;
	// Add IPv4 record, allocate enough space for cache entry including arbitrary domain name length
	// (the domain name is stored at the end of struct crec)
	if(has_IPv4 &&
	   (cache4 = malloc(sizeof(struct crec) + len+1-SMALLDNAME)))
	{
		strcpy(cache4->name.sname, domain);
		cache4->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_IPV4;
		int memorysize = INADDRSZ;
		if(config.blockingmode == MODE_NX)
		{
			// If we block in NXDOMAIN mode, we add the NXDOMAIN flag and make this host record
			// also valid for AAAA requests
			 cache4->flags |= F_IPV6 | F_NEG | F_NXDOMAIN;
		}
		else if(config.blockingmode == MODE_NULL)
		{
			// If we block in NULL mode, we make this host record also valid for AAAA requests
			// This is okay as the addr structs have been statically zero-initialized
			cache4->flags |= F_IPV6;
			memorysize = IN6ADDRSZ;
		}
		else if(config.blockingmode == MODE_NODATA)
		{
			// If we block in NODATA mode, we make this host record also valid for AAAA requests
			// and apply the NEG response flag (but not the NXDOMAIN flag)
			cache4->flags |= F_IPV6 | F_NEG;
		}
		cache4->ttd = daemon->local_ttl;
		add_hosts_entry(cache4, addr4, memorysize, index, rhash, hashsz);
		name_count++;
	}
	// Add IPv6 record only if we respond with a non-NULL IP address to blocked domains
	if(has_IPv6 && (config.blockingmode == MODE_IP || config.blockingmode == MODE_IP_NODATA_AAAA) &&
	   (cache6 = malloc(sizeof(struct crec) + len+1-SMALLDNAME)))
	{
		strcpy(cache6->name.sname, domain);
		cache6->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_IPV6;
		if(config.blockingmode == MODE_IP_NODATA_AAAA) cache6->flags |= F_NEG;
		cache6->ttd = daemon->local_ttl;
		add_hosts_entry(cache6, addr6, IN6ADDRSZ, index, rhash, hashsz);
		name_count++;
	}

	// Return 1 if only one cache slot was allocated (IPv4) or 2 if two slots were allocated (IPv4 + IPv6)
	return name_count;
}

// Add a single domain to resolver's cache. This respects the configured blocking mode
// Note: This routine is meant for adding a single domain at a time. It should not be
//       invoked for batch processing
static void block_single_domain_regex(char *domain)
{
	struct all_addr addr4 = {{{ 0 }}}, addr6 = {{{ 0 }}};
	bool has_IPv4 = false, has_IPv6 = false;

	// Get IPv4/v6 addresses for blocking depending on user configures blocking mode
	prepare_blocking_mode(&addr4, &addr6, &has_IPv4, &has_IPv6);
	regexlistname = files.regexlist;
	add_blocked_domain(&addr4, &addr6, has_IPv4, has_IPv6, domain, strlen(domain), NULL, 0, SRC_REGEX);

	if(config.debug & DEBUG_QUERIES) logg("Added %s to cache", domain);

	return;
}

int FTL_listsfile(char* filename, unsigned int index, FILE *f, int cache_size, struct crec **rhash, int hashsz)
{
	int name_count = cache_size;
	int added = 0;
	size_t size = 0;
	char *buffer = NULL;
	struct all_addr addr4 = {{{ 0 }}}, addr6 = {{{ 0 }}};
	bool has_IPv4 = false, has_IPv6 = false;

	// Handle only gravity.list and black.list
	// Skip all other files (they are interpreted in the usual format)
	if(strcmp(filename, files.gravity) != 0 &&
	   strcmp(filename, files.blacklist) != 0)
		return cache_size;

	// Start timer for list analysis
	timer_start(LISTS_TIMER);

	// Get IPv4/v6 addresses for blocking depending on user configured blocking mode
	prepare_blocking_mode(&addr4, &addr6, &has_IPv4, &has_IPv6);

	// If we have neither a valid IPv4 nor a valid IPv6 but the user asked for
	// blocking modes MODE_IP or MODE_IP_NODATA_AAAA then we cannot add any entries here
	if(!has_IPv4 && !has_IPv6)
	{
		logg("ERROR: found neither a valid IPV4_ADDRESS nor IPV6_ADDRESS in setupVars.conf");
		return cache_size;
	}

	// Walk file line by line
	bool firstline = true;
	while(getline(&buffer, &size, f) != -1)
	{
		char *domain = buffer;
		// Skip hashed out lines
		if(*domain == '#')
			continue;

		// Filter leading dots or spaces
		while (*domain == '.' || *domain == ' ') domain++;

		// Check for spaces or tabs
		// If found, then this list is still in HOSTS format and we
		// don't analyze it here. We only check the first line for
		// efficiency reasons (strstr() is slow)
		if(firstline &&
		   (strstr(domain, " ") != NULL || strstr(domain, "\t") != NULL))
		{
			// Reset file pointer back to beginning of the list
			rewind(f);
			logg("File %s is in HOSTS format, please run pihole -g!", filename);
			return name_count;
		}
		firstline = false;

		// Skip empty lines
		int len = strlen(domain);
		if(len == 0)
			continue;

		// Strip newline character at the end of line we just read
		if(domain[len-1] == '\n')
		{
			domain[len-1] = '\0';
			len -= 1;
		}

		// As of here we assume the entry to be valid
		// Rehash every 1000 valid names
		if(rhash && ((name_count - cache_size) > 1000))
		{
			rehash(name_count);
			cache_size = name_count;
		}

		// Add domain
		name_count += add_blocked_domain(&addr4, &addr6, has_IPv4, has_IPv6, domain, len, rhash, hashsz, index);

		// Count added domain
		added++;
	}

	// Rehash after having read all entries
	if(rhash)
		rehash(name_count);

	// Free allocated memory
	if(buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
	}

	logg("%s: parsed %i domains (took %.1f ms)", filename, added, timer_elapsed_msec(LISTS_TIMER));
	counters->gravity += added;
	return name_count;
}
