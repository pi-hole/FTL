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
#include "overTime.h"
#include "memory.h"
#include "database/common.h"
#include "database/database-thread.h"
#include "database/gravity-db.h"
#include "setupVars.h"
#include "daemon.h"
#include "timers.h"
#include "gc.h"
#include "api/socket.h"
#include "regex_r.h"
#include "datastructure.h"
#include "config.h"
#include "capabilities.h"
#include "resolve.h"
#include "files.h"
#include "log.h"
// Prototype of getCacheInformation()
#include "api/api.h"
// global variable daemonmode
#include "args.h"

static void print_flags(const unsigned int flags);
static void save_reply_type(const unsigned int flags, const int queryID, const struct timeval response);
static unsigned long converttimeval(const struct timeval time) __attribute__((const));
static void block_single_domain_regex(const char *domain);
static void detect_blocked_IP(const unsigned short flags, const char* answer, const int queryID);
static void query_externally_blocked(const int queryID, const unsigned char status);
static int findQueryID(const int id);

unsigned char* pihole_privacylevel = &config.privacylevel;
const char flagnames[][12] = {"F_IMMORTAL ", "F_NAMEP ", "F_REVERSE ", "F_FORWARD ", "F_DHCP ", "F_NEG ", "F_HOSTS ", "F_IPV4 ", "F_IPV6 ", "F_BIGNAME ", "F_NXDOMAIN ", "F_CNAME ", "F_DNSKEY ", "F_CONFIG ", "F_DS ", "F_DNSSECOK ", "F_UPSTREAM ", "F_RRNAME ", "F_SERVER ", "F_QUERY ", "F_NOERR ", "F_AUTH ", "F_DNSSEC ", "F_KEYTAG ", "F_SECSTAT ", "F_NO_RR ", "F_IPSET ", "F_NOEXTRA ", "F_SERVFAIL", "F_RCODE"};

void _FTL_new_query(const unsigned int flags, const char *name, const union all_addr *addr,
                    const char *types, const int id, const char type,
                    const char* file, const int line)
{
	// Create new query in data structure

	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Lock shared memory
	lock_shm();

	// Get timestamp
	const time_t querytimestamp = time(NULL);

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
		if(config.debug & DEBUG_QUERIES)
			logg("Notice: Skipping unknown query type: %s (%i)", types, id);
		unlock_shm();
		return;
	}

	// Skip AAAA queries if user doesn't want to have them analyzed
	if(!config.analyze_AAAA && querytype == TYPE_AAAA)
	{
		if(config.debug & DEBUG_QUERIES)
			logg("Not analyzing AAAA query");
		unlock_shm();
		return;
	}

	// Ensure we have enough space in the queries struct
	memory_check(QUERIES);
	const int queryID = counters->queries;

	// If domain is "pi.hole" we skip this query
	if(strcasecmp(name, "pi.hole") == 0)
	{
		unlock_shm();
		return;
	}

	// Convert domain to lower case
	char *domainString = strdup(name);
	strtolower(domainString);

	// Get client IP address
	char dest[ADDRSTRLEN];
	inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	char *clientIP = strdup(dest);
	strtolower(clientIP);

	// Check if user wants to skip queries coming from localhost
	if(config.ignore_localhost &&
	   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
	{
		free(domainString);
		free(clientIP);
		unlock_shm();
		return;
	}

	// Log new query if in debug mode
	const char *proto = (type == UDP) ? "UDP" : "TCP";
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** new %s %s \"%s\" from %s (ID %i, FTL %i, %s:%i)",
		     proto, types, domainString, clientIP, id, queryID, file, line);
	}

	// Update counters
	counters->querytype[querytype-1]++;

	// Update overTime
	const unsigned int timeidx = getOverTimeID(querytimestamp);
	overTime[timeidx].querytypedata[querytype-1]++;

	// Skip rest of the analysis if this query is not of type A or AAAA
	// but user wants to see only A and AAAA queries (pre-v4.1 behavior)
	if(config.analyze_only_A_AAAA && querytype != TYPE_A && querytype != TYPE_AAAA)
	{
		// Don't process this query further here, we already counted it
		if(config.debug & DEBUG_QUERIES) logg("Notice: Skipping new query: %s (%i)", types, id);
		free(domainString);
		free(clientIP);
		unlock_shm();
		return;
	}

	// Go through already knows domains and see if it is one of them
	const int domainID = findDomainID(domainString);

	// Go through already knows clients and see if it is one of them
	const int clientID = findClientID(clientIP, true);

	// Save everything
	queriesData* query = getQuery(queryID, false);
	query->magic = MAGICBYTE;
	query->timestamp = querytimestamp;
	query->type = querytype;
	query->status = QUERY_UNKNOWN;
	query->domainID = domainID;
	query->clientID = clientID;
	query->timeidx = timeidx;
	// Initialize database rowID with zero, will be set when the query is stored in the long-term DB
	query->db = 0;
	query->id = id;
	query->complete = false;
	query->response = converttimeval(request);
	// Initialize reply type
	query->reply = REPLY_UNKNOWN;
	// Store DNSSEC result for this domain
	query->dnssec = DNSSEC_UNSPECIFIED;

	// Check and apply possible privacy level rules
	// The currently set privacy level (at the time the query is
	// generated) is stored in the queries structure
	get_privacy_level(NULL);
	query->privacylevel = config.privacylevel;

	// Increase DNS queries counter
	counters->queries++;
	// Count this query as unknown as long as no reply has
	// been found and analyzed
	counters->unknown++;

	// Update overTime data
	overTime[timeidx].total++;

	// Get client pointer
	clientsData* client = getClient(clientID, true);

	// Update overTime data structure with the new client
	client->overTime[timeidx]++;

	// Set lastQuery timer and add one query for network table
	client->lastQuery = querytimestamp;
	client->numQueriesARP++;

	// Get domain pointer
	domainsData* domain = getDomain(domainID, true);

	// Try blocking regex if configured
	if(domain->regexmatch == REGEX_UNKNOWN && blockingstatus != BLOCKING_DISABLED)
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
		if(match_regex(domainString, REGEX_BLACKLIST) && !in_whitelist(domainString))
		{
			// We have to block this domain
			block_single_domain_regex(domainString);
			domain->regexmatch = REGEX_BLOCKED;
		}
		else
		{
			// Explicitly mark as not blocked to skip regex test
			// next time we see this domain
			domain->regexmatch = REGEX_NOTBLOCKED;
		}
	}

	// Free allocated memory
	free(domainString);
	free(clientIP);

	// Release thread lock
	unlock_shm();
}

static int findQueryID(const int id)
{
	// Loop over all queries - we loop in reverse order (start from the most recent query and
	// continuously walk older queries while trying to find a match. Ideally, we should always
	// find the correct query with zero iterations, but it may happen that queries are processed
	// asynchronously, e.g. for slow upstream relies to a huge amount of requests.
	// We iterate from the most recent query down to at most MAXITER queries in the past to avoid
	// iterating through the entire array of queries
	// MAX(0, a) is used to return 0 in case a is negative (negative array indices are harmful)
	const int until = MAX(0, counters->queries-MAXITER);
	const int start = MAX(0, counters->queries-1);

	// Check UUIDs of queries
	for(int i = start; i >= until; i--)
	{
		const queriesData* query = getQuery(i, true);
		if(query->id == id)
			return i;
	}

	// If not found
	return -1;
}

void _FTL_forwarded(const unsigned int flags, const char *name, const union all_addr *addr, const int id,
                    const char* file, const int line)
{
	// Save that this query got forwarded to an upstream server

	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Lock shared memory
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
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was a PTR query or "pi.hole"
		// as we ignore them altogether
		free(forward);
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destinations are coming in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	if(query->complete && query->status != QUERY_CACHE)
	{
		free(forward);
		unlock_shm();
		return;
	}

	// Get ID of forward destination, create new forward destination record
	// if not found in current data structure
	const int forwardID = findForwardID(forward, true);
	query->forwardID = forwardID;

	// Get time index for this query
	const unsigned int timeidx = query->timeidx;

	if(query->status == QUERY_CACHE)
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
		query->response = converttimeval(response) - query->response;
	}
	else
	{
		// Normal forwarded query (status is set below)
		// Query is no longer unknown
		counters->unknown--;
		// Hereby, this query is now fully determined
		query->complete = true;
	}

	// Set query status to forwarded only after the
	// if(query->status == QUERY_CACHE) { ... }
	// from above as otherwise this check will always
	// be negative
	query->status = QUERY_FORWARDED;

	// Update overTime data
	overTime[timeidx].forwarded++;

	// Update counter for forwarded queries
	counters->forwardedqueries++;

	// Release allocated memory
	free(forward);

	// Unlock shared memory
	unlock_shm();
}

void FTL_dnsmasq_reload(void)
{
	// This function is called by the dnsmasq code on receive of SIGHUP
	// *before* clearing the cache and rereading the lists
	// This is the only hook that is not skipped in PRIVACY_NOSTATS mode

	logg("Reloading DNS cache");

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

	// Reread pihole-FTL.conf to see which debugging flags are set
	read_debuging_settings(NULL);

	// (Re-)open gravity database connection
	gravityDB_close();
	gravityDB_open();

	// Read and compile possible regex filters
	// only after having called gravityDB_open()
	read_regex_from_database();

	// Print current set of capabilities if requested via debug flag
	if(config.debug & DEBUG_CAPS)
		check_capabilities();
}

void _FTL_reply(const unsigned short flags, const char *name, const union all_addr *addr, const int id,
                const char* file, const int line)
{
	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Lock shared memory
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

	// Possible debugging output
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** got reply %s is %s (ID %i, %s:%i)", name, answer, id, file, line);
		print_flags(flags);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Save status in corresponding query identified by dnsmasq's ID
	const int i = findQueryID(id);
	if(i < 0)
	{
		// This may happen e.g. if the original query was "pi.hole"
		if(config.debug & DEBUG_QUERIES) logg("FTL_reply(): Query %i has not been found", id);
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(i, true);

	// Check if reply time is still unknown
	// We only process the first reply in here
	if(query->reply != REPLY_UNKNOWN)
	{
		// Nothing to be done here
		unlock_shm();
		return;
	}

	// Determine if this reply is an exact match for the queried domain
	const int domainID = query->domainID;

	// Get domain pointer
	domainsData* domain = getDomain(domainID, true);

	// Check if this domain matches exactly
	const bool isExactMatch = (name != NULL && strcasecmp(getstr(domain->domainpos), name) == 0);

	if((flags & F_CONFIG) && isExactMatch && !query->complete)
	{
		// Answered from local configuration, might be a wildcard or user-provided
		// This query is no longer unknown
		counters->unknown--;

		// Get time index
		const unsigned int timeidx = query->timeidx;

		// Check whether this query was blocked
		if(strcmp(answer, "(NXDOMAIN)") == 0 ||
		   strcmp(answer, "0.0.0.0") == 0 ||
		   strcmp(answer, "::") == 0)
		{
			// Answered from user-defined blocking rules (dnsmasq config files)
			counters->blocked++;
			overTime[timeidx].blocked++;

			// Update domain blocked counter
			domain->blockedcount++;

			// Get client pointer
			clientsData* client = getClient(query->clientID, true);

			// Update client blocked counter
			client->blockedcount++;

			// Set query status to wildcard
			query->status = QUERY_WILDCARD;
		}
		else
		{
			// Answered from a custom (user provided) cache file
			counters->cached++;
			overTime[timeidx].cached++;

			query->status = QUERY_CACHE;
		}

		// Save reply type and update individual reply counters
		save_reply_type(flags, i, response);

		// Hereby, this query is now fully determined
		query->complete = true;
	}
	else if((flags & F_FORWARD) && isExactMatch)
	{
		// Only proceed if query is not already known
		// to have been blocked by Quad9
		if(query->reply != QUERY_EXTERNAL_BLOCKED_IP &&
		   query->reply != QUERY_EXTERNAL_BLOCKED_NULL &&
		   query->reply != QUERY_EXTERNAL_BLOCKED_NXRA)
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
		//   domain->domain = 8.8.8.8.in-addr.arpa
		// and will return
		//   name = google-public-dns-a.google.com
		// Hence, isExactMatch is always false

		// Save reply type and update individual reply counters
		save_reply_type(flags, i, response);
	}
	else if(isExactMatch && !query->complete)
	{
		logg("*************************** unknown REPLY ***************************");
		print_flags(flags);
	}

	unlock_shm();
}

static void detect_blocked_IP(const unsigned short flags, const char* answer, const int queryID)
{
	// Compare returned IP against list of known blocking splash pages

	// First, we check if we want to skip this result even before comparing against the known IPs
	if(flags & F_HOSTS || flags & F_REVERSE)
	{
		// Skip replies which originated locally. Otherwise, we would
		// count gravity.list blocked queries as externally blocked.
		// Also: Do not mark responses of PTR requests as externally blocked.
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			const char *cause = (flags & F_HOSTS) ? "origin is HOSTS" : "query is PTR";
			logg("Skipping detection of external blocking IP for ID %i as %s", queryID, cause);
		}

		// Return early, do not compare against known blocking page IP addresses below
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
			const queriesData* query = getQuery(queryID, true);
			const domainsData* domain = getDomain(query->domainID, true);
			logg("Upstream responded with known blocking page (IPv4), ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domain->domainpos), answer);
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
			const queriesData* query = getQuery(queryID, true);
			const domainsData* domain = getDomain(query->domainID, true);
			logg("Upstream responded with known blocking page (IPv6), ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domain->domainpos), answer);
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
			const queriesData* query = getQuery(queryID, true);
			const domainsData* domain = getDomain(query->domainID, true);
			logg("Upstream responded with 0.0.0.0, ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domain->domainpos), answer);
		}

		// Update status
		query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_NULL);
	}
	else if(flags & F_IPV6 && answer != NULL &&
		strcmp("::", answer) == 0)
	{
		if(config.debug & DEBUG_EXTBLOCKED)
		{
			const queriesData* query = getQuery(queryID, true);
			const domainsData* domain = getDomain(query->domainID, true);
			logg("Upstream responded with ::, ID %i:\n\t\"%s\" -> \"%s\"",
			     queryID, getstr(domain->domainpos), answer);
		}

		// Update status
		query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_NULL);
	}
}

static void query_externally_blocked(const int queryID, const unsigned char status)
{
	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// Get time index
	const unsigned int timeidx = query->timeidx;

	// If query is already known to be externally blocked,
	// then we have nothing to do here
	if(query->status == QUERY_EXTERNAL_BLOCKED_IP ||
	   query->status == QUERY_EXTERNAL_BLOCKED_NULL ||
	   query->status == QUERY_EXTERNAL_BLOCKED_NXRA)
		return;

	// Correct counters if necessary ...
	if(query->status == QUERY_FORWARDED)
	{
		counters->forwardedqueries--;
		overTime[timeidx].forwarded--;

		// Get forward pointer
		forwardedData* forward = getForward(query->forwardID, true);
		forward->count--;
	}
	// Mark query as blocked
	counters->blocked++;
	overTime[timeidx].blocked++;

	// Get domain pointer
	domainsData* domain = getDomain(query->domainID, true);
	domain->blockedcount++;

	// Get client pointer
	clientsData* client = getClient(query->clientID, true);
	client->blockedcount++;

	// Set query status
	query->status = status;
}

void _FTL_cache(const unsigned int flags, const char *name, const union all_addr *addr,
                const char *arg, const int id, const char* file, const int line)
{
	// Save that this query got answered from cache

	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Lock shared memory
	lock_shm();

	// Obtain destination IP address if available for this query type
	char dest[ADDRSTRLEN]; dest[0] = '\0';
	if(addr)
	{
		inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	}

	// If domain is "pi.hole", we skip this query
	// We compare case-insensitive here
	if(strcasecmp(name, "pi.hole") == 0)
	{
		unlock_shm();
		return;
	}

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
		// Local list: /etc/hosts, /etc/pihole/local.list, etc.
		// or
		// blocked domain from gravity database
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
			if(arg != NULL && strcmp(arg, SRC_GRAVITY_NAME) == 0)
				requesttype = QUERY_GRAVITY;
			else if(arg != NULL && strcmp(arg, SRC_BLACK_NAME) == 0)
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

		// Search query in FTL's query data
		const int queryID = findQueryID(id);
		if(queryID < 0)
		{
			// This may happen e.g. if the original query was a PTR query or "pi.hole"
			// as we ignore them altogether
			unlock_shm();
			return;
		}

		// Get query pointer
		queriesData* query = getQuery(queryID, true);

		// Skip this query if already marked as complete
		if(query->complete)
		{
			unlock_shm();
			return;
		}

		// This query is no longer unknown
		counters->unknown--;

		// Get time index
		const unsigned int timeidx = query->timeidx;

		// Get domain pointer
		domainsData* domain = getDomain(query->domainID, true);

		// Get client pointer
		clientsData* client = getClient(query->clientID, true);

		// Mark this query as blocked if domain was matched by a regex
		if(domain->regexmatch == REGEX_BLOCKED)
			requesttype = QUERY_WILDCARD;

		query->status = requesttype;

		// Detect if returned IP indicates that this query was blocked
		detect_blocked_IP(flags, dest, queryID);

		// Re-read requesttype as detect_blocked_IP() might have changed it
		requesttype = query->status;

		// Handle counters accordingly
		switch(requesttype)
		{
			case QUERY_GRAVITY: // gravity.list
			case QUERY_BLACKLIST: // black.list
			case QUERY_WILDCARD: // regex blocked
				counters->blocked++;
				overTime[timeidx].blocked++;
				domain->blockedcount++;
				client->blockedcount++;
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
		save_reply_type(flags, queryID, response);

		// Hereby, this query is now fully determined
		query->complete = true;
	}
	else
	{
		logg("*************************** unknown CACHE reply (2) ***************************");
		print_flags(flags);
	}
	unlock_shm();
}

void _FTL_dnssec(const int status, const int id, const char* file, const int line)
{
	// Process DNSSEC result for a domain

	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(query->domainID, true);

		logg("**** got DNSSEC details for %s: %i (ID %i, %s:%i)", getstr(domain->domainpos), status, id, file, line);
	}

	// Iterate through possible values
	if(status == STAT_SECURE)
		query->dnssec = DNSSEC_SECURE;
	else if(status == STAT_INSECURE)
		query->dnssec = DNSSEC_INSECURE;
	else
		query->dnssec = DNSSEC_BOGUS;

	// Unlock shared memory
	unlock_shm();
}

void _FTL_upstream_error(const unsigned int rcode, const int id, const char* file, const int line)
{
	// Process upstream errors
	// Queries with error are those where the RCODE
	// in the DNS header is neither NOERROR nor NXDOMAIN.

	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// Translate dnsmasq's rcode into something we can use
	const char *rcodestr = NULL;
	switch(rcode)
	{
		case SERVFAIL:
			rcodestr = "SERVFAIL";
			query->reply = REPLY_SERVFAIL;
			break;
		case REFUSED:
			rcodestr = "REFUSED";
			query->reply = REPLY_REFUSED;
			break;
		case NOTIMP:
			rcodestr = "NOT IMPLEMENTED";
			query->reply = REPLY_NOTIMP;
			break;
		default:
			rcodestr = "UNKNOWN";
			query->reply = REPLY_OTHER;
			break;
	}

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(query->domainID, true);

		logg("**** got error report for %s: %s (ID %i, %s:%i)", getstr(domain->domainpos), rcodestr, id, file, line);

		if(query->reply == REPLY_OTHER)
		{
			logg("Unknown rcode = %i", rcode);
		}
	}

	// Unlock shared memory
	unlock_shm();
}

void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const int id, const char* file, const int line)
{
	// Analyze DNS header bits

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

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// Possible debugging information
	if(config.debug & DEBUG_QUERIES)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(query->domainID, true);
		logg("**** %s externally blocked (ID %i, FTL %i, %s:%i)", getstr(domain->domainpos), id, queryID, file, line);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Store query as externally blocked
	query_externally_blocked(queryID, QUERY_EXTERNAL_BLOCKED_NXRA);

	// Store reply type as replied with NXDOMAIN
	save_reply_type(F_NEG | F_NXDOMAIN, queryID, response);

	// Unlock shared memory
	unlock_shm();
}

void print_flags(const unsigned int flags)
{
	// Debug function, listing resolver flags in clear text
	// e.g. "Flags: F_FORWARD F_NEG F_IPV6"

	// Only print flags if corresponding debugging flag is set
	if(!(config.debug & DEBUG_FLAGS))
		return;

	char *flagstr = calloc(sizeof(flagnames) + 1, sizeof(char));
	for (unsigned int i = 0; i < (sizeof(flagnames) / sizeof(*flagnames)); i++)
		if (flags & (1u << i))
			strcat(flagstr, flagnames[i]);
	logg("     Flags: %s", flagstr);
	free(flagstr);
}

void save_reply_type(const unsigned int flags, const int queryID, const struct timeval response)
{
	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// Iterate through possible values
	if(flags & F_NEG)
	{
		if(flags & F_NXDOMAIN)
		{
			// NXDOMAIN
			query->reply = REPLY_NXDOMAIN;
			counters->reply_NXDOMAIN++;
		}
		else
		{
			// NODATA(-IPv6)
			query->reply = REPLY_NODATA;
			counters->reply_NODATA++;
		}
	}
	else if(flags & F_CNAME)
	{
		// <CNAME>
		query->reply = REPLY_CNAME;
		counters->reply_CNAME++;
	}
	else if(flags & F_REVERSE)
	{
		// reserve lookup
		query->reply = REPLY_DOMAIN;
		counters->reply_domain++;
	}
	else if(flags & F_RRNAME)
	{
		// TXT query
		query->reply = REPLY_RRNAME;
	}
	else
	{
		// Valid IP
		query->reply = REPLY_IP;
		counters->reply_IP++;
	}

	// Save response time (relative time)
	query->response = converttimeval(response) -
	                            query->response;
}

pthread_t telnet_listenthreadv4;
pthread_t telnet_listenthreadv6;
pthread_t socket_listenthread;
pthread_t DBthread;
pthread_t GCthread;
pthread_t DNSclientthread;

void FTL_fork_and_bind_sockets(struct passwd *ent_pw)
{
	// Going into daemon mode involves storing the
	// PID of the generated child process. If FTL
	// is asked to stay in foreground, we just save
	// the PID of the current process in the PID file
	if(daemonmode)
		go_daemon();
	else
		savepid();

	// We will use the attributes object later to start all threads in
	// detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically
	// released back to the system without the need for another thread to
	// join with the terminated thread
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

	// Start thread that will stay in the background until garbage
	// collection needs to be done
	if(pthread_create( &GCthread, &attr, GC_thread, NULL ) != 0)
	{
		logg("Unable to open GC thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until host names
	// needs to be resolved
	if(pthread_create( &DNSclientthread, &attr, DNSclient_thread, NULL ) != 0)
	{
		logg("Unable to open DNS client thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Chown files if FTL started as user root but a dnsmasq config
	// option states to run as a different user/group (e.g. "nobody")
	if(ent_pw != NULL && getuid() == 0)
	{
		if(chown(FTLfiles.log, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
			logg("Setting ownership (%i:%i) of %s failed: %s (%i)",
			     ent_pw->pw_uid, ent_pw->pw_gid, FTLfiles.log, strerror(errno), errno);
		if(database && chown(FTLfiles.FTL_db, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
			logg("Setting ownership (%i:%i) of %s failed: %s (%i)",
			     ent_pw->pw_uid, ent_pw->pw_gid, FTLfiles.FTL_db, strerror(errno), errno);
	}
}

// int cache_inserted, cache_live_freed are defined in dnsmasq/cache.c
void getCacheInformation(const int *sock)
{
	ssend(*sock,"cache-size: %i\ncache-live-freed: %i\ncache-inserted: %i\n",
	            daemon->cachesize,
	            daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED],
	            daemon->metrics[METRIC_DNS_CACHE_INSERTED]);
	// cache-size is obvious
	// It means the resolver handled <cache-inserted> names lookups that
	// needed to be sent to upstream servers and that <cache-live-freed>
	// was thrown out of the cache before reaching the end of its
	// time-to-live, to make room for a newer name.
	// For <cache-live-freed>, smaller is better. New queries are always
	// cached. If the cache is full with entries which haven't reached
	// the end of their time-to-live, then the entry which hasn't been
	// looked up for the longest time is evicted.
}

void _FTL_forwarding_failed(const struct server *server, const char* file, const int line)
{
	// Save that this query got forwarded to an upstream server

	// Don't analyze anything if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Lock shared memory
	lock_shm();

	// Try to obtain destination IP address if available
	char dest[ADDRSTRLEN];
	if(server->addr.sa.sa_family == AF_INET)
		inet_ntop(AF_INET, &server->addr.in.sin_addr, dest, ADDRSTRLEN);
	else
		inet_ntop(AF_INET6, &server->addr.in6.sin6_addr, dest, ADDRSTRLEN);

	// Convert forward to lower case
	char *forwarddest = strdup(dest);
	strtolower(forwarddest);

	// Get forward ID
	const int forwardID = findForwardID(forwarddest, false);

	// Possible debugging information
	if(config.debug & DEBUG_QUERIES) logg("**** forwarding to %s (ID %i, %s:%i) failed", dest, forwardID, file, line);

	// Get forward pointer
	forwardedData* forward = getForward(forwardID, true);

	// Update counter
	forward->failed++;

	// Clean up and unlock shared memory
	free(forwarddest);
	unlock_shm();
	return;
}

static unsigned long __attribute__((const)) converttimeval(const struct timeval time)
{
	// Convert time from struct timeval into units
	// of 10*milliseconds
	return time.tv_sec*10000 + time.tv_usec/100;
}

// This subroutine prepares IPv4 and IPv6 addresses for blocking queries depending on the configured blocking mode
static void prepare_blocking_mode(union all_addr *addr4, union all_addr *addr6, bool *has_IPv4, bool *has_IPv6)
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
	// Free IPv4addr
	clearSetupVarsArray();

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
	// Free IPv6addr
	clearSetupVarsArray();
}

// Prototypes from functions in dnsmasq's source
void add_hosts_entry(struct crec *cache, union all_addr *addr, int addrlen, unsigned int index, struct crec **rhash, int hashsz);
void rehash(int size);

// This routine adds one domain to the resolver's cache. Depending on the configured blocking mode it may create
// a single entry valid for IPv4 & IPv6 or two entries one for IPv4 and one for IPv6.
// When IPv6 is not available on the machine, we do not add IPv6 cache entries (likewise for IPv4)
static int add_blocked_domain(union all_addr *addr4, union all_addr *addr6, const bool has_IPv4, const bool has_IPv6,
                              const char *domain, const int len, struct crec **rhash, int hashsz, const unsigned int index)
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
static void block_single_domain_regex(const char *domain)
{
	union all_addr addr4, addr6;
	memset(&addr4.addr4, 0, sizeof(addr4.addr4));
	memset(&addr6.addr6, 0, sizeof(addr6.addr6));
	bool has_IPv4 = false, has_IPv6 = false;

	// Get IPv4/v6 addresses for blocking depending on user configures blocking mode
	prepare_blocking_mode(&addr4, &addr6, &has_IPv4, &has_IPv6);
	add_blocked_domain(&addr4, &addr6, has_IPv4, has_IPv6, domain, strlen(domain), NULL, 0, SRC_REGEX);

	if(config.debug & DEBUG_QUERIES)
		logg("Added %s to cache", domain);
}

// Import a specified table from the gravity database and
// add the read domains to the cache using the currently
// selected blocking mode. This function is used to import
// both the blacklist and the gravity blocking domains
static int FTL_table_import(const char *tablename, const unsigned char list, const unsigned int index,
                             union all_addr addr4, union all_addr addr6, bool has_IPv4, bool has_IPv6,
                             int cache_size, struct crec **rhash, int hashsz)
{
	// Variables
	int name_count = cache_size, added = 0;

	// Start timer for list analysis
	timer_start(LISTS_TIMER);

	// Get database table handle
	if(!gravityDB_getTable(list))
	{
		logg("FTL_listsfile(): Error getting %s table from database", tablename);
		return name_count;
	}

	// Walk database table
	const char *domain = NULL;
	while((domain = gravityDB_getDomain()) != NULL)
	{
		int len = strlen(domain);
		// Skip empty database rows
		if(len == 0)
			continue;

		// Do not add gravity or blacklist domains that match
		// a regex-based whitelist filter
		if(match_regex(domain, REGEX_WHITELIST))
			continue;

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

	// Finalize statement and close gravity database handle
	gravityDB_finalizeTable();

	// Final logging
	logg("Database (%s): imported %i domains (took %.1f ms)", tablename, added, timer_elapsed_msec(LISTS_TIMER));

	// Return number of domains added to the cache
	return added;
}

// Import blocking domains from the gravity database
// This function is run whenever dnsmasq reads in HOSTS
// files (on startup as well as on receipt of SIGHUP)
int FTL_database_import(int cache_size, struct crec **rhash, int hashsz)
{
	union all_addr addr4, addr6;
	memset(&addr4.addr4, 0, sizeof(addr4.addr4));
	memset(&addr6.addr6, 0, sizeof(addr6.addr6));
	bool has_IPv4 = false, has_IPv6 = false;

	if(blockingstatus == BLOCKING_DISABLED)
	{
		logg("Skipping import of database tables because blocking is disabled");
		return cache_size;
	}

	// Get IPv4/v6 addresses for blocking depending on user configured blocking mode
	prepare_blocking_mode(&addr4, &addr6, &has_IPv4, &has_IPv6);

	// If we have neither a valid IPv4 nor a valid IPv6 but the user asked for
	// blocking modes MODE_IP or MODE_IP_NODATA_AAAA then we cannot add any entries here
	if(!has_IPv4 && !has_IPv6)
	{
		logg("ERROR: Cannot add domains from gravity because pihole-FTL found\n" \
		     "       neither a valid IPV4_ADDRESS nor IPV6_ADDRESS in setupVars.conf" \
		     "       This is an impossible configuration. Please contact the Pi-hole" \
		     "       support if you need assistance.");
		return cache_size;
	}

	// Import gravity and exact blacklisted domains
	int added;
	added  = FTL_table_import("gravity", GRAVITY_TABLE, SRC_GRAVITY, addr4, addr6, has_IPv4, has_IPv6, cache_size, rhash, hashsz);
	added += FTL_table_import("blacklist", EXACT_BLACKLIST_TABLE, SRC_BLACK, addr4, addr6, has_IPv4, has_IPv6, cache_size, rhash, hashsz);

	// Update counter of blocked domains
	counters->gravity = added;

	// Return new cache size which now includes more domains than before
	return cache_size + added;
}
