/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "received_reply.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config.h"
// logg()
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// query_set_reply()
#include "set_reply.h"
// converttimeval()
#include "../timers.h"
// query_to_database()
#include "../database/query-table.h"
// print_flags()
#include "print_flags.h"
// detect_blocked_IP()
#include "detect_blocked_IP.h"
// query_blocked()
#include "query_blocked.h"

void _FTL_reply(const unsigned int flags, const char *name, const union all_addr *addr, const int id,
                const unsigned long ttl, const char* file, const int line)
{
	const double now = double_time();

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
	else if(flags & F_RCODE && addr != NULL)
	{
		unsigned int rcode = addr->log.rcode;
		if(rcode == REFUSED)
		{
			// This happens, e.g., in a "nowhere to forward to" situation
			answer = "REFUSED (nowhere to forward to)";
		}
		else if(rcode == SERVFAIL)
		{
			// This happens on upstream destionation errors
			answer = "SERVFAIL";
		}
	}

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
	query->ttl = ttl;

	// Check if reply time is still unknown
	// We only process the first reply in here
	// Use short-circuit evaluation to check if query is NULL
	if(query == NULL || query->reply != REPLY_UNKNOWN)
	{
		// Nothing to be done here
		unlock_shm();
		return;
	}

	// Determine if this reply is an exact match for the queried domain
	const int domainID = query->domainID;

	// Get domain pointer
	domainsData* domain = getDomain(domainID, true);
	if(domain == NULL)
	{
		// Memory error, skip reply
		unlock_shm();
		return;
	}

	// Check if this domain matches exactly
	const bool isExactMatch = strcmp_escaped(name, getstr(domain->domainpos));

	if((flags & F_CONFIG) && isExactMatch && !query->flags.complete)
	{
		// Answered from local configuration, might be a wildcard or user-provided

		// Answered from a custom (user provided) cache file or because
		// we're the authorative DNS server (e.g. DHCP server and this
		// is our own domain)
		query_set_status(query, STATUS_CACHE);

		// Save reply type and update individual reply counters
		query_set_reply(flags, addr, query, now);

		// Hereby, this query is now fully determined
		query->flags.complete = true;
	}
	else if((flags & F_FORWARD) && isExactMatch)
	{
		// Save query response time
		upstreamsData *upstream = getUpstream(query->upstreamID, true);
		upstream->responses++;
		unsigned long rtime = converttimeval(response) - query->response;
		upstream->rtime += rtime;
		unsigned long mean = upstream->rtime / upstream->responses;
		upstream->rtuncertainty += (mean - rtime)*(mean - rtime);

		// Only proceed if query is not already known
		// to have been blocked by Quad9
		if(query->status != STATUS_EXTERNAL_BLOCKED_IP &&
		   query->status != STATUS_EXTERNAL_BLOCKED_NULL &&
		   query->status != STATUS_EXTERNAL_BLOCKED_NXRA)
		{
			// Save reply type and update individual reply counters
			query_set_reply(flags, addr, query, now);

			// Detect if returned IP indicates that this query was blocked
			const enum query_status new_status = detect_blocked_IP(flags, addr, query, domain);

			// Update status of this query if detected as external blocking
			if(new_status != query->status)
			{
				clientsData *client = getClient(query->clientID, true);
				if(client != NULL)
					query_blocked(query, domain, client, new_status);
			}
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
		query_set_reply(flags, addr, query, now);
	}
	else if(isExactMatch && !query->flags.complete)
	{
		logg("*************************** unknown REPLY ***************************");
		print_flags(flags);
	}

	// Update query in database
	query_to_database(query);

	unlock_shm();
}
