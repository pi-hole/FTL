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
#include "forwarded.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// converttimeval()
#include "../timers.h"
// query_to_database()
#include "../database/query-table.h"
// getOverTimeID()
#include "../overTime.h"

void FTL_forwarded(const unsigned int flags, const char *name, const union all_addr *addr,
                   const int id, const char* file, const int line)
{
	// Save that this query got forwarded to an upstream server
	const double now = double_time();

	// Lock shared memory
	lock_shm();

	// Get forward destination IP address and port
	in_port_t upstreamPort = 53;
	char dest[ADDRSTRLEN];
	// If addr == NULL, we will only duplicate an empty string instead of uninitialized memory
	dest[0] = '\0';
	if(addr != NULL)
	{
		if(flags & F_IPV4)
		{
			inet_ntop(AF_INET, addr, dest, ADDRSTRLEN);
			// Reverse-engineer port from underlying sockaddr_in structure
			const in_port_t *port = (in_port_t*)((void*)addr
			                                     - offsetof(struct sockaddr_in, sin_addr)
			                                     + offsetof(struct sockaddr_in, sin_port));
			upstreamPort = ntohs(*port);
		}
		else
		{
			inet_ntop(AF_INET6, addr, dest, ADDRSTRLEN);
			// Reverse-engineer port from underlying sockaddr_in6 structure
			const in_port_t *port = (in_port_t*)((void*)addr
			                                     - offsetof(struct sockaddr_in6, sin6_addr)
			                                     + offsetof(struct sockaddr_in6, sin6_port));
			upstreamPort = ntohs(*port);
		}
	}

	// Convert upstreamIP to lower case
	char *upstreamIP = strdup(dest);
	strtolower(upstreamIP);

	// Substitute "." if we are querying the root domain (e.g. DNSKEY)
	if(!name || strlen(name) == 0)
		name = ".";

	// Debug logging
	log_debug(DEBUG_QUERIES, "**** forwarded %s to %s#%u (ID %i, %s:%i)",
	          name, upstreamIP, upstreamPort, id, file, line);

	// Save status and upstreamID in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was a PTR query or "pi.hole"
		// as we ignore them altogether
		free(upstreamIP);
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);
	if(query == NULL)
	{
		free(upstreamIP);
		unlock_shm();
		return;
	}

	// Get ID of upstream destination, create new upstream record
	// if not found in current data structure
	const int upstreamID = findUpstreamID(upstreamIP, upstreamPort);
	query->upstreamID = upstreamID;

	upstreamsData *upstream = getUpstream(upstreamID, true);
	if(upstream != NULL)
	{
		// Only count upstream when there has been no reply so far
		if(query->reply == REPLY_UNKNOWN)
		{
			// Update overTime
			const int timeidx = getOverTimeID(query->timestamp);
			upstream->overTime[timeidx]++;
			// Update total count
			upstream->count++;
		}
		// Update lastQuery timestamp
		upstream->lastQuery = double_time();
	}

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destinations are coming in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	if(query->flags.complete && query->status != QUERY_CACHE)
	{
		free(upstreamIP);
		unlock_shm();
		return;
	}

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

		// Reset timer, shift slightly into the past to acknowledge the time
		// FTLDNS needed to look up the CNAME in its cache
		query->response = now;
	}
	else
	{
		// Normal forwarded query (status is set below)
		// Hereby, this query is now fully determined
		query->flags.complete = true;
	}

	// Set query status to forwarded only after the
	// if(query->status == QUERY_CACHE) { ... }
	// from above as otherwise this check will always
	// be negative
	query_set_status(query, QUERY_FORWARDED);

	// Release allocated memory
	free(upstreamIP);

	// Unlock shared memory
	unlock_shm();
}
