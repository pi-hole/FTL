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

void _FTL_forwarded(const unsigned int flags, const char *name, const struct server *serv, const int id,
                    const char *file, const int line)
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
	if(serv != NULL)
	{
		if(serv->addr.sa.sa_family == AF_INET)
		{
			inet_ntop(AF_INET, &serv->addr.in.sin_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in.sin_port);
		}
		else
		{
			inet_ntop(AF_INET6, &serv->addr.in6.sin6_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in6.sin6_port);
		}
	}

	// Convert upstreamIP to lower case
	char *upstreamIP = strdup(dest);
	strtolower(upstreamIP);

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

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destinations are coming in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	// Use short-circuit evaluation to check if query is NULL
	if(query == NULL || (query->flags.complete && query->status != STATUS_CACHE))
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
		upstream->count++;
		upstream->lastQuery = double_time();
	}

	if(query->status == STATUS_CACHE)
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
	// if(query->status == STATUS_CACHE) { ... }
	// from above as otherwise this check will always
	// be negative
	query_set_status(query, STATUS_FORWARDED);

	// Release allocated memory
	free(upstreamIP);

	// Update query in database
	query_to_database(query);

	// Unlock shared memory
	unlock_shm();
}
