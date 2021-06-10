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
#include "forwarding_failed.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// query_to_database()
#include "../database/query-table.h"

void FTL_forwarding_retried(const struct server *serv, const int oldID, const int newID, const bool dnssec)
{
	// Forwarding to upstream server failed

	if(oldID == newID)
	{
		log_debug(DEBUG_QUERIES, "%d: Ignoring self-retry", oldID);
		return;
	}

	// Lock shared memory
	lock_shm();

	// Try to obtain destination IP address if available
	char dest[ADDRSTRLEN];
	in_port_t upstreamPort = 53;
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

	// Convert upstream to lower case
	char *upstreamIP = strdup(dest);
	strtolower(upstreamIP);

	// Get upstream ID
	const int upstreamID = findUpstreamID(upstreamIP, upstreamPort);

	// Possible debugging information
	log_debug(DEBUG_QUERIES, "**** RETRIED query %i as %i to %s (ID %i)",
	          oldID, newID, dest, upstreamID);

	// Get upstream pointer
	upstreamsData* upstream = getUpstream(upstreamID, true);

	// Update counter
	if(upstream != NULL)
		upstream->failed++;

	// Search for corresponding query identified by ID
	// Retried DNSSEC queries are ignored, we have to flag themselves (newID)
	// Retried normal queries take over, we have to flag the original query (oldID)
	const int queryID = findQueryID(dnssec ? newID : oldID);
	if(queryID >= 0)
	{
		// Get query pointer
		queriesData* query = getQuery(queryID, true);

		// Set retried status
		if(query != NULL)
		{
			if(dnssec)
			{
				// There is no point in retrying the query when
				// we've already got an answer to this query,
				// but we're awaiting keys for DNSSEC
				// validation. We're retrying the DNSSEC query
				// instead
				query_set_status(query, STATUS_RETRIED_DNSSEC);
			}
			else
			{
				// Normal query retry due to answer not arriving
				// soon enough at the requestor
				query_set_status(query, STATUS_RETRIED);
			}
		}

		// Update query in database
		query_to_database(query);
	}

	// Clean up and unlock shared memory
	free(upstreamIP);

	unlock_shm();
	return;
}