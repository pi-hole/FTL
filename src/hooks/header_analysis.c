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
#include "header_analysis.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config.h"
// logg()
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// converttimeval()
#include "../timers.h"
// query_to_database()
#include "../database/query-table.h"
// query_blocked()
#include "query_blocked.h"
// query_set_reply()
#include "set_reply.h"

void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const int id, const char *file, const int line)
{
	// Analyze DNS header bits

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

	const double now = double_time();

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
	if(query == NULL)
	{
		// Memory error, skip this query
		unlock_shm();
		return;
	}

	// Get domain pointer
	domainsData *domain = getDomain(query->domainID, true);
	if(domain == NULL)
	{
		// Memory error, skip this query
		unlock_shm();
		return;
	}

	// Possible debugging information
	if(config.debug & DEBUG_QUERIES)
	{
		// Get domain name
		const char *domainname;
		if(domain != NULL)
			domainname = getstr(domain->domainpos);
		else
			domainname = "<cannot access domain struct>";

		logg("**** %s externally blocked (ID %i, FTL %i, %s:%i)", domainname, id, queryID, file, line);
	}

	// Store query as externally blocked
	clientsData *client = getClient(query->clientID, true);
	if(client != NULL)
		query_blocked(query, domain, client, STATUS_EXTERNAL_BLOCKED_NXRA);

	// Store reply type as replied with NXDOMAIN
	query_set_reply(F_NEG | F_NXDOMAIN, NULL, query, now);

	// Unlock shared memory
	unlock_shm();
}