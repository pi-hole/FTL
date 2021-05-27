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
#include "query_in_progress.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// query_to_database()
#include "../database/query-table.h"

void FTL_query_in_progress(const int id)
{
	// Query (possibly from new source), but the same query may be in
	// progress from another source.

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
		// Memory error, skip this DNSSEC details
		unlock_shm();
		return;
	}

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(query->domainID, true);
		if(domain != NULL)
		{
			logg("**** query for %s is already in progress (ID %i)",
			     getstr(domain->domainpos), id);
		}
	}

	// Store status
	query_set_status(query, STATUS_IN_PROGRESS);

	// Update query in database
	query_to_database(query);

	// Unlock shared memory
	unlock_shm();
}
