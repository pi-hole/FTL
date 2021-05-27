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
#include "multiple_replies.h"
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

void FTL_multiple_replies(const int id, int *firstID)
{
	// We are in the loop that iterates over all aggregated queries for the same
	// type + domain. Every query will receive the reply here so we need to
	// update the original queries to set their status

	// Don't process self-duplicates
	if(*firstID == id)
		return;

	// Skip if the original query was not found in FTL's memory
	if(*firstID == -2)
		return;

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		*firstID = -2;
		return;
	}

	if(*firstID == -1)
	{
		// This is not yet a duplicate, we just store the ID
		// of the successful reply here so we can get it quicker
		// during the next loop iterations
		unlock_shm();
		*firstID = queryID;
		return;
	}

	// Get (read-only) pointer of the query that contains all relevant
	// information (all others are mere duplicates and were only added to the
	// list of duplicates rather than havong been forwarded on their own)
	const queriesData* source_query = getQuery(*firstID, true);
	// Get query pointer of duplicated reply
	queriesData* duplicated_query = getQuery(queryID, true);

	if(duplicated_query == NULL || source_query == NULL)
	{
		// Memory error, skip this duplicate
		unlock_shm();
		return;
	}

	// Debug logging
	log_debug(DEBUG_QUERIES, "**** sending reply %d also to %d", *firstID, queryID);

	// Copy relevant information over
	duplicated_query->reply = source_query->reply;
	duplicated_query->dnssec = source_query->dnssec;
	duplicated_query->flags.complete = true;
	duplicated_query->CNAME_domainID = source_query->CNAME_domainID;

	// The original query may have been blocked during CNAME inspection,
	// correct status in this case
	if(source_query->status != STATUS_FORWARDED)
		query_set_status(duplicated_query, source_query->status);

	// Update duplicated query in database
	query_to_database(duplicated_query);

	// Unlock shared memory
	unlock_shm();
}
