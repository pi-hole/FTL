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
#include "dnssec.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config.h"
// logg()
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"

void _FTL_dnssec(const int status, const int id, const char* file, const int line)
{
	// Process DNSSEC result for a domain

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
			logg("**** got DNSSEC details for %s: %i (ID %i, %s:%i)", getstr(domain->domainpos), status, id, file, line);
		}
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
