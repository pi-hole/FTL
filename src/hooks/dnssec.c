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
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"

void FTL_dnssec(const char *arg, const union all_addr *addr, const int id, const char* file, const int line)
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
			log_debug(DEBUG_QUERIES, "**** DNSSEC %s is %s (ID %i, %s:%i)", getstr(domain->domainpos), arg, id, file, line);
		if(addr && addr->log.ede != EDE_UNSET) // This function is only called if (flags & F_SECSTAT)
			log_debug(DEBUG_QUERIES, "     EDE: %s (%d)", edestr(addr->log.ede), addr->log.ede);
	}

	// Store EDE
	if(addr && addr->log.ede != EDE_UNSET)
		query->ede = addr->log.ede;

	// Iterate through possible values
	if(strcmp(arg, "SECURE") == 0)
		query->dnssec = DNSSEC_SECURE;
	else if(strcmp(arg, "INSECURE") == 0)
		query->dnssec = DNSSEC_INSECURE;
	else if(strcmp(arg, "BOGUS") == 0)
		query->dnssec = DNSSEC_BOGUS;
	else if(strcmp(arg, "ABANDONED") == 0)
		query->dnssec = DNSSEC_ABANDONED;
	else
		log_warn("Ignored unkonwn DNSSEC status \"%s\"", arg);

	// Unlock shared memory
	unlock_shm();
}
