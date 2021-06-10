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
#include "upstream_error.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"

void _FTL_upstream_error(const unsigned int rcode, const int id, const char* file, const int line)
{
	// Process upstream errors
	// Queries with error are those where the RCODE
	// in the DNS header is neither NOERROR nor NXDOMAIN.

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

		// Get domain name
		const char *domainname;
		if(domain != NULL)
			domainname = getstr(domain->domainpos);
		else
			domainname = "<cannot access domain struct>";

		log_debug(DEBUG_QUERIES, "**** got error report for %s: %s (ID %i, %s:%i)", domainname, rcodestr, id, file, line);

	}

	if(query->reply == REPLY_OTHER)
	{
		log_info("Found unknown rcode = %i", rcode);
	}

	// Unlock shared memory
	unlock_shm();
}
