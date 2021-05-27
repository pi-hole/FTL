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
#include "extract_question_flags.h"
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

unsigned int FTL_extract_question_flags(struct dns_header *header, const size_t qlen)
{
	// Create working pointer
	unsigned char *p = (unsigned char *)(header+1);
	uint16_t qtype, qclass;

	// Go through the questions
	for (uint16_t i = ntohs(header->qdcount); i != 0; i--)
	{
		// Prime dnsmasq flags
		int flags = RCODE(header) == NXDOMAIN ? F_NXDOMAIN : 0;

		// Extract name from this question
		char name[MAXDNAME];
		if (!extract_name(header, qlen, &p, name, 1, 4))
			break; // bad packet, go to fallback solution

		// Extract query type
		GETSHORT(qtype, p);
		GETSHORT(qclass, p);

		// Only further analyze IN questions here (not CHAOS, etc.)
		if (qclass != C_IN)
			continue;

		// Very simple decision: If the question is AAAA, the reply
		// should be IPv6. We use IPv4 in all other cases
		if(qtype == T_AAAA)
			flags |= F_IPV6;
		else
			flags |= F_IPV4;

		// Debug logging if enabled
		if(config.debug & DEBUG_QUERIES)
		{
			char *qtype_str = querystr(NULL, qtype);
			log_debug(DEBUG_QUERIES, "CNAME header: Question was <IN> %s %s", qtype_str, name);
		}

		return flags;
	}

	// Fall back to IPv4 (type A) when for the unlikely event that we cannot
	// find any questions in this header
	log_debug(DEBUG_QUERIES, "CNAME header: No valid IN question found in header");

	return F_IPV4;
}
