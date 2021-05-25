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
#include "cache.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config.h"
// logg()
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// query_blocked()
#include "query_blocked.h"
// detect_blocked_IP()
#include "detect_blocked_IP.h"
// query_to_database()
#include "../database/query-table.h"
// print_flags()
#include "print_flags.h"
// query_set_reply()
#include "set_reply.h"

void _FTL_cache(const unsigned int flags, const char *name, const union all_addr *addr,
                const char *arg, const int id, const unsigned long ttl,
                const char *file, const int line)
{
	// Save that this query got answered from cache
	const double now = double_time();

	// If domain is "pi.hole", we skip this query
	// We compare case-insensitive here
	if(strcasecmp(name, "pi.hole") == 0)
	{
		return;
	}

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
	{
		// Obtain destination IP address if available for this query type
		char dest[ADDRSTRLEN]; dest[0] = '\0';
		if(addr)
		{
			inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
		}
		logg("**** got cache answer for %s / %s / %s (ID %i, %s:%i)", name, dest, arg, id, file, line);
		print_flags(flags);
	}

	// Lock shared memory
	lock_shm();

	if(((flags & F_HOSTS) && (flags & F_IMMORTAL)) ||
	   ((flags & F_NAMEP) && (flags & F_DHCP)) ||
	   (flags & F_FORWARD) ||
	   (flags & F_REVERSE) ||
	   (flags & F_RRNAME))
	{
		// Local list: /etc/hosts, /etc/pihole/local.list, etc.
		// or
		// DHCP server reply
		// or
		// cached answer to previously forwarded request

		// Determine requesttype
		if((flags & F_HOSTS) || // local.list, hostname.list, /etc/hosts and others
		  ((flags & F_NAMEP) && (flags & F_DHCP)) || // DHCP server reply
		   (flags & F_FORWARD) || // cached answer to previously forwarded request
		   (flags & F_REVERSE) || // cached answer to reverse request (PTR)
		   (flags & F_RRNAME)) // cached answer to TXT query
		{
			// We can handle this here
		}
		else
		{
			logg("*************************** unknown CACHE reply (1) ***************************");
			print_flags(flags);
			unlock_shm();
			return;
		}

		// Search query in FTL's query data
		const int queryID = findQueryID(id);
		if(queryID < 0)
		{
			// This may happen e.g. if the original query was a PTR query or "pi.hole"
			// as we ignore them altogether
			unlock_shm();
			return;
		}

		// Get query pointer
		queriesData *query = getQuery(queryID, true);

		// Skip this query if already marked as complete
		// Use short-circuit evaluation to check query if query is NULL
		if(query == NULL || query->flags.complete)
		{
			unlock_shm();
			return;
		}

		// Set status of this query
		query_set_status(query, STATUS_CACHE);
		query->ttl = ttl;

		domainsData *domain = getDomain(query->domainID, true);
		if(domain == NULL)
		{
			unlock_shm();
			return;
		}

		// Detect if returned IP indicates that this query was blocked
		const enum query_status new_status = detect_blocked_IP(flags, addr, query, domain);

		// Update status of this query if detected as external blocking
		if(new_status != query->status)
		{
			clientsData *client = getClient(query->clientID, true);
			if(client != NULL)
				query_blocked(query, domain, client, new_status);
		}

		// Save reply type and update individual reply counters
		query_set_reply(flags, addr, query, now);

		// Hereby, this query is now fully determined
		query->flags.complete = true;

		// Update query in database
		query_to_database(query);
	}
	else
	{
		logg("*************************** unknown CACHE reply (2) ***************************");
		print_flags(flags);
	}

	unlock_shm();
}
