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
#include "CNAME.h"
// force_next_DNS_reply
#include "iface.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config.h"
// logg()
#include "../log.h"
// lock_shm(), etc.
#include "../shmem.h"
// FTL_check_blocking()
#include "check_blocking.h"
// query_set_reply()
#include "set_reply.h"

bool _FTL_CNAME(const char *domain, const struct crec *cpp, const int id, const char* file, const int line)
{
	// Does the user want to skip deep CNAME inspection?
	if(!config.cname_inspection)
	{
		return false;
	}

	const double now = double_time();

	// Lock shared memory
	lock_shm();

	// Get CNAME destination and source (if applicable)
	const char *src = cpp != NULL ? cpp->flags & F_BIGNAME ? cpp->name.bname->name : cpp->name.sname : NULL;
	const char *dst = domain;

	// Save status and upstreamID in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was a PTR query
		// or "pi.hole" and we ignored them altogether
		unlock_shm();
		return false;
	}

	// Get query pointer so we can later extract the client requesting this domain for
	// the per-client blocking evaluation
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Nothing to be done here
		unlock_shm();
		return false;
	}

	// Example to make the terminology used in here clear:
	// CNAME abc -> 123
	// CNAME 123 -> 456
	// CNAME 456 -> 789
	// parent_domain: abc
	// child_domains: [123, 456, 789]

	// parent_domain = Domain at the top of the CNAME path
	// This is the domain which was queried first in this chain
	const int parent_domainID = query->domainID;

	// child_domain = Intermediate domain in CNAME path
	// This is the domain which was queried later in this chain
	char *child_domain = strdup(domain);
	// Convert to lowercase for matching
	strtolower(child_domain);
	const int child_domainID = findDomainID(child_domain, false);

	// Get client ID from the original query (the entire chain always
	// belongs to the same client)
	const int clientID = query->clientID;

	// Check per-client blocking for the child domain
	const char *blockingreason = NULL;
	const bool block = FTL_check_blocking(queryID, child_domainID, clientID, &blockingreason);

	// If we find during a CNAME inspection that we want to block the entire chain,
	// the originally queried domain itself was not counted as blocked. We have to
	// correct this when we are going to short-circuit the entire query
	if(block)
	{
		// Increase blocked count of parent domain
		domainsData* parent_domain = getDomain(parent_domainID, true);
		parent_domain->blockedcount++;

		// Store query response as CNAME type
		query_set_reply(F_CNAME, NULL, query, now);

		// Store domain that was the reason for blocking the entire chain
		query->CNAME_domainID = child_domainID;

		// Change blocking reason into CNAME-caused blocking
		if(query->status == STATUS_GRAVITY)
		{
			query_set_status(query, STATUS_GRAVITY_CNAME);
		}
		else if(query->status == STATUS_REGEX)
		{
			// Get parent and child DNS cache entries
			const int parent_cacheID = findCacheID(parent_domainID, clientID, query->type);
			const int child_cacheID = findCacheID(child_domainID, clientID, query->type);

			// Get cache pointers
			DNSCacheData *parent_cache = getDNSCache(parent_cacheID, true);
			DNSCacheData *child_cache = getDNSCache(child_cacheID, true);

			// Propagate ID of responsible regex up from the child to the parent domain
			if(parent_cache != NULL && child_cache != NULL)
			{
				child_cache->deny_regex_id = parent_cache->deny_regex_id;
			}

			// Set status
			query_set_status(query, STATUS_REGEX_CNAME);
		}
		else if(query->status == STATUS_DENYLIST)
		{
			// Only set status
			query_set_status(query, STATUS_DENYLIST_CNAME);
		}
	}

	// Debug logging for deep CNAME inspection (if enabled)
	if(config.debug & DEBUG_QUERIES)
	{
		if(src == NULL)
			logg("Query %d: CNAME %s", id, dst);
		else
			logg("Query %d: CNAME %s ---> %s", id, src, dst);
	}

	// Return result
	free(child_domain);
	unlock_shm();
	return block;
}
