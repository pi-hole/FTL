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
#include "received_reply.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// query_set_reply()
#include "set_reply.h"
// converttimeval()
#include "../timers.h"
// query_to_database()
#include "../database/query-table.h"
// print_flags()
#include "print_flags.h"
// detect_blocked_IP()
#include "detect_blocked_IP.h"
// query_blocked()
#include "query_blocked.h"
// mysockaddr_extract_ip_port()
#include "mysockaddr_extract_ip_port.h"
// last_server
#include "header_analysis.h"

void FTL_reply(const unsigned int flags, const char *name, const union all_addr *addr,
               const char *arg, const int id, const char* file, const int line)
{
	// If domain is "pi.hole", we skip this query
	// We compare case-insensitive here
	// Hint: name can be NULL, e.g. for NODATA replies
	if(name != NULL && strcasecmp(name, "pi.hole") == 0)
		return;

	// Get response time
	double now = double_time();

	// Lock shared memory
	lock_shm();

	// Save status in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was "pi.hole"
		log_debug(DEBUG_QUERIES, "FTL_reply(): Query %i has not been found", id);
		unlock_shm();
		return;
	}

	// Check if this reply came from our local cache
	bool cached = false;
	if(!(flags & F_UPSTREAM))
	{
		cached = true;
		if((flags & F_HOSTS) || // local.list, hostname.list, /etc/hosts and others
		   ((flags & F_NAMEP) && (flags & F_DHCP)) || // DHCP server reply
		   (flags & F_FORWARD) || // cached answer to previously forwarded request
		   (flags & F_REVERSE) || // cached answer to reverse request (PTR)
		   (flags & F_RRNAME)) // cached answer to TXT query
		{
			; // Okay
		}
		else
			log_debug(DEBUG_FLAGS, "Unknown cache query");
	}

	// Possible debugging output
	if(config.debug & DEBUG_QUERIES)
	{
		// Determine returned result if available
		char dest[ADDRSTRLEN]; dest[0] = '\0';
		if(addr)
			inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);

		// Extract answer (used e.g. for detecting if a local config is a user-defined
		// wildcard blocking entry in form "server=/tobeblocked.com/")
		const char *answer = dest;
		if(flags & F_CNAME)
			answer = "(CNAME)";
		else if((flags & F_NEG) && (flags & F_NXDOMAIN))
			answer = "(NXDOMAIN)";
		else if(flags & F_NEG)
			answer = "(NODATA)";
		else if(flags & F_RCODE && addr != NULL)
		{
			unsigned int rcode = addr->log.rcode;
			if(rcode == REFUSED)
			{
				// This happens, e.g., in a "nowhere to forward to" situation
				answer = "REFUSED (nowhere to forward to)";
			}
			else if(rcode == SERVFAIL)
			{
				// This happens on upstream destionation errors
				answer = "SERVFAIL";
			}
		}
		else if(flags & F_NOEXTRA)
		{
			if(flags & F_KEYTAG)
				answer = "DNSKEY";
			else
				answer = arg; // e.g. "reply <TLD> is no DS"
		}

		if(cached || last_server.sa.sa_family == 0)
			// Log cache or upstream reply from unknown source
			log_debug(DEBUG_QUERIES, "**** got %s reply: %s is %s (ID %i, %s:%i)", cached ? "cache" : "upstream", name, answer, id, file, line);
		else
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			in_port_t port = 0;
			mysockaddr_extract_ip_port(&last_server, ip, &port);
			// Log server which replied to our request
			log_debug(DEBUG_QUERIES, "**** got %s reply from %s#%d: %s is %s (ID %i, %s:%i)",
			          cached ? "cache" : "upstream", ip, port, name, answer, id, file, line);
		}
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// We only process the first reply further in here
	// Check if reply type is still UNKNOWN
	if(query == NULL || query->reply != REPLY_UNKNOWN)
	{
		// Nothing to be done here
		unlock_shm();
		return;
	}

	if(addr && flags & (F_RCODE | F_SECSTAT) && addr->log.ede != EDE_UNSET)
	{
		query->ede = addr->log.ede;
		log_debug(DEBUG_QUERIES, "     EDE: %s (%d)", edestr(addr->log.ede), addr->log.ede);
	}

	// If this is an upstream response and the answering upstream is known
	// (may not be the case for internally generated DNSSEC queries), we
	// have to check if the first answering upstream server is also the
	// first one we sent the query to. If not, we need to change the
	// upstream server associated with this query to get accurate statistics
	if(!cached && last_server.sa.sa_family != 0)
	{
		char ip[ADDRSTRLEN+1] = { 0 };
		in_port_t port = 0;
		mysockaddr_extract_ip_port(&last_server, ip, &port);
		int upstreamID = findUpstreamID(ip, port);
		if(upstreamID != query->upstreamID)
		{
			if(config.debug & DEBUG_QUERIES)
			{
				upstreamsData *upstream = getUpstream(query->upstreamID, true);
				if(upstream)
				{
					const char *oldaddr = getstr(upstream->ippos);
					const in_port_t oldport = upstream->port;
					log_notice("Query ID %d: Associated upstream changed from %s#%d to %s#%d (replied earlier)",
					           id, oldaddr, oldport, ip, port);
				}
			}
			query->upstreamID = upstreamID;
		}
	}


	// Determine if this reply is an exact match for the queried domain
	const int domainID = query->domainID;

	// Get domain pointer
	domainsData* domain = getDomain(domainID, true);
	if(domain == NULL)
	{
		// Memory error, skip reply
		unlock_shm();
		return;
	}

	// This is a reply served from cache
	if(cached)
	{
		// Set status of this query
		query_set_status(query, QUERY_CACHE);

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

		unlock_shm();
		return;
	}

	// else: This is a reply from upstream
	// Check if this domain matches exactly
	const bool isExactMatch = strcmp_escaped(name, getstr(domain->domainpos));

	if((flags & F_CONFIG) && isExactMatch && !query->flags.complete)
	{
		// Answered from local configuration, might be a wildcard or user-provided

		// Answered from a custom (user provided) cache file or because
		// we're the authorative DNS server (e.g. DHCP server and this
		// is our own domain)
		query_set_status(query, QUERY_CACHE);

		// Save reply type and update individual reply counters
		query_set_reply(flags, addr, query, now);

		// Hereby, this query is now fully determined
		query->flags.complete = true;
	}
	else if((flags & F_FORWARD) && isExactMatch)
	{
		// Only proceed if query is not already known
		// to have been blocked by Quad9
		if(query->status != QUERY_EXTERNAL_BLOCKED_IP &&
		   query->status != QUERY_EXTERNAL_BLOCKED_NULL &&
		   query->status != QUERY_EXTERNAL_BLOCKED_NXRA)
		{
			// Save reply type and update individual reply counters
			query_set_reply(flags, addr, query, now);

			// Detect if returned IP indicates that this query was blocked
			const enum query_status new_status = detect_blocked_IP(flags, addr, query, domain);

			// Update status of this query if detected as external blocking
			if(new_status != query->status)
			{
				clientsData *client = getClient(query->clientID, true);
				if(client != NULL)
					query_blocked(query, domain, client, new_status);
			}
		}
	}
	else if(flags & F_REVERSE)
	{
		// isExactMatch is not used here as the PTR is special.
		// Example:
		// Question: PTR 8.8.8.8
		// will lead to:
		//   domain->domain = 8.8.8.8.in-addr.arpa
		// and will return
		//   name = google-public-dns-a.google.com
		// Hence, isExactMatch is always false

		// Save reply type and update individual reply counters
		query_set_reply(flags, addr, query, now);
	}
	else if(flags & F_NOEXTRA)
	{
		// This can be, for instance, a reply of type
		// "reply <TLD> is no DS"

		// If is a *positive* reply to a DNSSEC query (reply <TLD> is DS keytag 1234, algo 8, digest 2),
		// we overwrite flags to stort NODATA for this query
		if(!(flags & F_KEYTAG))
			query_set_reply(F_NEG, addr, query, now);
		else
			query_set_reply(flags, addr, query, now);
	}
	else if(isExactMatch && !query->flags.complete)
	{
		log_err("Unknown REPLY");
	}

	unlock_shm();
}
