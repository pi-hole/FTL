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
#include "detect_blocked_IP.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"

enum query_status detect_blocked_IP(const unsigned short flags, const union all_addr *addr, const queriesData *query, const domainsData *domain)
{
	// Compare returned IP against list of known blocking splash pages

	if (!addr)
	{
		return query->status;
	}

	// First, we check if we want to skip this result even before comparing against the known IPs
	if(flags & F_HOSTS || flags & F_REVERSE)
	{
		// Skip replies which originated locally. Otherwise, we would
		// count gravity.list blocked queries as externally blocked.
		// Also: Do not mark responses of PTR requests as externally blocked.
		const char *cause = (flags & F_HOSTS) ? "origin is HOSTS" : "query is PTR";
		log_debug(DEBUG_QUERIES, "Skipping detection of external blocking IP for ID %i as %s", query->id, cause);

		// Return early, do not compare against known blocking page IP addresses below
		return query->status;
	}

	// If received one of the following IPs as reply, OpenDNS
	// (Cisco Umbrella) blocked this query
	// See https://support.opendns.com/hc/en-us/articles/227986927-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses-
	// for a full list of these IP addresses
	in_addr_t ipv4Addr = ntohl(addr->addr4.s_addr);
	in_addr_t ipv6Addr = ntohl(addr->addr6.s6_addr32[3]);
	// Check for IP block 146.112.61.104 - 146.112.61.110
	if((flags & F_IPV4) && ipv4Addr >= 0x92703d68 && ipv4Addr <= 0x92703d6e)
	{
		if(config.debug & DEBUG_QUERIES)
		{
			char answer[ADDRSTRLEN]; answer[0] = '\0';
			inet_ntop(AF_INET, addr, answer, ADDRSTRLEN);
			log_debug(DEBUG_QUERIES, "Upstream responded with known blocking page (IPv4), ID %i:\n\t\"%s\" -> \"%s\"",
			          query->id, getstr(domain->domainpos), answer);
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_IP;
	}
	// Check for IP block :ffff:146.112.61.104 - :ffff:146.112.61.110
	else if(flags & F_IPV6 &&
	        addr->addr6.s6_addr32[0] == 0 &&
	        addr->addr6.s6_addr32[1] == 0 &&
	        addr->addr6.s6_addr32[2] == 0xffff0000 &&
	        ipv6Addr >= 0x92703d68 && ipv6Addr <= 0x92703d6e)
	{
		if(config.debug & DEBUG_QUERIES)
		{
			char answer[ADDRSTRLEN]; answer[0] = '\0';
			inet_ntop(AF_INET6, addr, answer, ADDRSTRLEN);
			log_debug(DEBUG_QUERIES, "Upstream responded with known blocking page (IPv6), ID %i:\n\t\"%s\" -> \"%s\"",
			          query->id, getstr(domain->domainpos), answer);
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_IP;
	}

	// If upstream replied with 0.0.0.0 or ::,
	// we assume that it filtered the reply as
	// nothing is reachable under these addresses
	else if(flags & F_IPV4 && ipv4Addr == 0)
	{
		log_debug(DEBUG_QUERIES, "Upstream responded with 0.0.0.0, ID %i:\n\t\"%s\" -> \"0.0.0.0\"",
		          query->id, getstr(domain->domainpos));

		// Update status
		return QUERY_EXTERNAL_BLOCKED_NULL;
	}
	else if(flags & F_IPV6 &&
	        addr->addr6.s6_addr32[0] == 0 &&
	        addr->addr6.s6_addr32[1] == 0 &&
	        addr->addr6.s6_addr32[2] == 0 &&
	        addr->addr6.s6_addr32[3] == 0)
	{
		log_debug(DEBUG_QUERIES, "Upstream responded with ::, ID %i:\n\t\"%s\" -> \"::\"",
		          query->id, getstr(domain->domainpos));

		// Update status
		return QUERY_EXTERNAL_BLOCKED_NULL;
	}

	// Nothing happened here
	return query->status;
}
