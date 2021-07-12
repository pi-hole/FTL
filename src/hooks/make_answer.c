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
#include "make_answer.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// next_iface
#include "iface.h"
// blocking_reason
#include "check_blocking.h"
// dns_name()
#include "dns_name.h"
// print_flags()
#include "print_flags.h"
// alladdr_extract_ip()
#include "alladdr_extract_ip.h"

// Static blocking metadata
static union all_addr null_addrp = {{ 0 }};
unsigned char force_next_DNS_reply = 0u;
const char *blockingreason = NULL;

// This is inspired by make_local_answer()
size_t _FTL_make_answer(struct dns_header *header, char *limit, const size_t len, int *ede,
                        const char *file, const int line)
{
	// Exit early if there are no questions in this query
	if(ntohs(header->qdcount) == 0)
		return 0;

	// Get question name
	char name[MAXDNAME] = { 0 };
	unsigned char *p = (unsigned char *)(header+1);
	if (!extract_name(header, len, &p, name, 1, 4))
		return 0;

	// Debug logging
	if(*ede != EDE_UNSET)
		log_debug(DEBUG_FLAGS, "Preparing reply for \"%s\", EDE: %s (%d)", dns_name(name), edestr(*ede), *ede);
	else
		log_debug(DEBUG_FLAGS, "Preparing reply for \"%s\", EDE: N/A", dns_name(name));

	// Get question type
	int qtype, flags;
	GETSHORT(qtype, p);

	// Set flag based on what we will reply with
	if(qtype == T_A)
		flags = F_IPV4; // A type
	else if(qtype == T_AAAA)
		flags = F_IPV6; // AAAA type
	else if(qtype == T_ANY)
		flags = F_IPV4 | F_IPV6; // ANY type
	else
		flags = F_NOERR; // empty record

	// Prepare answer records
	bool forced_ip = false;
	// Check first if we need to force our reply to something different than the
	// default/configured blocking mode. For instance, we need to force NXDOMAIN
	// for intercepted _esni.* queries.
	if(force_next_DNS_reply == REPLY_NXDOMAIN)
	{
		flags = F_NXDOMAIN;
		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_FLAGS, "Forced DNS reply to NXDOMAIN");
	}
	else if(force_next_DNS_reply == REPLY_REFUSED)
	{
		// Empty flags result in REFUSED
		flags = 0;
		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_FLAGS, "Forced DNS reply to REFUSED");

		// Set EDE code to blocked
		*ede = EDE_BLOCKED;
	}
	else if(force_next_DNS_reply == REPLY_IP)
	{
		// We do not need to change the flags here,
		// they are already properly set (F_IPV4 and/or F_IPV6)
		forced_ip = true;

		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_FLAGS, "Forced DNS reply to IP");
	}
	else
	{
		// Overwrite flags only if not replying with a forced reply
		if(config.blockingmode == MODE_NX)
		{
			// If we block in NXDOMAIN mode, we add the NEGATIVE response
			// and the NXDOMAIN flags
			flags = F_NXDOMAIN;
			log_debug(DEBUG_FLAGS, "Configured blocking mode is NXDOMAIN");
		}
		else if(config.blockingmode == MODE_NODATA ||
				(config.blockingmode == MODE_IP_NODATA_AAAA && (flags & F_IPV6)))
		{
			// If we block in NODATA mode or NODATA for AAAA queries, we apply
			// the NOERROR response flag. This ensures we're sending an empty response
			flags = F_NOERR;
			log_debug(DEBUG_FLAGS, "Configured blocking mode is NODATA%s",
			          config.blockingmode == MODE_IP_NODATA_AAAA ? "-IPv6" : "");
		}
	}

	// Debug logging
	if(config.debug & DEBUG_FLAGS)
		print_flags(flags, false);

	// Setup reply header
	setup_reply(header, flags, *ede);

	// Add flags according to current blocking mode
	// Set blocking_flags to F_HOSTS so dnsmasq logs blocked queries being answered from a specific source
	// (it would otherwise assume it knew the blocking status from cache which would prevent us from
	// printing the blocking source (blacklist, regex, gravity) in dnsmasq's log file, our pihole.log)
	flags |= F_HOSTS;

	// Skip questions so we can start adding answers (if applicable)
	if (!(p = skip_questions(header, len)))
		return 0;

	int trunc = 0;
	// Add A answer record if requested
	if(flags & F_IPV4)
	{
		union all_addr *addr;
		if(config.blockingmode == MODE_IP ||
		   config.blockingmode == MODE_IP_NODATA_AAAA ||
		   forced_ip)
			addr = &next_iface.addr4;
		else
			addr = &null_addrp;

		// Debug logging
		if(config.debug & DEBUG_QUERIES)
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			alladdr_extract_ip(addr, AF_INET, ip);
			log_debug(DEBUG_QUERIES, "  Adding RR: \"%s A %s\"", dns_name(name), ip);
		}

		// Add A resource record
		header->ancount = htons(ntohs(header->ancount) + 1);
		add_resource_record(header, limit, &trunc, sizeof(struct dns_header),
		                    &p, daemon->local_ttl, NULL, T_A, C_IN,
		                    (char*)"4", &addr->addr4);
		log_query(flags & ~F_IPV6, name, addr, (char*)blockingreason);
	}

	// Add AAAA answer record if requested
	if(flags & F_IPV6)
	{
		union all_addr *addr;
		if(config.blockingmode == MODE_IP ||
		   forced_ip)
			addr = &next_iface.addr6;
		else
			addr = &null_addrp;

		// Debug logging
		if(config.debug & DEBUG_QUERIES)
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			alladdr_extract_ip(addr, AF_INET6, ip);
			log_debug(DEBUG_QUERIES, "  Adding RR: \"%s AAAA %s\"", dns_name(name), ip);
		}

		// Add AAAA resource record
		header->ancount = htons(ntohs(header->ancount) + 1);
		add_resource_record(header, limit, &trunc, sizeof(struct dns_header),
		                    &p, daemon->local_ttl, NULL, T_AAAA, C_IN,
		                    (char*)"6", &addr->addr6);
		log_query(flags & ~F_IPV4, name, addr, (char*)blockingreason);
	}

	// Indicate if truncated (client should retry over TCP)
	if (trunc)
		header->hb3 |= HB3_TC;

	return p - (unsigned char *)header;
}
