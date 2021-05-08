/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "enums.h"
#include "dnsmasq_interface.h"
#include "shmem.h"
#include "overTime.h"
#include "database/common.h"
#include "database/database-thread.h"
#include "datastructure.h"
#include "database/gravity-db.h"
#include "setupVars.h"
#include "daemon.h"
#include "timers.h"
#include "gc.h"
#include "api/socket.h"
#include "regex_r.h"
#include "config.h"
#include "capabilities.h"
#include "resolve.h"
#include "files.h"
#include "log.h"
// Prototype of getCacheInformation()
#include "api/api.h"
// global variable daemonmode
#include "args.h"
// handle_realtime_signals()
#include "signals.h"
// atomic_flag_test_and_set()
#include <stdatomic.h>
// Eventqueue routines
#include "events.h"

// Private prototypes
static void print_flags(const unsigned int flags);
static void query_set_reply(const unsigned int flags, const union all_addr *addr,
                            queriesData* query, const struct timeval response);
static unsigned long converttimeval(const struct timeval time) __attribute__((const));
static enum query_status detect_blocked_IP(const unsigned short flags,
                                           const union all_addr *addr,
                                           const queriesData *query,
                                           const domainsData *domain);
static void query_blocked(queriesData* query,
                          domainsData* domain,
                          clientsData* client,
                          const unsigned char new_status);

// Static blocking metadata
static union all_addr null_addrp = {{ 0 }};
static unsigned char force_next_DNS_reply = 0u;

// Adds debug information to the regular pihole.log file
char debug_dnsmasq_lines = 0;

// Fork-private copy of the interface name the most recent query came from
static struct {
	char name[IFNAMSIZ];
	union all_addr addr4;
	union all_addr addr6;
} next_iface = {"", {{0}}, {{0}}};

unsigned char* pihole_privacylevel = &config.privacylevel;
const char flagnames[][12] = {"F_IMMORTAL ", "F_NAMEP ", "F_REVERSE ", "F_FORWARD ", "F_DHCP ", "F_NEG ", "F_HOSTS ", "F_IPV4 ", "F_IPV6 ", "F_BIGNAME ", "F_NXDOMAIN ", "F_CNAME ", "F_DNSKEY ", "F_CONFIG ", "F_DS ", "F_DNSSECOK ", "F_UPSTREAM ", "F_RRNAME ", "F_SERVER ", "F_QUERY ", "F_NOERR ", "F_AUTH ", "F_DNSSEC ", "F_KEYTAG ", "F_SECSTAT ", "F_NO_RR ", "F_IPSET ", "F_NOEXTRA ", "F_SERVFAIL", "F_RCODE"};

void FTL_iface(const int ifidx, const struct irec *ifaces)
{
	// Invalidate data we have from the last interface/query
	// Set addresses to 0.0.0.0 and ::, respectively
	memset(&next_iface.addr4, 0, sizeof(next_iface.addr4));
	memset(&next_iface.addr6, 0, sizeof(next_iface.addr6));

	// Copy overwrite addresses if configured via REPLY_ADDR4 and/or REPLY_ADDR6 settings
	if(config.reply_addr.overwrite_v4)
		memcpy(&next_iface.addr4, &config.reply_addr.v4, sizeof(config.reply_addr.v4));
	if(config.reply_addr.overwrite_v6)
		memcpy(&next_iface.addr6, &config.reply_addr.v6, sizeof(config.reply_addr.v6));

	// Use dummy when interface record is not available
	next_iface.name[0] = '-';
	next_iface.name[1] = '\0';

	// Return early when there is no interface available at this point
	if(ifidx == -1 || ifaces == NULL)
		return;

	// Determine addresses of this interface
	const struct irec *iface;
	bool haveIPv4 = false, haveGUAv6 = false, haveULAv6 = false;
	for (iface = ifaces; iface != NULL; iface = iface->next)
	{
		// If this interface has no name, we skip it
		if(iface->name == NULL)
			continue;

		// Check if this is the interface we want
		if(iface->index != ifidx)
			continue;

		// Copy interface name
		strncpy(next_iface.name, iface->name, sizeof(next_iface.name)-1);
		next_iface.name[sizeof(next_iface.name)-1] = '\0';

		// Check if this family type is overwritten by config settings
		const int family = iface->addr.sa.sa_family;
		if((config.reply_addr.overwrite_v4 && family == AF_INET) ||
		   (config.reply_addr.overwrite_v6 && family == AF_INET6))
			continue;

		bool isULA = false, isGUA = false;
		// Check if this address is different from 0000:0000:0000:0000:0000:0000:0000:0000
		if(family == AF_INET6 && memcmp(&next_iface.addr6.addr6, &iface->addr.in6.sin6_addr, sizeof(iface->addr.in6.sin6_addr)) != 0)
		{
			// Extract first byte
			// We do not directly access the underlying union as
			// MUSL defines it differently than GNU C
			uint8_t firstbyte;
			memcpy(&firstbyte, &iface->addr.in6.sin6_addr, 1);
		        // Global Unicast Address (2000::/3, RFC 4291)
			isGUA = (firstbyte & 0x70) == 0x20;
			// Unique Local Address   (fc00::/7, RFC 4193)
			isULA = (firstbyte & 0xfe) == 0xfc;
			// Store IPv6 address only if we don't already have a GUA or ULA address
			// This makes the preference:
			//  1. ULA
			//  2. GUA
			//  3. Link-local
			if((!haveGUAv6 && !haveULAv6) || (haveGUAv6 && isULA))
			{
				memcpy(&next_iface.addr6.addr6, &iface->addr.in6.sin6_addr, sizeof(iface->addr.in6.sin6_addr));
				if(isGUA)
					haveGUAv6 = true;
				else if(isULA)
					haveULAv6 = true;
			}
		}
		// Check if this address is different from 0.0.0.0
		else if(family == AF_INET && memcmp(&next_iface.addr4.addr4, &iface->addr.in.sin_addr, sizeof(iface->addr.in.sin_addr)) != 0)
		{
			haveIPv4 = true;
			// Store IPv4 address
			memcpy(&next_iface.addr4.addr4, &iface->addr.in.sin_addr, sizeof(iface->addr.in.sin_addr));
		}

		// Debug logging
		if(config.debug & DEBUG_NETWORKING)
		{
			char buffer[ADDRSTRLEN+1] = { 0 };
			if(family == AF_INET)
				inet_ntop(AF_INET, &iface->addr.in.sin_addr, buffer, ADDRSTRLEN);
			else if(family == AF_INET6)
				inet_ntop(AF_INET6, &iface->addr.in6.sin6_addr, buffer, ADDRSTRLEN);
			logg("Interface (%d) %s has IPv%i address %s %s", ifidx, next_iface.name,
				family == AF_INET ? 4 : 6, buffer, isGUA ? "(GUA)" : isULA ? "(ULA)" : "(other)");
		}


		// Exit loop early if we already have everything we need
		// (a valid IPv4 address + a valid ULA IPv6 address)
		if(haveIPv4 && haveULAv6)
			break;
	}
}

static bool check_domain_blocked(const char *domain, const int clientID,
                                 clientsData *client, queriesData *query, DNSCacheData *dns_cache,
                                 const char **blockingreason, unsigned char *new_status)
{
	// Check domains against exact blacklist
	// Skipped when the domain is whitelisted
	bool blockDomain = false;
	if(in_blacklist(domain, client))
	{
		// We block this domain
		blockDomain = true;
		*new_status = QUERY_BLACKLIST;
		*blockingreason = "exactly blacklisted";

		// Mark domain as exactly blacklisted for this client
		dns_cache->blocking_status = BLACKLIST_BLOCKED;
		return true;
	}

	// Check domains against gravity domains
	// Skipped when the domain is whitelisted or blocked by exact blacklist
	if(!query->flags.whitelisted && !blockDomain &&
	   in_gravity(domain, client))
	{
		// We block this domain
		blockDomain = true;
		*new_status = QUERY_GRAVITY;
		*blockingreason = "gravity blocked";

		// Mark domain as gravity blocked for this client
		dns_cache->blocking_status = GRAVITY_BLOCKED;
		return true;
	}

	// Check domain against blacklist regex filters
	// Skipped when the domain is whitelisted or blocked by exact blacklist or gravity
	int regex_idx = 0;
	if(!query->flags.whitelisted && !blockDomain &&
	   (regex_idx = match_regex(domain, dns_cache, client->id, REGEX_BLACKLIST, false)) > -1)
	{
		// We block this domain
		blockDomain = true;
		*new_status = QUERY_REGEX;
		*blockingreason = "regex blacklisted";

		// Mark domain as regex matched for this client
		dns_cache->blocking_status = REGEX_BLOCKED;
		dns_cache->black_regex_idx = regex_idx;
		return true;
	}

	// Not blocked
	return false;
}

static bool _FTL_check_blocking(int queryID, int domainID, int clientID, const char **blockingreason,
                                const char* file, const int line)
{
	// Only check blocking conditions when global blocking is enabled
	if(blockingstatus == BLOCKING_DISABLED)
	{
		return false;
	}

	// Get query, domain and client pointers
	queriesData* query  = getQuery(queryID,   true);
	domainsData* domain = getDomain(domainID, true);
	clientsData* client = getClient(clientID, true);
	unsigned int cacheID = findCacheID(domainID, clientID, query->type);
	DNSCacheData *dns_cache = getDNSCache(cacheID, true);
	if(query == NULL || domain == NULL || client == NULL || dns_cache == NULL)
	{
		// Encountered memory error, skip query
		logg("WARN: No memory available, skipping query analysis");
		return false;
	}

	// Skip the entire chain of tests if we already know the answer for this
	// particular client
	unsigned char blockingStatus = dns_cache->blocking_status;
	char *domainstr = (char*)getstr(domain->domainpos);
	switch(blockingStatus)
	{
		case UNKNOWN_BLOCKED:
			// New domain/client combination.
			// We have to go through all the tests below
			if(config.debug & DEBUG_QUERIES)
			{
				logg("%s is not known", domainstr);
			}

			break;

		case BLACKLIST_BLOCKED:
			// Known as exactly blacklistes, we
			// return this result early, skipping
			// all the lengthy tests below
			*blockingreason = "exactly blacklisted";
			if(config.debug & DEBUG_QUERIES)
			{
				logg("%s is known as %s", domainstr, *blockingreason);
			}

			// Do not block if the entire query is to be permitted
			// as something along the CNAME path hit the whitelist
			if(!query->flags.whitelisted)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				query_blocked(query, domain, client, QUERY_BLACKLIST);
				return true;
			}
			break;

		case GRAVITY_BLOCKED:
			// Known as gravity blocked, we
			// return this result early, skipping
			// all the lengthy tests below
			*blockingreason = "gravity blocked";
			if(config.debug & DEBUG_QUERIES)
			{
				logg("%s is known as %s", domainstr, *blockingreason);
			}

			// Do not block if the entire query is to be permitted
			// as sometving along the CNAME path hit the whitelist
			if(!query->flags.whitelisted)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				query_blocked(query, domain, client, QUERY_GRAVITY);
				return true;
			}
			break;

		case REGEX_BLOCKED:
			// Known as regex blacklisted, we
			// return this result early, skipping
			// all the lengthy tests below
			*blockingreason = "regex blacklisted";
			if(config.debug & DEBUG_QUERIES)
			{
				logg("%s is known as %s", domainstr, *blockingreason);
				force_next_DNS_reply = dns_cache->force_reply;
			}

			// Do not block if the entire query is to be permitted
			// as sometving along the CNAME path hit the whitelist
			if(!query->flags.whitelisted)
			{
				query_blocked(query, domain, client, QUERY_REGEX);
				return true;
			}
			break;

		case WHITELISTED:
			// Known as whitelisted, we
			// return this result early, skipping
			// all the lengthy tests below
			if(config.debug & DEBUG_QUERIES)
			{
				logg("%s is known as not to be blocked (whitelisted)", domainstr);
			}

			query->flags.whitelisted = true;

			return false;
			break;

		case NOT_BLOCKED:
			// Known as not blocked, we
			// return this result early, skipping
			// all the lengthy tests below
			if(config.debug & DEBUG_QUERIES)
			{
				logg("%s is known as not to be blocked", domainstr);
			}

			return false;
			break;
	}

	// Skip all checks and continue if we hit already at least one whitelist in the chain
	if(query->flags.whitelisted)
	{
		if(config.debug & DEBUG_QUERIES)
		{
			logg("Query is permitted as at least one whitelist entry matched");
		}
		return false;
	}

	// Make a local copy of the domain string. The  string memory may get
	// reorganized in the following. We cannot expect domainstr to remain
	// valid for all time.
	domainstr = strdup(domainstr);
	const char *blockedDomain = domainstr;

	// Check whitelist (exact + regex) for match
	query->flags.whitelisted = in_whitelist(domainstr, dns_cache, client);

	bool blockDomain = false;
	unsigned char new_status = QUERY_UNKNOWN;

	// Check blacklist (exact + regex) and gravity for queried domain
	if(!query->flags.whitelisted)
	{
		blockDomain = check_domain_blocked(domainstr, clientID, client, query, dns_cache, blockingreason, &new_status);
	}

	// Check blacklist (exact + regex) and gravity for _esni.domain if enabled (defaulting to true)
	if(config.block_esni && !query->flags.whitelisted && !blockDomain && strncasecmp(domainstr, "_esni.", 6u) == 0)
	{
		blockDomain = check_domain_blocked(domainstr + 6u, clientID, client, query, dns_cache, blockingreason, &new_status);

		if(blockDomain)
		{
			// Truncate "_esni." from queried domain if the parenting domain was the reason for blocking this query
			blockedDomain = domainstr + 6u;
			// Force next DNS reply to be NXDOMAIN for _esni.* queries
			force_next_DNS_reply = NXDOMAIN;
			dns_cache->force_reply = NXDOMAIN;
		}
	}

	// Common actions regardless what the possible blocking reason is
	if(blockDomain)
	{
		// Adjust counters
		query_blocked(query, domain, client, new_status);

		// Debug output
		if(config.debug & DEBUG_QUERIES)
			logg("Blocking %s as %s is %s", domainstr, blockedDomain, *blockingreason);
	}
	else
	{
		// Explicitly mark as not blocked to skip the entire
		// gravity/blacklist chain when the same client asks
		// for the same domain in the future. Explicitly store
		// domain as whitelisted if this is the case
		dns_cache->blocking_status = query->flags.whitelisted ? WHITELISTED : NOT_BLOCKED;
	}

	free(domainstr);
	return blockDomain;
}


bool _FTL_CNAME(const char *domain, const struct crec *cpp, const int id, const char* file, const int line)
{
	// Does the user want to skip deep CNAME inspection?
	if(!config.cname_inspection)
	{
		return false;
	}

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
	queriesData* query = getQuery(queryID, true);
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
		struct timeval response;
		gettimeofday(&response, 0);
		query_set_reply(F_CNAME, NULL, query, response);

		// Store domain that was the reason for blocking the entire chain
		query->CNAME_domainID = child_domainID;

		// Change blocking reason into CNAME-caused blocking
		if(query->status == QUERY_GRAVITY)
		{
			query_set_status(query, QUERY_GRAVITY_CNAME);
		}
		else if(query->status == QUERY_REGEX)
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
				child_cache->black_regex_idx = parent_cache->black_regex_idx;
			}

			// Set status
			query_set_status(query, QUERY_REGEX_CNAME);
		}
		else if(query->status == QUERY_BLACKLIST)
		{
			// Only set status
			query_set_status(query, QUERY_BLACKLIST_CNAME);
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


bool _FTL_new_query(const unsigned int flags, const char *name,
                    const char **blockingreason, union mysockaddr *addr,
                    const char *types, const unsigned short qtype, const int id,
                    const ednsData *edns, const enum protocol proto,
                    const char* file, const int line)
{
	// Create new query in data structure

	// Get timestamp
	const time_t querytimestamp = time(NULL);

	// Save request time
	struct timeval request;
	gettimeofday(&request, 0);

	// Determine query type
	enum query_types querytype;
	switch(qtype)
	{
		case T_A:
			querytype = TYPE_A;
			break;
		case T_AAAA:
			querytype = TYPE_AAAA;
			break;
		case T_ANY:
			querytype = TYPE_ANY;
			break;
		case T_SRV:
			querytype = TYPE_SRV;
			break;
		case T_SOA:
			querytype = TYPE_SOA;
			break;
		case T_PTR:
			querytype = TYPE_PTR;
			break;
		case T_TXT:
			querytype = TYPE_TXT;
			break;
		case T_NAPTR:
			querytype = TYPE_NAPTR;
			break;
		case T_MX:
			querytype = TYPE_MX;
			break;
		case T_DS:
			querytype = TYPE_DS;
			break;
		case T_RRSIG:
			querytype = TYPE_RRSIG;
			break;
		case T_DNSKEY:
			querytype = TYPE_DNSKEY;
			break;
		case T_NS:
			querytype = TYPE_NS;
			break;
		case 64: // Scn. 2 of https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
			querytype = TYPE_SVCB;
			break;
		case 65: // Scn. 2 of https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
			querytype = TYPE_HTTPS;
			break;
		default:
			querytype = TYPE_OTHER;
			break;
	}

	// Skip AAAA queries if user doesn't want to have them analyzed
	if(!config.analyze_AAAA && querytype == TYPE_AAAA)
	{
		if(config.debug & DEBUG_QUERIES)
			logg("Not analyzing AAAA query");
		return false;
	}

	// If domain is "pi.hole" we skip this query
	if(strcasecmp(name, "pi.hole") == 0)
		return false;

	// Convert domain to lower case
	char *domainString = strdup(name);
	strtolower(domainString);

	// Get client IP address
	// The requestor's IP address can be rewritten using EDNS(0) client
	// subnet (ECS) data), however, we do not rewrite the IPs ::1 and
	// 127.0.0.1 to avoid queries originating from localhost of the
	// *distant* machine as queries coming from the *local* machine
	const sa_family_t family = addr->sa.sa_family;
	char clientIP[ADDRSTRLEN+1] = { 0 };
	if(config.edns0_ecs && edns->client_set)
	{
		// Use ECS provided client
		strncpy(clientIP, edns->client, ADDRSTRLEN);
		clientIP[ADDRSTRLEN] = '\0';
	}
	else
	{
		// Use original requestor
		inet_ntop(family,
		          family == AF_INET ?
		             (union mysockaddr*)&addr->in.sin_addr :
				(union mysockaddr*)&addr->in6.sin6_addr,
		          clientIP, ADDRSTRLEN);
	}

	// Check if user wants to skip queries coming from localhost
	if(config.ignore_localhost &&
	   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
	{
		free(domainString);
		return false;
	}

	// Lock shared memory
	lock_shm();
	const int queryID = counters->queries;

	// Find client IP
	const int clientID = findClientID(clientIP, true, false);

	// Get client pointer
	clientsData* client = getClient(clientID, true);
	if(client == NULL)
	{
		// Encountered memory error, skip query
		// Free allocated memory
		free(domainString);
		// Release thread lock
		unlock_shm();
		return false;
	}

	// Check rate-limit for this client
	if(config.rate_limit.count > 0 &&
	   ++client->rate_limit > config.rate_limit.count)
	{
		if(config.debug & DEBUG_QUERIES)
		{
			logg("Rate-limiting %s %s query \"%s\" from %s:%s",
			     proto == TCP ? "TCP" : "UDP",
			     types, domainString, next_iface.name, clientIP);
		}

		// Block this query
		force_next_DNS_reply = REFUSED;

		// Do not further process this query, Pi-hole has never seen it
		unlock_shm();
		return true;
	}

	// Log new query if in debug mode
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** new %s %s query \"%s\" from %s:%s (ID %i, FTL %i, %s:%i)",
		     proto == TCP ? "TCP" : "UDP",
		     types, domainString, next_iface.name, clientIP, id, queryID, file, line);
	}

	// Update counters
	counters->querytype[querytype-1]++;

	// Update overTime
	const unsigned int timeidx = getOverTimeID(querytimestamp);

	// Skip rest of the analysis if this query is not of type A or AAAA
	// but user wants to see only A and AAAA queries (pre-v4.1 behavior)
	if(config.analyze_only_A_AAAA && querytype != TYPE_A && querytype != TYPE_AAAA)
	{
		// Don't process this query further here, we already counted it
		if(config.debug & DEBUG_QUERIES) logg("Notice: Skipping new query: %s (%i)", types, id);
		free(domainString);
		unlock_shm();
		return false;
	}

	// Go through already knows domains and see if it is one of them
	const int domainID = findDomainID(domainString, true);

	// Save everything
	queriesData* query = getQuery(queryID, false);
	if(query == NULL)
	{
		// Encountered memory error, skip query
		logg("WARN: No memory available, skipping query analysis");
		// Free allocated memory
		free(domainString);
		// Release thread lock
		unlock_shm();
		return false;
	}

	// Fill query object with available data
	query->magic = MAGICBYTE;
	query->timestamp = querytimestamp;
	query->type = querytype;
	query->qtype = qtype;
	query->id = id; // Has to be set before calling query_set_status()

	// This query is unknown as long as no reply has been found and analyzed
	counters->status[QUERY_UNKNOWN]++;
	query_set_status(query, QUERY_UNKNOWN);
	query->domainID = domainID;
	query->clientID = clientID;
	query->timeidx = timeidx;
	// Initialize database rowID with zero, will be set when the query is stored in the long-term DB
	query->db = 0;
	query->flags.complete = false;
	query->response = converttimeval(request);
	// Initialize reply type
	query->reply = REPLY_UNKNOWN;
	// Store DNSSEC result for this domain
	query->dnssec = DNSSEC_UNSPECIFIED;
	query->CNAME_domainID = -1;
	// This query is not yet known ad forwarded or blocked
	query->flags.blocked = false;
	query->flags.whitelisted = false;

	// Indicator that this query was not forwarded so far
	query->upstreamID = -1;

	// Check and apply possible privacy level rules
	// The currently set privacy level (at the time the query is
	// generated) is stored in the queries structure
	query->privacylevel = config.privacylevel;

	// Increase DNS queries counter
	counters->queries++;

	// Update overTime data
	overTime[timeidx].total++;

	// Update overTime data structure with the new client
	change_clientcount(client, 0, 0, timeidx, 1);

	// Set lastQuery timer and add one query for network table
	client->lastQuery = querytimestamp;
	client->numQueriesARP++;

	// Process interface information of client (if available)
	// Skip interface name length 1 to skip "-". No real interface should
	// have a name with a length of 1...
	if(strlen(next_iface.name) > 1)
	{
		if(client->ifacepos == 0u)
		{
			// Store in the client data if unknown so far
			client->ifacepos = addstr(next_iface.name);
		}
		else
		{
			// Check if this is still the same interface or
			// if the client moved to another interface
			// (may require group re-processing)
			const char *oldiface = getstr(client->ifacepos);
			if(strcasecmp(oldiface, next_iface.name) != 0)
			{
				if(config.debug & DEBUG_CLIENTS)
				{
					const char *clientName = getstr(client->namepos);
					logg("Client %s (%s) changed interface: %s -> %s",
					     clientIP, clientName, oldiface, next_iface.name);
				}

				gravityDB_reload_groups(client);
			}
		}
	}

	// Set client MAC address from EDNS(0) information (if available)
	if(config.edns0_ecs && edns->mac_set)
	{
		memcpy(client->hwaddr, edns->mac_byte, 6);
		client->hwlen = 6;
	}

	// Try to obtain MAC address from dnsmasq's cache (also asks the kernel)
	if(client->hwlen < 1)
	{
		client->hwlen = find_mac(addr, client->hwaddr, 1, time(NULL));
		if(config.debug & DEBUG_ARP)
		{
			if(client->hwlen == 6)
				logg("find_mac(\"%s\") returned hardware address "
				     "%02X:%02X:%02X:%02X:%02X:%02X", clientIP,
				     client->hwaddr[0], client->hwaddr[1], client->hwaddr[2],
				     client->hwaddr[3], client->hwaddr[4], client->hwaddr[5]);
			else
				logg("find_mac(\"%s\") returned %i bytes of data",
				     clientIP, client->hwlen);
		}
	}

	bool blockDomain = FTL_check_blocking(queryID, domainID, clientID, blockingreason);

	// Free allocated memory
	free(domainString);

	// Release thread lock
	unlock_shm();

	return blockDomain;
}

void _FTL_get_blocking_metadata(union all_addr **addrp, unsigned int *flags, const char* file, const int line)
{
	// Check first if we need to force our reply to something different than the
	// default/configured blocking mode. For instance, we need to force NXDOMAIN
	// for intercepted _esni.* queries.
	if(force_next_DNS_reply == NXDOMAIN)
	{
		*flags = F_NXDOMAIN;
		// Reset DNS reply forcing
		force_next_DNS_reply = 0u;
		return;
	}
	else if(force_next_DNS_reply == REFUSED)
	{
		// Empty flags result in REFUSED
		*flags = 0;
		// Reset DNS reply forcing
		force_next_DNS_reply = 0u;
		return;
	}

	// Add flags according to current blocking mode
	// We bit-add here as flags already contains either F_IPV4 or F_IPV6
	// Set blocking_flags to F_HOSTS so dnsmasq logs blocked queries being answered from a specific source
	// (it would otherwise assume it knew the blocking status from cache which would prevent us from
	// printing the blocking source (blacklist, regex, gravity) in dnsmasq's log file, our pihole.log)
	*flags |= F_HOSTS;

	if(*flags & F_IPV6)
	{
		// Pass blocking IPv6 address
		if(config.blockingmode == MODE_IP)
			*addrp = &next_iface.addr6;
		else
			*addrp = &null_addrp;
	}
	else
	{
		// Pass blocking IPv4 address
		if(config.blockingmode == MODE_IP || config.blockingmode == MODE_IP_NODATA_AAAA)
			*addrp = &next_iface.addr4;
		else
			*addrp = &null_addrp;
	}

	if(config.blockingmode == MODE_NX)
	{
		// If we block in NXDOMAIN mode, we add the NEGATIVE response
		// and the NXDOMAIN flags
		*flags = F_NXDOMAIN;
	}
	else if(config.blockingmode == MODE_NODATA ||
	       (config.blockingmode == MODE_IP_NODATA_AAAA && (*flags & F_IPV6)))
	{
		// If we block in NODATA mode or NODATA for AAAA queries, we apply
		// the NOERROR response flag. This ensures we're sending an empty response
		*flags = F_NOERR;
	}
}

void _FTL_forwarded(const unsigned int flags, const char *name, const struct server *serv, const int id,
                    const char* file, const int line)
{
	// Save that this query got forwarded to an upstream server

	// Lock shared memory
	lock_shm();

	// Get forward destination IP address and port
	in_port_t upstreamPort = 53;
	char dest[ADDRSTRLEN];
	// If addr == NULL, we will only duplicate an empty string instead of uninitialized memory
	dest[0] = '\0';
	if(serv != NULL)
	{
		if(serv->addr.sa.sa_family == AF_INET)
		{
			inet_ntop(AF_INET, &serv->addr.in.sin_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in.sin_port);
		}
		else
		{
			inet_ntop(AF_INET6, &serv->addr.in6.sin6_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in6.sin6_port);
		}
	}

	// Convert upstreamIP to lower case
	char *upstreamIP = strdup(dest);
	strtolower(upstreamIP);

	// Debug logging
	if(config.debug & DEBUG_QUERIES)
		logg("**** forwarded %s to %s#%u (ID %i, %s:%i)",
		     name, upstreamIP, upstreamPort, id, file, line);

	// Save status and upstreamID in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was a PTR query or "pi.hole"
		// as we ignore them altogether
		free(upstreamIP);
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destinations are coming in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	// Use short-circuit evaluation to check if query is NULL
	if(query == NULL || (query->flags.complete && query->status != QUERY_CACHE))
	{
		free(upstreamIP);
		unlock_shm();
		return;
	}

	// Get ID of upstream destination, create new upstream record
	// if not found in current data structure
	const int upstreamID = findUpstreamID(upstreamIP, upstreamPort);
	query->upstreamID = upstreamID;

	upstreamsData *upstream = getUpstream(upstreamID, true);
	if(upstream != NULL)
	{
		upstream->count++;
		upstream->lastQuery = time(NULL);
	}

	if(query->status == QUERY_CACHE)
	{
		// Detect if we cached the <CNAME> but need to ask the upstream
		// servers for the actual IPs now, we remove this query from the
		// counters for cache replied queries as we had to forward a
		// request for it. Example:
		// Assume a domain a.com is a CNAME which is cached and has a very
		// long TTL. It point to another domain server.a.com which has an
		// A record but this has a much lower TTL.
		// If you now query a.com and then again after some time, you end
		// up in a situation where dnsmasq can answer the first level of
		// the DNS result (the CNAME) from cache, hence the status of this
		// query is marked as "answered from cache" in FTLDNS. However, for
		// server.a.com wit the much shorter TTL, we still have to forward
		// something and ask the upstream server for the final IP address.

		// Correct reply timer
		struct timeval response;
		gettimeofday(&response, 0);
		// Reset timer, shift slightly into the past to acknowledge the time
		// FTLDNS needed to look up the CNAME in its cache
		query->response = converttimeval(response) - query->response;
	}
	else
	{
		// Normal forwarded query (status is set below)
		// Hereby, this query is now fully determined
		query->flags.complete = true;
	}

	// Set query status to forwarded only after the
	// if(query->status == QUERY_CACHE) { ... }
	// from above as otherwise this check will always
	// be negative
	query_set_status(query, QUERY_FORWARDED);

	// Release allocated memory
	free(upstreamIP);

	// Unlock shared memory
	unlock_shm();
}

void FTL_dnsmasq_reload(void)
{
	// This function is called by the dnsmasq code on receive of SIGHUP
	// *before* clearing the cache and rereading the lists
	logg("Reloading DNS cache");

	// Request reload the privacy level
	set_event(RELOAD_PRIVACY_LEVEL);

	// Inspect 01-pihole.conf to see if Pi-hole blocking is enabled,
	// i.e. if /etc/pihole/gravity.list is sourced as addn-hosts file
	check_blocking_status();

	// Reread pihole-FTL.conf to see which blocking mode the user wants to use
	// It is possible to change the blocking mode here as we anyhow clear the
	// cache and reread all blocking lists
	// Passing NULL to this function means it has to open the config file on
	// its own behalf (on initial reading, the config file is already opened)
	get_blocking_mode(NULL);

	// Reread pihole-FTL.conf to see which debugging flags are set
	read_debuging_settings(NULL);

	// Gravity database updates
	// - (Re-)open gravity database connection
	// - Get number of blocked domains
	// - Read and compile regex filters (incl. per-client)
	// - Flush FTL's DNS cache
	set_event(RELOAD_GRAVITY);

	// Print current set of capabilities if requested via debug flag
	if(config.debug & DEBUG_CAPS)
		check_capabilities();

	// Set resolver as ready
	resolver_ready = true;
}

void _FTL_reply(const unsigned int flags, const char *name, const union all_addr *addr, const int id,
                const char* file, const int line)
{
	// Lock shared memory
	lock_shm();

	// Determine returned result if available
	char dest[ADDRSTRLEN]; dest[0] = '\0';
	if(addr)
	{
		inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	}

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

	// Possible debugging output
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** got reply %s is %s (ID %i, %s:%i)", name, answer, id, file, line);
		print_flags(flags);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Save status in corresponding query identified by dnsmasq's ID
	const int i = findQueryID(id);
	if(i < 0)
	{
		// This may happen e.g. if the original query was "pi.hole"
		if(config.debug & DEBUG_QUERIES) logg("FTL_reply(): Query %i has not been found", id);
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(i, true);

	// Check if reply time is still unknown
	// We only process the first reply in here
	// Use short-circuit evaluation to check if query is NULL
	if(query == NULL || query->reply != REPLY_UNKNOWN)
	{
		// Nothing to be done here
		unlock_shm();
		return;
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
		query_set_reply(flags, addr, query, response);

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
			query_set_reply(flags, addr, query, response);

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
		query_set_reply(flags, addr, query, response);
	}
	else if(isExactMatch && !query->flags.complete)
	{
		logg("*************************** unknown REPLY ***************************");
		print_flags(flags);
	}

	unlock_shm();
}

static enum query_status detect_blocked_IP(const unsigned short flags, const union all_addr *addr, const queriesData *query, const domainsData *domain)
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
		if(config.debug & DEBUG_QUERIES)
		{
			const char *cause = (flags & F_HOSTS) ? "origin is HOSTS" : "query is PTR";
			logg("Skipping detection of external blocking IP for ID %i as %s", query->id, cause);
		}

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
			logg("Upstream responded with known blocking page (IPv4), ID %i:\n\t\"%s\" -> \"%s\"",
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
			logg("Upstream responded with known blocking page (IPv6), ID %i:\n\t\"%s\" -> \"%s\"",
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
		if(config.debug & DEBUG_QUERIES)
		{
			logg("Upstream responded with 0.0.0.0, ID %i:\n\t\"%s\" -> \"0.0.0.0\"",
			     query->id, getstr(domain->domainpos));
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_NULL;
	}
	else if(flags & F_IPV6 &&
	        addr->addr6.s6_addr32[0] == 0 &&
	        addr->addr6.s6_addr32[1] == 0 &&
	        addr->addr6.s6_addr32[2] == 0 &&
	        addr->addr6.s6_addr32[3] == 0)
	{
		if(config.debug & DEBUG_QUERIES)
		{
			logg("Upstream responded with ::, ID %i:\n\t\"%s\" -> \"::\"",
			     query->id, getstr(domain->domainpos));
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_NULL;
	}

	// Nothing happened here
	return query->status;
}

void _FTL_cache(const unsigned int flags, const char *name, const union all_addr *addr,
                const char *arg, const int id, const char* file, const int line)
{
	// Save that this query got answered from cache

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

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

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
		query_set_status(query, QUERY_CACHE);

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
		query_set_reply(flags, addr, query, response);

		// Hereby, this query is now fully determined
		query->flags.complete = true;
	}
	else
	{
		logg("*************************** unknown CACHE reply (2) ***************************");
		print_flags(flags);
	}
	unlock_shm();
}

static void query_blocked(queriesData* query, domainsData* domain, clientsData* client, const enum query_status new_status)
{
	// Get response time
	int blocking_flags = 0;
	struct timeval response;
	gettimeofday(&response, 0);
	query_set_reply(blocking_flags, NULL, query, response);

	// Adjust counters if we recorded a non-blocking status
	if(query->status == QUERY_FORWARDED)
	{
		// Get forward pointer
		upstreamsData* upstream = getUpstream(query->upstreamID, true);
		if(upstream != NULL)
			upstream->count--;
	}
	else if(is_blocked(query->status))
	{
		// Already a blocked query, no need to change anything
		return;
	}

	// Count as blocked query
	if(domain != NULL)
		domain->blockedcount++;
	if(client != NULL)
		change_clientcount(client, 0, 1, -1, 0);

	// Update status
	query_set_status(query, new_status);
	query->flags.blocked = true;
}

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

		logg("**** got error report for %s: %s (ID %i, %s:%i)", domainname, rcodestr, id, file, line);

		if(query->reply == REPLY_OTHER)
		{
			logg("Unknown rcode = %i", rcode);
		}
	}

	// Unlock shared memory
	unlock_shm();
}

void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const int id, const char* file, const int line)
{
	// Analyze DNS header bits

	// Check if RA bit is unset in DNS header and rcode is NXDOMAIN
	// If the response code (rcode) is NXDOMAIN, we may be seeing a response from
	// an externally blocked query. As they are not always accompany a necessary
	// SOA record, they are not getting added to our cache and, therefore,
	// FTL_reply() is never getting called from within the cache routines.
	// Hence, we have to store the necessary information about the NXDOMAIN
	// reply already here.
	if((header4 & 0x80) || rcode != NXDOMAIN)
	{
		// RA bit is set or rcode is not NXDOMAIN
		return;
	}

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

	// Get domain pointer
	domainsData *domain = getDomain(query->domainID, true);
	if(domain == NULL)
	{
		// Memory error, skip this query
		unlock_shm();
		return;
	}

	// Possible debugging information
	if(config.debug & DEBUG_QUERIES)
	{
		// Get domain name
		const char *domainname;
		if(domain != NULL)
			domainname = getstr(domain->domainpos);
		else
			domainname = "<cannot access domain struct>";

		logg("**** %s externally blocked (ID %i, FTL %i, %s:%i)", domainname, id, queryID, file, line);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Store query as externally blocked
	clientsData *client = getClient(query->clientID, true);
	if(client != NULL)
		query_blocked(query, domain, client, QUERY_EXTERNAL_BLOCKED_NXRA);

	// Store reply type as replied with NXDOMAIN
	query_set_reply(F_NEG | F_NXDOMAIN, NULL, query, response);

	// Unlock shared memory
	unlock_shm();
}

void print_flags(const unsigned int flags)
{
	// Debug function, listing resolver flags in clear text
	// e.g. "Flags: F_FORWARD F_NEG F_IPV6"

	// Only print flags if corresponding debugging flag is set
	if(!(config.debug & DEBUG_FLAGS))
		return;

	char *flagstr = calloc(sizeof(flagnames) + 1, sizeof(char));
	for (unsigned int i = 0; i < (sizeof(flagnames) / sizeof(*flagnames)); i++)
		if (flags & (1u << i))
			strcat(flagstr, flagnames[i]);
	logg("     Flags: %s", flagstr);
	free(flagstr);
}

static const char *reply_status_str[QUERY_REPLY_MAX] = {
	"UNKNOWN",
	"NODATA",
	"NXDOMAIN",
	"CNAME",
	"IP",
	"DOMAIN",
	"RRNAME",
	"SERVFAIL",
	"REFUSED",
	"NOTIMP",
	"OTHER"
};

static void query_set_reply(const unsigned int flags, const union all_addr *addr,
                            queriesData* query, const struct timeval response)
{
	// Iterate through possible values
	if(flags & F_NEG || force_next_DNS_reply == NXDOMAIN)
	{
		if(flags & F_NXDOMAIN)
			// NXDOMAIN
			query->reply = REPLY_NXDOMAIN;
		else
			// NODATA(-IPv6)
			query->reply = REPLY_NODATA;
	}
	else if(flags & F_CNAME)
		// <CNAME>
		query->reply = REPLY_CNAME;
	else if(flags & F_REVERSE)
		// reserve lookup
		query->reply = REPLY_DOMAIN;
	else if(flags & F_RRNAME)
		// TXT query
		query->reply = REPLY_RRNAME;
	else if((flags & F_RCODE && addr != NULL) || force_next_DNS_reply == REFUSED)
	{
		if((addr != NULL && addr->log.rcode == REFUSED)
		   || force_next_DNS_reply == REFUSED )
		{
			// REFUSED query
			query->reply = REPLY_REFUSED;
		}
		else if(addr != NULL && addr->log.rcode == SERVFAIL)
		{
			// SERVFAIL query
			query->reply = REPLY_SERVFAIL;
		}
	}
	else
	{
		// Valid IP
		query->reply = REPLY_IP;
	}

	if(config.debug & DEBUG_QUERIES)
		logg("Set reply to %s (%d)", reply_status_str[query->reply], query->reply);

	counters->reply[query->reply]++;

	// Save response time (relative time)
	query->response = converttimeval(response) -
	                            query->response;
}

void FTL_fork_and_bind_sockets(struct passwd *ent_pw)
{
	// Going into daemon mode involves storing the
	// PID of the generated child process. If FTL
	// is asked to stay in foreground, we just save
	// the PID of the current process in the PID file
	if(daemonmode)
		go_daemon();
	else
		savepid();

	// Handle real-time signals in this process (and its children)
	// Helper processes are already split from the main instance
	// so they will not listen to real-time signals
	handle_realtime_signals();

	// We will use the attributes object later to start all threads in
	// detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);

	// Start TELNET IPv4 thread
	if(pthread_create( &threads[TELNETv4], &attr, telnet_listening_thread_IPv4, NULL ) != 0)
	{
		logg("Unable to open IPv4 telnet listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start TELNET IPv6 thread
	if(pthread_create( &threads[TELNETv6], &attr, telnet_listening_thread_IPv6, NULL ) != 0)
	{
		logg("Unable to open IPv6 telnet listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start SOCKET thread
	if(pthread_create( &threads[SOCKET], &attr, socket_listening_thread, NULL ) != 0)
	{
		logg("Unable to open Unix socket listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start database thread if database is used
	if(pthread_create( &threads[DB], &attr, DB_thread, NULL ) != 0)
	{
		logg("Unable to open database thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until garbage
	// collection needs to be done
	if(pthread_create( &threads[GC], &attr, GC_thread, NULL ) != 0)
	{
		logg("Unable to open GC thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until host names
	// needs to be resolved
	if(pthread_create( &threads[DNSclient], &attr, DNSclient_thread, NULL ) != 0)
	{
		logg("Unable to open DNS client thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Chown files if FTL started as user root but a dnsmasq config
	// option states to run as a different user/group (e.g. "nobody")
	if(getuid() == 0)
	{
		// Only print this and change ownership of shmem objects when
		// we're actually dropping root (user/group my be set to root)
		if(ent_pw != NULL && ent_pw->pw_uid != 0)
		{
			logg("INFO: FTL is going to drop from root to user %s (UID %d)",
			     ent_pw->pw_name, (int)ent_pw->pw_uid);
			if(chown(FTLfiles.log, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
				logg("Setting ownership (%i:%i) of %s failed: %s (%i)",
				ent_pw->pw_uid, ent_pw->pw_gid, FTLfiles.log, strerror(errno), errno);
			if(chown(FTLfiles.FTL_db, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
				logg("Setting ownership (%i:%i) of %s failed: %s (%i)",
				ent_pw->pw_uid, ent_pw->pw_gid, FTLfiles.FTL_db, strerror(errno), errno);
			chown_all_shmem(ent_pw);
		}
		else
		{
			logg("INFO: FTL is running as root");
		}
	}
	else
	{
		uid_t uid;
		struct passwd *current_user;
		if ((current_user = getpwuid(uid = geteuid())) != NULL)
			logg("INFO: FTL is running as user %s (UID %d)",
			     current_user->pw_name, (int)current_user->pw_uid);
		else
			logg("INFO: Failed to obtain information about FTL user");
	}

	// Obtain DNS port from dnsmasq daemon
	config.dns_port = daemon->port;
}

// int cache_inserted, cache_live_freed are defined in dnsmasq/cache.c
void getCacheInformation(const int *sock)
{
	ssend(*sock,"cache-size: %i\ncache-live-freed: %i\ncache-inserted: %i\n",
	            daemon->cachesize,
	            daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED],
	            daemon->metrics[METRIC_DNS_CACHE_INSERTED]);
	// cache-size is obvious
	// It means the resolver handled <cache-inserted> names lookups that
	// needed to be sent to upstream servers and that <cache-live-freed>
	// was thrown out of the cache before reaching the end of its
	// time-to-live, to make room for a newer name.
	// For <cache-live-freed>, smaller is better. New queries are always
	// cached. If the cache is full with entries which haven't reached
	// the end of their time-to-live, then the entry which hasn't been
	// looked up for the longest time is evicted.
}

void FTL_forwarding_retried(const struct server *serv, const int oldID, const int newID, const bool dnssec)
{
	// Forwarding to upstream server failed

	if(oldID == newID)
	{
		if(config.debug & DEBUG_QUERIES)
			logg("%d: Ignoring self-retry", oldID);
		return;
	}

	// Lock shared memory
	lock_shm();

	// Try to obtain destination IP address if available
	char dest[ADDRSTRLEN];
	in_port_t upstreamPort = 53;
	dest[0] = '\0';
	if(serv != NULL)
	{
		if(serv->addr.sa.sa_family == AF_INET)
		{
			inet_ntop(AF_INET, &serv->addr.in.sin_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in.sin_port);
		}
		else
		{
			inet_ntop(AF_INET6, &serv->addr.in6.sin6_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in6.sin6_port);
		}
	}

	// Convert upstream to lower case
	char *upstreamIP = strdup(dest);
	strtolower(upstreamIP);

	// Get upstream ID
	const int upstreamID = findUpstreamID(upstreamIP, upstreamPort);

	// Possible debugging information
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** RETRIED query %i as %i to %s (ID %i)",
		     oldID, newID, dest, upstreamID);
	}

	// Get upstream pointer
	upstreamsData* upstream = getUpstream(upstreamID, true);

	// Update counter
	if(upstream != NULL)
		upstream->failed++;

	// Search for corresponding query identified by ID
	// Retried DNSSEC queries are ignored, we have to flag themselves (newID)
	// Retried normal queries take over, we have to flag the original query (oldID)
	const int queryID = findQueryID(dnssec ? newID : oldID);
	if(queryID >= 0)
	{
		// Get query pointer
		queriesData* query = getQuery(queryID, true);

		// Set retried status
		if(query != NULL)
		{
			if(dnssec)
			{
				// There is no point in retrying the query when
				// we've already got an answer to this query,
				// but we're awaiting keys for DNSSEC
				// validation. We're retrying the DNSSEC query
				// instead
				query_set_status(query, QUERY_RETRIED_DNSSEC);
			}
			else
			{
				// Normal query retry due to answer not arriving
				// soon enough at the requestor
				query_set_status(query, QUERY_RETRIED);
			}
		}
	}

	// Clean up and unlock shared memory
	free(upstreamIP);
	unlock_shm();
	return;
}

static unsigned long __attribute__((const)) converttimeval(const struct timeval time)
{
	// Convert time from struct timeval into units
	// of 10*milliseconds
	return time.tv_sec*10000 + time.tv_usec/100;
}

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
			logg("CNAME header: Question was <IN> %s %s", qtype_str, name);
		}

		return flags;
	}

	// Fall back to IPv4 (type A) when for the unlikely event that we cannot
	// find any questions in this header
	if(config.debug & DEBUG_QUERIES)
		logg("CNAME header: No valid IN question found in header");

	return F_IPV4;
}

// Called when a (forked) TCP worker is terminated by receiving SIGALRM
// We close the dedicated database connection this client had opened
// to avoid dangling database locks
volatile atomic_flag worker_already_terminating = ATOMIC_FLAG_INIT;
void FTL_TCP_worker_terminating(bool finished)
{
	if(dnsmasq_debug)
	{
		// Nothing to be done here, forking does not happen in debug mode
		return;
	}

	if(atomic_flag_test_and_set(&worker_already_terminating))
	{
		logg("TCP worker already terminating!");
		return;
	}

	// Possible debug logging
	if(config.debug != 0)
	{
		const char *reason = finished ? "client disconnected" : "timeout";
		logg("TCP worker terminating (%s)", reason);
	}

	if(main_pid() == getpid())
	{
		// If this is not really a fork (e.g. in debug mode), we don't
		// actually close gravity here
		return;
	}

	// Close dedicated database connections of this fork
	gravityDB_close();
}

// Called when a (forked) TCP worker is created
// FTL forked to handle TCP connections with dedicated (forked) workers
// SQLite3's mentions that carrying an open database connection across a
// fork() can lead to all kinds of locking problems as SQLite3 was not
// intended to work under such circumstances. Doing so may easily lead
// to ending up with a corrupted database.
void FTL_TCP_worker_created(const int confd)
{
	if(dnsmasq_debug)
	{
		// Nothing to be done here, TCP worker forking does not happen
		// in debug mode
		return;
	}

	// Print this if any debug setting is enabled
	if(config.debug != 0)
	{
		// Get peer IP address (client)
		char peer_ip[ADDRSTRLEN] = { 0 };
		union mysockaddr peer_sockaddr = {{ 0 }};
		socklen_t peer_len = sizeof(union mysockaddr);
		if (getpeername(confd, (struct sockaddr *)&peer_sockaddr, &peer_len) != -1)
		{
			union all_addr peer_addr = {{ 0 }};
			if (peer_sockaddr.sa.sa_family == AF_INET6)
				peer_addr.addr6 = peer_sockaddr.in6.sin6_addr;
			else
				peer_addr.addr4 = peer_sockaddr.in.sin_addr;
			inet_ntop(peer_sockaddr.sa.sa_family, &peer_addr, peer_ip, ADDRSTRLEN);
		}

		// Get local IP address (interface)
		char local_ip[ADDRSTRLEN] = { 0 };
		union mysockaddr iface_sockaddr = {{ 0 }};
		socklen_t iface_len = sizeof(union mysockaddr);
		if(getsockname(confd, (struct sockaddr *)&iface_sockaddr, &iface_len) != -1)
		{
			union all_addr iface_addr = {{ 0 }};
			if (iface_sockaddr.sa.sa_family == AF_INET6)
				iface_addr.addr6 = iface_sockaddr.in6.sin6_addr;
			else
				iface_addr.addr4 = iface_sockaddr.in.sin_addr;
			inet_ntop(iface_sockaddr.sa.sa_family, &iface_addr, local_ip, ADDRSTRLEN);
		}

		// Print log
		logg("TCP worker forked for client %s on interface %s with IP %s", peer_ip, next_iface.name, local_ip);
	}

	if(main_pid() == getpid())
	{
		// If this is not really a fork (e.g. in debug mode), we don't
		// actually re-open gravity or close sockets here
		return;
	}

	// Reopen gravity database handle in this fork as the main process's
	// handle isn't valid here
	if(config.debug != 0)
		logg("Reopening Gravity database for this fork");
	gravityDB_forked();

	// Children inherit file descriptors from their parents
	// We don't need them in the forks, so we clean them up
	if(config.debug != 0)
		logg("Closing Telnet socket for this fork");
	close_telnet_socket();
	if(config.debug != 0)
		logg("Closing Unix socket for this fork");
	close_unix_socket(false);
}

bool FTL_unlink_DHCP_lease(const char *ipaddr)
{
	struct dhcp_lease *lease;
	union all_addr addr;
	const time_t now = dnsmasq_time();

	// Try to extract IP address
	if (inet_pton(AF_INET, ipaddr, &addr.addr4) > 0)
	{
		lease = lease_find_by_addr(addr.addr4);
	}
#ifdef HAVE_DHCP6
	else if (inet_pton(AF_INET6, ipaddr, &addr.addr6) > 0)
	{
		lease = lease6_find_by_addr(&addr.addr6, 128, 0);
	}
#endif
	else
	{
		return false;
	}

	// If a lease exists for this IP address, we unlink it and immediately
	// update the lease file to reflect the removal of this lease
	if (lease)
	{
		// Unlink the lease for dnsmasq's database
		lease_prune(lease, now);
		// Update the lease file
		lease_update_file(now);
		// Argument force == 0 ensures the DNS records are only updated
		// when unlinking the lease above actually changed something
		// (variable lease.c:dns_dirty is used here)
		lease_update_dns(0);
	}

	// Return success
	return true;
}

void FTL_query_in_progress(const int id)
{
	// Query (possibly from new source), but the same query may be in
	// progress from another source.

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
			logg("**** query for %s is already in progress (ID %i)", getstr(domain->domainpos), id);
		}
	}

	// Store status
	query_set_status(query, QUERY_IN_PROGRESS);

	// Unlock shared memory
	unlock_shm();
}

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
	if(config.debug & DEBUG_QUERIES)
	{
		logg("**** sending reply %d also to %d", *firstID, queryID);
	}

	// Copy relevant information over
	duplicated_query->reply = source_query->reply;
	duplicated_query->dnssec = source_query->dnssec;
	duplicated_query->flags.complete = true;
	duplicated_query->CNAME_domainID = source_query->CNAME_domainID;

	// The original query may have been blocked during CNAME inspection,
	// correct status in this case
	if(source_query->status != QUERY_FORWARDED)
		query_set_status(duplicated_query, source_query->status);

	// Unlock shared memory
	unlock_shm();
}
