/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query processing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "datastructure.h"
#include "shmem.h"
#include "log.h"
// enum REGEX
#include "regex_r.h"
// reload_per_client_regex()
#include "database/gravity-db.h"
// flush_message_table()
#include "database/message-table.h"
// bool startup
#include "main.h"
// reset_aliasclient()
#include "database/aliasclients.h"
// config struct
#include "config.h"
// set_event(RESOLVE_NEW_HOSTNAMES)
#include "events.h"
// overTime array
#include "overTime.h"

// converts upper to lower case, and leaves other characters unchanged
void strtolower(char *str)
{
	int i = 0;
	while(str[i]){ str[i] = tolower(str[i]); i++; }
}

int findQueryID(const int id)
{
	// Loop over all queries - we loop in reverse order (start from the most recent query and
	// continuously walk older queries while trying to find a match. Ideally, we should always
	// find the correct query with zero iterations, but it may happen that queries are processed
	// asynchronously, e.g. for slow upstream relies to a huge amount of requests.
	// We iterate from the most recent query down to at most MAXITER queries in the past to avoid
	// iterating through the entire array of queries
	// MAX(0, a) is used to return 0 in case a is negative (negative array indices are harmful)
	const int until = MAX(0, counters->queries-MAXITER);
	const int start = MAX(0, counters->queries-1);

	// Check UUIDs of queries
	for(int i = start; i >= until; i--)
	{
		const queriesData* query = getQuery(i, true);

		// Check if the returned pointer is valid before trying to access it
		if(query == NULL)
			continue;

		if(query->id == id)
			return i;
	}

	// If not found
	return -1;
}

int findUpstreamID(const char * upstreamString, const in_port_t port)
{
	// Go through already knows upstream servers and see if we used one of those
	for(int upstreamID=0; upstreamID < counters->upstreams; upstreamID++)
	{
		// Get upstream pointer
		upstreamsData* upstream = getUpstream(upstreamID, true);

		// Check if the returned pointer is valid before trying to access it
		if(upstream == NULL)
			continue;

		if(strcmp(getstr(upstream->ippos), upstreamString) == 0 && upstream->port == port)
			return upstreamID;
	}
	// This upstream server is not known
	// Store ID
	const int upstreamID = counters->upstreams;
	logg("New upstream server: %s:%u (%i/%u)", upstreamString, port, upstreamID, counters->upstreams_MAX);

	// Get upstream pointer
	upstreamsData* upstream = getUpstream(upstreamID, false);
	if(upstream == NULL)
	{
		logg("ERROR: Encountered serious memory error in findupstreamID()");
		return -1;
	}

	// Set magic byte
	upstream->magic = MAGICBYTE;
	// Initialize its counter
	upstream->count = 0;
	// Save upstream destination IP address
	upstream->ippos = addstr(upstreamString);
	upstream->failed = 0;
	// Initialize upstream hostname
	// Due to the nature of us being the resolver,
	// the actual resolving of the host name has
	// to be done separately to be non-blocking
	upstream->flags.new = true;
	upstream->namepos = 0; // 0 -> string with length zero
	// Initialize response time values
	upstream->rtime = 0u;
	upstream->rtuncertainty = 0u;
	upstream->responses = 0u;
	// This is a new upstream server
	set_event(RESOLVE_NEW_HOSTNAMES);
	upstream->lastQuery = 0.0;
	// Store port
	upstream->port = port;
	// Increase counter by one
	counters->upstreams++;

	return upstreamID;
}

int findDomainID(const char *domainString, const bool count)
{
	for(int domainID = 0; domainID < counters->domains; domainID++)
	{
		// Get domain pointer
		domainsData* domain = getDomain(domainID, true);

		// Check if the returned pointer is valid before trying to access it
		if(domain == NULL)
			continue;

		// Quick test: Does the domain start with the same character?
		if(getstr(domain->domainpos)[0] != domainString[0])
			continue;

		// If so, compare the full domain using strcmp
		if(strcmp(getstr(domain->domainpos), domainString) == 0)
		{
			if(count)
				domain->count++;
			return domainID;
		}
	}

	// If we did not return until here, then this domain is not known
	// Store ID
	const int domainID = counters->domains;

	// Get domain pointer
	domainsData* domain = getDomain(domainID, false);
	if(domain == NULL)
	{
		logg("ERROR: Encountered serious memory error in findDomainID()");
		return -1;
	}

	// Set magic byte
	domain->magic = MAGICBYTE;
	// Set its counter to 1 only if this domain is to be counted
	// Domains only encountered during CNAME inspection are NOT counted here
	domain->count = count ? 1 : 0;
	// Set blocked counter to zero
	domain->blockedcount = 0;
	// Store domain name - no need to check for NULL here as it doesn't harm
	domain->domainpos = addstr(domainString);
	// Increase counter by one
	counters->domains++;

	return domainID;
}

int findClientID(const char *clientIP, const bool count, const bool aliasclient)
{
	// Compare content of client against known client IP addresses
	for(int clientID=0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		clientsData* client = getClient(clientID, true);

		// Check if the returned pointer is valid before trying to access it
		if(client == NULL)
			continue;

		// Quick test: Does the clients IP start with the same character?
		if(getstr(client->ippos)[0] != clientIP[0])
			continue;

		// If so, compare the full IP using strcmp
		if(strcmp(getstr(client->ippos), clientIP) == 0)
		{
			// Add one if count == true (do not add one, e.g., during ARP table processing)
			if(count && !aliasclient) change_clientcount(client, 1, 0, -1, 0);
			return clientID;
		}
	}

	// Return -1 (= not found) if count is false because we do not want to create a new client here
	// Proceed if we are looking for a alias-client because we want to create a new record
	if(!count && !aliasclient)
		return -1;

	// If we did not return until here, then this client is definitely new
	// Store ID
	const int clientID = counters->clients;

	// Get client pointer
	clientsData* client = getClient(clientID, false);
	if(client == NULL)
	{
		logg("ERROR: Encountered serious memory error in findClientID()");
		return -1;
	}

	// Set magic byte
	client->magic = MAGICBYTE;
	// Set its counter to 1
	client->count = (count && !aliasclient)? 1 : 0;
	// Initialize blocked count to zero
	client->blockedcount = 0;
	// Store client IP - no need to check for NULL here as it doesn't harm
	client->ippos = addstr(clientIP);
	// Initialize client hostname
	// Due to the nature of us being the resolver,
	// the actual resolving of the host name has
	// to be done separately to be non-blocking
	client->flags.new = true;
	client->namepos = 0;
	set_event(RESOLVE_NEW_HOSTNAMES);
	// No query seen so far
	client->lastQuery = 0.0;
	client->numQueriesARP = client->count;
	// Configured groups are yet unknown
	client->flags.found_group = false;
	client->groupspos = 0u;
	// Store time this client was added, we re-read group settings
	// some time after adding a client to ensure we pick up possible
	// group configuration though hostname, MAC address or interface
	client->reread_groups = 0u;
	client->firstSeen = time(NULL);
	// Interface is not yet known
	client->ifacepos = 0;
	// Set all MAC address bytes to zero
	client->hwlen = -1;
	memset(client->hwaddr, 0, sizeof(client->hwaddr));
	// This may be a alias-client, the ID is set elsewhere
	client->flags.aliasclient = aliasclient;
	client->aliasclient_id = -1;

	// Initialize client-specific overTime data
	memset(client->overTime, 0, sizeof(client->overTime));

	// Store client ID
	client->id = clientID;

	// Increase counter by one
	counters->clients++;

	// Get groups for this client and set enabled regex filters
	// Note 1: We do this only after increasing the clients counter to
	//         ensure sufficient shared memory is available in the
	//         pre_client_regex object.
	// Note 2: We don't do this before starting up is done as the gravity
	//         database may not be available. All clients initialized
	//         during history reading get their enabled regexs reloaded
	//         in the initial call to FTL_reload_all_domainlists()
	if(!startup && !aliasclient)
		reload_per_client_regex(client);

	// Check if this client is managed by a alias-client
	if(!aliasclient)
		reset_aliasclient(NULL, client);

	return clientID;
}

void change_clientcount(clientsData *client, int total, int blocked, int overTimeIdx, int overTimeMod)
{
		client->count += total;
		client->blockedcount += blocked;
		if(overTimeIdx > -1 && overTimeIdx < OVERTIME_SLOTS)
			client->overTime[overTimeIdx] += overTimeMod;

		// Also add counts to the conencted alias-client (if any)
		if(client->flags.aliasclient)
		{
			logg("WARN: Should not add to alias-client directly (client \"%s\" (%s))!",
			     getstr(client->namepos), getstr(client->ippos));
			return;
		}
		if(client->aliasclient_id > -1)
		{
			clientsData *aliasclient = getClient(client->aliasclient_id, true);
			aliasclient->count += total;
			aliasclient->blockedcount += blocked;
			if(overTimeIdx > -1 && overTimeIdx < OVERTIME_SLOTS)
				aliasclient->overTime[overTimeIdx] += overTimeMod;
		}
}

int findCacheID(int domainID, int clientID, enum query_types query_type)
{
	// Compare content of client against known client IP addresses
	for(int cacheID = 0; cacheID < counters->dns_cache_size; cacheID++)
	{
		// Get cache pointer
		DNSCacheData* dns_cache = getDNSCache(cacheID, true);

		// Check if the returned pointer is valid before trying to access it
		if(dns_cache == NULL)
			continue;

		if(dns_cache->domainID == domainID &&
		   dns_cache->clientID == clientID &&
		   dns_cache->query_type == query_type)
		{
			return cacheID;
		}
	}

	// Get ID of new cache entry
	const int cacheID = counters->dns_cache_size;

	// Get client pointer
	DNSCacheData* dns_cache = getDNSCache(cacheID, false);

	if(dns_cache == NULL)
	{
		logg("ERROR: Encountered serious memory error in findCacheID()");
		return -1;
	}

	// Initialize cache entry
	dns_cache->magic = MAGICBYTE;
	dns_cache->blocking_status = UNKNOWN_BLOCKED;
	dns_cache->domainID = domainID;
	dns_cache->clientID = clientID;
	dns_cache->query_type = query_type;
	dns_cache->force_reply = 0u;

	// Increase counter by one
	counters->dns_cache_size++;

	return cacheID;
}

bool isValidIPv4(const char *addr)
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, addr, &(sa.sin_addr)) != 0;
}

bool isValidIPv6(const char *addr)
{
	struct sockaddr_in6 sa;
	return inet_pton(AF_INET6, addr, &(sa.sin6_addr)) != 0;
}

// Privacy-level sensitive subroutine that returns the domain name
// only when appropriate for the requested query
const char *getDomainString(const queriesData* query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(query->domainID, true);

		// Return string
		return getstr(domain->domainpos);
	}
	else
		return HIDDEN_DOMAIN;
}

// Privacy-level sensitive subroutine that returns the domain name
// only when appropriate for the requested query
const char *getCNAMEDomainString(const queriesData* query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(query->CNAME_domainID, true);

		// Return string
		return getstr(domain->domainpos);
	}
	else
		return HIDDEN_DOMAIN;
}

// Privacy-level sensitive subroutine that returns the client IP
// only when appropriate for the requested query
const char *getClientIPString(const queriesData* query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		// Get client pointer
		const clientsData* client = getClient(query->clientID, false);

		// Return string
		return getstr(client->ippos);
	}
	else
		return HIDDEN_CLIENT;
}

// Privacy-level sensitive subroutine that returns the client host name
// only when appropriate for the requested query
const char *getClientNameString(const queriesData* query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		// Get client pointer
		const clientsData* client = getClient(query->clientID, true);

		// Return string
		return getstr(client->namepos);
	}
	else
		return HIDDEN_CLIENT;
}

void FTL_reset_per_client_domain_data(void)
{
	if(config.debug & DEBUG_DATABASE)
		logg("Resetting per-client DNS cache, size is %i", counters->dns_cache_size);

	for(int cacheID = 0; cacheID < counters->dns_cache_size; cacheID++)
	{
		// Reset all blocking yes/no fields for all domains and clients
		// This forces a reprocessing of all available filters for any
		// given domain and client the next time they are seen
		DNSCacheData *dns_cache = getDNSCache(cacheID, true);
		if(dns_cache != NULL)
			dns_cache->blocking_status = UNKNOWN_BLOCKED;
	}
}

// Reloads all domainlists and performs a few extra tasks such as cleaning the
// message table
// May only be called from the database thread
void FTL_reload_all_domainlists(void)
{
	lock_shm();

	// Flush messages stored in the long-term database
	flush_message_table();

	// (Re-)open gravity database connection
	gravityDB_reopen();

	// Get size of gravity, number of domains, groups, clients, and lists
	counters->database.gravity = gravityDB_count(GRAVITY_TABLE);
	counters->database.groups = gravityDB_count(GROUPS_TABLE);
	counters->database.clients = gravityDB_count(CLIENTS_TABLE);
	counters->database.lists = gravityDB_count(ADLISTS_TABLE);
	counters->database.domains.allowed = gravityDB_count(DENIED_DOMAINS_TABLE);
	counters->database.domains.denied = gravityDB_count(ALLOWED_DOMAINS_TABLE);

	// Read and compile possible regex filters
	// only after having called gravityDB_open()
	read_regex_from_database();

	// Reset FTL's internal DNS cache storing whether a specific domain
	// has already been validated for a specific user
	FTL_reset_per_client_domain_data();

	unlock_shm();
}

const char *get_query_type_str(const queriesData *query, char *buffer)
{
	switch (query->type)
	{
		case TYPE_A:
			return "A";
		case TYPE_AAAA:
			return "AAAA";
		case TYPE_ANY:
			return "ANY";
		case TYPE_SRV:
			return "SRV";
		case TYPE_SOA:
			return "SOA";
		case TYPE_PTR:
			return "PTR";
		case TYPE_TXT:
			return "TXT";
		case TYPE_NAPTR:
			return "NAPTR";
		case TYPE_MX:
			return "MX";
		case TYPE_DS:
			return "DS";
		case TYPE_RRSIG:
			return "RRSIG";
		case TYPE_DNSKEY:
			return "DNSKEY";
		case TYPE_NS:
			return "NS";
		case TYPE_OTHER:
			if(buffer != NULL)
			{
				// Build custom query type string in buffer
				sprintf(buffer, "TYPE%d", query->qtype);
				return buffer;
			}
			else
			{
				// Used, e.g., for regex type matching
				return "OTHER";
			}
		case TYPE_SVCB:
			return "SVCB";
		case TYPE_HTTPS:
			return "HTTPS";
		case TYPE_MAX:
		default:
			return "N/A";
	}
}

const char * __attribute__ ((pure)) get_query_status_str(const queriesData *query)
{
	switch (query->status)
	{
		case STATUS_UNKNOWN:
			return "UNKNOWN";
		case STATUS_GRAVITY:
			return "GRAVITY";
		case STATUS_FORWARDED:
			return "FORWARDED";
		case STATUS_CACHE:
			return "CACHE";
		case STATUS_REGEX:
			return "REGEX";
		case STATUS_DENYLIST:
			return "DENYLIST";
		case STATUS_EXTERNAL_BLOCKED_IP:
			return "EXTERNAL_BLOCKED_IP";
		case STATUS_EXTERNAL_BLOCKED_NULL:
			return "EXTERNAL_BLOCKED_NULL";
		case STATUS_EXTERNAL_BLOCKED_NXRA:
			return "EXTERNAL_BLOCKED_NXRA";
		case STATUS_GRAVITY_CNAME:
			return "GRAVITY_CNAME";
		case STATUS_REGEX_CNAME:
			return "REGEX_CNAME";
		case STATUS_DENYLIST_CNAME:
			return "DENYLIST_CNAME";
		case STATUS_RETRIED:
			return "RETRIED";
		case STATUS_RETRIED_DNSSEC:
			return "RETRIED_DNSSEC";
		case STATUS_IN_PROGRESS:
			return "IN_PROGRESS";
		case STATUS_MAX:
		default:
			return "STATUS_MAX";
	}
}

const char * __attribute__ ((pure)) get_query_reply_str(const queriesData *query)
{
	switch (query->reply)
	{
		case REPLY_UNKNOWN:
			return "UNKNOWN";
		case REPLY_NODATA:
			return "NODATA";
		case REPLY_NXDOMAIN:
			return "NXDOMAIN";
		case REPLY_CNAME:
			return "CNAME";
		case REPLY_IP:
			return "IP";
		case REPLY_DOMAIN:
			return "DOMAIN";
		case REPLY_RRNAME:
			return "RRNAME";
		case REPLY_SERVFAIL:
			return "SERVFAIL";
		case REPLY_REFUSED:
			return "REFUSED";
		case REPLY_NOTIMP:
			return "NOTIMP";
		case REPLY_OTHER:
			return "OTHER";
		case REPLY_MAX:
		default:
			return "N/A";
	}
}

const char * __attribute__ ((pure)) get_query_dnssec_str(const queriesData *query)
{
	switch (query->dnssec)
	{
		case DNSSEC_UNKNOWN:
			return "UNKNOWN";
		case DNSSEC_SECURE:
			return "SECURE";
		case DNSSEC_INSECURE:
			return "INSECURE";
		case DNSSEC_BOGUS:
			return "BOGUS";
		case DNSSEC_ABANDONED:
			return "ABANDONED";
		case DNSSEC_MAX:
		default:
			return "N/A";
	}
}

bool __attribute__ ((const)) is_blocked(const enum query_status status)
{
	switch (status)
	{
		case STATUS_UNKNOWN:
		case STATUS_FORWARDED:
		case STATUS_CACHE:
		case STATUS_RETRIED:
		case STATUS_RETRIED_DNSSEC:
		case STATUS_IN_PROGRESS:
		case STATUS_MAX:
		default:
			return false;

		case STATUS_GRAVITY:
		case STATUS_REGEX:
		case STATUS_DENYLIST:
		case STATUS_EXTERNAL_BLOCKED_IP:
		case STATUS_EXTERNAL_BLOCKED_NULL:
		case STATUS_EXTERNAL_BLOCKED_NXRA:
		case STATUS_GRAVITY_CNAME:
		case STATUS_REGEX_CNAME:
		case STATUS_DENYLIST_CNAME:
			return true;
	}
}

int __attribute__ ((pure)) get_blocked_count(void)
{
	int blocked = 0;
	for(enum query_status status = 0; status < STATUS_MAX; status++)
		if(is_blocked(status))
			blocked += counters->status[status];

	return blocked;
}

int __attribute__ ((pure)) get_forwarded_count(void)
{
	return counters->status[STATUS_FORWARDED] +
	       counters->status[STATUS_RETRIED] +
	       counters->status[STATUS_RETRIED_DNSSEC];
}

int __attribute__ ((pure)) get_cached_count(void)
{
	return counters->status[STATUS_CACHE];
}

void query_set_status(queriesData *query, const enum query_status new_status)
{
	// Debug logging
	char buffer[16] = { 0 };
	if(config.debug & DEBUG_STATUS)
	{
		const char *oldstr = query->status < STATUS_MAX ? get_query_type_str(query, buffer) : "INVALID";
		if(query->status == new_status)
		{
			logg("Query %i: status unchanged: %s (%d)",
			     query->id, oldstr, query->status);
		}
		else
		{
			const char *newstr = new_status < STATUS_MAX ? get_query_type_str(query, buffer) : "INVALID";
			logg("Query %i: status changed: %s (%d) -> %s (%d)",
			     query->id, oldstr, query->status, newstr, new_status);
		}
	}

	// Update counters
	if(query->status != new_status)
	{
		counters->status[query->status]--;
		counters->status[new_status]++;

		if(is_blocked(query->status))
			overTime[query->timeidx].blocked--;
		if(is_blocked(new_status))
			overTime[query->timeidx].blocked++;

		if(query->status == STATUS_CACHE)
			overTime[query->timeidx].cached--;
		if(new_status == STATUS_CACHE)
			overTime[query->timeidx].cached++;

		if(query->status == STATUS_FORWARDED)
			overTime[query->timeidx].forwarded--;
		if(new_status == STATUS_FORWARDED)
			overTime[query->timeidx].forwarded++;
	}

	// Update status
	query->status = new_status;
}
