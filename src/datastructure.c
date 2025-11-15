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
// bool startup
#include "main.h"
// reset_aliasclient()
#include "database/aliasclients.h"
// config struct
#include "config/config.h"
// set_event(RESOLVE_NEW_HOSTNAMES)
#include "events.h"
// overTime array
#include "overTime.h"
// short_path()
#include "files.h"
// lookup_insert
#include "lookup-table.h"

// converts upper to lower case, and leaves other characters unchanged
// Optimized version using pointer arithmetic for better performance
void strtolower(char *str)
{
	for(; *str; ++str)
		*str = tolower(*str);
}

/**
 * @brief Computes a hash value for a given string using Jenkins' One-at-a-Time
 * hash algorithm.
 *
 * This function is marked as pure, indicating that it has no side effects and
 * its return value depends only on the input parameters.
 *
 * @param s The input string to be hashed.
 * @return The computed hash value as a 32-bit unsigned integer.
 *
 * @note Jenkins' One-at-a-Time hash is a simple and effective hash function for
 *       strings. More details can be found at:
 *       http://www.burtleburtle.net/bob/hash/doobs.html
 */
static uint32_t __attribute__ ((pure)) hashStr(const char *s)
{
	// Jenkins' One-at-a-Time hash (optimized version)
	// (http://www.burtleburtle.net/bob/hash/doobs.html)
	uint32_t hash = 0;
	for(; *s; ++s)
	{
		hash += *s;
		hash += hash << 10;
		hash ^= hash >> 6;
	}

	// Final mixing to ensure good distribution
	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;
	return hash;
}

/**
 * @brief Computes a hash value for the cache IDs using a simple XOR operation.
 *
 * This function is marked as pure, indicating that it has no side effects and
 * its return value depends only on the input parameters.
 *
 * @param a The first unsigned integer (domain ID).
 * @param b The second unsigned integer (client ID).
 * @param c The third unsigned integer (enum query_type ID).
 * @return The computed hash value as a 32-bit unsigned integer.
 */
static uint32_t __attribute__ ((pure)) hashCacheIDs(const unsigned int domainID,
                                                    const unsigned int clientID,
                                                    const enum query_type query_type)
{
	// We distribute the available bits as follows:
	// - 16 bits for the domain ID (2^16 = 65536 unique domains)
	// - 11 bits for the client ID (2^11 = 2048 unique clients)
	// -  	5 bits for the query type (2^5 = 32 unique query types)
	//
	// It is unlikely that we will ever reach these number of unique domains
	// or clients due to recycling, so this hash function should always
	// return unique hash values.
	//
	// Even if more than 65536 domains or more than 2048 clients are used,
	// the hash works as our binsearch implementation handles collisions
	// gracefully. Furthermore, it is rather unlikely that collisions will
	// ever really occur in practice even if the numbers above are exceeded
	// as not every single domain will be queried by every single client for
	// every possible query type.
	//
	// We use the XOR operation to combine the three values into a single
	// hash value. XOR uses less transistors than other operations, making
	// it possibly slightly more efficient on embedded systems. Both XOR and
	// addition happen faster than a single clock cycle on pretty much every
	// CPU, so the performance difference is negligible.

	return (((uint32_t)domainID) << 16) ^ ((uint32_t)(clientID) << 5) ^ query_type;
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
	const unsigned int until = counters->queries > MAXITER ? counters->queries - MAXITER : 0;
	const unsigned int start = counters->queries > 0 ? counters->queries - 1 : 0;

	// Check UUIDs of queries
	for(unsigned int i = start; i >= until; i--)
	{
		const queriesData *query = getQuery(i, true);

		// Check if the returned pointer is valid before trying to access it
		if(query != NULL && query->id == id)
			return i;

		// If we reached the beginning of the array, we can stop
		if(i == 0)
			break;
	}

	// If not found
	return -1;
}

int _findUpstreamID(const char *upstreamString, const in_port_t port, int line, const char *func, const char *file)
{
	// Go through already knows upstream servers and see if we used one of those
	for(unsigned int upstreamID = 0; upstreamID < counters->upstreams; upstreamID++)
	{
		// Get upstream pointer
		const upstreamsData *upstream = _getUpstream(upstreamID, true, line, func, file);

		// Check if the returned pointer is valid before trying to access it
		if(upstream == NULL)
			continue;

		if(strcmp(getstr(upstream->ippos), upstreamString) == 0 && upstream->port == port)
			return upstreamID;
	}
	// This upstream server is not known
	// Store ID
	const unsigned int upstreamID = counters->upstreams;
	log_debug(DEBUG_GC, "New upstream server: %s:%u (ID %u)", upstreamString, port, upstreamID);

	// Get upstream pointer
	upstreamsData *upstream = _getUpstream(upstreamID, false, line, func, file);
	if(upstream == NULL)
	{
		log_err("Encountered serious memory error in findupstreamID()");
		return -1;
	}

	// Set magic byte
	upstream->magic = MAGICBYTE;
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
	upstream->rtime = 0.0;
	upstream->rtuncertainty = 0.0;
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

static int get_next_free_domainID(void)
{
	// First, try to obtain a previously recycled domain ID
	unsigned int domainID = 0;
	if(get_next_recycled_ID(DOMAINS, &domainID))
		return domainID;

	// If we did not return until here, then we need to allocate a new domain ID
	return counters->domains;
}

static bool cmp_domain(const struct lookup_table *entry, const struct lookup_data *lookup_data)
{
	// Get domain pointer
	const domainsData *domain = getDomain(entry->id, true);

	// Check if the returned pointer is valid before trying to access it
	if(domain == NULL)
		return false;

	// Compare domain strings
	return strcmp(getstr(domain->domainpos), lookup_data->domain) == 0;
}

int _findDomainID(const char *domainString, const bool count, int line, const char *func, const char *file)
{
	// Get domain hash
	const uint32_t hash = hashStr(domainString);

	// Use lookup table to speed up domain lookups
	const struct lookup_data lookup_data = { .domain = domainString	};
	unsigned int domainID = 0;
	if(lookup_find_id(DOMAINS_LOOKUP, hash, &lookup_data, &domainID, cmp_domain))
	{
		// Get domain pointer
		domainsData *domain = getDomain(domainID, true);

		// Check if the returned pointer is valid before trying to access it
		if(domain == NULL)
			return -1;

		// Add one if count == true (do not add one, e.g., during CNAME inspection)
		if(count) domain->count++;
		return domainID;
	}

	// If we did not return until here, then this domain is not known and we
	// need to create a new domain entry

	// Get new domain ID
	domainID = get_next_free_domainID();

	// Get domain pointer
	domainsData *domain = _getDomain(domainID, false, line, func, file);
	if(domain == NULL)
	{
		log_err("Encountered serious memory error in findDomainID()");
		return -1;
	}

	log_debug(DEBUG_GC, "New domain: %s (ID %u)", domainString, domainID);

	// Insert domain into lookup table
	lookup_insert(DOMAINS_LOOKUP, domainID, hash);

	// Set magic byte
	domain->magic = MAGICBYTE;
	// Set its counter to 1 only if this domain is to be counted
	// Domains only encountered during CNAME inspection are NOT counted here
	domain->count = count ? 1 : 0;
	// Set blocked counter to zero
	domain->blockedcount = 0;
	// Store domain name - no need to check for NULL here as it doesn't harm
	domain->domainpos = addstr(domainString);
	// Store pre-computed hash for faster lookups later on
	domain->hash = hash;
	domain->lastQuery = 0.0;
	// Increase counter by one
	counters->domains++;

	return domainID;
}

static int get_next_free_clientID(void)
{
	// First, try to obtain a previously recycled client ID
	unsigned int clientID = 0;
	if(get_next_recycled_ID(CLIENTS, &clientID))
		return clientID;

	// If we did not return until here, then we need to allocate a new client ID
	return counters->clients;
}

static bool cmp_client(const struct lookup_table *entry, const struct lookup_data *lookup_data)
{
	// Get client pointer
	const clientsData *client = getClient(entry->id, true);

	// Check if the returned pointer is valid before trying to access it
	if(client == NULL)
		return false;

	// Compare client strings
	return strcmp(getstr(client->ippos), lookup_data->client) == 0;
}

int _findClientID(const char *clientIP, const bool count, const bool aliasclient,
                  const double now, int line, const char *func, const char *file)
{
	// Get client hash
	const uint32_t hash = hashStr(clientIP);

	// Use lookup table to speed up domain lookups
	const struct lookup_data lookup_data = { .client = clientIP };
	unsigned int clientID = 0;
	if(lookup_find_id(CLIENTS_LOOKUP, hash, &lookup_data, &clientID, cmp_client))
	{
		// Get client pointer
		clientsData *client = getClient(clientID, true);

		// Check if the returned pointer is valid before trying to access it
		if(client == NULL)
			return -1;

		// Add one if count == true (do not add one, e.g., during ARP table processing)
		if(count && !aliasclient) change_clientcount(client, 1, 0, -1, 0);
		return clientID;
	}

	// Return -1 (= not found) if count is false because we do not want to create a new client here
	// Proceed if we are looking for a alias-client because we want to create a new record
	if(!count && !aliasclient)
		return -1;

	// If we did not return until here, then this client is definitely new
	// Get new client ID
	clientID = get_next_free_clientID();

	// Get client pointer
	clientsData *client = _getClient(clientID, false, line, func, file);
	if(client == NULL)
	{
		log_err("Encountered serious memory error in findClientID()");
		return -1;
	}

	log_debug(DEBUG_GC, "New client: %s (ID %u)", clientIP, clientID);

	// Insert domain into lookup table
	lookup_insert(CLIENTS_LOOKUP, clientID, hash);

	// Set magic byte
	client->magic = MAGICBYTE;
	// Set its counter to 1
	client->count = (count && !aliasclient)? 1 : 0;
	// Initialize blocked count to zero
	client->blockedcount = 0;
	// Store client IP - no need to check for NULL here as it doesn't harm
	client->ippos = addstr(clientIP);
	// Store pre-computed hash for faster lookups later on
	client->hash = hash;
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
	client->firstSeen = now;
	// Interface is not yet known
	client->ifacepos = 0;
	// Set all MAC address bytes to zero
	client->hwlen = -1;
	memset(client->hwaddr, 0, sizeof(client->hwaddr));
	// This may be an alias-client, the ID is set elsewhere
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

/**
 * @brief Updates the client count, blocked count, and overtime data for a given
 * client.
 *
 * This function modifies the client's count and blocked count by the specified
 * amounts. Additionally, if a valid overtime index is provided, it updates the
 * overtime data for the client and the global overtime array. This update can
 * be avoided by setting overTimeIdx to -1.
 *
 * @param client Pointer to the clientsData structure representing the client.
 * @param total The amount to add to the client's count.
 * @param blocked The amount to add to the client's blocked count.
 * @param overTimeIdx The index of the overtime slot to update. Must be between
 * 0 and OVERTIME_SLOTS - 1 or -1 to skip updating the overtime data.
 * @param overTimeMod The amount to add to the specified overtime slot.
 */
void change_clientcount(clientsData *client, const int total, const int blocked,
                        const int overTimeIdx, const int overTimeMod)
{
		client->count += total;
		client->blockedcount += blocked;
		if(overTimeIdx > -1 && (unsigned int)overTimeIdx < OVERTIME_SLOTS)
		{
			overTime[overTimeIdx].total += overTimeMod;
			log_debug(DEBUG_OVERTIME, "overTime[%d].total += %d = %d",
			          overTimeIdx, overTimeMod, overTime[overTimeIdx].total);
			client->overTime[overTimeIdx] += overTimeMod;
		}

		// Also add counts to the connected alias-client (if any)
		if(client->flags.aliasclient)
		{
			log_warn("Should not add to alias-client directly (client \"%s\" (%s))!",
			         getstr(client->namepos), getstr(client->ippos));
			return;
		}
		if(client->aliasclient_id > -1)
		{
			clientsData *aliasclient = getClient(client->aliasclient_id, true);
			aliasclient->count += total;
			aliasclient->blockedcount += blocked;
			if(overTimeIdx > -1 && (unsigned int)overTimeIdx < OVERTIME_SLOTS)
				aliasclient->overTime[overTimeIdx] += overTimeMod;
		}
}

static int get_next_free_cacheID(void)
{
	// First, try to obtain a previously recycled cache ID
	unsigned int cacheID = 0;
	if(get_next_recycled_ID(DNS_CACHE, &cacheID))
		return cacheID;

	// If we did not return until here, then we need to allocate a new cache ID
	return counters->dns_cache_size;
}

static bool cmp_cache(const struct lookup_table *entry, const struct lookup_data *lookup_data)
{
	// Get cache pointer
	const DNSCacheData *cache = getDNSCache(entry->id, true);

	// Check if the returned pointer is valid before trying to access it
	if(cache == NULL)
		return false;

	// Compare cache data
	return cache->domainID == lookup_data->domainID &&
	       cache->clientID == lookup_data->clientID &&
	       cache->query_type == lookup_data->query_type;
}

int _findCacheID(const unsigned int domainID, const unsigned int clientID, const enum query_type query_type,
                 const bool create_new, const char *func, int line, const char *file)
{
	// Get cache hash
	const uint32_t hash = hashCacheIDs(domainID, clientID, query_type);

	// Use lookup table to speed up cache lookups
	const struct lookup_data lookup_data = { .domainID = domainID, .clientID = clientID, .query_type = query_type };
	unsigned int cacheID = 0;
	if(lookup_find_id(DNS_CACHE_LOOKUP, hash, &lookup_data, &cacheID, cmp_cache))
	{
		// Get cache pointer
		DNSCacheData *cache = getDNSCache(cacheID, true);

		// Check if the returned pointer is valid before trying to access it
		if(cache == NULL)
			return -1;

		return cacheID;
	}

	if(!create_new)
		return -1;

	// Get ID of new cache entry
	cacheID = get_next_free_cacheID();

	// Get client pointer
	DNSCacheData *dns_cache = _getDNSCache(cacheID, false, line, func, file);

	if(dns_cache == NULL)
	{
		log_err("Encountered serious memory error in findCacheID()");
		return -1;
	}

	log_debug(DEBUG_GC, "New cache entry: domainID %u, clientID %u, query_type %u (ID %u)",
	          domainID, clientID, query_type, cacheID);

	// Insert cache into lookup table
	lookup_insert(DNS_CACHE_LOOKUP, cacheID, hash);

	// Initialize cache entry
	dns_cache->magic = MAGICBYTE;
	dns_cache->blocking_status = QUERY_UNKNOWN;
	dns_cache->expires = 0;
	dns_cache->hash = hash;
	dns_cache->domainID = domainID;
	dns_cache->clientID = clientID;
	dns_cache->query_type = query_type;
	dns_cache->force_reply = 0u;
	dns_cache->list_id = -1; // -1 = not set

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
const char *getDomainString(const queriesData *query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS)
	{
		// Get domain pointer
		const domainsData *domain = getDomain(query->domainID, true);

		// Check if the returned pointer is valid before trying to access it
		if(domain == NULL)
			return "";

		// Return string
		return getstr(domain->domainpos);
	}
	else
		return HIDDEN_DOMAIN;
}

// Privacy-level sensitive subroutine that returns the domain name
// only when appropriate for the requested query
const char *getCNAMEDomainString(const queriesData *query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL || query->CNAME_domainID < 0)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS)
	{
		// Get domain pointer
		const domainsData *domain = getDomain(query->CNAME_domainID, true);

		// Check if the returned pointer is valid before trying to access it
		if(domain == NULL)
			return "";

		// Return string
		return getstr(domain->domainpos);
	}
	else
		return HIDDEN_DOMAIN;
}

// Privacy-level sensitive subroutine that returns the client IP
// only when appropriate for the requested query
const char *getClientIPString(const queriesData *query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		// Get client pointer
		const clientsData *client = getClient(query->clientID, true);

		// Check if the returned pointer is valid before trying to access it
		if(client == NULL)
			return "";

		// Return string
		return getstr(client->ippos);
	}
	else
		return HIDDEN_CLIENT;
}

// Privacy-level sensitive subroutine that returns the client host name
// only when appropriate for the requested query
const char *getClientNameString(const queriesData *query)
{
	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

	if(query->privacylevel < PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		// Get client pointer
		const clientsData *client = getClient(query->clientID, true);

		// Check if the returned pointer is valid before trying to access it
		if(client == NULL)
			return "";

		// Return string
		return getstr(client->namepos);
	}
	else
		return HIDDEN_CLIENT;
}

void FTL_reset_per_client_domain_data(void)
{
	log_debug(DEBUG_DATABASE, "Resetting per-client DNS cache, size is %u", counters->dns_cache_size);

	for(unsigned int cacheID = 0; cacheID < counters->dns_cache_size; cacheID++)
	{
		// Get cache pointer
		DNSCacheData *dns_cache = getDNSCache(cacheID, true);

		// Check if the returned pointer is valid before trying to access it
		if(dns_cache == NULL)
			continue;

		// Reset blocking status
		dns_cache->blocking_status = QUERY_UNKNOWN;
		// Reset expiry
		dns_cache->expires = 0;
		// Reset domainlist ID
		dns_cache->list_id = -1;
	}
}

// Reloads all domainlists and performs a few extra tasks such as cleaning the
// message table
// May only be called from the database thread
void FTL_reload_all_domainlists(void)
{
	lock_shm();

	// (Re-)open gravity database connection
	gravityDB_reopen();

	// Get size of gravity, number of domains, groups, clients, and lists
	counters->database.gravity = gravityDB_count(GRAVITY_TABLE, false);
	counters->database.groups = gravityDB_count(GROUPS_TABLE, false);
	counters->database.clients = gravityDB_count(CLIENTS_TABLE, false);
	counters->database.lists = gravityDB_count(ADLISTS_TABLE, false);

	counters->database.domains.allowed.exact.total = gravityDB_count(EXACT_ALLOW_TABLE, true);
	counters->database.domains.allowed.exact.enabled = gravityDB_count(EXACT_ALLOW_TABLE, false);

	counters->database.domains.denied.exact.total = gravityDB_count(EXACT_DENY_TABLE, true);
	counters->database.domains.denied.exact.enabled = gravityDB_count(EXACT_DENY_TABLE, false);

	counters->database.domains.allowed.regex.total = gravityDB_count(REGEX_ALLOW_TABLE, true);
	counters->database.domains.allowed.regex.enabled = gravityDB_count(REGEX_ALLOW_TABLE, false);

	counters->database.domains.denied.regex.total = gravityDB_count(REGEX_DENY_TABLE, true);
	counters->database.domains.denied.regex.enabled = gravityDB_count(REGEX_DENY_TABLE, false);

	// Read and compile possible regex filters
	// only after having called gravityDB_reopen()
	read_regex_from_database();

	// Check for inaccessible adlist URLs
	check_inaccessible_adlists();

	// Check for restored gravity database
	check_restored_gravity();

	// Reset FTL's internal DNS cache storing whether a specific domain
	// has already been validated for a specific user
	FTL_reset_per_client_domain_data();

	unlock_shm();
}

const char *get_query_type_str(const enum query_type type, const queriesData *query, char buffer[20])
{
	switch (type)
	{
		case TYPE_NONE:
			return "NONE";
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
			if(query != NULL && buffer != NULL)
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

const char * __attribute__ ((const)) get_query_status_str(const enum query_status status)
{
	switch (status)
	{
		case QUERY_UNKNOWN:
			return "UNKNOWN";
		case QUERY_GRAVITY:
			return "GRAVITY";
		case QUERY_FORWARDED:
			return "FORWARDED";
		case QUERY_CACHE:
			return "CACHE";
		case QUERY_REGEX:
			return "REGEX";
		case QUERY_DENYLIST:
			return "DENYLIST";
		case QUERY_EXTERNAL_BLOCKED_IP:
			return "EXTERNAL_BLOCKED_IP";
		case QUERY_EXTERNAL_BLOCKED_NULL:
			return "EXTERNAL_BLOCKED_NULL";
		case QUERY_EXTERNAL_BLOCKED_NXRA:
			return "EXTERNAL_BLOCKED_NXRA";
		case QUERY_GRAVITY_CNAME:
			return "GRAVITY_CNAME";
		case QUERY_REGEX_CNAME:
			return "REGEX_CNAME";
		case QUERY_DENYLIST_CNAME:
			return "DENYLIST_CNAME";
		case QUERY_RETRIED:
			return "RETRIED";
		case QUERY_RETRIED_DNSSEC:
			return "RETRIED_DNSSEC";
		case QUERY_IN_PROGRESS:
			return "IN_PROGRESS";
		case QUERY_DBBUSY:
			return "DBBUSY";
		case QUERY_SPECIAL_DOMAIN:
			return "SPECIAL_DOMAIN";
		case QUERY_CACHE_STALE:
			return "CACHE_STALE";
		case QUERY_EXTERNAL_BLOCKED_EDE15:
			return "EXTERNAL_BLOCKED_EDE15";
		case QUERY_STATUS_MAX:
		default:
			return "INVALID";
	}
}

const char * __attribute__ ((const)) get_query_reply_str(const enum reply_type reply)
{
	switch (reply)
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
		case REPLY_DNSSEC:
			return "DNSSEC";
		case REPLY_NONE:
			return "NONE";
		case REPLY_BLOB:
			return "BLOB";
		case QUERY_REPLY_MAX:
		default:
			return "N/A";
	}
}

const char * __attribute__ ((const)) get_query_dnssec_str(const enum dnssec_status dnssec)
{
	switch (dnssec)
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
		case DNSSEC_TRUNCATED:
			return "TRUNCATED";
		case DNSSEC_MAX:
		default:
			return "N/A";
	}
}

const char * __attribute__ ((const)) get_refresh_hostnames_str(const enum refresh_hostnames refresh)
{
	switch (refresh)
	{
		case REFRESH_ALL:
			return "ALL";
		case REFRESH_IPV4_ONLY:
			return "IPV4_ONLY";
		case REFRESH_UNKNOWN:
			return "UNKNOWN";
		case REFRESH_NONE:
			return "NONE";
		case REFRESH_MAX:
		default:
			return "N/A";
	}
}

int __attribute__ ((pure)) get_refresh_hostnames_val(const char *refresh_hostnames)
{
	if(strcasecmp(refresh_hostnames, "ALL") == 0)
		return REFRESH_ALL;
	else if(strcasecmp(refresh_hostnames, "IPV4_ONLY") == 0)
		return REFRESH_IPV4_ONLY;
	else if(strcasecmp(refresh_hostnames, "UNKNOWN") == 0)
		return REFRESH_UNKNOWN;
	else if(strcasecmp(refresh_hostnames, "NONE") == 0)
		return REFRESH_NONE;

	// Invalid value
	return -1;
}

const char * __attribute__ ((const)) get_blocking_mode_str(const enum blocking_mode mode)
{
	switch (mode)
	{
		case MODE_IP:
			return "IP";
		case MODE_NX:
			return "NX";
		case MODE_NULL:
			return "NULL";
		case MODE_IP_NODATA_AAAA:
			return "IP_NODATA_AAAA";
		case MODE_NODATA:
			return "NODATA";
		case MODE_MAX:
		default:
			return "N/A";
	}
}

int __attribute__ ((pure)) get_blocking_mode_val(const char *blocking_mode)
{
	if(strcasecmp(blocking_mode, "IP") == 0)
		return MODE_IP;
	else if(strcasecmp(blocking_mode, "NX") == 0)
		return MODE_NX;
	else if(strcasecmp(blocking_mode, "NULL") == 0)
		return MODE_NULL;
	else if(strcasecmp(blocking_mode, "IP_NODATA_AAAA") == 0)
		return MODE_IP_NODATA_AAAA;
	else if(strcasecmp(blocking_mode, "NODATA") == 0)
		return MODE_NODATA;

	// Invalid value
	return -1;
}

const char * __attribute__ ((const)) get_blocking_status_str(const enum blocking_status blocking)
{
	switch(blocking)
	{
		case BLOCKING_ENABLED:
			return "enabled";
		case BLOCKING_DISABLED:
			return "disabled";
		case DNS_FAILED:
			return "failure";
		case BLOCKING_UNKNOWN:
		default:
			return "unknown";
	}
}

bool __attribute__ ((const)) is_blocked(const enum query_status status)
{
	switch (status)
	{
		case QUERY_UNKNOWN:
		case QUERY_FORWARDED:
		case QUERY_CACHE:
		case QUERY_RETRIED:
		case QUERY_RETRIED_DNSSEC:
		case QUERY_IN_PROGRESS:
		case QUERY_CACHE_STALE:
		case QUERY_STATUS_MAX:
		default:
			return false;

		case QUERY_GRAVITY:
		case QUERY_REGEX:
		case QUERY_DENYLIST:
		case QUERY_EXTERNAL_BLOCKED_IP:
		case QUERY_EXTERNAL_BLOCKED_NULL:
		case QUERY_EXTERNAL_BLOCKED_NXRA:
		case QUERY_EXTERNAL_BLOCKED_EDE15:
		case QUERY_GRAVITY_CNAME:
		case QUERY_REGEX_CNAME:
		case QUERY_DENYLIST_CNAME:
		case QUERY_DBBUSY:
		case QUERY_SPECIAL_DOMAIN:
			return true;
	}
}

static char blocked_list[32] = { 0 };
const char * __attribute__ ((pure)) get_blocked_statuslist(void)
{
	if(blocked_list[0] != '\0')
		return blocked_list;

	// Build a list of blocked query statuses
	unsigned int first = 0;
	// Open parenthesis
	blocked_list[0] = '(';
	size_t pos = 1;  // Track current position instead of calling strlen repeatedly
	for(enum query_status status = 0; status < QUERY_STATUS_MAX; status++)
		if(is_blocked(status))
		{
			int written = snprintf(blocked_list + pos, sizeof(blocked_list) - pos,
			                      "%s%d", first++ < 1 ? "" : ",", status);
			if(written > 0 && (size_t)written < sizeof(blocked_list) - pos)
				pos += written;
		}

	// Close parenthesis
	blocked_list[pos] = ')';
	blocked_list[pos + 1] = '\0';
	return blocked_list;
}

static char cached_list[32] = { 0 };
const char * __attribute__ ((pure)) get_cached_statuslist(void)
{
	if(cached_list[0] != '\0')
		return cached_list;

	// Build a list of cached query statuses
	unsigned int first = 0;
	// Open parenthesis
	cached_list[0] = '(';
	size_t pos = 1;  // Track current position instead of calling strlen repeatedly
	for(enum query_status status = 0; status < QUERY_STATUS_MAX; status++)
		if(is_cached(status))
		{
			int written = snprintf(cached_list + pos, sizeof(cached_list) - pos,
			                      "%s%d", first++ < 1 ? "" : ",", status);
			if(written > 0 && (size_t)written < sizeof(cached_list) - pos)
				pos += written;
		}

	// Close parenthesis
	cached_list[pos] = ')';
	cached_list[pos + 1] = '\0';
	return cached_list;
}

static char permitted_list[32] = { 0 };
const char * __attribute__ ((pure)) get_permitted_statuslist(void)
{
	if(permitted_list[0] != '\0')
		return permitted_list;

	// Build a list of permitted query statuses
	unsigned int first = 0;
	// Open parenthesis
	permitted_list[0] = '(';
	size_t pos = 1;  // Track current position instead of calling strlen repeatedly
	for(enum query_status status = 0; status < QUERY_STATUS_MAX; status++)
		if(!is_blocked(status))
		{
			int written = snprintf(permitted_list + pos, sizeof(permitted_list) - pos,
			                      "%s%d", first++ < 1 ? "" : ",", status);
			if(written > 0 && (size_t)written < sizeof(permitted_list) - pos)
				pos += written;
		}

	// Close parenthesis
	permitted_list[pos] = ')';
	permitted_list[pos + 1] = '\0';
	return permitted_list;
}

unsigned int __attribute__ ((pure)) get_blocked_count(void)
{
	int blocked = 0;
	for(enum query_status status = 0; status < QUERY_STATUS_MAX; status++)
		if(is_blocked(status))
			blocked += counters->status[status];

	return blocked;
}

unsigned int __attribute__ ((pure)) get_forwarded_count(void)
{
	return counters->status[QUERY_FORWARDED] +
	       counters->status[QUERY_RETRIED] +
	       counters->status[QUERY_RETRIED_DNSSEC];
}

unsigned int __attribute__ ((pure)) get_cached_count(void)
{
	return counters->status[QUERY_CACHE] + counters->status[QUERY_CACHE_STALE];
}

bool __attribute__ ((const)) is_cached(const enum query_status status)
{
	switch (status)
	{
		case QUERY_CACHE:
		case QUERY_CACHE_STALE:
			return true;

		case QUERY_UNKNOWN:
		case QUERY_FORWARDED:
		case QUERY_RETRIED:
		case QUERY_RETRIED_DNSSEC:
		case QUERY_IN_PROGRESS:
		case QUERY_STATUS_MAX:
		case QUERY_GRAVITY:
		case QUERY_REGEX:
		case QUERY_DENYLIST:
		case QUERY_EXTERNAL_BLOCKED_IP:
		case QUERY_EXTERNAL_BLOCKED_NULL:
		case QUERY_EXTERNAL_BLOCKED_NXRA:
		case QUERY_EXTERNAL_BLOCKED_EDE15:
		case QUERY_GRAVITY_CNAME:
		case QUERY_REGEX_CNAME:
		case QUERY_DENYLIST_CNAME:
		case QUERY_DBBUSY:
		case QUERY_SPECIAL_DOMAIN:
		default:
			return false;
	}
}

static const char* __attribute__ ((const)) query_status_str(const enum query_status status)
{
	switch (status)
	{
		case QUERY_UNKNOWN:
			return "UNKNOWN";
		case QUERY_GRAVITY:
			return "GRAVITY";
		case QUERY_FORWARDED:
			return "FORWARDED";
		case QUERY_CACHE:
			return "CACHE";
		case QUERY_REGEX:
			return "REGEX";
		case QUERY_DENYLIST:
			return "DENYLIST";
		case QUERY_EXTERNAL_BLOCKED_IP:
			return "EXTERNAL_BLOCKED_IP";
		case QUERY_EXTERNAL_BLOCKED_NULL:
			return "EXTERNAL_BLOCKED_NULL";
		case QUERY_EXTERNAL_BLOCKED_NXRA:
			return "EXTERNAL_BLOCKED_NXRA";
		case QUERY_GRAVITY_CNAME:
			return "GRAVITY_CNAME";
		case QUERY_REGEX_CNAME:
			return "REGEX_CNAME";
		case QUERY_DENYLIST_CNAME:
			return "DENYLIST_CNAME";
		case QUERY_RETRIED:
			return "RETRIED";
		case QUERY_RETRIED_DNSSEC:
			return "RETRIED_DNSSEC";
		case QUERY_IN_PROGRESS:
			return "IN_PROGRESS";
		case QUERY_DBBUSY:
			return "DBBUSY";
		case QUERY_SPECIAL_DOMAIN:
			return "SPECIAL_DOMAIN";
		case QUERY_CACHE_STALE:
			return "CACHE_STALE";
		case QUERY_EXTERNAL_BLOCKED_EDE15:
			return "EXTERNAL_BLOCKED_EDE15";
		case QUERY_STATUS_MAX:
			return NULL;
	}
	return NULL;
}

void _query_set_status(queriesData *query, const enum query_status new_status, const bool init,
                       const char *func, const int line, const char *file)
{
	// Debug logging
	if(config.debug.status.v.b)
	{
		if(init)
		{
			const char *newstr = new_status < QUERY_STATUS_MAX ? query_status_str(new_status) : "INVALID";
			log_debug(DEBUG_STATUS, "Query %i: status initialized: %s (%d) in %s() (%s:%i)",
			          query->id, newstr, new_status, func, short_path(file), line);
		}
		else if(query->status == new_status)
		{
			const char *oldstr = query->status < QUERY_STATUS_MAX ? query_status_str(query->status) : "INVALID";
			log_debug(DEBUG_STATUS, "Query %i: status unchanged: %s (%d) in %s() (%s:%i)",
			          query->id, oldstr, query->status, func, short_path(file), line);
		}
		else
		{
			const char *oldstr = query->status < QUERY_STATUS_MAX ? query_status_str(query->status) : "INVALID";
			const char *newstr = new_status < QUERY_STATUS_MAX ? query_status_str(new_status) : "INVALID";
			log_debug(DEBUG_STATUS, "Query %i: status changed: %s (%d) -> %s (%d) in %s() (%s:%i)",
			          query->id, oldstr, query->status, newstr, new_status, func, short_path(file), line);
		}
	}

	// Sanity check
	if(new_status >= QUERY_STATUS_MAX)
		return;

	const enum query_status old_status = query->status;
	if(old_status == new_status && !init)
	{
		// Nothing to do
		return;
	}

	// Memorize this in the DNS cache if blocked due to the response
	// We do not cache intermittent statuses as they are subject to change
	if(!init &&
	   new_status != QUERY_UNKNOWN &&
	   new_status != QUERY_DBBUSY &&
	   new_status != QUERY_IN_PROGRESS &&
	   new_status != QUERY_RETRIED &&
	   new_status != QUERY_RETRIED_DNSSEC)
	{
		const unsigned int cacheID = query->cacheID > 0 ? query->cacheID : findCacheID(query->domainID, query->clientID, query->type, true);
		DNSCacheData *dns_cache = getDNSCache(cacheID, true);
		if(dns_cache != NULL && dns_cache->blocking_status != new_status)
		{
			// Memorize blocking status DNS cache for the domain/client combination
			dns_cache->blocking_status = new_status;

			// Set expiration time for this cache entry (if applicable)
			// We set this only if not already set to avoid extending the TTL of an
			// existing entry
			if(config.dns.cache.upstreamBlockedTTL.v.ui > 0 &&
			   dns_cache->expires == 0 &&
			   (new_status == QUERY_EXTERNAL_BLOCKED_NXRA ||
			    new_status == QUERY_EXTERNAL_BLOCKED_NULL ||
			    new_status == QUERY_EXTERNAL_BLOCKED_IP ||
			    new_status == QUERY_EXTERNAL_BLOCKED_EDE15))
			{
				// Set expiration time for this cache entry
				dns_cache->expires = time(NULL) + config.dns.cache.upstreamBlockedTTL.v.ui;
			}

			if(config.debug.queries.v.b)
			{
				// Debug logging
				const char *qtype = get_query_type_str(dns_cache->query_type, NULL, NULL);
				const char *domain = getDomainString(query);
				const char *clientstr = getClientIPString(query);
				const char *statusstr = get_query_status_str(new_status);

				if(dns_cache->expires > 0)
				{
					log_debug(DEBUG_QUERIES, "DNS cache: %s/%s/%s -> %s, expires in %lis",
					          qtype, clientstr, domain, statusstr,
					          (long)(dns_cache->expires - time(NULL)));
				}
				else
				{
					log_debug(DEBUG_QUERIES, "DNS cache: %s/%s/%s -> %s, no expiry",
					          qtype, clientstr, domain, statusstr);
				}
			}
		}
	}

	// else: update global counters, ...
	if(!init)
	{
		counters->status[old_status]--;
		log_debug(DEBUG_STATUS, "status %d removed (!init), ID = %d, new count = %u", QUERY_UNKNOWN, query->id, counters->status[QUERY_UNKNOWN]);
	}
	counters->status[new_status]++;
	log_debug(DEBUG_STATUS, "status %d set, ID = %d, new count = %u", new_status, query->id, counters->status[new_status]);

	// ... update overTime counters, ...
	const int timeidx = getOverTimeID(query->timestamp);
	if(is_blocked(old_status) && !init)
	{
		overTime[timeidx].blocked--;
		log_debug(DEBUG_OVERTIME, "overTime[%d].blocked-- = %d (old_status = %s), ID = %d",
		          timeidx, overTime[timeidx].blocked, get_query_status_str(old_status), query->id);
	}
	if(is_blocked(new_status))
	{
		overTime[timeidx].blocked++;
		log_debug(DEBUG_OVERTIME, "overTime[%d].blocked++ = %d (new_status = %s), ID = %d",
		          timeidx, overTime[timeidx].blocked, get_query_status_str(new_status), query->id);
	}

	if((old_status == QUERY_CACHE || old_status == QUERY_CACHE_STALE) && !init)
	{
		overTime[timeidx].cached--;
		log_debug(DEBUG_OVERTIME, "overTime[%d].cached-- = %d (old_status = %s), ID = %d",
		          timeidx, overTime[timeidx].cached, get_query_status_str(old_status), query->id);
	}
	if(new_status == QUERY_CACHE || new_status == QUERY_CACHE_STALE)
	{
		overTime[timeidx].cached++;
		log_debug(DEBUG_OVERTIME, "overTime[%d].cached++ = %d (new_status = %s), ID = %d",
		          timeidx, overTime[timeidx].cached, get_query_status_str(new_status), query->id);
	}

	if(old_status == QUERY_FORWARDED && !init)
	{
		overTime[timeidx].forwarded--;
		log_debug(DEBUG_OVERTIME, "overTime[%d].forwarded-- = %d (old_status = %s), ID = %d",
		          timeidx, overTime[timeidx].forwarded, get_query_status_str(old_status), query->id);
	}
	if(new_status == QUERY_FORWARDED)
	{
		overTime[timeidx].forwarded++;
		log_debug(DEBUG_OVERTIME, "overTime[%d].forwarded++ = %d (new_status = %s), ID = %d",
		          timeidx, overTime[timeidx].forwarded, get_query_status_str(new_status), query->id);
	}

	// ... and set new status
	query->status = new_status;
}

const char * __attribute__ ((const)) get_ptr_type_str(const enum ptr_type piholePTR)
{
	switch(piholePTR)
	{
		case PTR_PIHOLE:
			return "PI.HOLE";
		case PTR_HOSTNAME:
			return "HOSTNAME";
		case PTR_HOSTNAMEFQDN:
			return "HOSTNAMEFQDN";
		case PTR_NONE:
			return "NONE";
		case PTR_MAX:
		default:
			return NULL;
	}
}

int __attribute__ ((pure)) get_ptr_type_val(const char *piholePTR)
{
	if(strcasecmp(piholePTR, "pi.hole") == 0)
		return PTR_PIHOLE;
	else if(strcasecmp(piholePTR, "hostname") == 0)
		return PTR_HOSTNAME;
	else if(strcasecmp(piholePTR, "hostnamefqdn") == 0)
		return PTR_HOSTNAMEFQDN;
	else if(strcasecmp(piholePTR, "none") == 0 ||
		strcasecmp(piholePTR, "false") == 0)
		return PTR_NONE;

	// Invalid value
	return -1;
}

const char * __attribute__ ((const)) get_busy_reply_str(const enum busy_reply replyWhenBusy)
{
	switch(replyWhenBusy)
	{
		case BUSY_BLOCK:
			return "BLOCK";
		case BUSY_ALLOW:
			return "ALLOW";
		case BUSY_REFUSE:
			return "REFUSE";
		case BUSY_DROP:
			return "DROP";
		case BUSY_MAX:
		default:
			return NULL;
	}
}

int __attribute__ ((pure)) get_busy_reply_val(const char *replyWhenBusy)
{
	if(strcasecmp(replyWhenBusy, "BLOCK") == 0)
		return BUSY_BLOCK;
	else if(strcasecmp(replyWhenBusy, "ALLOW") == 0)
		return BUSY_ALLOW;
	else if(strcasecmp(replyWhenBusy, "REFUSE") == 0)
		return BUSY_REFUSE;
	else if(strcasecmp(replyWhenBusy, "DROP") == 0)
		return BUSY_DROP;

	// Invalid value
	return -1;
}

const char * __attribute__ ((const)) get_listeningMode_str(const enum listening_mode listeningMode)
{
	switch(listeningMode)
	{
		case LISTEN_LOCAL:
			return "LOCAL";
		case LISTEN_ALL:
			return "ALL";
		case LISTEN_SINGLE:
			return "SINGLE";
		case LISTEN_BIND:
			return "BIND";
		case LISTEN_NONE:
			return "NONE";
		case LISTEN_MAX:
		default:
			return NULL;
	}
}

int __attribute__ ((pure)) get_listeningMode_val(const char *listeningMode)
{
	if(strcasecmp(listeningMode, "LOCAL") == 0)
		return LISTEN_LOCAL;
	else if(strcasecmp(listeningMode, "ALL") == 0)
		return LISTEN_ALL;
	else if(strcasecmp(listeningMode, "SINGLE") == 0)
		return LISTEN_SINGLE;
	else if(strcasecmp(listeningMode, "BIND") == 0)
		return LISTEN_BIND;
	else if(strcasecmp(listeningMode, "NONE") == 0)
		return LISTEN_NONE;

	// Invalid value
	return -1;
}

const char * __attribute__ ((const)) get_temp_unit_str(const enum temp_unit temp_unit)
{
	switch(temp_unit)
	{
		case TEMP_UNIT_C:
			return "C";
		case TEMP_UNIT_F:
			return "F";
		case TEMP_UNIT_K:
			return "K";
		case TEMP_UNIT_MAX:
		default:
			return NULL;
	}
}

int __attribute__ ((pure)) get_temp_unit_val(const char *temp_unit)
{
	if(strcasecmp(temp_unit, "C") == 0)
		return TEMP_UNIT_C;
	else if(strcasecmp(temp_unit, "F") == 0)
		return TEMP_UNIT_F;
	else if(strcasecmp(temp_unit, "K") == 0)
		return TEMP_UNIT_K;

	// Invalid value
	return -1;
}

const char * __attribute__ ((const)) get_edns_mode_str(const enum edns_mode edns_mode)
{
	switch(edns_mode)
	{
		case EDNS_MODE_NONE:
			return "NONE";
		case EDNS_MODE_CODE:
			return "CODE";
		case EDNS_MODE_TEXT:
			return "TEXT";
		case EDNS_MODE_MAX:
		default:
			return NULL;
	}
}

int __attribute__ ((pure)) get_edns_mode_val(const char *edns_mode)
{
	if(strcasecmp(edns_mode, "NONE") == 0)
		return EDNS_MODE_NONE;
	else if(strcasecmp(edns_mode, "CODE") == 0)
		return EDNS_MODE_CODE;
	else if(strcasecmp(edns_mode, "TEXT") == 0)
		return EDNS_MODE_TEXT;

	// Invalid value
	return -1;
}
