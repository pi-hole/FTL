/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Datastructure prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DATASTRUCTURE_H
#define DATASTRUCTURE_H

// Definition of sqlite3_stmt
#include "database/sqlite3.h"

// enum privacy_level
#include "enums.h"

// Definitions like OVERTIME_SLOT
#include "FTL.h"

typedef struct {
	// Fields ordered by alignment (8-byte, 4-byte, 2-byte, 1-byte) to
	// eliminate padding, reducing struct size from 72 to 64 bytes (~2.4 MB
	// saved per 300K queries). No size_t or pointer fields -> identical
	// 64-byte layout on all architectures (32-bit armhf, aarch64, x86,
	// x86_64).
	double response;
	double timestamp;
	sqlite3_int64 db;
	unsigned int domainID;
	unsigned int clientID;
	int upstreamID; // -1 if not forwarded
	int cacheID;
	int id; // the ID is a (signed) int in dnsmasq, so no need for a long int here
	int CNAME_domainID; // only valid if query has a CNAME blocking status, -1 otherwise
	int ede;
	uint16_t qtype;
	unsigned char magic;
	enum query_status status;
	enum query_type type;
	enum privacy_level privacylevel;
	enum reply_type reply;
	enum dnssec_status dnssec;
	// Adjacent bit field members in the struct flags may be packed to share
	// and straddle the individual bytes. It is useful to pack the memory as
	// tightly as possible as there may be dozens of thousands of these
	// objects in memory (one per query). C99 guarantees that bit-fields
	// will be packed as tightly as possible, provided they don't cross
	// storage unit boundaries (6.7.2.1 #10).
	struct query_flags {
		bool allowed :1;
		bool complete :1;
		bool blocked :1;
		bool response_calculated :1;
		// Query is filtered but never recorded (dns.ignoreLocalhost). Such
		// queries live on the stack only, so every counter update has to be
		// skipped - nothing would ever hand the count back.
		bool hidden :1;
		struct database_flags {
			bool changed :1;
			bool imported :1;
		} database;
	} flags;
} queriesData;

typedef struct {
	// Contains size_t and double fields -> size differs by architecture
	// (64-bit: 64 bytes with 4 bytes internal padding before ippos; 32-bit:
	// ~52 bytes, no padding). The whole struct fits in exactly one 64-byte
	// cache line, so internal padding has no cache impact. Total size
	// cannot be reduced below 64 bytes (struct alignment requires a
	// multiple of 8).
	unsigned char magic;
	struct upstream_flags {
		bool new:1;
		bool in_database:1;
	} flags;
	in_port_t port;
	int count;
	int failed;
	int db_id;
	unsigned int responses;
	size_t ippos;
	size_t namepos;
	double rtime;
	double rtuncertainty;
	double lastQuery;
} upstreamsData;

typedef struct {
	// Hot fields ordered first for cache locality; cold overTime[] array at
	// end. Contains size_t fields -> size differs by architecture (64-bit:
	// 684 bytes for OVERTIME_SLOTS=145; 32-bit: ~668 bytes).
	// On 64-bit, 4 bytes between hash (offset 48) and groupspos (offset
	// 56) are intentional alignment padding: they ensure ippos lands at
	// offset 64, the start of cache line 1. Without them, ippos would be
	// at offset 60 and straddle the cache line boundary (bytes 60–67),
	// causing a split load on every client IP comparison.
	unsigned char magic;
	char hwlen;
	unsigned char hwaddr[16]; // See DHCP_CHADDR_MAX in dnsmasq/dhcp-protocol.h
	struct client_flags {
		bool new:1;
		bool found_group:1;
		bool aliasclient:1;
		bool rate_limited:1;
		bool in_database:1;
	} flags;
	int count;
	int blockedcount;
	// Queries kept out of the statistics (dns.ignoreLocalhost) are counted
	// here instead. Not a statistic - it only tells garbage collection that
	// this client is still referenced by a query
	int hiddencount;
	int aliasclient_id; // -1 if not an alias-client
	int db_id;
	unsigned int id;
	unsigned int rate_limit;
	unsigned int numQueriesARP;
	uint32_t hash;
	size_t groupspos; // SHM intarray: client's assigned group IDs
	size_t ippos;
	size_t namepos;
	size_t ifacepos;
	double firstSeen;
	double lastQuery;
	// overTime is accessed only every 10 minutes (cold), so it lives at the
	// end to keep hot fields within the first two 64-byte cache lines:
	// line 0 (0–63): magic...hash + groupspos; line 1 (64–127): ippos...lastQuery.
	int overTime[OVERTIME_SLOTS];
} clientsData;

typedef struct {
	// Contains size_t and double fields -> size differs by architecture
	// (64-bit: 48 bytes; 32-bit: ~40 bytes). The whole struct fits in a
	// single 64-byte cache line, so internal padding (6 bytes on 64-bit: 2
	// before count and 4 before domainpos) has no cache impact.
	// Reordering to put 4-byte fields first would eliminate internal
	// padding but cannot reduce total size below 48 bytes (struct alignment
	// requires a multiple of 8).
	unsigned char magic;
	struct domain_flags {
		bool in_database:1;
	} flags;
	int count;
	int blockedcount;
	int cname_refcount;
	// See clientsData.hiddencount
	int hiddencount;
	int db_id;
	unsigned int id;
	uint32_t hash;
	size_t domainpos;
	double lastQuery;
} domainsData;

typedef struct {
	// Fields ordered by alignment (4-byte, then 1-byte) to eliminate
	// padding. No pointer or size_t fields -> identical 36-byte layout on
	// all architectures (32-bit armhf, aarch64, x86, x86_64).
	unsigned int domainID;
	unsigned int clientID;
	unsigned int CNAME_domainID; // only valid if query has a CNAME blocking status
	int list_id;
	int refcount;
	uint32_t hash;
	// Stored as seconds since SHM_TIME_EPOCH (see shmem.h). Avoids the
	// Y2038 problem: valid until ~2160 on all supported platforms. The
	// reference timestamp may easily be changed in the future if needed
	// without side-effects.
	uint32_t expires;
	// Position of the regex CNAME target string in the shared string pool
	// (0 = no CNAME target)
	uint32_t cname_strpos;
	// 1-byte fields at end to avoid padding before the 4-byte fields above
	unsigned char magic;
	struct {
		bool allowed :1;
	} flags;
	enum query_status blocking_status;
	enum reply_type force_reply;
	enum query_type query_type;
} DNSCacheData;

struct lookup_data {
	const char *domain;
	const char *client;
	unsigned int domainID;
	unsigned int clientID;
	enum query_type query_type;
};

void strtolower(char *str);
void strcpy_tolower(char *dst, const char *src, size_t dstsize);
int findQueryID(const int id);
void queryIDMap_insert(const int dnsmasq_id, const int query_index);
void queryIDMap_clear(void);
#define findUpstreamID(upstream, port) _findUpstreamID(upstream, port, __LINE__, __FUNCTION__, __FILE__)
int _findUpstreamID(const char *upstream, const in_port_t port, int line, const char *func, const char *file);
#define findDomainID(domain, count, hidden) _findDomainID(domain, count, hidden, __LINE__, __FUNCTION__, __FILE__)
int _findDomainID(const char *domain, const bool count, const bool hidden, int line, const char *func, const char *file);
#define findClientID(client, count, aliasclient, now, hidden) _findClientID(client, count, aliasclient, now, hidden, __LINE__, __FUNCTION__, __FILE__)
int _findClientID(const char *client, const bool count, const bool aliasclient, const double now, const bool hidden, int line, const char *func, const char *file);
#define findCacheID(domainID, clientID, query_type, create_new) _findCacheID(domainID, clientID, query_type, create_new, __FUNCTION__, __LINE__, __FILE__)
int _findCacheID(const unsigned int domainID, const unsigned int clientID, const enum query_type query_type, const bool create_new, const char *func, const int line, const char *file);
bool isValidIPv4(const char *addr);
bool isValidIPv6(const char *addr);

bool is_blocked(const enum query_status status) __attribute__ ((const));
bool is_cached(const enum query_status status) __attribute__ ((const));
bool is_forwarded(const enum query_status status) __attribute__ ((const));
const char *get_blocked_statuslist(void) __attribute__ ((pure));
const char *get_cached_statuslist(void) __attribute__ ((pure));
const char *get_permitted_statuslist(void) __attribute__ ((pure));
unsigned int get_blocked_count(void) __attribute__ ((pure));
unsigned int get_forwarded_count(void) __attribute__ ((pure));
unsigned int get_cached_count(void) __attribute__ ((pure));
#define query_set_status(query, new_status) _query_set_status(query, new_status, false, __FUNCTION__, __LINE__, __FILE__)
#define query_set_status_init(query, new_status) _query_set_status(query, new_status, true, __FUNCTION__, __LINE__, __FILE__)
void _query_set_status(queriesData *query, const enum query_status new_status, const bool init, const char *func, const int line, const char *file);

void FTL_reload_all_domainlists(void);
void FTL_reset_per_client_domain_data(void);

const char *getDomainString(const queriesData *query);
const char *getCNAMEDomainString(const queriesData *query);
const char *getClientIPString(const queriesData *query);
const char *getClientNameString(const queriesData *query);

void change_clientcount(clientsData *client, const int total, const int blocked, const int overTimeIdx, const int overTimeMod, const bool hidden);
unsigned int get_visible_query_count(void) __attribute__ ((pure));
const char *get_query_type_str(const enum query_type type, const queriesData *query, char buffer[20]);
const char *get_query_status_str(const enum query_status status) __attribute__ ((const));
const char *get_query_dnssec_str(const enum dnssec_status dnssec) __attribute__ ((const));
const char *get_query_reply_str(const enum reply_type query) __attribute__ ((const));
const char *get_refresh_hostnames_str(const enum refresh_hostnames refresh) __attribute__ ((const));
int get_refresh_hostnames_val(const char *refresh_hostnames) __attribute__ ((pure));
const char *get_blocking_mode_str(const enum blocking_mode mode) __attribute__ ((const));
int get_blocking_mode_val(const char *blocking_mode) __attribute__ ((pure));
const char * __attribute__ ((const)) get_blocking_status_str(const enum blocking_status blocking);
const char *get_ptr_type_str(const enum ptr_type piholePTR) __attribute__ ((const));
int get_ptr_type_val(const char *piholePTR) __attribute__ ((pure));
const char *get_busy_reply_str(const enum busy_reply replyWhenBusy) __attribute__ ((const));
int get_busy_reply_val(const char *replyWhenBusy) __attribute__ ((pure));
const char * get_listeningMode_str(const enum listening_mode listeningMode) __attribute__ ((const));
int get_listeningMode_val(const char *listeningMode) __attribute__ ((pure));
const char * __attribute__ ((const)) get_temp_unit_str(const enum temp_unit temp_unit);
int __attribute__ ((pure)) get_temp_unit_val(const char *temp_unit);
const char * __attribute__ ((const)) get_edns_mode_str(const enum edns_mode edns_mode);
int __attribute__ ((pure)) get_edns_mode_val(const char *edns_mode);

// Pointer getter functions
#define getQuery(queryID, checkMagic) _getQuery(queryID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
queriesData *_getQuery(const unsigned int queryID, const bool checkMagic, const int line, const char *func, const char *file);
#define getClient(clientID, checkMagic) _getClient(clientID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
clientsData *_getClient(const unsigned int clientID, const bool checkMagic, const int line, const char *func, const char *file);
#define getDomain(domainID, checkMagic) _getDomain(domainID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
domainsData *_getDomain(const unsigned int domainID, const bool checkMagic, const int line, const char *func, const char *file);
#define getUpstream(upstreamID, checkMagic) _getUpstream(upstreamID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
upstreamsData *_getUpstream(const unsigned int upstreamID, const bool checkMagic, const int line, const char *func, const char *file);
#define getDNSCache(cacheID, checkMagic) _getDNSCache(cacheID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
DNSCacheData *_getDNSCache(const unsigned int cacheID, const bool checkMagic, const int line, const char *func, const char *file);

// Helper functions
uint32_t __attribute__ ((pure)) hashStr(const char *s);

#endif //DATASTRUCTURE_H
