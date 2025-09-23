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
	unsigned char magic;
	enum query_status status;
	enum query_type type;
	enum privacy_level privacylevel;
	enum reply_type reply;
	enum dnssec_status dnssec;
	uint16_t qtype;
	unsigned int domainID;
	unsigned int clientID;
	int upstreamID; // -1 if not forwarded
	int cacheID;
	int id; // the ID is a (signed) int in dnsmasq, so no need for a long int here
	int CNAME_domainID; // only valid if query has a CNAME blocking status, -1 otherwise
	int ede;
	double response;
	double timestamp;
	sqlite3_int64 db;
	// Adjacent bit field members in the struct flags may be packed to share
	// and straddle the individual bytes. It is useful to pack the memory as
	// tightly as possible as there may be dozens of thousands of these
	// objects in memory (one per query).
	// C99 guarantees that bit-fields will be packed as tightly as possible,
	// provided they don't cross storage unit boundaries (6.7.2.1 #10).
	struct query_flags {
		bool allowed :1;
		bool complete :1;
		bool blocked :1;
		bool response_calculated :1;
		struct database_flags {
			bool changed :1;
			bool stored :1;
		} database;
	} flags;
} queriesData;

typedef struct {
	unsigned char magic;
	struct upstream_flags {
		bool new:1;
	} flags;
	in_port_t port;
	int count;
	int failed;
	unsigned int responses;
	size_t ippos;
	size_t namepos;
	double rtime;
	double rtuncertainty;
	double lastQuery;
} upstreamsData;

typedef struct {
	unsigned char magic;
	unsigned char reread_groups;
	char hwlen;
	unsigned char hwaddr[16]; // See DHCP_CHADDR_MAX in dnsmasq/dhcp-protocol.h
	struct client_flags {
		bool new:1;
		bool found_group:1;
		bool aliasclient:1;
		bool rate_limited:1;
	} flags;
	int count;
	int blockedcount;
	int aliasclient_id; // -1 if not an alias-client
	unsigned int id;
	unsigned int rate_limit;
	unsigned int numQueriesARP;
	int overTime[OVERTIME_SLOTS];
	uint32_t hash;
	size_t groupspos;
	size_t ippos;
	size_t namepos;
	size_t ifacepos;
	double firstSeen;
	double lastQuery;
} clientsData;

typedef struct {
	unsigned char magic;
	int count;
	int blockedcount;
	uint32_t hash;
	size_t domainpos;
	double lastQuery;
} domainsData;

typedef struct {
	unsigned char magic;
	struct {
		bool allowed :1;
	} flags;
	enum query_status blocking_status;
	enum reply_type force_reply;
	enum query_type query_type;
	unsigned int domainID;
	unsigned int clientID;
	unsigned int CNAME_domainID; // only valid if query has a CNAME blocking status
	int list_id;
	uint32_t hash;
	time_t expires;
	char *cname_target;
} DNSCacheData;

struct lookup_data {
	const char *domain;
	const char *client;
	unsigned int domainID;
	unsigned int clientID;
	enum query_type query_type;
};

void strtolower(char *str);
int findQueryID(const int id);
#define findUpstreamID(upstream, port) _findUpstreamID(upstream, port, __LINE__, __FUNCTION__, __FILE__)
int _findUpstreamID(const char *upstream, const in_port_t port, int line, const char *func, const char *file);
#define findDomainID(domain, count) _findDomainID(domain, count, __LINE__, __FUNCTION__, __FILE__)
int _findDomainID(const char *domain, const bool count, int line, const char *func, const char *file);
#define findClientID(client, count, aliasclient, now) _findClientID(client, count, aliasclient, now, __LINE__, __FUNCTION__, __FILE__)
int _findClientID(const char *client, const bool count, const bool aliasclient, const double now, int line, const char *func, const char *file);
#define findCacheID(domainID, clientID, query_type, create_new) _findCacheID(domainID, clientID, query_type, create_new, __FUNCTION__, __LINE__, __FILE__)
int _findCacheID(const unsigned int domainID, const unsigned int clientID, const enum query_type query_type, const bool create_new, const char *func, const int line, const char *file);
bool isValidIPv4(const char *addr);
bool isValidIPv6(const char *addr);

bool is_blocked(const enum query_status status) __attribute__ ((const));
bool is_cached(const enum query_status status) __attribute__ ((const));
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

void change_clientcount(clientsData *client, const int total, const int blocked, const int overTimeIdx, const int overTimeMod);
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

#endif //DATASTRUCTURE_H
