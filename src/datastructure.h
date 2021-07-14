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

// assert_sizeof
#include "static_assert.h"

typedef struct {
	unsigned char magic;
	enum query_status status;
	enum query_type type;
	enum privacy_level privacylevel;
	enum reply_type reply;
	enum dnssec_status dnssec;
	uint16_t qtype;
	int domainID;
	int clientID;
	int upstreamID;
	int id; // the ID is a (signed) int in dnsmasq, so no need for a long int here
	int CNAME_domainID; // only valid if query has a CNAME blocking status
	int ede;
	unsigned int ttl;
	double response;
	double timestamp;
	int64_t db;
	// Adjacent bit field members in the struct flags may be packed to share
	// and straddle the individual bytes. It is useful to pack the memory as
	// tightly as possible as there may be dozens of thousands of these
	// objects in memory (one per query).
	// C99 guarentees that bit-fields will be packed as tightly as possible,
	// provided they don’t cross storageau unit boundaries (6.7.2.1 #10).
	struct query_flags {
		bool allowed :1;
		bool complete :1;
		bool blocked :1;
		bool database :1;
	} flags;
} queriesData;

// ARM needs alignment to 8-byte boundary
//ASSERT_SIZEOF(queriesData, 64, 64, 64);

typedef struct {
	unsigned char magic;
	struct upstream_flags {
		bool new:1;
	} flags;
	in_port_t port;
	int count;
	int failed;
	unsigned int responses;
	int overTime[OVERTIME_SLOTS];
	size_t ippos;
	size_t namepos;
	double rtime;
	double rtuncertainty;
	double lastQuery;
} upstreamsData;
//ASSERT_SIZEOF(upstreamsData, 640, 628, 628);

typedef struct {
	unsigned char magic;
	unsigned char reread_groups;
	char hwlen;
	unsigned char hwaddr[16]; // See DHCP_CHADDR_MAX in dnsmasq/dhcp-protocol.h
	struct client_flags {
		bool new :1;
		bool found_group: 1;
		bool aliasclient :1;
	} flags;
	int count;
	int blockedcount;
	int aliasclient_id;
	unsigned int id;
	unsigned int rate_limit;
	unsigned int numQueriesARP;
	int overTime[OVERTIME_SLOTS];
	size_t groupspos;
	size_t ippos;
	size_t namepos;
	size_t ifacepos;
	time_t firstSeen;
	double lastQuery;
} clientsData;

// ARM needs alignment to 8-byte boundary
//ASSERT_SIZEOF(clientsData, 696, 672, 672);

typedef struct {
	unsigned char magic;
	int count;
	int blockedcount;
	size_t domainpos;
} domainsData;
//ASSERT_SIZEOF(domainsData, 24, 16, 16);

typedef struct {
	unsigned char magic;
	enum domain_client_status blocking_status;
	enum reply_type force_reply;
	enum query_type query_type;
	int domainID;
	int clientID;
	int deny_regex_id;
} DNSCacheData;
//ASSERT_SIZEOF(DNSCacheData, 16, 16, 16);

void strtolower(char *str);
int findQueryID(const int id);
int findUpstreamID(const char * upstream, const in_port_t port);
int findDomainID(const char *domain, const bool count);
int findClientID(const char *client, const bool count, const bool aliasclient);
int findCacheID(int domainID, int clientID, enum query_type query_type);
bool isValidIPv4(const char *addr);
bool isValidIPv6(const char *addr);

bool is_blocked(const enum query_status status) __attribute__ ((const));
int get_blocked_count(void) __attribute__ ((pure));
int get_forwarded_count(void) __attribute__ ((pure));
int get_cached_count(void) __attribute__ ((pure));
void query_set_status(queriesData *query, const enum query_status new_status);
#define query_set_status(query, new_status) _query_set_status(query, new_status, __FILE__, __LINE__)
void _query_set_status(queriesData *query, const enum query_status new_status, const char *file, const int line);

void FTL_reload_all_domainlists(void);
void FTL_reset_per_client_domain_data(void);

const char *getDomainString(const queriesData* query);
const char *getCNAMEDomainString(const queriesData* query);
const char *getClientIPString(const queriesData* query);
const char *getClientNameString(const queriesData* query);

void change_clientcount(clientsData *client, int total, int blocked, int overTimeIdx, int overTimeMod);
const char *get_query_type_str(const enum query_type type, const queriesData *query, char *buffer);
const char *get_query_status_str(const enum query_status status) __attribute__ ((const));
const char *get_query_dnssec_str(const enum dnssec_status dnssec) __attribute__ ((const));
const char *get_query_reply_str(const enum reply_type query) __attribute__ ((const));
const char *get_refresh_hostnames_str(const enum refresh_hostnames refresh) __attribute__ ((const));
const char *get_blocking_mode_str(const enum blocking_mode mode) __attribute__ ((const));

// Pointer getter functions
#define getQuery(queryID, checkMagic) _getQuery(queryID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
queriesData* _getQuery(int queryID, bool checkMagic, int line, const char * function, const char * file);
#define getClient(clientID, checkMagic) _getClient(clientID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
clientsData* _getClient(int clientID, bool checkMagic, int line, const char * function, const char * file);
#define getDomain(domainID, checkMagic) _getDomain(domainID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
domainsData* _getDomain(int domainID, bool checkMagic, int line, const char * function, const char * file);
#define getUpstream(upstreamID, checkMagic) _getUpstream(upstreamID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
upstreamsData* _getUpstream(int upstreamID, bool checkMagic, int line, const char * function, const char * file);
#define getDNSCache(cacheID, checkMagic) _getDNSCache(cacheID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
DNSCacheData* _getDNSCache(int cacheID, bool checkMagic, int line, const char * function, const char * file);

#endif //DATASTRUCTURE_H
