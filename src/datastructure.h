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
// struct ucharvec
#include "vector.h"

void strtolower(char *str);
int findForwardID(const char * forward, const bool count);
int findDomainID(const char *domain);
int findClientID(const char *client, const bool count);
bool isValidIPv4(const char *addr);
bool isValidIPv6(const char *addr);
const char *getDomainString(const int queryID);
const char *getClientIPString(const int queryID);
const char *getClientNameString(const int queryID);

typedef struct {
	unsigned char magic;
	unsigned char type;
	unsigned char status;
	unsigned char privacylevel;
	unsigned char reply;
	unsigned char dnssec;
	time_t timestamp;
	int domainID;
	int clientID;
	int forwardID;
	int id; // the ID is a (signed) int in dnsmasq, so no need for a long int here
	unsigned long response; // saved in units of 1/10 milliseconds (1 = 0.1ms, 2 = 0.2ms, 2500 = 250.0ms, etc.)
	int64_t db;
	unsigned int timeidx;
	bool complete;
} queriesData;

typedef struct {
	unsigned char magic;
	size_t ippos;
	size_t namepos;
	int count;
	int failed;
	bool new;
} forwardedData;

typedef struct {
	unsigned char magic;
	size_t ippos;
	size_t namepos;
	time_t lastQuery;
	int count;
	int blockedcount;
	int overTime[OVERTIME_SLOTS];
	unsigned int numQueriesARP;
	bool new;
	sqlite3_stmt* whitelist_stmt;
	sqlite3_stmt* gravity_stmt;
	sqlite3_stmt* blacklist_stmt;
	bool *regex_enabled[2];
} clientsData;

typedef struct {
	unsigned char magic;
	size_t domainpos;
	int count;
	int blockedcount;
	ucharvec *clientstatus; // FTL-internal cache, not accessible over shared memory!
} domainsData;

// Pointer getter functions
#define getQuery(queryID, checkMagic) _getQuery(queryID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
queriesData* _getQuery(int queryID, bool checkMagic, int line, const char * function, const char * file);
#define getClient(clientID, checkMagic) _getClient(clientID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
clientsData* _getClient(int clientID, bool checkMagic, int line, const char * function, const char * file);
#define getDomain(domainID, checkMagic) _getDomain(domainID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
domainsData* _getDomain(int domainID, bool checkMagic, int line, const char * function, const char * file);
#define getForward(forwardID, checkMagic) _getForward(forwardID, checkMagic, __LINE__, __FUNCTION__, __FILE__)
forwardedData* _getForward(int forwardID, bool checkMagic, int line, const char * function, const char * file);

#endif //DATASTRUCTURE_H
