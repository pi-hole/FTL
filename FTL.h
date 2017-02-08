/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global definitions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#define __USE_XOPEN
#define _GNU_SOURCE
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
// struct sockaddr_in
#include <netinet/in.h>
// char* inet_ntoa(struct in_addr in)
#include <arpa/inet.h>
// getnameinfo();
#include <netdb.h>
#include <errno.h>

#include "routines.h"

// Be more verbose, don't go into background
// #define DEBUG

// Listen only locally
#define LISTENLOCALHOST

// Next we define the step size in which the struct arrays are reallocated if they
// grow too large. This number should be large enough so that reallocation does not
// have to run very often, but should be as small as possible to avoid wasting memory
#define QUERIESALLOCSTEP 10000
#define FORWARDEDALLOCSTEP 4
#define CLIENTSALLOCSTEP 20
#define DOMAINSALLOCSTEP 1000

#define SOCKETBUFFERLEN 1024

// Static structs
typedef struct {
	const char* log;
	const char* pid;
	const char* port;
} FTLFileNamesStruct;

typedef struct {
	const char* log;
	const char* gravity;
	const char* whitelist;
	const char* blacklist;
	const char* setupVars;
} logFileNamesStruct;

typedef struct {
	int queries;
	int blocked;
	int wildcardblocked;
	int cached;
	int unknown;
	int forwarded;
	int clients;
	int domains;
	int queries_MAX;
	int forwarded_MAX;
	int clients_MAX;
	int domains_MAX;
	int gravity;
	int overtime;
	int IPv4;
	int IPv6;
	int PTR;
	int SRV;
} countersStruct;

// Dynamic structs
typedef struct {
	int timestamp;
	unsigned char type;
	unsigned char status;
	// 0 = unknown, 1 = gravity.list (blocked), 2 = reply from upstream, 3 = cache
	int domainID;
	int clientID;
} queriesDataStruct;

typedef struct {
	int count;
	char *ip;
	char *name;
} forwardedDataStruct;

typedef struct {
	int count;
	char *ip;
	char *name;
} clientsDataStruct;

typedef struct {
	int count;
	int blockedcount;
	char *domain;
} domainsDataStruct;

typedef struct {
	int total;
	int blocked;
} overTimeDataStruct;

enum { QUERIES, FORWARDED, CLIENTS, DOMAINS };

logFileNamesStruct files;
FTLFileNamesStruct FTLfiles;
countersStruct counters;

queriesDataStruct *queries;
forwardedDataStruct *forwarded;
clientsDataStruct *clients;
domainsDataStruct *domains;

overTimeDataStruct overTime[600];

FILE *logfile;
FILE *dnsmasqlog;
int dnsmasqlogpos;
volatile sig_atomic_t killed;
int clientsocket;

char socketrecvbuffer[SOCKETBUFFERLEN];
char socketsendbuffer[SOCKETBUFFERLEN];

char ** setupVarsArray;
int setupVarsElements;

bool initialscan;
bool debug;
