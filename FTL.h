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
#include <pthread.h>
#include <sys/prctl.h>
#include <math.h>
#include <pwd.h>

#include "routines.h"

// Next we define the step size in which the struct arrays are reallocated if they
// grow too large. This number should be large enough so that reallocation does not
// have to run very often, but should be as small as possible to avoid wasting memory
#define QUERIESALLOCSTEP 10000
#define FORWARDEDALLOCSTEP 4
#define CLIENTSALLOCSTEP 20
#define DOMAINSALLOCSTEP 1000
#define OVERTIMEALLOCSTEP 100

#define SOCKETBUFFERLEN 1024

// Maximum time from now until we will parse logs that are in the past [seconds]
// Default: 86400 (24 hours)
#define MAXLOGAGE 86400

// How often do we garbage collect (to ensure we only have data fitting to the MAXLOGAGE defined above)? [seconds]
// Default: 3600 (once per hour)
#define GCinterval 3600

// Delay applied to the garbage collecting [seconds]
// Default -60 (one minute before a full hour)
#define GCdelay (-60)

// Static structs
typedef struct {
	const char* conf;
	const char* log;
	const char* pid;
	const char* port;
} FTLFileNamesStruct;

typedef struct {
	const char* log;
	const char* log1;
	const char* gravity;
	const char* whitelist;
	const char* blacklist;
	const char* setupVars;
	const char* wildcards;
} logFileNamesStruct;

typedef struct {
	int queries;
	int invalidqueries;
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
	int overTime_MAX;
	int gravity;
	int overTime;
	int IPv4;
	int IPv6;
	int PTR;
	int SRV;
	int wildcarddomains;
	int forwardedqueries;
} countersStruct;

typedef struct {
	bool socket_listenlocal;
	bool include_yesterday;
	bool rolling_24h;
	bool query_display;
} ConfigStruct;

// Dynamic structs
typedef struct {
	int timestamp;
	int timeidx;
	unsigned char type;
	unsigned char status;
	// 0 = unknown, 1 = gravity.list (blocked), 2 = reply from upstream, 3 = cache, 4 = wildcard blocked
	int domainID;
	int clientID;
	int forwardID;
	bool valid;
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
	bool wildcard;
} domainsDataStruct;

typedef struct {
	int timestamp;
	int total;
	int blocked;
	int forwardnum;
	int *forwarddata;
	int *querytypedata;
} overTimeDataStruct;

typedef struct {
	int wildcarddomains;
	int domainnames;
	int clientips;
	int clientnames;
	int forwardedips;
	int forwardednames;
	int forwarddata;
	int querytypedata;
} memoryStruct;

enum { QUERIES, FORWARDED, CLIENTS, DOMAINS, OVERTIME };

logFileNamesStruct files;
FTLFileNamesStruct FTLfiles;
countersStruct counters;
ConfigStruct config;

queriesDataStruct *queries;
forwardedDataStruct *forwarded;
clientsDataStruct *clients;
domainsDataStruct *domains;
overTimeDataStruct *overTime;

FILE *logfile;
FILE *dnsmasqlog;
unsigned long int dnsmasqlogpos;
volatile sig_atomic_t killed;

char ** setupVarsArray;
int setupVarsElements;

bool initialscan;
bool debug;
bool debugthreads;
bool debugclients;
bool debugGC;
bool threadwritelock;
bool threadreadlock;

char ** wildcarddomains;

memoryStruct memory;
bool runtest;

char * username;
char timestamp[16];
bool flush;
bool needGC;

