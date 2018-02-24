/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global definitions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define __USE_XOPEN
#define _GNU_SOURCE
#include <stdio.h>
// variable argument lists
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
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
//#include <math.h>
#include <pwd.h>
// syslog
#include <syslog.h>
// SQLite
#include "sqlite3.h"
// tolower()
#include <ctype.h>
// Unix socket
#include <sys/un.h>
// Interfaces
#include <ifaddrs.h>
#include <net/if.h>


#include "routines.h"

// Next we define the step size in which the struct arrays are reallocated if they
// grow too large. This number should be large enough so that reallocation does not
// have to run very often, but should be as small as possible to avoid wasting memory
#define QUERIESALLOCSTEP 10000
#define FORWARDEDALLOCSTEP 4
#define CLIENTSALLOCSTEP 10
#define DOMAINSALLOCSTEP 1000
#define OVERTIMEALLOCSTEP 100
#define WILDCARDALLOCSTEP 100

#define SOCKETBUFFERLEN 1024

// How often do we garbage collect (to ensure we only have data fitting to the MAXLOGAGE defined above)? [seconds]
// Default: 3600 (once per hour)
#define GCinterval 3600

// Delay applied to the garbage collecting [seconds]
// Default -60 (one minute before a full hour)
#define GCdelay (-60)

// How many client connection do we accept at once?
#define MAXCONNS 40

// Static structs
typedef struct {
	const char* conf;
	const char* log;
	const char* pid;
	const char* port;
	char* db;
	const char* socketfile;
} FTLFileNamesStruct;

typedef struct {
	const char* log;
	const char* gravity;
	const char* whitelist;
	const char* blacklist;
	const char* setupVars;
	const char* wildcards;
	const char* auditlist;
	const char* dnsmasqconfig;
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
	int overTime_MAX;
	int wildcarddomains_MAX;
	int gravity;
	int overTime;
	int querytype[7];
	int wildcarddomains;
	int forwardedqueries;
	int reply_NODATA;
	int reply_NXDOMAIN;
	int reply_CNAME;
	int reply_IP;
} countersStruct;

typedef struct {
	bool socket_listenlocal;
	bool analyze_AAAA;
	int maxDBdays;
	bool resolveIPv6;
	bool resolveIPv4;
	int DBinterval;
	int port;
	int maxlogage;
	int privacylevel;
} ConfigStruct;

// Dynamic structs
typedef struct {
	unsigned char magic;
	time_t timestamp;
	int timeidx;
	unsigned char type;
	unsigned char status;
	// 0 = unknown, 1 = gravity.list (blocked), 2 = reply from upstream, 3 = cache, 4 = wildcard blocked
	int domainID;
	int clientID;
	int forwardID;
	bool db;
	// the ID is a (signed) int in dnsmasq, so no need for a long int here
	int id;
	bool complete;
	bool private;
	unsigned long ttl;
} queriesDataStruct;

typedef struct {
	unsigned char magic;
	int count;
	char *ip;
} forwardedDataStruct;

typedef struct {
	unsigned char magic;
	int count;
	char *ip;
} clientsDataStruct;

typedef struct {
	unsigned char magic;
	int count;
	int blockedcount;
	char *domain;
	bool wildcard;
	unsigned char dnssec;
	char *IPv4;
	char *IPv6;
	unsigned char reply[2];
} domainsDataStruct;

typedef struct {
	unsigned char magic;
	time_t timestamp;
	int total;
	int blocked;
	int cached;
	int clientnum;
	int *clientdata;
	int querytypedata[7];
} overTimeDataStruct;

typedef struct {
	int wildcarddomains;
	int domainnames;
	int clientips;
	int forwardedips;
	int forwarddata;
	int clientdata;
	int querytypedata;
} memoryStruct;

// Prepare timers, used mainly for debugging purposes
#define NUMTIMERS 3
enum { DATABASE_WRITE_TIMER, EXIT_TIMER, GC_TIMER };

enum { QUERIES, FORWARDED, CLIENTS, DOMAINS, OVERTIME, WILDCARD };
enum { DNSSEC_UNSPECIFIED, DNSSEC_SECURE, DNSSEC_INSECURE, DNSSEC_BOGUS, DNSSEC_ABANDONED, DNSSEC_UNKNOWN };
enum { QUERY_UNKNOWN, QUERY_GRAVITY, QUERY_FORWARDED, QUERY_CACHE, QUERY_WILDCARD, QUERY_BLACKLIST };
enum { TYPE_A = 1, TYPE_AAAA, TYPE_ANY, TYPE_SRV, TYPE_SOA, TYPE_PTR, TYPE_TXT, TYPE_MAX };
enum { REPLY_UNKNOWN, REPLY_NODATA, REPLY_NXDOMAIN, REPLY_CNAME, REPLY_IP };
enum { PRIVACY_SHOW_ALL = 0, PRIVACY_HIDE_DOMAINS, PRIVACY_HIDE_DOMAINS_CLIENTS, PRIVACY_MAXIMUM };

// Used to check memory integrity in various structs
#define MAGICBYTE 0x57

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
volatile sig_atomic_t killed;

char ** setupVarsArray;
int setupVarsElements;

bool initialscan;
bool debug;
bool debugthreads;
bool debugclients;
bool debugGC;
bool debugDB;
bool threadwritelock;
bool threadreadlock;
unsigned char blockingstatus;

char ** wildcarddomains;

memoryStruct memory;
bool runtest;

char * username;
char timestamp[16];
bool flush;
bool needGC;
bool daemonmode;
bool database;
long int lastdbindex;
bool travis;
bool DBdeleteoldqueries;
bool rereadgravity;
long int lastDBimportedtimestamp;
bool ipv4telnet, ipv6telnet;
bool istelnet[MAXCONNS];

// Use out own memory handling functions that will detect possible errors
// and report accordingly in the log. This will make debugging FTL crashs
// caused by insufficient memory or by code bugs (not properly dealing
// with NULL pointers) much easier.
#define free(param) FTLfree(param, __FILE__,  __FUNCTION__,  __LINE__)
#define lib_strdup() strdup()
#undef strdup
#define strdup(param) FTLstrdup(param, __FILE__,  __FUNCTION__,  __LINE__)
#define calloc(p1,p2) FTLcalloc(p1,p2, __FILE__,  __FUNCTION__,  __LINE__)
#define realloc(p1,p2) FTLrealloc(p1,p2, __FILE__,  __FUNCTION__,  __LINE__)

int argc_dnsmasq;
char **argv_dnsmasq;

pthread_t telnet_listenthreadv4;
pthread_t telnet_listenthreadv6;
pthread_t socket_listenthread;
pthread_t DBthread;
pthread_t GCthread;
