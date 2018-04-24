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
#define MAXCONNS 255

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
	const char* preEventHorizon;
	const char* whitelist;
	const char* blacklist;
	const char* gravity;
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
	int gravity_conf;
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
	bool ignore_localhost;
	unsigned char blockingmode;
	bool blockingregex;
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
	unsigned long response; // saved in units of 1/10 milliseconds (1 = 0.1ms, 2 = 0.2ms, 2500 = 250.0ms, etc.)
	unsigned char reply;
	unsigned char dnssec;
} queriesDataStruct;

typedef struct {
	unsigned char magic;
	int count;
	int failed;
	char *ip;
	char *name;
	bool new;
} forwardedDataStruct;

typedef struct {
	unsigned char magic;
	int count;
	char *ip;
	char *name;
	bool new;
} clientsDataStruct;

typedef struct {
	unsigned char magic;
	int count;
	int blockedcount;
	char *domain;
	bool wildcard;
	unsigned char regexmatch;
} domainsDataStruct;

typedef struct {
	unsigned char magic;
	time_t timestamp;
	int total;
	int blocked;
	int cached;
	int forwarded;
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
#define NUMTIMERS 5
enum { DATABASE_WRITE_TIMER, EXIT_TIMER, GC_TIMER, LISTS_TIMER, REGEX_TIMER };

enum { QUERIES, FORWARDED, CLIENTS, DOMAINS, OVERTIME, WILDCARD };
enum { DNSSEC_UNSPECIFIED, DNSSEC_SECURE, DNSSEC_INSECURE, DNSSEC_BOGUS, DNSSEC_ABANDONED, DNSSEC_UNKNOWN };
enum { QUERY_UNKNOWN, QUERY_GRAVITY, QUERY_FORWARDED, QUERY_CACHE, QUERY_WILDCARD, QUERY_BLACKLIST };
enum { TYPE_A = 1, TYPE_AAAA, TYPE_ANY, TYPE_SRV, TYPE_SOA, TYPE_PTR, TYPE_TXT, TYPE_MAX };
enum { REPLY_UNKNOWN, REPLY_NODATA, REPLY_NXDOMAIN, REPLY_CNAME, REPLY_IP };
enum { PRIVACY_SHOW_ALL = 0, PRIVACY_HIDE_DOMAINS, PRIVACY_HIDE_DOMAINS_CLIENTS, PRIVACY_MAXIMUM };
enum { MODE_IP, MODE_NX };
enum { REGEX_UNKNOWN, REGEX_BLOCKED, REGEX_NOTBLOCKED };

// Used to check memory integrity in various structs
#define MAGICBYTE 0x57

extern logFileNamesStruct files;
extern FTLFileNamesStruct FTLfiles;
extern countersStruct counters;
extern ConfigStruct config;

extern queriesDataStruct *queries;
extern forwardedDataStruct *forwarded;
extern clientsDataStruct *clients;
extern domainsDataStruct *domains;
extern overTimeDataStruct *overTime;

extern FILE *logfile;
extern volatile sig_atomic_t killed;

extern char ** setupVarsArray;
extern int setupVarsElements;

extern bool initialscan;
extern bool debug;
extern bool debugthreads;
extern bool debugclients;
extern bool debugGC;
extern bool debugDB;
extern bool threadwritelock;
extern bool threadreadlock;
extern unsigned char blockingstatus;

extern char ** wildcarddomains;

extern memoryStruct memory;
extern bool runtest;

extern char * username;
extern char timestamp[16];
extern bool flush;
extern bool needGC;
extern bool daemonmode;
extern bool database;
extern long int lastdbindex;
extern bool travis;
extern bool DBdeleteoldqueries;
extern bool rereadgravity;
extern long int lastDBimportedtimestamp;
extern bool ipv4telnet, ipv6telnet;
extern bool istelnet[MAXCONNS];

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

extern int argc_dnsmasq;
extern char **argv_dnsmasq;

extern pthread_t telnet_listenthreadv4;
extern pthread_t telnet_listenthreadv6;
extern pthread_t socket_listenthread;
extern pthread_t DBthread;
extern pthread_t GCthread;
