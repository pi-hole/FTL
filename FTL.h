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
// tolower()
#include <ctype.h>
// Unix socket
#include <sys/un.h>
// Interfaces
#include <ifaddrs.h>
#include <net/if.h>

// Define MIN and MAX macros, use them only when x and y are of the same type
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
// MIN(x,y) is already defined in dnsmasq.h

#include "routines.h"

#define SOCKETBUFFERLEN 1024

// How often do we garbage collect (to ensure we only have data fitting to the MAXLOGAGE defined above)? [seconds]
// Default: 3600 (once per hour)
#define GCinterval 3600

// Delay applied to the garbage collecting [seconds]
// Default: -60 (one minute before a full hour)
#define GCdelay (-60)

// How many client connection do we accept at once?
#define MAXCONNS 255

// Over how many queries do we iterate at most when trying to find a match?
#define MAXITER 1000

// How many hours do we want to store in FTL's memory? [hours]
#define MAXLOGAGE 24

// Interval for overTime data [seconds]
// Default: 600 (10 minute intervals)
#define OVERTIME_INTERVAL 600

// How many overTime slots do we need?
// (24+1) hours * number of intervals per hour
// We need to be able to hold 25 hours as we need some reserve
// due to that GC is only running once an hours so the shown data
// can be 24 hours + 59 minutes
#define OVERTIME_SLOTS ((MAXLOGAGE+1)*3600/OVERTIME_INTERVAL)

// FTLDNS enums
enum { DATABASE_WRITE_TIMER, EXIT_TIMER, GC_TIMER, LISTS_TIMER, REGEX_TIMER, ARP_TIMER, LAST_TIMER };
enum { QUERIES, FORWARDED, CLIENTS, DOMAINS, OVERTIME, WILDCARD };
enum { DNSSEC_UNSPECIFIED, DNSSEC_SECURE, DNSSEC_INSECURE, DNSSEC_BOGUS, DNSSEC_ABANDONED, DNSSEC_UNKNOWN };
enum { QUERY_UNKNOWN, QUERY_GRAVITY, QUERY_FORWARDED, QUERY_CACHE, QUERY_WILDCARD, QUERY_BLACKLIST, QUERY_EXTERNAL_BLOCKED_IP, QUERY_EXTERNAL_BLOCKED_NULL, QUERY_EXTERNAL_BLOCKED_NXRA };
enum { TYPE_A = 1, TYPE_AAAA, TYPE_ANY, TYPE_SRV, TYPE_SOA, TYPE_PTR, TYPE_TXT, TYPE_MAX };
enum { REPLY_UNKNOWN, REPLY_NODATA, REPLY_NXDOMAIN, REPLY_CNAME, REPLY_IP, REPLY_DOMAIN, REPLY_RRNAME, REPLY_SERVFAIL, REPLY_REFUSED, REPLY_NOTIMP, REPLY_OTHER };
enum { PRIVACY_SHOW_ALL = 0, PRIVACY_HIDE_DOMAINS, PRIVACY_HIDE_DOMAINS_CLIENTS, PRIVACY_MAXIMUM, PRIVACY_NOSTATS };
enum { MODE_IP, MODE_NX, MODE_NULL, MODE_IP_NODATA_AAAA, MODE_NODATA };
enum { REGEX_UNKNOWN, REGEX_BLOCKED, REGEX_NOTBLOCKED };
enum { BLOCKING_DISABLED, BLOCKING_ENABLED, BLOCKING_UNKNOWN };
enum {
  DEBUG_DATABASE   = (1 << 0),  /* 00000000 00000001 */
  DEBUG_NETWORKING = (1 << 1),  /* 00000000 00000010 */
  DEBUG_LOCKS      = (1 << 2),  /* 00000000 00000100 */
  DEBUG_QUERIES    = (1 << 3),  /* 00000000 00001000 */
  DEBUG_FLAGS      = (1 << 4),  /* 00000000 00010000 */
  DEBUG_SHMEM      = (1 << 5),  /* 00000000 00100000 */
  DEBUG_GC         = (1 << 6),  /* 00000000 01000000 */
  DEBUG_ARP        = (1 << 7),  /* 00000000 10000000 */
  DEBUG_REGEX      = (1 << 8),  /* 00000001 00000000 */
  DEBUG_API        = (1 << 9),  /* 00000010 00000000 */
  DEBUG_OVERTIME   = (1 << 10), /* 00000100 00000000 */
  DEBUG_EXTBLOCKED = (1 << 11), /* 00001000 00000000 */
  DEBUG_CAPS       = (1 << 12), /* 00010000 00000000 */
};

// Database table "ftl"
enum { DB_VERSION, DB_LASTTIMESTAMP, DB_FIRSTCOUNTERTIMESTAMP };
// Database table "counters"
enum { DB_TOTALQUERIES, DB_BLOCKEDQUERIES };

// Privacy mode constants
#define HIDDEN_DOMAIN "hidden"
#define HIDDEN_CLIENT "0.0.0.0"

// Static structs
typedef struct {
	const char* conf;
	const char* snapConf;
	char* log;
	char* pid;
	char* port;
	char* db;
	char* socketfile;
	char* macvendordb;
} FTLFileNamesStruct;

typedef struct {
	char* whitelist;
	char* blacklist;
	char* gravity;
	char* regexlist;
	char* setupVars;
	char* auditlist;
} logFileNamesStruct;

typedef struct {
	int queries;
	int blocked;
	int cached;
	int unknown;
	int forwarded;
	int clients;
	int domains;
	int queries_MAX;
	int forwarded_MAX;
	int clients_MAX;
	int domains_MAX;
	int strings_MAX;
	int gravity;
	int gravity_conf;
	int querytype[TYPE_MAX-1];
	int forwardedqueries;
	int reply_NODATA;
	int reply_NXDOMAIN;
	int reply_CNAME;
	int reply_IP;
	int reply_domain;
} countersStruct;

typedef struct {
	int maxDBdays;
	int DBinterval;
	int port;
	int maxlogage;
	int16_t debug;
	unsigned char privacylevel;
	unsigned char blockingmode;
	bool socket_listenlocal;
	bool analyze_AAAA;
	bool resolveIPv6;
	bool resolveIPv4;
	bool ignore_localhost;
	bool analyze_only_A_AAAA;
	bool DBimport;
	bool parse_arp_cache;
} ConfigStruct;

// Dynamic structs
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
} queriesDataStruct;

typedef struct {
	unsigned char magic;
	size_t ippos;
	size_t namepos;
	int count;
	int failed;
	bool new;
} forwardedDataStruct;

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
} clientsDataStruct;

typedef struct {
	unsigned char magic;
	unsigned char regexmatch;
	size_t domainpos;
	int count;
	int blockedcount;
} domainsDataStruct;

typedef struct {
	unsigned char magic;
	time_t timestamp;
	int total;
	int blocked;
	int cached;
	int forwarded;
	int querytypedata[TYPE_MAX-1];
} overTimeDataStruct;

typedef struct {
	char **domains;
	int count;
} whitelistStruct;

typedef struct {
	int version;
	unsigned int global_shm_counter;
	unsigned int next_str_pos;
} ShmSettings;

// Prepare timers, used mainly for debugging purposes
#define NUMTIMERS LAST_TIMER

// Used to check memory integrity in various structs
#define MAGICBYTE 0x57

// Some magic database constants
#define DB_FAILED -2
#define DB_NODATA -1

extern logFileNamesStruct files;
extern FTLFileNamesStruct FTLfiles;
extern countersStruct *counters;
extern ConfigStruct config;

extern queriesDataStruct *queries;
extern forwardedDataStruct *forwarded;
extern clientsDataStruct *clients;
extern domainsDataStruct *domains;
extern overTimeDataStruct *overTime;

// Used in gc.c, memory.c, resolve.c, signals.c, and socket.c
extern volatile sig_atomic_t killed;
// Used in api.c, grep.c, and dnsmasq_interface.c
extern unsigned char blockingstatus;
// Used in main.c, log.c, and others
extern char * username;
// Used in main.c, args.c, log.c, and others
extern bool daemonmode;
// Used in main.c, database.c, and others
extern bool database;
// Used in database.c and gc.c
extern long int lastdbindex;
// Used in database.c and gc.c
extern bool DBdeleteoldqueries;
// Used in main.c, socket.c, and dnsmasq_interface.c
extern bool ipv4telnet, ipv6telnet;
// Used in api.c, and socket.c
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
extern const char ** argv_dnsmasq;

extern pthread_t telnet_listenthreadv4;
extern pthread_t telnet_listenthreadv6;
extern pthread_t socket_listenthread;
extern pthread_t DBthread;
extern pthread_t GCthread;
extern pthread_t DNSclientthread;
