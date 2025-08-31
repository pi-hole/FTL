/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global definitions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_H
#define FTL_H

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
#include <sys/time.h>
#include <sys/socket.h>
// struct sockaddr_in
#include <netinet/in.h>
// char *inet_ntoa(struct in_addr in)
#include <arpa/inet.h>
// getnameinfo();
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <pwd.h>
// syslog
#include <syslog.h>
// tolower()
#include <ctype.h>
// Interfaces
#include <ifaddrs.h>
#include <net/if.h>

// Define MIN and MAX macros, use them only when x and y are of the same type
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
// MIN(x,y) is already defined in dnsmasq.h

// Number of elements in an array
#define ArraySize(X) (sizeof(X)/sizeof(*X))

// Constant socket buffer length
#define SOCKETBUFFERLEN 1024

// How many client connection do we accept at once?
#define MAXCONNS 255

// Over how many queries do we iterate at most when trying to find a match?
#define MAXITER 1000

// How many hours do we want to store in FTL's memory? [hours]
#define MAXLOGAGE 24u

// Interval for overTime data [seconds]
// Default: 600 (10 minutes)
#define OVERTIME_INTERVAL 600u

// How many overTime slots do we need?
// This is the maximum log age divided by the overtime interval
// plus one extra timeslot for the very first timeslot.
// Example (default settings): 24*3600/600 + 1 = 144 + 1 slots
// Which corresponds to something like
//    Mon 08:05:00 - Tue 08:05:00
// Without the extra last timestamp, the first timeslot
// would incorrectly be located at Mon 08:15:00
#define OVERTIME_SLOTS ((MAXLOGAGE*3600)/OVERTIME_INTERVAL + 1)

// Interval for re-resolving ALL known host names [seconds]
// Default: 3600 (once every hour)
#define RERESOLVE_INTERVAL 3600

// Privacy mode constants
#define HIDDEN_DOMAIN "hidden"
#define HIDDEN_CLIENT "0.0.0.0"

// Used to check memory integrity in various structs
#define MAGICBYTE 0x57

// Some magic database constants
#define DB_FAILED -2
#define DB_NODATA -1

// Add a timeout for the pihole-FTL.db database connection [milliseconds]
// This prevents immediate failures when the database is busy for a short time.
// Default: 1000 (one second)
#define DATABASE_BUSY_TIMEOUT 1000

// After how much time does a valid API session expire? [seconds]
// Default: 300 (five minutes)
#define API_SESSION_EXPIRE 300u

// After how many seconds do we check again if a client can be identified by other means?
// (e.g., interface, MAC address, hostname)
// Default: 60 (after one minutee)
#define RECHECK_DELAY 60

// How often should we check again if a client can be identified by other means?
// (e.g., interface, MAC address, hostname)
// Default: 3 (once after RECHECK_DELAY seconds, then again after 2*RECHECK_DELAY and 3*RECHECK_DELAY)
// Important: This number has to be smaller than 256 for this mechanism to work
#define NUM_RECHECKS 3

// DELAY_STARTUP should only delay the startup of the resolver during a starting up system
// This setting control how long after boot we consider a system to be in starting-up mode
// Default: 180 [seconds]
#define DELAY_UPTIME 180

// REPLY_TIMEOUT defines until how far back in the history of queries we are
// checking for changed/updated queries. This value should not be set too high
// to avoid unnecessary spinning in the updating loop of the queries running
// every second. The value should be set to a value that is high enough to
// catch all queries that are still in the process of being resolved.
// Default: 30 [seconds]
#define REPLY_TIMEOUT 30

// Special exit code used to signal that FTL wants to restart
#define RESTART_FTL_CODE 22

// How often should the database be analyzed?
// Default: 604800 (once per week)
#define DATABASE_ANALYZE_INTERVAL 604800

// How often should we update client vendor's from the MAC vendor database?
// Default: 2592000 (once per month)
#define DATABASE_MACVENDOR_INTERVAL 2592000

// Over how many seconds should the query-per-second (QPS) value be averaged?
// Default: 30 (seconds)
#define QPS_AVGLEN 30

// How long should IPv6 client host name resolution be postponed?
// This is done to ensure that the network table had time to catch up on new
// clients in the network
// Default: 2 x database.DBinterval (seconds) = 120 s
#define DELAY_V6_RESOLUTION 2*config.database.DBinterval.v.ui

// How many characters do we expect domains to have at maximum?
// Background: The maximum length for a full domain name is 253 characters in
// its textual representation, while individual labels (parts of the domain name
// separated by dots) are limited to a maximum of 63 characters. The 255-octet
// limit on the internal network "wire" format is effectively 253 characters
// when converted to the standard dot-separated, user-facing string without a
// trailing dot.
// RFC 1034 section 3.1 applies
// Default: 256, should not be changed
#define MAXDOMAINLEN 256

// Maximum length of an interface name string
// Background: The maximum length for an interface name is 15 characters
// (e.g., "eth0", "wlan0", etc.) in its textual representation.
// Default: 32 (2x safety margin, just in case), should not be changed
#define MAXIFACESTRLEN 32

// Maximum length of a MAC address string
// Background: The maximum length for a MAC address is 17 characters
// (e.g., "00:11:22:33:44:55") in its textual representation.
// Default: 18, should not be changed
#define MAXMACLEN 18

// Use our own syscalls handling functions that will detect possible errors
// and report accordingly in the log. This will make debugging FTL crash
// caused by insufficient memory or by code bugs (not properly dealing
// with NULL pointers) much easier.
#undef strdup // strdup() is a macro in itself, it needs special handling
#define free(ptr) { FTLfree(ptr, __FILE__,  __FUNCTION__,  __LINE__); ptr = NULL; }
#define strdup(str_in) FTLstrdup(str_in, __FILE__,  __FUNCTION__,  __LINE__)
#define calloc(numer_of_elements, element_size) FTLcalloc(numer_of_elements, element_size, __FILE__,  __FUNCTION__,  __LINE__)
#define realloc(ptr, new_size) FTLrealloc(ptr, new_size, __FILE__,  __FUNCTION__,  __LINE__)
#define printf(format, ...) FTLfprintf(stdout, __FILE__, __FUNCTION__,  __LINE__, format, ##__VA_ARGS__)
#define fprintf(stream, format, ...) FTLfprintf(stream, __FILE__, __FUNCTION__,  __LINE__, format, ##__VA_ARGS__)
#define vprintf(format, args) FTLvfprintf(stdout, __FILE__, __FUNCTION__,  __LINE__, format, args)
#define vfprintf(stream, format, args) FTLvfprintf(stream, __FILE__, __FUNCTION__,  __LINE__, format, args)
#define sprintf(buffer, format, ...) FTLsprintf(__FILE__, __FUNCTION__,  __LINE__, buffer, format, ##__VA_ARGS__)
#define vsprintf(buffer, format, args) FTLvsprintf(__FILE__, __FUNCTION__,  __LINE__, buffer, format, args)
#define asprintf(buffer, format, ...) FTLasprintf(__FILE__, __FUNCTION__,  __LINE__, buffer, format, ##__VA_ARGS__)
#define vasprintf(buffer, format, args) FTLvasprintf(__FILE__, __FUNCTION__,  __LINE__, buffer, format, args)
#define snprintf(buffer, maxlen, format, ...) FTLsnprintf(__FILE__, __FUNCTION__,  __LINE__, buffer, maxlen, format, ##__VA_ARGS__)
#define vsnprintf(buffer, maxlen, format, args) FTLvsnprintf(__FILE__, __FUNCTION__,  __LINE__, buffer, maxlen, format, args)
#define write(fd, buf, n) FTLwrite(fd, buf, n, __FILE__,  __FUNCTION__,  __LINE__)
#define accept(sockfd, addr, addrlen) FTLaccept(sockfd, addr, addrlen, __FILE__,  __FUNCTION__,  __LINE__)
#define recv(sockfd, buf, len, flags) FTLrecv(sockfd, buf, len, flags, true, __FILE__,  __FUNCTION__,  __LINE__)
#define recv_nowarn(sockfd, buf, len, flags) FTLrecv(sockfd, buf, len, flags,false,  __FILE__,  __FUNCTION__,  __LINE__)
#define recvfrom(sockfd, buf, len, flags, src_addr, addrlen) FTLrecvfrom(sockfd, buf, len, flags, src_addr, addrlen, __FILE__,  __FUNCTION__,  __LINE__)
#define sendto(sockfd, buf, len, flags, dest_addr, addrlen) FTLsendto(sockfd, buf, len, flags, dest_addr, addrlen, __FILE__,  __FUNCTION__,  __LINE__)
#define select(nfds, readfds, writefds, exceptfds, timeout) FTLselect(nfds, readfds, writefds, exceptfds, timeout, __FILE__,  __FUNCTION__,  __LINE__)
#define pthread_mutex_lock(mutex) FTLpthread_mutex_lock(mutex, __FILE__,  __FUNCTION__,  __LINE__)
#define fopen(pathname, mode) FTLfopen(pathname, mode, __FILE__,  __FUNCTION__,  __LINE__)
#define ftlallocate(fd, offset, len) FTLfallocate(fd, offset, len, __FILE__,  __FUNCTION__,  __LINE__)
#define strlen(str) FTLstrlen(str, __FILE__,  __FUNCTION__,  __LINE__)
#define strnlen(str, maxlen) FTLstrnlen(str, maxlen, __FILE__,  __FUNCTION__,  __LINE__)
#define strcpy(dest, src) FTLstrcpy(dest, src, __FILE__,  __FUNCTION__,  __LINE__)
#define strncpy(dest, src, n) FTLstrncpy(dest, src, n, __FILE__,  __FUNCTION__,  __LINE__)
#define memset(s, c, n) FTLmemset(s, c, n, __FILE__,  __FUNCTION__,  __LINE__)
#define memcpy(dest, src, n) FTLmemcpy(dest, src, n, __FILE__,  __FUNCTION__,  __LINE__)
#define memmove(dest, src, n) FTLmemmove(dest, src, n, __FILE__,  __FUNCTION__,  __LINE__)
#define strstr(haystack, needle) FTLstrstr(haystack, needle, __FILE__,  __FUNCTION__,  __LINE__)
#define strcmp(s1, s2) FTLstrcmp(s1, s2, __FILE__,  __FUNCTION__,  __LINE__)
#define strncmp(s1, s2, n) FTLstrncmp(s1, s2, n, __FILE__,  __FUNCTION__,  __LINE__)
#define strcasecmp(s1, s2) FTLstrcasecmp(s1, s2, __FILE__,  __FUNCTION__,  __LINE__)
#define strncasecmp(s1, s2, n) FTLstrncasecmp(s1, s2, n, __FILE__,  __FUNCTION__,  __LINE__)
#define strcat(dest, src) FTLstrcat(dest, src, __FILE__,  __FUNCTION__,  __LINE__)
#define strncat(dest, src, n) FTLstrncat(dest, src, n, __FILE__,  __FUNCTION__,  __LINE__)
#define memcmp(s1, s2, n) FTLmemcmp(s1, s2, n, __FILE__,  __FUNCTION__,  __LINE__)
#define memmem(haystack, haystacklen, needle, needlelen) FTLmemmem(haystack, haystacklen, needle, needlelen, __FILE__,  __FUNCTION__,  __LINE__)
#include "syscalls/syscalls.h"

// Preprocessor help functions
#define str(x) #x
#define xstr(x) str(x)

// Intentionally ignore result of function declared warn_unused_result
#define igr(x) {__typeof__(x) __attribute__((unused)) d=(x);}

#define max(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define min(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

// defined in cache.c
const char *edestr(int ede);

#endif // FTL_H
