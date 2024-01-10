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
// Interfaces
#include <ifaddrs.h>
#include <net/if.h>

// Define MIN and MAX macros, use them only when x and y are of the same type
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
// MIN(x,y) is already defined in dnsmasq.h

// Number of elements in an array
#define ArraySize(X) (sizeof(X)/sizeof(X[0]))

// Constant socket buffer length
#define SOCKETBUFFERLEN 1024

// How often do we garbage collect (to ensure we only have data fitting to the MAXLOGAGE defined above)? [seconds]
// Default: 600 (10 minute intervals)
#define GCinterval 600

// Delay applied to the garbage collecting [seconds]
// Default: -60 (one minute before the end of the interval set above)
#define GCdelay (-60)

// How many client connection do we accept at once?
#define MAXCONNS 255

// Over how many queries do we iterate at most when trying to find a match?
#define MAXITER 1000

// How many hours do we want to store in FTL's memory? [hours]
#define MAXLOGAGE 24

// Interval for overTime data [seconds]
// Default: same as GCinterval
#define OVERTIME_INTERVAL GCinterval

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

// DB_QUERY_MAX_ITER defines how many queries we check periodically for updates to be added
// to the in-memory database. This value may need to be increased on *very* busy systems.
// However, there is an algorithm in place that tries to ensure we are not missing queries
// on systems with > 100 queries per second
// Default: 100 (per second)
#define DB_QUERY_MAX_ITER 100

// Special exit code used to signal that FTL wants to restart
#define RESTART_FTL_CODE 22

// How often should the database be analyzed?
// Default: 604800 (once per week)
#define DATABASE_ANALYZE_INTERVAL 604800

// How often should we update client vendor's from the MAC vendor database?
// Default: 2592000 (once per month)
#define DATABASE_MACVENDOR_INTERVAL 2592000

// Use out own syscalls handling functions that will detect possible errors
// and report accordingly in the log. This will make debugging FTL crash
// caused by insufficient memory or by code bugs (not properly dealing
// with NULL pointers) much easier.
#undef strdup // strdup() is a macro in itself, it needs special handling
#define free(ptr) FTLfree((void**)&ptr, __FILE__,  __FUNCTION__,  __LINE__)
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
#define recv(sockfd, buf, len, flags) FTLrecv(sockfd, buf, len, flags, __FILE__,  __FUNCTION__,  __LINE__)
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

#endif // FTL_H
