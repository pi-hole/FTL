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
// Unix socket
#include <sys/un.h>
// Interfaces
#include <ifaddrs.h>
#include <net/if.h>

// Define MIN and MAX macros, use them only when x and y are of the same type
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
// MIN(x,y) is already defined in dnsmasq.h

#define SOCKETBUFFERLEN 1024

// How often do we garbage collect (to ensure we only have data fitting to the MAXLOGAGE defined above)? [seconds]
// Default: 600 (10 minute intervals)
#define GCinterval 600

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

// Use out own syscalls handling functions that will detect possible errors
// and report accordingly in the log. This will make debugging FTL crash
// caused by insufficient memory or by code bugs (not properly dealing
// with NULL pointers) much easier.
#undef strdup // strdup() is a macro in itself, it needs special handling
#define free(ptr) FTLfree(ptr, __FILE__,  __FUNCTION__,  __LINE__)
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
#include "syscalls/syscalls.h"

// Preprocessor help functions
#define str(x) # x
#define xstr(x) str(x)

#endif // FTL_H
