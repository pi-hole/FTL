/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Memory prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef MEMORY_H
#define MEMORY_H

void memory_check(const int which);
char *FTLstrdup(const char *src, const char *file, const char *function, const int line) __attribute__((malloc));
void *FTLcalloc(size_t nmemb, size_t size, const char *file, const char *function, const int line) __attribute__((malloc)) __attribute__((alloc_size(1,2)));
void *FTLrealloc(void *ptr_in, size_t size, const char *file, const char *function, const int line) __attribute__((alloc_size(2)));
void FTLfree(void *ptr, const char* file, const char *function, const int line);

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
	int querytype[TYPE_MAX-1];
	int forwardedqueries;
	int reply_NODATA;
	int reply_NXDOMAIN;
	int reply_CNAME;
	int reply_IP;
	int reply_domain;
} countersStruct;

extern countersStruct *counters;

#endif //MEMORY_H
