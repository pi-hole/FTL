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

extern countersStruct *counters;

#endif //MEMORY_H
