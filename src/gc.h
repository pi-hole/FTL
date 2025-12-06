/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Garbage collection prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef GC_H
#define GC_H

#include <stdbool.h>
#include <time.h>

void *GC_thread(void *val);
void runGC(const time_t now, time_t *lastGCrun, const bool flush);
unsigned int get_max_overtime_slot(void) __attribute__((pure));
int get_rate_limit_turnaround(const unsigned int rate_limit_count);
unsigned int set_gc_interval(void);

// Defined in src/dnsmasq_interface.c
void set_dnsmasq_debug(const bool debug, const pid_t pid);

extern bool db_import_done;

#endif //GC_H
