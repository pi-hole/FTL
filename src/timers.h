/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Timer prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef TIMERS_H
#define TIMERS_H

// Timer enumeration
enum timers {
	DATABASE_WRITE_TIMER,
	EXIT_TIMER,
	GC_TIMER,
	LISTS_TIMER,
	REGEX_TIMER,
	ARP_TIMER,
	LAST_TIMER
	} __attribute__ ((packed));

#define NUMTIMERS LAST_TIMER

void timer_start(const enum timers i);
double timer_elapsed_msec(const enum timers i);
void sleepms(const int milliseconds);

#define CHECK_TIME(x) {\
    struct timespec start,end;\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);\
    x;\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);\
    double f = ((double)end.tv_sec*1e9 + end.tv_nsec) - ((double)start.tv_sec*1e9 + start.tv_nsec); \
    logg("TIMED %s: %f ms\n", xstr(x), 1e-6*f); \
    }

#endif //TIMERS_H
