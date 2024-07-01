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

#include "enums.h"

#define NUMTIMERS LAST_TIMER

void timer_start(const enum timers i);
double timer_elapsed_msec(const enum timers i);
void sleepms(const int milliseconds);
void set_blockingmode_timer(double delay, bool blocked);
void get_blockingmode_timer(double *delay, bool *target_status);
void *timer(void *val);
unsigned long converttimeval(const struct timeval time) __attribute__((const));

#endif //TIMERS_H
