/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Timing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "timers.h"
#include "memory.h"
#include "log.h"

struct timespec t0[NUMTIMERS];

void timer_start(const enum timers i)
{
	if(i >= NUMTIMERS)
	{
		logg("Code error: Timer %i not defined in timer_start().", i);
		exit(EXIT_FAILURE);
	}
	clock_gettime(CLOCK_REALTIME, &t0[i]);
}

static struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec diff;
	if(end.tv_nsec-start.tv_nsec < 0L)
	{
		diff.tv_sec = end.tv_sec - start.tv_sec - 1; // subtract one second here...
		diff.tv_nsec = end.tv_nsec - start.tv_nsec + 1000000000L; // ...we have to add it here
	}
	else
	{
		diff.tv_sec = end.tv_sec - start.tv_sec;
		diff.tv_nsec = end.tv_nsec - start.tv_nsec;
	}
	return diff;
}

double timer_elapsed_msec(const enum timers i)
{
	if(i >= NUMTIMERS)
	{
		logg("Code error: Timer %i not defined in timer_elapsed_msec().", i);
		exit(EXIT_FAILURE);
	}
	struct timespec t1, td;
	clock_gettime(CLOCK_REALTIME, &t1);
	td = diff(t0[i], t1);
	return td.tv_sec * 1e3 + td.tv_nsec * 1e-6;
}

void sleepms(const int milliseconds)
{
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	select(0, NULL, NULL, NULL, &tv);
}
