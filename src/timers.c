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

struct timeval t0[NUMTIMERS];

void timer_start(enum timers i)
{
	if(i >= NUMTIMERS)
	{
		logg("Code error: Timer %i not defined in timer_start().", i);
		exit(EXIT_FAILURE);
	}
	gettimeofday(&t0[i], 0);
}

double timer_elapsed_msec(enum timers i)
{
	if(i >= NUMTIMERS)
	{
		logg("Code error: Timer %i not defined in timer_elapsed_msec().", i);
		exit(EXIT_FAILURE);
	}
	struct timeval t1;
	gettimeofday(&t1, 0);
	return (t1.tv_sec - t0[i].tv_sec) * 1000.0f + (t1.tv_usec - t0[i].tv_usec) / 1000.0f;
}

void sleepms(const int milliseconds)
{
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	select(0, NULL, NULL, NULL, &tv);
}
