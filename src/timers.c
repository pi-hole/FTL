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
#include "log.h"
// killed
#include "signals.h"
// set_blockingmode()
#include "setupVars.h"

struct timespec t0[NUMTIMERS];

void timer_start(const enum timers i)
{
	if(i >= NUMTIMERS)
	{
		log_crit("Timer %i not defined in timer_start().", i);
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
		log_crit("Timer %i not defined in timer_elapsed_msec().", i);
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

static int timer_delay = -1;
static bool timer_target_status;

void set_blockingmode_timer(int delay, bool target_status)
{
	timer_delay = delay;
	timer_target_status = target_status;
}

void get_blockingmode_timer(int *delay, bool *target_status)
{
	*delay = timer_delay;
	*target_status = timer_target_status;
}

void *timer(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"int.timer",0,0,0);

	// Save timestamp as we do not want to store immediately
	// to the database
	//lastGCrun = time(NULL) - time(NULL)%GCinterval;
	while(!killed)
	{
		if(timer_delay > 0)
		{
			timer_delay--;
		}
		else if(timer_delay == 0)
		{
			set_blockingstatus(timer_target_status);
			timer_delay = -1;
		}
		sleepms(1000);
	}

	return NULL;
}

unsigned long __attribute__((const)) converttimeval(const struct timeval time)
{
	// Convert time from struct timeval into units
	// of 10*milliseconds
	return time.tv_sec*10000 + time.tv_usec/100;
}
