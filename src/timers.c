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
// get_blockingstatus()
#include "config/config.h"
#include <stdatomic.h>

static struct timespec t0[NUMTIMERS];

void timer_start(const enum timers i)
{
	if(i >= NUMTIMERS)
	{
		log_crit("Timer %i not defined in timer_start().", i);
		exit(EXIT_FAILURE);
	}
	clock_gettime(CLOCK_MONOTONIC, &t0[i]);
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


/**
 * @brief Calculates the difference in seconds between two timespec values.
 *
 * @param start The starting timespec value.
 * @param end   The ending timespec value.
 * @return The time difference in seconds as a double.
 */
double __attribute__((const)) time_diff(struct timespec start, struct timespec end)
{
	struct timespec td = diff(start, end);
	return td.tv_sec + td.tv_nsec * 1e-9;
}

double timer_elapsed_msec(const enum timers i)
{
	if(i >= NUMTIMERS)
	{
		log_crit("Timer %i not defined in timer_elapsed_msec().", i);
		exit(EXIT_FAILURE);
	}
	struct timespec t1, td;
	clock_gettime(CLOCK_MONOTONIC, &t1);
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

// A temporary blocking status overrides dns.blocking.active until its timer
// expires. It is kept in memory only, so a restart drops it and the configured
// status applies again. timer_lock guards the state shared between the timer
// thread and the API workers
static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
static double timer_delay = -1.0;
// -1 = no temporary status, else the temporary blocking status
static _Atomic int temp_status = -1;

// Reload so the DNS cache reflects a changed effective blocking status
static void reload_on_change(const enum blocking_status before)
{
	if(get_blockingstatus() != before)
		raise(SIGHUP);
}

int get_temp_blockingstatus(void)
{
	return atomic_load(&temp_status);
}

double get_temp_blockingstatus_timer(void)
{
	pthread_mutex_lock(&timer_lock);
	const double delay = timer_delay;
	pthread_mutex_unlock(&timer_lock);
	return delay;
}

void set_temp_blockingstatus(const bool status, const double delay)
{
	const enum blocking_status before = get_blockingstatus();
	pthread_mutex_lock(&timer_lock);
	timer_delay = delay;
	atomic_store(&temp_status, status);
	pthread_mutex_unlock(&timer_lock);
	reload_on_change(before);
}

void clear_temp_blockingstatus(void)
{
	const enum blocking_status before = get_blockingstatus();
	pthread_mutex_lock(&timer_lock);
	timer_delay = -1.0;
	atomic_store(&temp_status, -1);
	pthread_mutex_unlock(&timer_lock);
	reload_on_change(before);
}

#define SLEEPING_TIME 0.1 // seconds
void *timer(void *val)
{
	(void)val;
	// Set thread name
	prctl(PR_SET_NAME, thread_names[TIMER], 0, 0, 0);

	// Save timestamp as we do not want to store immediately
	// to the database
	while(!killed)
	{
		const enum blocking_status before = get_blockingstatus();
		bool expired = false;
		// Hold the lock across the tick so a new timer set through the API
		// is neither overwritten by the decrement nor discarded on expiry
		pthread_mutex_lock(&timer_lock);
		if(timer_delay > 0)
		{
			log_debug(DEBUG_EXTRA, "Temporary blocking status ends in %.1f seconds...",
			          timer_delay);

			timer_delay -= SLEEPING_TIME;
		}
		else if(timer_delay <= 0.0 && timer_delay > -1.0)
		{
			log_debug(DEBUG_EXTRA, "Timer expired, blocking status is %s again",
			          config.dns.blocking.active.v.b ? "enabled" : "disabled");

			timer_delay = -1.0;
			atomic_store(&temp_status, -1);
			expired = true;
		}
		pthread_mutex_unlock(&timer_lock);

		if(expired)
			reload_on_change(before);
		thread_sleepms(TIMER, SLEEPING_TIME * 1000);
	}

	log_info("Terminating timer thread");
	return NULL;
}
