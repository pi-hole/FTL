/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Thread routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

// Logic of the locks:
// Any of the various threads (logparser, GC, client threads) is accessing FTL's data structure. Hence, they should
// never run at the same time since the data can change half-way through, leading to unspecified behavior.
// threadlock:  The threadlock ensures that only one thread can be active at any given time
bool threadlock = false;

void enable_thread_lock(const char *message)
{
	while(threadlock) sleepms(5);

	if(debugthreads)
		logg("Thread lock enabled: %s", message);

	// Set threadlock
	threadlock = true;
}

void disable_thread_lock(const char *message)
{
	threadlock = false;

	if(debugthreads)
		logg("Thread lock disabled: %s", message);
}
