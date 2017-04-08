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
// threadwritelock:  The threadwritelock ensures that only one thread with write-access to FTL's data structure can
//                   be active at any given time
// threadreadlock:   An expection to the rule of non-concurrency are the client threads, as they do need read-access
//                   Therefore, it is no problem to have several of them running concurrently. Accordingly, client
//                   threads do *not* have to wait at the lock if threadreadlocks is true (i.e. a client listener
//                   thread has activated this thread lock earlier)
bool threadwritelock = false;
bool threadreadlock = false;

void enable_read_lock(const char *message)
{
	while(threadwritelock) sleepms(5);

	if(debugthreads)
		logg("Thread lock enabled (R ): %s", message);

	// Set threadwritelock
	threadwritelock = false;
	// Set threadreadlock (see above)
	threadreadlock = true;
}

void enable_read_write_lock(const char *message)
{
	while(threadwritelock || threadreadlock) sleepms(5);

	if(debugthreads)
		logg("Thread lock enabled (RW): %s", message);

	// Set threadwritelock
	threadwritelock = true;
}

void disable_thread_locks(const char *message)
{
	threadwritelock = false;
	threadreadlock = false;
	if(debugthreads)
		logg("Thread lock disabled: %s", message);
}
