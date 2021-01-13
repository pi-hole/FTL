/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for pthread_mutex_lock
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#include <pthread.h>

#undef pthread_mutex_lock
int FTLpthread_mutex_lock(pthread_mutex_t *__mutex, const char *file, const char *func, const int line)
{
	int ret = 0;
	do
	{
		ret = pthread_mutex_lock(__mutex);
	}
	// Try again if the last accept() call failed due to an interruption by an
	// incoming signal
	while(ret == EINTR);

	// Final errer checking (may have faild for some other reason then an
	// EINTR = interrupted system call)
	if(ret != 0)
		logg("WARN: Could not pthread_mutex_lock() in %s() (%s:%i): %s",
		     func, file, line, strerror(ret));

	return ret;
}
