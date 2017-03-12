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

void enable_lock(const char *message)
{
	while(threadlock) sleepms(5);

	if(debugthreads)
		logg_const_str("Thread lock enabled: ", message);
	threadlock = true;
}

void disable_lock(const char *message)
{
	threadlock = false;
	if(debugthreads)
		logg_const_str("Thread lock disabled: ", message);
}
