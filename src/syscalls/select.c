/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for select
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#include <sys/select.h>

#undef select
int FTLselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout, const char *file, const char *func, const int line)
{
	int ret = 0;
	do
	{
		// Reset errno before trying to write
		errno = 0;
		ret = select(nfds, readfds, writefds, exceptfds, timeout);
	}
	// Try again if the last accept() call failed due to an interruption by an
	// incoming signal
	while(ret < 0 && errno == EINTR);

	// Backup errno value
	const int _errno = errno;

	// Final error checking (may have failed for some other reason then an
	// EINTR = interrupted system call)
	if(ret < 0)
		logg("WARN: Could not select() in %s() (%s:%i): %s",
		     func, file, line, strerror(errno));

	// Restore errno value
	errno = _errno;

	return ret;
}