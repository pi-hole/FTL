/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for fallocate
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"
#include <fcntl.h>

// off_t is automatically set as off64_t when this is a 64bit system
int FTLfallocate(const int fd, const off_t offset, const off_t len, const char *file, const char *func, const int line)
{
	int ret = 0;
	do
	{
		// posix_fallocate directly returns errno and doesn't set the
		// actual errno system global
		ret = posix_fallocate(fd, offset, len);
	}
	// Try again if the last posix_fallocate() call failed due to an
	// interruption by an incoming signal
	while(ret == EINTR);

	// Final error checking (may have failed for some other reason then an
	// EINTR = interrupted system call)
	if(ret > 0)
		logg("WARN: Could not fallocate() in %s() (%s:%i): %s",
		     func, file, line, strerror(ret));

	// Set errno ourselves as posix_fallocate doesn't do it
	errno = ret;

	return ret;
}
