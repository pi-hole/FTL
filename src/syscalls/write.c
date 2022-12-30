/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for write
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#undef write
ssize_t FTLwrite(int fd, const void *buf, size_t total, const char *file, const char *func, const int line)
{
	if(buf == NULL)
	{
		log_err("Trying to write a NULL string in %s() (%s:%i)", func, file, line);
		return 0;
	}

	ssize_t ret = 0;
	size_t written = 0;
	do
	{
		// Reset errno before trying to write
		errno = 0;
		ret = write(fd, buf, total);
		if(ret > 0)
			written += ret;
	}
	// Try to write the remaining content into the stream if
	// (a) we haven't written all the data, however, there was no other error
	// (b) the last write() call failed due to an interruption by an incoming signal
	while((written < total && errno == 0) || (ret < 0 && errno == EINTR));

	// Backup errno value
	const int _errno = errno;

	// Final error checking (may have failed for some other reason then an
	// EINTR = interrupted system call)
	if(written < total)
		log_warn("Could not write() everything in %s() [%s:%i]: %s",
		         func, file, line, strerror(errno));

	// Restore errno value
	errno = _errno;

	// Return number of written bytes
	return written;
}