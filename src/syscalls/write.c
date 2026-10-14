/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for write
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "log.h"

#undef write

// EAGAIN and EWOULDBLOCK are the same value on Linux; test both only where they
// actually differ so -Wlogical-op stays quiet
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
#define WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
#define WOULDBLOCK(e) ((e) == EAGAIN)
#endif

ssize_t FTLwrite(int fd, const void *buf, size_t total, const char *file, const char *func, const int line)
{
	if(buf == NULL)
	{
		log_err("Trying to write a NULL string in %s() (%s:%i)", func, file, line);
		return 0;
	}

	size_t written = 0;
	while(written < total)
	{
		// Reset errno before trying to write
		errno = 0;
		const ssize_t ret = write(fd, (const char *)buf + written, total - written);
		if(ret > 0)
		{
			written += ret;
			continue;
		}

		// Try again if the last write() call failed due to an interruption
		// by an incoming signal, stop on any other error (or on no progress)
		if(ret < 0 && errno == EINTR)
			continue;
		break;
	}

	// Backup errno value
	const int _errno = errno;

	// Final error checking (may have failed for some other reason then an
	// EINTR = interrupted system call). A non-blocking descriptor without
	// room is not an error, the caller polls for it.
	if(written < total && _errno != 0 && !WOULDBLOCK(_errno))
		log_warn("Could not write() everything in %s() [%s:%i]: %s",
		         func, file, line, strerror(_errno));

	// Restore errno value
	errno = _errno;

	// Return the number of written bytes, or -1 (with errno set) if nothing
	// could be written
	if(written == 0 && _errno != 0)
		return -1;
	return written;
}
