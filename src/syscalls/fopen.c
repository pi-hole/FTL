/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for fopen
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

static uint8_t already_writing = 0;

#undef fopen
FILE * __attribute__ ((__malloc__)) FTLfopen(const char *pathname, const char *mode, const char *file, const char *func, const int line)
{
	FILE *file_ptr = 0;
	do
	{
		// Reset errno before trying to write
		errno = 0;
		file_ptr = fopen(pathname, mode);
	}
	// Try again if the last accept() call failed due to an interruption by an
	// incoming signal
	while(file_ptr == NULL && errno == EINTR);

	// Backup errno value
	const int _errno = errno;

	// Final error checking (may have failed for some other reason then an
	// EINTR = interrupted system call)
	// The already_writing counter prevents a possible infinite loop
	if(file_ptr == NULL && (already_writing++) == 1)
		logg("WARN: Could not fopen(\"%s\", \"%s\") in %s() (%s:%i): %s",
		     pathname, mode, func, file, line, strerror(errno));

	// Decrement warning counter
	already_writing--;

	// Restore errno value
	errno = _errno;

	// Return file pointer
	return file_ptr;
}
