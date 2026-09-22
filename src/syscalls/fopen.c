/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for fopen
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "log.h"

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
	// EINTR = interrupted system call). A missing file is left to the caller,
	// many of them probe for optional files.
	if(file_ptr == NULL && _errno != ENOENT)
		log_warn("Could not fopen(\"%s\", \"%s\") in %s() (%s:%i): %s",
		         pathname, mode, func, file, line, strerror(_errno));

	// Restore errno value
	errno = _errno;

	// Return file pointer
	return file_ptr;
}
