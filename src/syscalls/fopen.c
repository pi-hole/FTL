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
// open()
#include <fcntl.h>

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

// Open one of FTL's own log files. Unlike FTLfopen(), a failure is not logged:
// the warning would be written to FTL.log, which is opened for that again, so a
// log file that cannot be opened would recurse until the stack runs out. The
// callers in log.c handle a failed open themselves
FILE * __attribute__ ((__malloc__)) FTLfopen_nowarn(const char *pathname, const char *mode)
{
	// As root, refuse a symbolic link as the log file, as the pihole user owns
	// the log directory. These are the two modes log.c uses
	int flags = -1;
	if(geteuid() == 0)
	{
		if(strcmp(mode, "a+") == 0)
			flags = O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW;
		else if(strcmp(mode, "w") == 0)
			flags = O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW;
	}

	FILE *file_ptr = 0;
	do
	{
		// Reset errno before trying to open
		errno = 0;
		if(flags == -1)
			file_ptr = fopen(pathname, mode);
		else
		{
			const int fd = open(pathname, flags, 0666);
			if(fd >= 0 && (file_ptr = fdopen(fd, mode)) == NULL)
			{
				const int _errno = errno;
				close(fd);
				errno = _errno;
			}
		}
	}
	// Try again if the call was interrupted by an incoming signal
	while(file_ptr == NULL && errno == EINTR);

	return file_ptr;
}
