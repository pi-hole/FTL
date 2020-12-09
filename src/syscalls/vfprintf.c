/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for vfprintf
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

int FTLvfprintf(FILE *stream, const char *format, va_list args)
{
	// Print into dynamically allocated memory
	char *buffer = NULL;
	int _errno, length = 0;
	do
	{
        // The va_copy() macro copies the (previously initialized) variable
        // argument list args to the local _args. The behavior is as if
        // va_start() were applied to _args with the same last argument,
        // followed by the same number of va_arg() invocations that was used to
        // reach the current state of args. We do this to be able to reuse the
        // arguments in args when we need to redo the string preparation
        // procedure
        va_list _args;
        va_copy(_args, args);
		// Reset errno before trying to get the string
		errno = 0;
        // Do the actual string transformation
		length = vasprintf(&buffer, format, _args);
        // Copy errno into buffer before calling va_end()
        _errno = errno;
        va_end(_args);
	}
	// Try again to allocate memory if this failed due to an interruption by
	// an incoming signal
	while(length < 0 && _errno == EINTR);

	// Handle other errors than EINTR
	if(length < 0 || buffer == NULL)
	{
		fputs("WARN: fprintf() failed to allocate memory: ", stream);
		fputs(strerror(errno), stream);
		fputs("\n", stream);
		fputs("Not processing string: ", stream);
		fputs(format, stream);
		fputs("\n", stream);

        // Free the buffer in case anything got allocated
        if(buffer != NULL)
            free(buffer);

		// Return early, there isn't anything we can do here
		return length;
	}

	// Actually write into the requested stream now
	char *_buffer = buffer;
	do
	{
		// Reset errno before trying to write
		errno = 0;
		// Print buffer into stream and advance working pointer by number of
		// written bytes
		_buffer += fputs(_buffer, stream);
	}
	// Try to write the remaining content into the stream if this failed due
	// to an interruption by an incoming signal
	while(_buffer < buffer && errno == EINTR);

	// Final error checking (may have faild for some other reason then an
	// EINTR = interrupted system call)
	if(_buffer < buffer)
	{
		fputs("WARN: fprintf() did not print all characters: ", stream);
		fputs(strerror(errno), stream);
		fputs("\n", stream);
		fputs("Not processing string: ", stream);
		fputs(format, stream);
		fputs("\n", stream);
	}

	// Free allocated memory
	free(buffer);

	// Return number of written bytes
	return length;
}
