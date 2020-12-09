/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for fprintf
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

int FTLfprintf(FILE *stream, const char *format, ...)
{
	// Print into dynamically allocated memory
	va_list arg;
	char *buffer = NULL;
	int length = 0;
	do
	{
		va_start(arg, format);
		// Reset errno before trying to get the string
		errno = 0;
		length = vasprintf(&buffer, format, arg);
		va_end(arg);
	}
	// Try again to allocate memory if this failed due to an interruption by
	// an incoming signal
	while(length < 0 && errno == EINTR);

	// Error handling
	if(length < 0 || buffer == NULL)
	{
		fputs("WARN: fprintf() failed to allocate memory: ", stream);
		fputs(strerror(errno), stream);
		fputs("\n", stream);
		fputs("Not processing string: ", stream);
		fputs(format, stream);
		fputs("\n", stream);

		// Return early, there isn't anything we can do here
		return length;
	}

	// Actually write into file now
	char *_buffer = buffer;
	int bytes_written = 0;
	do
	{
		// Reset errno before trying to write
		errno = 0;
		// Print buffer into stream
		bytes_written = fputs(_buffer, stream);
		// Add number of written bytes
		_buffer += bytes_written;
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
