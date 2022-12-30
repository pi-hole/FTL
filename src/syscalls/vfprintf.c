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

// itoa implementation using only static memory
// taken from Kernighan and Ritchie's "The C Programming Language"
// see https://clc-wiki.net/wiki/K&R2_solutions:Chapter_3:Exercise_4
// This implementation has its drawbacks, however, we only use it for
// automated conversion of code line numbers to strings so we're not
// interested in its performance outside the range of [1, 10'000]
static void itoa(int n, char s[])
{
	int i = 0, sign = n;

	// Make n positive if negative
	if (sign < 0)
		n = -n;

	// Generate digits in reverse order
	do
	{
		s[i++] = n % 10 + '0';   /* get next digit */
	} while ((n /= 10) > 0);     /* delete it */

	// Add sign (if needed)
	if (sign < 0)
		s[i++] = '-';

	// Rero-terminate string
	s[i] = '\0';

	// Reverse string s in place
	int j;
	char c;
	int len = strlen(s);
	for (i = 0, j = len-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

// Variant of fputs that prints newline characters as "\n"
static int fputs_convert_newline(const char *string, FILE *stream)
{
	int pos = 0;
	while(string[pos] != '\0')
	{
		if(string[pos] == '\n')
		{
			fputc('\\', stream);
			fputc('n', stream);
		}
		else
		{
			fputc(string[pos], stream);
		}

		pos++;
	}

	return pos;
}

// Special error reporting for our own vfprintf()
// Since we cannot rely on (heap) being available (allocation may have failed
// earlier), we do the reporting entirely manually, writing one string at a time
void syscalls_report_error(const char *error, FILE *stream, const int _errno, const char *format, const char *func, const char *file, const int line)
{
	char linestr[16] = { 0 };
	itoa(line, linestr);

	fputs("WARN: ", stream);
	fputs(error, stream);
	fputs(": ", stream);
	fputs(strerror(_errno), stream);
	fputs("\n      Not processing string \"", stream);
	fputs_convert_newline(format, stream);
	fputs("\" in ", stream);
	fputs(func, stream);
	fputs("() [", stream);
	fputs(file, stream);
	fputs(":", stream);
	fputs(linestr, stream);
	fputs("]\n", stream);
}

// The actual vfprintf() routine
int FTLvfprintf(FILE *stream, const char *file, const char *func, const int line, const char *format, va_list args)
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
		syscalls_report_error("vfprintf() failed to allocate memory",
		                      stream, _errno, format, func, file, line);

		// Free the buffer in case anything got allocated
		if(buffer != NULL)
			free(buffer);

		// Restore errno value
		errno = _errno;

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

	// Backup errno value
	_errno = errno;

	// Final error checking (may have failed for some other reason then an
	// EINTR = interrupted system call)
	if(_buffer < buffer)
	{
		syscalls_report_error("vfprintf() did not print all characters",
		                      stream, errno, format, func, file, line);
	}

	// Free allocated memory
	free(buffer);

	// Restore errno value
	errno = _errno;

	// Return number of written bytes
	return length;
}
