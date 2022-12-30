/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for vsprintf
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#undef vsprintf
int FTLvsprintf(const char *file, const char *func, const int line, char *__restrict__ buffer, const char *format, va_list args)
{
	// Sanity check
	if(buffer == NULL)
	{
		syscalls_report_error("vsprintf() called with NULL buffer",
		                      stdout, 0, format, func, file, line);
		return 0;
	}
	// Print into dynamically allocated memory
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
		length = vsprintf(buffer, format, _args);
		// Copy errno into buffer before calling va_end()
		_errno = errno;
		va_end(_args);
	}
	// Try again to allocate memory if this failed due to an interruption by
	// an incoming signal
	while(length < 0 && _errno == EINTR);

	// Handle other errors than EINTR
	if(length < 0)
	{
		syscalls_report_error("vsprintf() failed to print into buffer",
		                      stdout, _errno, format, func, file, line);
	}

	// Restore errno value
	errno = _errno;

	// Return number of written bytes
	return length;
}
