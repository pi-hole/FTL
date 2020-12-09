/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for calloc
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#undef calloc
void* __attribute__((malloc)) __attribute__((alloc_size(1,2))) FTLcalloc(const size_t nmemb, const size_t size, const char * file, const char * function, const int line)
{
	// The FTLcalloc() function allocates memory for an array of nmemb elements
	// of size bytes each and returns a pointer to the allocated memory. The
	// memory is set to zero. If nmemb or size is 0, then calloc() returns
	// either NULL, or a unique pointer value that can later be successfully
	// passed to free().
	void *ptr = calloc(nmemb, size);
	if(ptr == NULL)
		logg("FATAL: Memory allocation (%zu x %zu) failed in %s() (%s:%i)",
		     nmemb, size, function, file, line);

	return ptr;
}
