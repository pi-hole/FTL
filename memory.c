/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global variable definitions and memory reallocation handling
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "shmem.h"

FTLFileNamesStruct FTLfiles = {
	// Default path for config file (regular installations)
	"/etc/pihole/pihole-FTL.conf",
	// Alternative path for config file (snap installations)
	"/var/snap/pihole/common/etc/pihole/pihole-FTL.conf",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

logFileNamesStruct files = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

// Fixed size structs
countersStruct *counters = NULL;
overTimeData *overTime = NULL;
ConfigStruct config;

// The special memory handling routines have to be the last ones in this source file
// as we restore the original definition of the strdup, free, calloc, and realloc
// functions in here, i.e. if anything extra would come below these lines, it would
// not be protected by our (error logging) functions!

#undef strdup
char* __attribute__((malloc)) FTLstrdup(const char *src, const char * file, const char * function, int line)
{
	// The FTLstrdup() function returns a pointer to a new string which is a
	// duplicate of the string s. Memory for the new string is obtained with
	// calloc(3), and can be freed with free(3).
	if(src == NULL)
	{
		logg("WARN: Trying to copy a NULL string in %s() (%s:%i)", function, file, line);
		return NULL;
	}
	size_t len = strlen(src);
	char *dest = calloc(len+1, sizeof(char));
	if(dest == NULL)
	{
		logg("FATAL: Memory allocation failed in %s() (%s:%i)", function, file, line);
		return NULL;
	}
	// Use memcpy as memory areas cannot overlap
	memcpy(dest, src, len);
	dest[len] = '\0';

	return dest;
}

#undef calloc
void* __attribute__((malloc)) __attribute__((alloc_size(1,2))) FTLcalloc(size_t nmemb, size_t size, const char * file, const char * function, int line)
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

#undef realloc
void __attribute__((alloc_size(2))) *FTLrealloc(void *ptr_in, size_t size, const char * file, const char * function, int line)
{
	// The FTLrealloc() function changes the size of the memory block pointed to
	// by ptr to size bytes. The contents will be unchanged in the range from
	// the start of the region up to the minimum of the old and new sizes. If
	// the new size is larger than the old size, the added memory will not be
	// initialized. If ptr is NULL, then the call is equivalent to malloc(size),
	// for all values of size; if size is equal to zero, and ptr is
	// not NULL, then the call is equivalent to free(ptr). Unless ptr is
	// NULL, it must have been returned by an earlier call to malloc(), cal‐
	// loc() or realloc(). If the area pointed to was moved, a free(ptr) is
	// done.
	void *ptr_out = realloc(ptr_in, size);
	if(ptr_out == NULL)
		logg("FATAL: Memory reallocation (%p -> %zu) failed in %s() (%s:%i)",
		     ptr_in, size, function, file, line);

	return ptr_out;
}

#undef free
void FTLfree(void *ptr, const char * file, const char * function, int line)
{
	// The free() function frees the memory space pointed  to  by  ptr,  which
	// must  have  been  returned by a previous call to malloc(), calloc(), or
	// realloc().  Otherwise, or if free(ptr) has already been called  before,
	// undefined behavior occurs.  If ptr is NULL, no operation is performed.
	if(ptr == NULL)
		logg("FATAL: Trying to free NULL pointer in %s() (%s:%i)", function, file, line);

	// We intentionally run free() nevertheless to see the crash in the debugger
	free(ptr);
}
