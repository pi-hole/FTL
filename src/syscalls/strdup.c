/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for strdup
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#undef strdup
char* __attribute__((malloc)) FTLstrdup(const char *src, const char * file, const char * function, const int line)
{
	// The FTLstrdup() function returns a pointer to a new string which is a
	// duplicate of the string s. Memory for the new string is obtained with
	// calloc(3), and can be freed with free(3).
	if(src == NULL)
	{
		logg("WARN: Trying to copy a NULL string in %s() (%s:%i)", function, file, line);
		return NULL;
	}
	const size_t len = strlen(src);
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