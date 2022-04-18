
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2022 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Struct size checking routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "struct_size.h"
#include <stdio.h>

int check_one_struct(const char *struct_name, const long found_size, const long size64, const long size32, const long sizeARM)
{
#if defined(__x86_64__)
	const long expected_size = size64;
	const char *arch = "x86_64";
#elif defined(__aarch64__)
	const long expected_size = size64;
	const char *arch = "aarch64";
#elif defined(__i386__)
	const long expected_size = size32;
	const char *arch = "i386";
#elif defined(__mips__) // issue #290
	const long expected_size = size32;
	const char *arch = "mips";
#elif defined(__arm__)
	const long expected_size = sizeARM;
	const char *arch = "arm";
#endif

	// Check struct size meets expectation
	if(found_size == expected_size)
		return 0;

	// Size mismatch
	printf("WARNING: sizeof(%s) should be %lu on %s but is %lu\n",
	       struct_name, expected_size, arch, found_size);
	return 1;
}


