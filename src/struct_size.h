/* Pi-hole: A black hole for Internet advertisements
*  (c) 2022 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Struct size checking prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef STRUCT_SIZE_HEADER
#define STRUCT_SIZE_HEADER

// type size_t
#include <stddef.h>

int check_one_struct(const char *struct_name, const size_t found_size, const size_t size64, const size_t size32);

#endif // STRUCT_SIZE_HEADER