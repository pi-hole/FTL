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

int check_one_struct(const char *struct_name, const long found_size, const long size64, const long size32, const long sizeARM);

#endif // STRUCT_SIZE_HEADER