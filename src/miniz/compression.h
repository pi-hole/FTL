/* Pi-hole: A black hole for Internet advertisements
*  (c) 2323 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <stdbool.h>

bool deflate_file(const char *in, const char *out, bool verbose);
bool inflate_file(const char *infile, const char *outfile, bool verbose);

#endif // COMPRESSION_H
