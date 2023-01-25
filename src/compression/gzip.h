/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  GZIP compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef GZIP_H
#define GZIP_H

#include <stdbool.h>

bool deflate_file(const char *in, const char *out, bool verbose);
bool inflate_file(const char *infile, const char *outfile, bool verbose);

#endif // GZIP_H
