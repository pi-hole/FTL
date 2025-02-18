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
#include "miniz/miniz.h"

bool inflate_buffer(unsigned char *buffer_compressed, mz_ulong size_compressed,
                    unsigned char **buffer_uncompressed, mz_ulong *size_uncompressed);

bool deflate_file(const char *in, const char *out, bool verbose);
bool inflate_file(const char *infile, const char *outfile, bool verbose);

#endif // GZIP_H
