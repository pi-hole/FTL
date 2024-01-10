/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TAR reading routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef TAR_H
#define TAR_H

#include "FTL.h"
#include "webserver/cJSON/cJSON.h"

const char *find_file_in_tar(const uint8_t *tar, const size_t tarSize, const char *fileName, size_t *fileSize) __attribute__((nonnull (1,3,4)));
cJSON *list_files_in_tar(const uint8_t *tarData, const size_t tarSize) __attribute__((nonnull (1)));

#endif // TAR_H