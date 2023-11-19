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

const uint8_t *find_file_in_tar(const uint8_t *tar, const size_t tarSize, const char *fileName, size_t *fileSize);
cJSON *list_files_in_tar(const uint8_t *tarData, const size_t tarSize);

#endif // TAR_H