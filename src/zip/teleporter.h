/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef TELEPORTER_H
#define TELEPORTER_H

#include "zip/miniz/miniz.h"
#include "webserver/cJSON/cJSON.h"

const char *generate_teleporter_zip(mz_zip_archive *zip, char filename[128], void **ptr, size_t *size);
bool free_teleporter_zip(mz_zip_archive *zip);
const char *read_teleporter_zip(uint8_t *buffer, const size_t buflen, char *hint, cJSON *import, cJSON *json_files);

bool write_teleporter_zip_to_disk(void);
bool read_teleporter_zip_from_disk(const char *filename);

#endif // TELEPORTER_H
