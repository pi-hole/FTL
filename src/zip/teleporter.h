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

// The list tables alone, for the cluster synchronization
const char *generate_cluster_zip(mz_zip_archive *zip, void **ptr, size_t *size);
bool free_teleporter_zip(mz_zip_archive *zip);
// max_entries bounds how many files the archive may hold, or zero for no bound.
// The one a cluster peer sends holds a single table dump; an export made here
// holds one entry per file in /etc/dnsmasq.d on top of the fixed four
const char *read_teleporter_zip(uint8_t *buffer, const size_t buflen, const unsigned int max_entries, char *hint, cJSON *import, cJSON *json_files);

bool write_teleporter_zip_to_disk(void);
bool read_teleporter_zip_from_disk(const char *filename);

#endif // TELEPORTER_H
