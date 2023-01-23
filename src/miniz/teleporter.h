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

#include "miniz/miniz.h"
const char *generate_teleporter_zip(mz_zip_archive *zip, void *ptr, size_t *size);
bool free_teleporter_zip(mz_zip_archive *zip);

#endif // TELEPORTER_H