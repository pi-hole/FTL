/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TOML config reader prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef TOML_READER_H
#define TOML_READER_H

#include "config/config.h"
#include "tomlc17/tomlc17.h"

bool readFTLtoml(struct config *oldconf, struct config *newconf,
                 toml_datum_t toml, const bool verbose, bool *restart,
                 const unsigned int version, const bool teleporter);
bool getLogFilePathTOML(void);

#endif //TOML_READER_H
