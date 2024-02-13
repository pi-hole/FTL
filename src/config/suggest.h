/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  String suggestion prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LEVENSHTEIN_H
#define LEVENSHTEIN_H

#include "FTL.h"
// union conf_value
#include "config.h"

char **suggest_closest_conf_key(const bool env, const char *string, unsigned int *N);

#endif //LEVENSHTEIN_H
