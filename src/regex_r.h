/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Regex prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef REGEX_H
#define REGEX_H

// clientsData type
#include "datastructure.h"

bool match_regex(const char *input, const clientsData *client, const unsigned char regexid);
void allocate_regex_client_enabled(clientsData *client);
void read_regex_from_database(void);

enum { REGEX_UNKNOWN, REGEX_BLOCKED, REGEX_NOTBLOCKED };
enum { REGEX_BLACKLIST, REGEX_WHITELIST };

#endif //REGEX_H
