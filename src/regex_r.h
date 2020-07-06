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

extern const char *regextype[];

#ifdef USE_TRE_REGEX
#include "tre-regex/regex.h"
#else
#include <regex.h>
#endif

struct regex_data {
	regex_t regex;
	char *string;
	int database_id;
	bool available;
};

int match_regex(const char *input, const int clientID, const enum regex_type, const bool regextest);
void allocate_regex_client_enabled(clientsData *client, const int clientID);
void read_regex_from_database(void);

int regex_test(const bool debug_mode, const bool quiet, const char *domainin, const char *regexin);

#endif //REGEX_H
