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

// Use TRE instead of GNU regex library (compiled into FTL itself)
#define USE_TRE_REGEX

#ifdef USE_TRE_REGEX
#include "tre-regex/regex.h"
#else
#include <regex.h>
#endif

// assert_sizeof
#include "static_assert.h"

typedef struct {
	bool available;
	bool inverted;
	bool query_type_inverted;
	enum query_type query_type;
	int database_id;
	char *string;
	regex_t regex;
} regexData;
ASSERT_SIZEOF(regexData, 32, 20, 20);

#define REGEX_MSG_LEN 256

bool compile_regex(const char *regexin, regexData *regex, char **message);
unsigned int get_num_regex(const enum regex_type regexid) __attribute__((pure));
int match_regex(const char *input, const DNSCacheData* dns_cache, const int clientID,
                const enum regex_type regexid, const bool regextest);
void allocate_regex_client_enabled(clientsData *client, const int clientID);
void reload_per_client_regex(clientsData *client);
void read_regex_from_database(void);

int regex_test(const bool debug_mode, const bool quiet, const char *domainin, const char *regexin);

#endif //REGEX_H
