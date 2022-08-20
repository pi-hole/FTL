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

#include <netinet/in.h>

typedef struct {
	bool available :1;
	struct {
		bool inverted :1;
		bool query_type_inverted :1;
		bool custom_ip4 :1;
		bool custom_ip6 :1;
		enum query_types query_type;
		enum reply_type reply;
		struct in_addr addr4;
		struct in6_addr addr6;
	} ext;
	int database_id;
	char *string;
	regex_t regex;
} regexData;

unsigned int get_num_regex(const enum regex_type regexid) __attribute__((pure));
bool in_regex(const char *domain, DNSCacheData *dns_cache, const int clientID, const enum regex_type regexid);
void allocate_regex_client_enabled(clientsData *client, const int clientID);
void reload_per_client_regex(clientsData *client);
void read_regex_from_database(void);
bool regex_get_redirect(const int regexID, struct in_addr *addr4, struct in6_addr *addr6);

int regex_test(const bool debug_mode, const bool quiet, const char *domainin, const char *regexin);

#endif //REGEX_H
