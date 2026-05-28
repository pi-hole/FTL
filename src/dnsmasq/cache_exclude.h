#ifndef CACHE_EXCLUDE_H
#define CACHE_EXCLUDE_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "webserver/cJSON/cJSON.h"

struct cache_exclude_cidr {
	int family;
	uint8_t addr[16];
	unsigned int prefix;
};

bool cache_exclude_cidr_parse(const char *input, struct cache_exclude_cidr *cidr);
bool cache_exclude_cidr_matches(const struct cache_exclude_cidr *cidr, int family, const void *addr);
bool cache_exclude_address_matches_json(cJSON *cidrs, int family, const void *addr);

#endif
