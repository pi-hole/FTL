#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "../src/dnsmasq/cache_exclude.h"

static void test_ipv4_cidr_match(void)
{
	struct cache_exclude_cidr cidr;
	struct in_addr inside;
	struct in_addr outside;

	assert(cache_exclude_cidr_parse("198.18.0.0/15", &cidr));
	assert(inet_pton(AF_INET, "198.18.4.112", &inside) == 1);
	assert(inet_pton(AF_INET, "8.8.8.8", &outside) == 1);

	assert(cache_exclude_cidr_matches(&cidr, AF_INET, &inside));
	assert(!cache_exclude_cidr_matches(&cidr, AF_INET, &outside));
}

static void test_ipv6_cidr_match(void)
{
	struct cache_exclude_cidr cidr;
	struct in6_addr inside;
	struct in6_addr outside;

	assert(cache_exclude_cidr_parse("fd00::/8", &cidr));
	assert(inet_pton(AF_INET6, "fd00::1234", &inside) == 1);
	assert(inet_pton(AF_INET6, "2001:4860:4860::8888", &outside) == 1);

	assert(cache_exclude_cidr_matches(&cidr, AF_INET6, &inside));
	assert(!cache_exclude_cidr_matches(&cidr, AF_INET6, &outside));
}

static void test_invalid_cidrs_are_rejected(void)
{
	struct cache_exclude_cidr cidr;

	assert(!cache_exclude_cidr_parse("198.18.0.0/33", &cidr));
	assert(!cache_exclude_cidr_parse("fd00::/129", &cidr));
	assert(!cache_exclude_cidr_parse("not-a-cidr", &cidr));
}

int main(void)
{
	test_ipv4_cidr_match();
	test_ipv6_cidr_match();
	test_invalid_cidrs_are_rejected();
	puts("cache_exclude_cidr_test: ok");
	return 0;
}
