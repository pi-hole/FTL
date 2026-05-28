#include "cache_exclude.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>

static void mask_address(uint8_t *addr, size_t len, unsigned int prefix)
{
	const unsigned int full_bytes = prefix / 8;
	const unsigned int remaining_bits = prefix % 8;

	if(full_bytes < len && remaining_bits > 0)
		addr[full_bytes] &= (uint8_t)(0xffu << (8u - remaining_bits));

	for(size_t i = full_bytes + (remaining_bits > 0 ? 1u : 0u); i < len; i++)
		addr[i] = 0;
}

bool cache_exclude_cidr_parse(const char *input, struct cache_exclude_cidr *cidr)
{
	char addrbuf[INET6_ADDRSTRLEN];
	const char *slash = NULL;
	unsigned long prefix = 0;
	size_t addrlen = 0;
	int family = AF_UNSPEC;

	if(input == NULL || cidr == NULL)
		return false;

	slash = strchr(input, '/');
	if(slash == NULL || slash == input || slash[1] == '\0')
		return false;

	addrlen = (size_t)(slash - input);
	if(addrlen >= sizeof(addrbuf))
		return false;

	for(const char *p = slash + 1; *p != '\0'; p++)
	{
		if(!isdigit((unsigned char)*p))
			return false;
		prefix = prefix * 10u + (unsigned long)(*p - '0');
		if(prefix > 128u)
			return false;
	}

	memcpy(addrbuf, input, addrlen);
	addrbuf[addrlen] = '\0';
	memset(cidr, 0, sizeof(*cidr));

	if(inet_pton(AF_INET, addrbuf, cidr->addr) == 1)
		family = AF_INET;
	else if(inet_pton(AF_INET6, addrbuf, cidr->addr) == 1)
		family = AF_INET6;
	else
		return false;

	if((family == AF_INET && prefix > 32u) ||
	   (family == AF_INET6 && prefix > 128u))
		return false;

	cidr->family = family;
	cidr->prefix = (unsigned int)prefix;
	mask_address(cidr->addr, family == AF_INET ? 4u : 16u, cidr->prefix);
	return true;
}

bool cache_exclude_cidr_matches(const struct cache_exclude_cidr *cidr, int family, const void *addr)
{
	uint8_t candidate[16];
	size_t len = 0;
	const unsigned int full_bytes = cidr != NULL ? cidr->prefix / 8 : 0;
	const unsigned int remaining_bits = cidr != NULL ? cidr->prefix % 8 : 0;

	if(cidr == NULL || addr == NULL || cidr->family != family)
		return false;

	len = family == AF_INET ? 4u : 16u;
	memcpy(candidate, addr, len);
	mask_address(candidate, len, cidr->prefix);

	if(full_bytes > 0 && memcmp(candidate, cidr->addr, full_bytes) != 0)
		return false;

	if(remaining_bits > 0 && candidate[full_bytes] != cidr->addr[full_bytes])
		return false;

	return true;
}

bool cache_exclude_address_matches_json(cJSON *cidrs, int family, const void *addr)
{
	cJSON *item = NULL;

	if(!cJSON_IsArray(cidrs))
		return false;

	cJSON_ArrayForEach(item, cidrs)
	{
		struct cache_exclude_cidr cidr;

		if(!cJSON_IsString(item) || item->valuestring == NULL)
			continue;

		if(cache_exclude_cidr_parse(item->valuestring, &cidr) &&
		   cache_exclude_cidr_matches(&cidr, family, addr))
			return true;
	}

	return false;
}
