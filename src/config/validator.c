/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config validation routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "validator.h"
#include "log.h"

// Validate the dns.hosts array
// Each entry needs to be a string in form "IP HOSTNAME"
bool validate_dns_hosts(union conf_value *val, char err[VALIDATOR_ERRBUF_LEN])
{
	if(!cJSON_IsArray(val->json))
	{
		strncat(err, "Not an array", VALIDATOR_ERRBUF_LEN);
		return false;
	}

	for(int i = 1; i <= cJSON_GetArraySize(val->json); i++)
	{
		// Get array item
		cJSON *item = cJSON_GetArrayItem(val->json, i-1);

		// Check if it's a string
		if(!cJSON_IsString(item))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not a string", i, get_ordinal_suffix(i));
			return false;
		}

		// Check if it's in the form "IP HOSTNAME"
		char *str = strdup(item->valuestring);
		char *tmp = str;
		char *ip = strsep(&tmp, " ");
		char *host = strsep(&tmp, " ");

		if(!ip || !host || !*ip || !*host)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not in the form \"IP HOSTNAME\" (\"%s\")", i, get_ordinal_suffix(i), str);
			free(str);
			return false;
		}

		// Check if IP is valid
		struct in_addr addr;
		struct in6_addr addr6;
		if(inet_pton(AF_INET, ip, &addr) != 1 && inet_pton(AF_INET6, ip, &addr6) != 1)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is neither a valid IPv4 nor IPv6 address (\"%s\")", i, get_ordinal_suffix(i), ip);
			free(str);
			return false;
		}

		// Check if hostname is valid
		if(strlen(host) < 1 || strlen(host) > 128)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not a valid hostname (\"%s\")", i, get_ordinal_suffix(i), host);
			free(str);
			return false;
		}

		free(str);
	}

	return true;
}

// Validate the dns.cnames array
// Each entry needs to be a string in form "<cname>,[<cname>,]<target>[,<TTL>]"
bool validate_dns_cnames(union conf_value *val, char err[VALIDATOR_ERRBUF_LEN])
{
	if(!cJSON_IsArray(val->json))
	{
		strncat(err, "Not an array", VALIDATOR_ERRBUF_LEN);
		return false;
	}

	for(int i = 1; i <= cJSON_GetArraySize(val->json); i++)
	{
		// Get array item
		cJSON *item = cJSON_GetArrayItem(val->json, i-1);

		// Check if it's a string
		if(!cJSON_IsString(item))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not a string", i, get_ordinal_suffix(i));
			return false;
		}

		// Count the number of elements in the string
		unsigned int elements = 1;
		for(unsigned int j = 0; j < strlen(item->valuestring); j++)
			if(item->valuestring[j] == ',')
				elements++;

		// Check if it's in the form "<cname>,[<cnameX>,]<target>[,<TTL>]"
		// <cnameX> is optional and may be repeated
		char *str = strdup(item->valuestring);
		char *tmp = str, *s = NULL;
		unsigned int j = 0;

		while((s = strsep(&tmp, ",")) != NULL)
		{
			// Check if it's a valid cname
			if(strlen(s) == 0)
			{
				// Contains an empty string
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element contains an empty string at position %u", i, get_ordinal_suffix(i), j);
				free(str);
				return false;
			}

			j++;
		}
		free(str);

		// Check if there are at least one cname and a target
		if(j < 2)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not a valid CNAME definition", i, get_ordinal_suffix(i));
			return false;
		}
	}

	return true;
}