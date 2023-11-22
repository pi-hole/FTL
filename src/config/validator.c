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
// valid_domain()
#include "tools/gravity-parseList.h"

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
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not a string",
			         i, get_ordinal_suffix(i));
			return false;
		}

		// Check if it's in the form "IP HOSTNAME"
		char *str = strdup(item->valuestring);
		char *tmp = str;
		char *ip = strsep(&tmp, " ");
		char *host = strsep(&tmp, " ");
		char *tail = strsep(&tmp, " ");

		if(!ip || !host || !*ip || !*host || tail)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not in the form \"IP HOSTNAME\" (\"%s\")",
			         i, get_ordinal_suffix(i), item->valuestring);
			free(str);
			return false;
		}

		// Check if IP is valid
		struct in_addr addr;
		struct in6_addr addr6;
		if(inet_pton(AF_INET, ip, &addr) != 1 && inet_pton(AF_INET6, ip, &addr6) != 1)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is neither a valid IPv4 nor IPv6 address (\"%s\")",
			         i, get_ordinal_suffix(i), ip);
			free(str);
			return false;
		}

		// Check if hostname is valid
		if(strlen(host) < 1 || strlen(host) > 128)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%d%s element is not a valid hostname (\"%s\")",
			         i, get_ordinal_suffix(i), host);
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

// Validate IPs in CIDR notation
bool validate_cidr(union conf_value *val, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if it's a valid CIDR
	char *str = strdup(val->s);
	char *tmp = str;
	char *ip = strsep(&tmp, "/");
	char *cidr = strsep(&tmp, "/");
	char *tail = strsep(&tmp, "/");

	// Check if there is an IP and no tail
	if(!ip || !*ip || tail)
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid IP in CIDR notation (\"%s\")", val->s);
		free(str);
		return false;
	}

	// Check if IP is valid
	struct in_addr addr;
	struct in6_addr addr6;
	int ip4 = 0, ip6 = 0;
	if((ip4 = inet_pton(AF_INET, ip, &addr) != 1) && (ip6 = inet_pton(AF_INET6, ip, &addr6)) != 1)
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid IPv4 nor IPv6 address (\"%s\")", ip);
		free(str);
		return false;
	}

	// Check if CIDR is valid
	if(cidr)
	{
		if(strlen(cidr) == 0)
		{
			strncat(err, "Empty CIDR value", VALIDATOR_ERRBUF_LEN);
			free(str);
			return false;
		}
		int cidr_int = atoi(cidr);
		if(ip4 && (cidr_int < 0 || cidr_int > 32))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid IPv4 CIDR (\"%s\")", cidr);
			free(str);
			return false;
		}
		else if(ip6 && (cidr_int < 0 || cidr_int > 128))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid IPv6 CIDR (\"%s\")", cidr);
			free(str);
			return false;
		}
	}

	free(str);
	return true;
}

// Validate IP address optionally followed by a port (separator is "#")
bool validate_ip_port(union conf_value *val, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if it's a valid IP
	char *str = strdup(val->s);
	char *tmp = str;
	char *ip = strsep(&tmp, "#");
	char *port = strsep(&tmp, "#");
	char *tail = strsep(&tmp, "#");

	// Check if there is an IP and no tail
	if(!ip || !*ip || tail)
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid IP (\"%s\")", val->s);
		free(str);
		return false;
	}

	// Check if IP is valid
	struct in_addr addr;
	struct in6_addr addr6;
	int ip4 = 0, ip6 = 0;
	if((ip4 = inet_pton(AF_INET, ip, &addr) != 1) && (ip6 = inet_pton(AF_INET6, ip, &addr6)) != 1)
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid IPv4 nor IPv6 address (\"%s\")", ip);
		free(str);
		return false;
	}

	// Check if port is valid
	if(port)
	{
		if(strlen(port) == 0)
		{
			strncat(err, "Empty port value", VALIDATOR_ERRBUF_LEN);
			free(str);
			return false;
		}
		int port_int = atoi(port);
		if(port_int < 0 || port_int > 65535)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid port (\"%s\")", port);
			free(str);
			return false;
		}
	}

	free(str);
	return true;
}

// Validate domain
bool validate_domain(union conf_value *val, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if domain is valid
	if(!valid_domain(val->s, strlen(val->s), false))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid domain (\"%s\")", val->s);
		return false;
	}

	return true;
}

// Validate file path
bool validate_filepath(union conf_value *val, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if the path contains only valid characters
	for(unsigned int i = 0; i < strlen(val->s); i++)
	{
		if(!isalnum(val->s[i]) && val->s[i] != '/' && val->s[i] != '.' && val->s[i] != '-' && val->s[i] != '_' && val->s[i] != ' ')
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "Not a valid file path (\"%s\")", val->s);
			return false;
		}
	}

	return true;
}

// Validate file path (empty allowed)
bool validate_filepath_empty(union conf_value *val, char err[VALIDATOR_ERRBUF_LEN])
{
	// Empty paths are allowed, e.g., to disable a feature like PCAP
	if(strlen(val->s) == 0)
		return true;

	// else:
	return validate_filepath(val, err);
}