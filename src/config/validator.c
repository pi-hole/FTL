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
// regex
#include "regex_r.h"
// parse_upstream_uri()
#include "dotdoh/upstream_uri.h"

// Stub validator for config types that need to dedicated validation as they can
// be tested by their type only (e.g., integers, strings, booleans, enums, etc.)
bool __attribute__((const)) validate_stub(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	return true;
}

// Validate the dns.hosts array
// Each entry needs to be a string in form "IP HOSTNAME"
bool validate_dns_hosts(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	if(!cJSON_IsArray(val->json))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not an array", key);
		return false;
	}

	// Walk the linked list directly: cJSON_GetArrayItem() is O(index) and
	// cJSON_GetArraySize() in the loop condition re-walks the whole list
	// every iteration, which made this loop O(n^2). item->next is O(1).
	int i = 0;
	for(cJSON *item = val->json != NULL ? val->json->child : NULL; item != NULL; item = item->next, i++)
	{

		// Check if it's a string
		if(!cJSON_IsString(item))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: not a string",
			         key, i);
			return false;
		}

		// Check if the string contains newline characters
		// Unlike the tokenizer below (which stops at the first '#'
		// comment), this scans the entire entry so an embedded newline
		// cannot be smuggled into the generated hosts file
		const unsigned int len = strlen(item->valuestring);
		for(unsigned int k = 0; k < len; k++)
		{
			if(item->valuestring[k] == '\n' || item->valuestring[k] == '\r')
			{
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: contains newline characters",
				         key, i);
				return false;
			}
		}

		// Check if it's in the form "IP[ \t]HOSTNAME"
		char *str = strdup(item->valuestring);
		char *tmp = str;
		
		// Strip leading spaces/tabs
		while(isspace((unsigned char)*tmp))
			tmp++;
		
		char *ip = strsep(&tmp, " \t");

		// Skip any extra whitespace/tabs after the IP
		while(tmp && isspace((unsigned char)*tmp))
			tmp++;

		if(!ip || !*ip)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: found no first element (\"%s\")",
			         key, i, item->valuestring);
			free(str);
			return false;
		}

		// Check if IP is valid
		struct in_addr addr;
		struct in6_addr addr6;
		if(inet_pton(AF_INET, ip, &addr) != 1 && inet_pton(AF_INET6, ip, &addr6) != 1)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: neither a valid IPv4 nor IPv6 address (\"%s\")",
			         key, i, ip);
			free(str);
			return false;
		}

		// Check if all hostnames are valid
		// The HOSTS format allows any number of space-separated
		// hostnames to come after the IP address
		unsigned int hosts = 0;
		char *host = NULL;
		while((host = strsep(&tmp, " \t")) != NULL)
		{
			// Skip extra whitespace/tabs
			while(isspace((unsigned char)*host))
				host++;

			// Skip this entry if it's empty after trimming
			// the whitespaces/tabs (due to multiple consecutive spaces)
			if(strlen(host) == 0)
				continue;

			// If this hostname is actually the start of a comment
			// (first letter is '#'), skip parsing the rest of the
			// entire line
			if(host[0] == '#')
				break;

			if(!valid_domain(host, strlen(host), false))
			{
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: invalid hostname (\"%s\")",
				         key, i, host);
				free(str);
				return false;
			}
			hosts++;
		}

		// Check if there is at least one hostname in this record
		if(hosts < 1)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: entry does not have at least one hostname (\"%s\")",
			         key, i, item->valuestring);
			free(str);
			return false;
		}

		free(str);
	}

	return true;
}

// Validate the dns.cnames array
// Each entry needs to be a string in form "<cname>,[<cname>,]<target>[,<TTL>]"
// Newline characters are not allowed in any of the entries
bool validate_dns_cnames(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	if(!cJSON_IsArray(val->json))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not an array", key);
		return false;
	}

	// Walk the linked list directly: cJSON_GetArrayItem() is O(index) and
	// cJSON_GetArraySize() in the loop condition re-walks the whole list
	// every iteration, which made this loop O(n^2). item->next is O(1).
	int i = 0;
	for(cJSON *item = val->json != NULL ? val->json->child : NULL; item != NULL; item = item->next, i++)
	{

		// Check if it's a string
		if(!cJSON_IsString(item))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: not a string", key, i);
			return false;
		}

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
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: contains an empty string at position %u", key, i, j);
				free(str);
				return false;
			}

			j++;
		}
		free(str);

		// Check if there are at least one cname and a target
		if(j < 2)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: not a valid CNAME definition (too few elements)", key, i);
			return false;
		}

		// Check if the string contains newline characters
		const unsigned int len = strlen(item->valuestring);
		for(unsigned int k = 0; k < len; k++)
		{
			if(item->valuestring[k] == '\n' || item->valuestring[k] == '\r')
			{
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: contains newline characters",
				         key, i);
				return false;
			}
		}
	}

	return true;
}

// Validate dns.domain string
// Accepts an empty string or a valid domain
bool validate_dns_domain(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if domain is valid
	if(strlen(val->s)!=0 && !valid_domain(val->s, strlen(val->s), false))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid domain (\"%s\")", key, val->s);
		return false;
	}

	return true;
}

// Validate IPs in CIDR notation
bool validate_cidr(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
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
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid IP in CIDR notation (\"%s\")", key, val->s);
		free(str);
		return false;
	}

	// Check if IP is valid
	struct in_addr addr;
	struct in6_addr addr6;
	int ip4 = 0, ip6 = 0;
	if(((ip4 = inet_pton(AF_INET, ip, &addr)) != 1) && ((ip6 = inet_pton(AF_INET6, ip, &addr6)) != 1))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid IPv4 nor IPv6 address (\"%s\")", key, ip);
		free(str);
		return false;
	}

	// Check if CIDR is valid
	if(cidr)
	{
		if(strlen(cidr) == 0)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: empty CIDR value", key);
			free(str);
			return false;
		}
		int cidr_int = atoi(cidr);
		if(ip4 && (cidr_int < 0 || cidr_int > 32))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid IPv4 CIDR (\"%s\")", key, cidr);
			free(str);
			return false;
		}
		else if(ip6 && (cidr_int < 0 || cidr_int > 128))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid IPv6 CIDR (\"%s\")", key, cidr);
			free(str);
			return false;
		}
	}

	free(str);
	return true;
}

// Validate a netmask
// The one-bits have to be contiguous and leading, anything else describes no
// subnet and has neither a network nor a broadcast address. 0.0.0.0 is allowed
// and means the netmask is determined from the interface
bool validate_netmask(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	const uint32_t hostmask = ~ntohl(val->in_addr.s_addr);
	if((hostmask & (hostmask + 1)) != 0)
	{
		char addr[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &val->in_addr, addr, sizeof(addr));
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid netmask (\"%s\"), the one-bits are not contiguous", key, addr);
		return false;
	}

	return true;
}

// Validate domain
bool validate_domain(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if domain is valid
	if(!valid_domain(val->s, strlen(val->s), false))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid domain (\"%s\")", key, val->s);
		return false;
	}

	return true;
}

// Validate file path
bool validate_filepath(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Accept every printable ASCII character. The range is not widened beyond
	// it because these paths are handed out as JSON, which has to be UTF-8, and
	// are written into the generated dnsmasq config, where a control character
	// would start a second directive. The comparison is explicit rather than
	// isprint(), which follows the locale FTL picks up from the environment
	for(unsigned int i = 0; i < strlen(val->s); i++)
	{
		const unsigned char c = val->s[i];
		if(c < 0x20 || c > 0x7E)
		{
			// The offending byte is named by position, not echoed - it
			// would break the line it is reported on
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not a valid file path (invalid character at position %u)", key, i);
			return false;
		}
	}

	return true;
}

// Validate a file path that needs to have both a slash at the beginning and at
// the end
bool validate_filepath_two_slash(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if the path starts and ends with a slash
	if(strlen(val->s) < 1 || val->s[0] != '/' || val->s[strlen(val->s) - 1] != '/')
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: file path does not start and end with a slash (\"%s\")", key, val->s);
		return false;
	}

	// Check if the path contains only valid characters
	return validate_filepath(val, key, err);
}

// Validate file path (empty allowed)
bool validate_filepath_empty(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Empty paths are allowed, e.g., to disable a feature like PCAP
	if(strlen(val->s) == 0)
		return true;

	// else:
	return validate_filepath(val, key, err);
}

// Whether two absolute paths are the same or one contains the other. Comparing
// at component boundaries keeps a sibling sharing a prefix ("/etc-backup")
// apart from a real parent ("/etc").
static bool paths_overlap(const char *a, const size_t alen, const char *b)
{
	const size_t blen = strlen(b);
	const size_t shorter = alen < blen ? alen : blen;

	if(strncmp(a, b, shorter) != 0)
		return false;

	return alen == blen ||
	       (alen > blen && a[blen] == '/') ||
	       (blen > alen && b[alen] == '/');
}

// Rewrite an absolute path into the one spelling of it we compare against:
// repeated slashes collapsed, "." segments dropped and ".." resolved, clamping
// at the root. Without this the comparisons below are defeated by writing the
// same directory differently - "/." and "//etc/pihole" name the root and the
// configuration directory just as well as "/" and "/etc/pihole" do.
//
// Resolution is lexical, so a symbolic link still points where it points. That
// is deliberate: realpath() needs the path to exist, which would stop a
// directory from being configured before it is created, and planting a link in
// the first place already requires access to the host.
//
// Returns the length written, or 0 if the path is not absolute or does not fit,
// which callers treat as "reject" rather than "skip the check".
#define NORMALIZED_PATH_LEN 4096
static size_t normalize_path(const char *path, char *out, const size_t outlen)
{
	if(path == NULL || path[0] != '/' || outlen < 2)
		return 0;

	size_t o = 0;
	out[o++] = '/';

	for(const char *p = path; *p != '\0';)
	{
		// Skip over the separator(s) before this segment
		while(*p == '/')
			p++;
		if(*p == '\0')
			break;

		const char *seg = p;
		while(*p != '\0' && *p != '/')
			p++;
		const size_t seglen = (size_t)(p - seg);

		// "." is the directory we are already in
		if(seglen == 1 && seg[0] == '.')
			continue;

		// ".." drops the segment before it, and does nothing at the root
		if(seglen == 2 && seg[0] == '.' && seg[1] == '.')
		{
			while(o > 1 && out[o - 1] != '/')
				o--;
			if(o > 1)
				o--;
			continue;
		}

		// Separator, unless we are still at the leading slash
		if(o > 1)
		{
			if(o + 1 >= outlen)
				return 0;
			out[o++] = '/';
		}

		if(o + seglen >= outlen)
			return 0;
		memcpy(out + o, seg, seglen);
		o += seglen;
	}

	out[o] = '\0';

	return o;
}

// The files Pi-hole writes and therefore must keep out of the document root.
// Their content follows from what clients send - logged requests, resolved
// names, imported settings - so serving them hands that straight back out, and a
// name matching the Lua server-page pattern makes the web server evaluate them
// rather than serve them.
#define WRITTEN_FILES(conf) { \
	&(conf).files.log.ftl, &(conf).files.log.dnsmasq, &(conf).files.log.webserver, \
	&(conf).files.database, &(conf).files.tmp_db, &(conf).files.gravity, \
	&(conf).files.gravity_tmp, &(conf).files.pcap }

// Check the path relationships of a complete configuration.
//
// The per-item validators can only compare a new value against the values
// currently in effect, which is not enough when several of them change together:
// a request moving the document root and a log file below it in one go passes
// both individual checks. Config also reaches FTL through the Teleporter, which
// parses a whole file at once and never ran the per-item validators at all. This
// runs over the resulting configuration instead and is the authoritative check -
// call it before putting a new configuration in place.
bool validate_config_paths(struct config *conf, char err[VALIDATOR_ERRBUF_LEN],
                           struct conf_item **offender)
{
	if(offender != NULL)
		*offender = &conf->webserver.paths.webroot;

	const char *webroot = conf->webserver.paths.webroot.v.s;
	if(webroot == NULL || webroot[0] != '/')
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: must be an absolute path",
		         conf->webserver.paths.webroot.k);
		return false;
	}

	char wnorm[NORMALIZED_PATH_LEN];
	const size_t wlen = normalize_path(webroot, wnorm, sizeof(wnorm));
	if(wlen == 0 || wlen == 1 || paths_overlap(wnorm, wlen, CONFIG_DIR))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN,
		         "%s: must not be \"/\" or overlap Pi-hole's configuration directory (\"%s\")",
		         conf->webserver.paths.webroot.k, CONFIG_DIR);
		return false;
	}

	struct conf_item *written[] = WRITTEN_FILES(*conf);
	for(size_t i = 0; i < ArraySize(written); i++)
	{
		const char *path = written[i]->v.s;
		if(path == NULL || path[0] == '\0')
			continue;

		// A relative path is resolved from the working directory and cannot
		// be compared with the document root
		if(path[0] != '/')
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s (\"%s\") must be an absolute path",
			         written[i]->k, path);
			if(offender != NULL)
				*offender = written[i];
			return false;
		}

		char pnorm[NORMALIZED_PATH_LEN];
		if(normalize_path(path, pnorm, sizeof(pnorm)) == 0 ||
		   paths_overlap(wnorm, wlen, pnorm))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN,
			         "%s (\"%s\") must not be inside %s (\"%s\")",
			         written[i]->k, path, conf->webserver.paths.webroot.k, webroot);
			if(offender != NULL)
				*offender = written[i];
			return false;
		}
	}

	return true;
}


// Validate the web server's document root.
//
// Every file below this directory can be requested over the network once
// webserver.serve_all is enabled, and files outside the web home are served
// without authentication. A document root spanning Pi-hole's own configuration
// would therefore hand out the API password hash, the TLS private key and the
// databases; "/" would hand out everything the pihole user can open.
//
// Whether it comes to span a file Pi-hole writes depends on a second item, so
// that half is checked in validate_config_paths() on the assembled config.
bool validate_webroot(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Regular file-path validation first
	if(!validate_filepath(val, key, err))
		return false;

	if(val->s[0] != '/')
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: must be an absolute path (\"%s\")", key, val->s);
		return false;
	}

	char norm[NORMALIZED_PATH_LEN];
	const size_t len = normalize_path(val->s, norm, sizeof(norm));

	if(len == 0 || len == 1 || paths_overlap(norm, len, CONFIG_DIR))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN,
		         "%s: must not be \"/\" or overlap Pi-hole's configuration directory (\"%s\")",
		         key, CONFIG_DIR);
		return false;
	}

	return true;
}

// Validate a single regular expression
static bool validate_regex(const char *regex, char err[VALIDATOR_ERRBUF_LEN])
{
	// Compile regex
	regex_t preg = { 0 };
	const int ret = regcomp(&preg, regex, REG_EXTENDED);
	if(ret != 0)
	{
		regerror(ret, &preg, err, VALIDATOR_ERRBUF_LEN);
		regfree(&preg);
		return false;
	}

	// Free regex
	regfree(&preg);

	return true;
}

// Validate array of regexes
bool validate_regex_array(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	if(val == NULL || !cJSON_IsArray(val->json))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not an array", key);
		return false;
	}

	// Walk the linked list directly: cJSON_GetArrayItem() is O(index) and
	// cJSON_GetArraySize() in the loop condition re-walks the whole list
	// every iteration, which made this loop O(n^2). item->next is O(1).
	int i = 0;
	for(cJSON *item = val->json != NULL ? val->json->child : NULL; item != NULL; item = item->next, i++)
	{

		// Check if it's a string
		if(!cJSON_IsString(item))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: not a string",
			         key, i);
			return false;
		}

		// Check if it's a valid regex
		char errbuf[VALIDATOR_ERRBUF_LEN] = { 0 };
		if(!validate_regex(item->valuestring, errbuf))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: not a valid regex (\"%s\"): %s",
			         key, i, item->valuestring, errbuf);
			return false;
		}
	}

	return true;
}

// Validate dns.revServers array
// Each entry has to be of form "<enabled>,<ip-address>[/<prefix-len>],<server>[#<port>][,<domain>"]
bool validate_dns_revServers(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if it's an array
	if(!cJSON_IsArray(val->json))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not an array", key);
		return false;
	}

	// Iterate over all array items
	// Walk the linked list directly: cJSON_GetArrayItem() is O(index) and
	// cJSON_GetArraySize() in the loop condition re-walks the whole list
	// every iteration, which made this loop O(n^2). item->next is O(1).
	int i = 0;
	for(cJSON *item = val->json != NULL ? val->json->child : NULL; item != NULL; item = item->next, i++)
	{

		// Check if it's a string
		if(!cJSON_IsString(item))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: not a string", key, i);
			return false;
		}

		// Check if it's in the form "<enabled>,<ip-address>[/<prefix-len>],<server>[#<port>][,<domain>]"
		// Mandatory elements are: <enabled>, <ip-address>, and <server>
		// Optional elements are: [/<prefix-len>] and [#<port>], and [,<domain>]
		char *str = strdup(item->valuestring);
		char *tmp = str, *s = NULL;
		unsigned int e = 0;

		while((s = strsep(&tmp, ",")) != NULL)
		{
			// Check if it's a valid element
			if(strlen(s) == 0)
			{
				// Contains an empty string
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: contains two commas following each other immediately", key, i);
				free(str);
				return false;
			}
			// Check if the zeroth element is a boolean
			if(e == 0)
			{
				if(strcmp(s, "true") != 0 && strcmp(s, "false") != 0)
				{
					snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: <enabled> not a boolean (\"%s\")", key, i, s);
					free(str);
					return false;
				}
			}
			// Check if the first element is an IP address
			else if(e == 1)
			{
				// Extract IP and prefix length (if present)
				char *ip = strsep(&s, "/");
				char *prefix = strsep(&s, "/");
				if(strlen(ip) == 0)
				{
					snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: <ip-address> empty", key, i);
					free(str);
					return false;
				}

				// Check if IP is valid
				struct in_addr addr = { 0 };
				struct in6_addr addr6 = { 0 };
				const bool ipv4 = inet_pton(AF_INET, ip, &addr) == 1;
				const bool ipv6 = inet_pton(AF_INET6, ip, &addr6) == 1;
				if(!ipv4 && !ipv6)
				{
					snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: <ip-address> neither a valid IPv4 nor IPv6 address (\"%s\")", key, i, ip);
					free(str);
					return false;
				}

				// Check if prefix length is valid (if present)
				if(prefix != NULL)
				{
					if(strlen(prefix) == 0)
					{
						snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: <prefix-len> empty", key, i);
						free(str);
						return false;
					}
					const int prefix_int = atoi(prefix);
					if(prefix_int < 0 || (ipv4 && prefix_int > 32) || (ipv6 && prefix_int > 128))
					{
						snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: <prefix-len> not a valid %sprefix length (\"%s\")",
						         key, i, ipv4 ? "IPv4 " : ipv6 ? "IPv6 " : "", prefix);
						free(str);
						return false;
					}
				}
			}
			// Check if the second element is a valid server (either an IP address or a domain, optionally with a port)
			else if(e == 2)
			{
				// Extract server and port (if present)
				char *server = strsep(&s, "#");
				char *port = strsep(&s, "#");
				if(strlen(server) == 0)
				{
					snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: <server> empty", key, i);
					free(str);
					return false;
				}

				struct in_addr addr = { 0 };
				struct in6_addr addr6 = { 0 };
				const bool server_ipv4 = inet_pton(AF_INET, server, &addr) == 1;
				const bool server_ipv6 = inet_pton(AF_INET6, server, &addr6) == 1;
				const bool server_domain = valid_domain(server, strlen(server), false);

				// Check if server is valid
				if(!server_ipv4 && !server_ipv6 && !server_domain)
				{
					snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: <server> neither a valid domain nor an IPv4 or IPv6 address (\"%s\")", key, i, server);
					free(str);
					return false;
				}

				// Check if port is valid (if present)
				if(port != NULL)
				{
					if(strlen(port) == 0)
					{
						snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: specified server <port> empty", key, i);
						free(str);
						return false;
					}
					const int port_int = atoi(port);
					if(port_int < 0 || port_int > 65535)
					{
						snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: server <port> not a valid port (\"%s\")", key, i, port);
						free(str);
						return false;
					}
				}
			}
			// Check if the third element is a valid domain
			else if(e == 3)
			{
				if(!valid_domain(s, strlen(s), false))
				{
					snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: specified <domain> not a valid domain (\"%s\")", key, i, s);
					free(str);
					return false;
				}
			}
			// Check if there are too many elements
			else
			{
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: too many elements", key, i);
				free(str);
				return false;
			}

			// Increment element counter
			e++;
		}

		// Check if there are all required elements
		if(e < 3)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: entry does not have all required elements (<enabled>,<ip-address>[/<prefix-len>],<server>[#<port>][,<domain>])", key, i);
			free(str);
			return false;
		}

		// Ensure there are no newline characters in the entry
		const unsigned int len = strlen(item->valuestring);
		for(unsigned int k = 0; k < len; k++)
		{
			if(item->valuestring[k] == '\n' || item->valuestring[k] == '\r')
			{
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: contains newline characters",
				         key, i);
				free(str);
				return false;
			}
		}
	}

	// Return success
	return true;
}

bool validate_ui_min_7_or_0(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	if(val->ui < 7 && val->ui != 0)
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: cannot be lower than 7", key);
		return false;
	}

	return true;
}

// Sanitize the dns.hosts array
// This function normalizes whitespace formatting in the dns.hosts entries
// to ensure consistent formatting when saving to pihole.toml
void sanitize_dns_hosts(union conf_value *val)
{
	if(!cJSON_IsArray(val->json))
		return;

	// Walk the linked list directly: cJSON_GetArrayItem() is O(index) and
	// cJSON_GetArraySize() in the loop condition re-walks the whole list
	// every iteration, which made this loop O(n^2). item->next is O(1).
	for(cJSON *item = val->json != NULL ? val->json->child : NULL; item != NULL; item = item->next)
	{

		// Check if it's a string
		if(!cJSON_IsString(item))
			continue;

		// Parse and sanitize the entry
		char *str = strdup(item->valuestring);
		char *tmp = str;
		
		// Strip leading spaces/tabs
		while(isspace((unsigned char)*tmp))
			tmp++;
		
		// If the string is empty or starts with a comment, skip it
		if(strlen(tmp) == 0 || tmp[0] == '#')
		{
			free(str);
			continue;
		}
		
		char *ip = strsep(&tmp, " \t");

		// Skip any extra whitespace/tabs after the IP
		while(tmp && isspace((unsigned char)*tmp))
			tmp++;

		// If no IP found or IP is empty, skip this entry
		if(!ip || !*ip)
		{
			free(str);
			continue;
		}

		// Build the sanitized string (allocate based on original string size)
		const size_t original_len = strlen(item->valuestring);
		char *sanitized = calloc(original_len + 1, sizeof(char));
		if(sanitized == NULL)
		{
			free(str);
			continue;
		}
		strcpy(sanitized, ip);
		size_t current_len = strlen(ip);
		
		// Process hostnames
		char *host = NULL;
		while(tmp && (host = strsep(&tmp, " \t")) != NULL)
		{
			// Skip extra whitespace/tabs
			while(isspace((unsigned char)*host))
				host++;

			// Skip empty entries
			if(strlen(host) == 0)
				continue;

			// If this hostname starts with a comment, add it and the rest to the sanitized string, then stop processing
			if(host[0] == '#')
			{
				// Add the comment part with single space separator
				if(current_len < original_len)
				{
					sanitized[current_len++] = ' ';
				}
				size_t host_len = strlen(host);
				if(current_len + host_len <= original_len)
				{
					strcpy(sanitized + current_len, host);
					current_len += host_len;
				}
				
				// Add any remaining content after this comment token
				if(tmp && strlen(tmp) > 0)
				{
					size_t tmp_len = strlen(tmp);
					if(current_len < original_len)
					{
						sanitized[current_len++] = ' ';
					}
					if(current_len + tmp_len <= original_len)
					{
						strcpy(sanitized + current_len, tmp);
						current_len += tmp_len;
					}
				}
				break;
			}

			// Add hostname to sanitized string with single space separator
			if(current_len < original_len)
			{
				sanitized[current_len++] = ' ';
			}
			size_t host_len = strlen(host);
			if(current_len + host_len <= original_len)
			{
				strcpy(sanitized + current_len, host);
				current_len += host_len;
			}
		}

		// Update the JSON item with the sanitized string
		cJSON_SetValuestring(item, sanitized);

		free(sanitized);
		free(str);
	}
}

// Validate a single domain or IP address
bool validate_dns_domain_or_ip(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	// Check if it's a valid domain
	if(valid_domain(val->s, strlen(val->s), false))
	{
		return true;
	}

	// Check if IP is valid
	struct in_addr addr;
	struct in6_addr addr6;
	int ip4 = 0, ip6 = 0;
	if((ip4 = inet_pton(AF_INET, val->s, &addr) == 1) || (ip6 = inet_pton(AF_INET6, val->s, &addr6)) == 1)
	{
		return true;
	}

	// If neither, return an error
	snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: neither a valid domain nor IP address", key);
	return false;
}

bool validate_str_no_newline(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	if(val->s == NULL)
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: null string", key);
		return false;
	}

	// Check if the string contains newline characters
	const unsigned int len = strlen(val->s);
	for(unsigned int i = 0; i < len; i++)
	{
		if(val->s[i] == '\n' || val->s[i] == '\r')
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: contains newline characters", key);
			return false;
		}
	}

	return true;
}

// Validator for dns.upstreams. Enforces the same array/string/newline rules as
// validate_array_no_newline() and, in addition, requires every encrypted entry
// (tls:// or https://) to parse as a valid encrypted-upstream URI. Plaintext
// entries are left untouched - dnsmasq validates those itself.
bool validate_upstreams(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	if(!validate_array_no_newline(val, key, err))
		return false;

	int i = 0;
	for(cJSON *item = val->json != NULL ? val->json->child : NULL; item != NULL; item = item->next, i++)
	{
		const char *s = item->valuestring;
		if(s == NULL)
			continue;

		// Anything carrying a URI scheme ("://") must be a supported encrypted
		// upstream (tls:// or https://) that parses cleanly. A plaintext server
		// specification handled downstream by dnsmasq never contains "://", so
		// an entry that does but is not a valid encrypted URI (e.g. http://,
		// ftp:// or a malformed tls://) is rejected here rather than being
		// written into dnsmasq.conf and breaking DNS startup.
		if(strstr(s, "://") != NULL)
		{
			struct upstream_uri u;
			if(!parse_upstream_uri(s, &u) || u.type == UST_PLAIN)
			{
				snprintf(err, VALIDATOR_ERRBUF_LEN,
				         "%s[%d]: invalid encrypted upstream URI", key, i);
				return false;
			}
		}
	}

	return true;
}

bool validate_array_no_newline(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN])
{
	if(!cJSON_IsArray(val->json))
	{
		snprintf(err, VALIDATOR_ERRBUF_LEN, "%s: not an array", key);
		return false;
	}

	// Walk the linked list directly: cJSON_GetArrayItem() is O(index) and
	// cJSON_GetArraySize() in the loop condition re-walks the whole list
	// every iteration, which made this loop O(n^2). item->next is O(1).
	int i = 0;
	for(cJSON *item = val->json != NULL ? val->json->child : NULL; item != NULL; item = item->next, i++)
	{

		// Check if it's a string
		if(!cJSON_IsString(item))
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: not a string",
			         key, i);
			return false;
		}

		if(item->valuestring == NULL)
		{
			snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: null string",
			         key, i);
			return false;
		}

		// Check if the string contains newline characters
		const unsigned int len = strlen(item->valuestring);
		for(unsigned int j = 0; j < len; j++)
		{
			if(item->valuestring[j] == '\n' || item->valuestring[j] == '\r')
			{
				snprintf(err, VALIDATOR_ERRBUF_LEN, "%s[%d]: contains newline characters",
				         key, i);
				return false;
			}
		}
	}

	return true;
}

// Reset offending items until the path rules hold.
//
// Resetting one item can expose a conflict with another, so a single pass is
// not enough. Each pass returns the item the check names to its default, and
// the defaults do not conflict, so every item is reset at most once.
void resolve_config_paths(struct config *conf)
{
	struct conf_item *written[] = WRITTEN_FILES(*conf);
	for(size_t pass = 0; pass <= ArraySize(written); pass++)
	{
		struct conf_item *offender = NULL;
		char err[VALIDATOR_ERRBUF_LEN] = { 0 };
		if(validate_config_paths(conf, err, &offender))
			return;

		log_err("Inconsistent configuration: %s", err);

		// Resetting a file that is at its default already changes
		// nothing, the document root has to give way then
		if(compare_config_item(offender->t, &offender->v, &offender->d))
			offender = &conf->webserver.paths.webroot;

		log_err("----> %s has been reset to its default value", offender->k);
		reset_config_default(offender);
	}
}
