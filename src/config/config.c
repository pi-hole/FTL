/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "config/config.h"
#include "config/toml_reader.h"
#include "config/toml_writer.h"
#include "setupVars.h"
#include "log.h"
#include "log.h"
// readFTLlegacy()
#include "legacy_reader.h"
// file_exists()
#include "files.h"
// write_dnsmasq_config()
#include "config/dnsmasq_config.h"

struct config config = { 0 };

void set_all_debug(const bool status)
{
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(&config, i);

		// Skip config entries whose path's are not starting in "debug."
		if(strcmp("debug", conf_item->p[0]) != 0)
			continue;

		// Set status
		conf_item->v.b = status;
	}

	// Update debug flags
	set_debug_flags();
}

// Extract and store key from full path
char **gen_config_path(const char *pathin, const char delim)
{
	char *path = (char*)pathin;
	char *saveptr = path;

	// Allocate memory for the path elements
	char **paths = calloc(MAX_CONFIG_PATH_DEPTH, sizeof(char*));

	// Sanity check
	if(!pathin)
	{
		log_err("Config path is empty");
		return paths;
	}

	size_t pathlen = 0;
	// Extract all path elements
	while(*path != '\0')
	{
		// Advance to either the next delimiter
		// But only until the end of the string
		while(*path != delim && *path != '\0')
			path++;

		// Get length of the extracted string
		size_t len = path - saveptr;
		// Create a private copy of this element in the chain of elements
		paths[pathlen] = calloc(len + 1, sizeof(char));
		// No need to NULL-terminate, strncpy does this for us
		strncpy(paths[pathlen], saveptr, len);

		// Did we reach the end of the string?
		if(*path == '\0')
			break;

		// Advance to next character
		saveptr = ++path;
		// Advance to next path element
		pathlen++;

		// Safetly measure: Exit if this path is too deep
		if(pathlen > MAX_CONFIG_PATH_DEPTH-1)
			break;
	}

	return paths;
}

void free_config_path(char **paths)
{
	if(paths == NULL)
		return;

	for(unsigned int i = 0; i < MAX_CONFIG_PATH_DEPTH; i++)
		if(paths[i] != NULL)
			free(paths[i]);
}

bool __attribute__ ((pure)) check_paths_equal(char **paths1, char **paths2, unsigned int max_level)
{
	if(paths1 == NULL || paths2 == NULL)
		return false;

	for(unsigned int i = 0; i < MAX_CONFIG_PATH_DEPTH; i++)
	{
		if(i > 0 && paths1[i] == NULL && paths2[i] == NULL)
		{
			// Exact match so far and we reached the end, e.g.
			// config.dnsmasq.upstreams.(null) <-> config.dnsmasq.upstreams.(null)
			return true;
		}

		if(i > max_level)
		{
			// Reached end of maximum to inspect level (to get children)
			return true;
		}

		if(paths1[i] == NULL || paths2[i] == NULL || strcmp(paths1[i],paths2[i]) != 0)
		{
			// One of the paths is shorter than the other or one of the elements
			// doesn't match
			return false;
		}
	}
	return true;
}
struct conf_item *get_conf_item(struct config *conf, const unsigned int n)
{
	// Sanity check
	if(n > CONFIG_ELEMENTS-1)
	{
		log_err("Config item with index %u requested but we have only %u elements", n, (unsigned int)CONFIG_ELEMENTS-1);
		return NULL;
	}

	// Return n-th config element
	return (void*)conf + n*sizeof(struct conf_item);
}

struct conf_item *get_debug_item(const enum debug_flag debug)
{
	// Sanity check
	if(debug > DEBUG_MAX-1)
	{
		log_err("Debug config item with index %u requested but we have only %u debug elements", debug, DEBUG_MAX-1);
		return NULL;
	}

	// Return n-th config element
	return (void*)&config.debug + debug*sizeof(struct conf_item);
}

unsigned int __attribute__ ((pure)) config_path_depth(char **paths)
{
	// Determine depth of this config path
	for(unsigned int i = 0; i < MAX_CONFIG_PATH_DEPTH; i++)
		if(paths[i] == NULL)
			return i;

	// This should never happen as we have a maximum depth of
	// MAX_CONFIG_PATH_DEPTH
	return MAX_CONFIG_PATH_DEPTH;

}

void duplicate_config(struct config *conf)
{
	// Post-processing:
	// Initialize and verify config data
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item (original)
		struct conf_item *conf_item = get_conf_item(&config, i);

		// Get pointer to memory location of this conf_item (copy)
		struct conf_item *copy_item = get_conf_item(conf, i);

		// Copy constant/static fields
		memcpy(copy_item, conf_item, sizeof(*conf_item));

		// Make a type-dependent copy of the value
		switch(conf_item->t)
		{
			case CONF_BOOL:
			case CONF_INT:
			case CONF_UINT:
			case CONF_UINT16:
			case CONF_LONG:
			case CONF_ULONG:
			case CONF_DOUBLE:
			case CONF_STRING:
			case CONF_ENUM_PTR_TYPE:
			case CONF_ENUM_BUSY_TYPE:
			case CONF_ENUM_BLOCKING_MODE:
			case CONF_ENUM_REFRESH_HOSTNAMES:
			case CONF_ENUM_PRIVACY_LEVEL:
			case CONF_ENUM_LISTENING_MODE:
			case CONF_STRUCT_IN_ADDR:
			case CONF_STRUCT_IN6_ADDR:
				// Nothing to do, the memcpy above has already covered this
				break;
			case CONF_STRING_ALLOCATED:
				copy_item->v.s = strdup(conf_item->v.s);
				break;
			case CONF_JSON_STRING_ARRAY:
				copy_item->v.json = cJSON_Duplicate(conf_item->v.json, true);
				break;
		}
	}
}

void free_config(struct config *conf)
{
	// Post-processing:
	// Initialize and verify config data
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item (copy)
		struct conf_item *copy_item = get_conf_item(conf, i);

		// Make a type-dependent copy of the value
		switch(copy_item->t)
		{
			case CONF_BOOL:
			case CONF_INT:
			case CONF_UINT:
			case CONF_UINT16:
			case CONF_LONG:
			case CONF_ULONG:
			case CONF_DOUBLE:
			case CONF_STRING:
			case CONF_ENUM_PTR_TYPE:
			case CONF_ENUM_BUSY_TYPE:
			case CONF_ENUM_BLOCKING_MODE:
			case CONF_ENUM_REFRESH_HOSTNAMES:
			case CONF_ENUM_PRIVACY_LEVEL:
			case CONF_ENUM_LISTENING_MODE:
			case CONF_STRUCT_IN_ADDR:
			case CONF_STRUCT_IN6_ADDR:
				// Nothing to do
				break;
			case CONF_STRING_ALLOCATED:
				free(copy_item->v.s);
				break;
			case CONF_JSON_STRING_ARRAY:
				cJSON_Delete(copy_item->v.json);
				break;
		}
	}
}

void initConfig(void)
{
	// struct dns
	config.dns.CNAMEdeepInspect.k = "dns.CNAMEdeepInspect";
	config.dns.CNAMEdeepInspect.h = "Should FTL walk CNAME paths?";
	config.dns.CNAMEdeepInspect.t = CONF_BOOL;
	config.dns.CNAMEdeepInspect.d.b = true;

	config.dns.blockESNI.k = "dns.blockESNI";
	config.dns.blockESNI.h = "Should _esni. subdomains be blocked by default?";
	config.dns.blockESNI.t = CONF_BOOL;
	config.dns.blockESNI.d.b = true;

	config.dns.EDNS0ECS.k = "dns.EDNS0ECS";
	config.dns.EDNS0ECS.h = "Should FTL analyze possible ECS information to obtain client IPs hidden behind NATs?";
	config.dns.EDNS0ECS.t = CONF_BOOL;
	config.dns.EDNS0ECS.d.b = true;

	config.dns.ignoreLocalhost.k = "dns.ignoreLocalhost";
	config.dns.ignoreLocalhost.h = "Should FTL hide queries made by localhost?";
	config.dns.ignoreLocalhost.t = CONF_BOOL;
	config.dns.ignoreLocalhost.d.b = false;

	config.dns.showDNSSEC.k = "dns.showDNSSEC";
	config.dns.showDNSSEC.h = "Should FTL should internally generated DNSSEC queries?";
	config.dns.showDNSSEC.t = CONF_BOOL;
	config.dns.showDNSSEC.d.b = true;

	config.dns.analyzeAAAA.k = "dns.analyzeAAAA";
	config.dns.analyzeAAAA.h = "Should FTL analyze AAAA queries?";
	config.dns.analyzeAAAA.t = CONF_BOOL;
	config.dns.analyzeAAAA.d.b = true;

	config.dns.analyzeOnlyAandAAAA.k = "dns.analyzeOnlyAandAAAA";
	config.dns.analyzeOnlyAandAAAA.h = "Should FTL analyze *only* A and AAAA queries?";
	config.dns.analyzeOnlyAandAAAA.t = CONF_BOOL;
	config.dns.analyzeOnlyAandAAAA.d.b = false;

	config.dns.piholePTR.k = "dns.piholePTR";
	config.dns.piholePTR.h = "Should FTL return \"pi.hole\" as name for PTR requests to local IP addresses?";
	config.dns.piholePTR.a = "[ \"NONE\", \"HOSTNAME\", \"HOSTNAMEFQDN\", \"PI.HOLE\" ]";
	config.dns.piholePTR.t = CONF_ENUM_PTR_TYPE;
	config.dns.piholePTR.d.ptr_type = PTR_PIHOLE;

	config.dns.replyWhenBusy.k = "dns.replyWhenBusy";
	config.dns.replyWhenBusy.h = "How should FTL handle queries when the gravity database is not available?";
	config.dns.replyWhenBusy.a = "[ \"BLOCK\", \"ALLOW\", \"REFUSE\", \"DROP\" ]";
	config.dns.replyWhenBusy.t = CONF_ENUM_BUSY_TYPE;
	config.dns.replyWhenBusy.d.busy_reply = BUSY_ALLOW;

	config.dns.blockTTL.k = "dns.blockTTL";
	config.dns.blockTTL.h = "TTL for blocked queries [seconds]";
	config.dns.blockTTL.t = CONF_UINT;
	config.dns.blockTTL.d.ui = 2;

	// sub-struct dns.blocking
	config.dns.blocking.active.k = "dns.blocking.active";
	config.dns.blocking.active.h = "Should FTL block queries?";
	config.dns.blocking.active.t = CONF_BOOL;
	config.dns.blocking.active.d.b = true;

	config.dns.blocking.mode.k = "dns.blocking.mode";
	config.dns.blocking.mode.h = "How should FTL reply to blocked queries?";
	config.dns.blocking.mode.a = "[ \"NULL\", \"IP-NODATA-AAAA\", \"IP\", \"NXDOMAIN\", \"NODATA\" ]";
	config.dns.blocking.mode.t = CONF_ENUM_BLOCKING_MODE;
	config.dns.blocking.mode.d.blocking_mode = MODE_NULL;

	// sub-struct dns.rate_limit
	config.dns.rateLimit.count.k = "dns.rateLimit.count";
	config.dns.rateLimit.count.h = "How many queries are permitted...";
	config.dns.rateLimit.count.t = CONF_UINT;
	config.dns.rateLimit.count.d.ui = 1000;

	config.dns.rateLimit.interval.k = "dns.rateLimit.interval";
	config.dns.rateLimit.interval.h = "... in the set interval before rate-limiting?";
	config.dns.rateLimit.interval.t = CONF_UINT;
	config.dns.rateLimit.interval.d.ui = 60;

	// sub-struct dns.special_domains
	config.dns.specialDomains.mozillaCanary.k = "dns.specialDomains.mozillaCanary";
	config.dns.specialDomains.mozillaCanary.h = "Should FTL handle use-application-dns.net specifically and always return NXDOMAIN?";
	config.dns.specialDomains.mozillaCanary.t = CONF_BOOL;
	config.dns.specialDomains.mozillaCanary.d.b = true;

	config.dns.specialDomains.iCloudPrivateRelay.k = "dns.specialDomains.iCloudPrivateRelay";
	config.dns.specialDomains.iCloudPrivateRelay.h = "Should FTL handle the iCloud privacy relay domains specifically and always return NXDOMAIN?";
	config.dns.specialDomains.iCloudPrivateRelay.t = CONF_BOOL;
	config.dns.specialDomains.iCloudPrivateRelay.d.b = true;

	// sub-struct dns.reply_addr
	config.dns.reply.host.overwrite_v4.k = "dns.reply.host.overwrite_v4";
	config.dns.reply.host.overwrite_v4.h = "Use a specific IPv4 address for the Pi-hole host?";
	config.dns.reply.host.overwrite_v4.t = CONF_BOOL;
	config.dns.reply.host.overwrite_v4.d.b = false;

	config.dns.reply.host.v4.k = "dns.reply.host.IPv4";
	config.dns.reply.host.v4.h = "Custom IPv4 address for the Pi-hole host";
	config.dns.reply.host.v4.a = "<valid IPv4 address> or empty string (\"\")";
	config.dns.reply.host.v4.t = CONF_STRUCT_IN_ADDR;
	memset(&config.dns.reply.host.v4.d.in_addr, 0, sizeof(struct in_addr));

	config.dns.reply.host.overwrite_v6.k = "dns.reply.host.overwrite_v6";
	config.dns.reply.host.overwrite_v6.h = "Use a specific IPv6 address for the Pi-hole host?";
	config.dns.reply.host.overwrite_v6.t = CONF_BOOL;
	config.dns.reply.host.overwrite_v6.d.b = false;

	config.dns.reply.host.v6.k = "dns.reply.host.IPv6";
	config.dns.reply.host.v6.h = "Custom IPv6 address for the Pi-hole host";
	config.dns.reply.host.v6.a = "<valid IPv6 address> or empty string (\"\")";
	config.dns.reply.host.v6.t = CONF_STRUCT_IN6_ADDR;
	memset(&config.dns.reply.host.v6.d.in6_addr, 0, sizeof(struct in6_addr));

	config.dns.reply.blocking.overwrite_v4.k = "dns.reply.blocking.overwrite_v4";
	config.dns.reply.blocking.overwrite_v4.h = "Use a specific IPv4 address in IP blocking mode?";
	config.dns.reply.blocking.overwrite_v4.t = CONF_BOOL;
	config.dns.reply.blocking.overwrite_v4.d.b = false;

	config.dns.reply.blocking.v4.k = "dns.reply.blocking.IPv4";
	config.dns.reply.blocking.v4.h = "Custom IPv4 address for IP blocking mode";
	config.dns.reply.blocking.v4.a = "<valid IPv4 address> or empty string (\"\")";
	config.dns.reply.blocking.v4.t = CONF_STRUCT_IN_ADDR;
	memset(&config.dns.reply.blocking.v4.d.in_addr, 0, sizeof(struct in_addr));

	config.dns.reply.blocking.overwrite_v6.k = "dns.reply.blocking.overwrite_v6";
	config.dns.reply.blocking.overwrite_v6.h = "Use a specific IPv6 address in IP blocking mode?";
	config.dns.reply.blocking.overwrite_v6.t = CONF_BOOL;
	config.dns.reply.blocking.overwrite_v6.d.b = false;

	config.dns.reply.blocking.v6.k = "dns.reply.blocking.IPv6";
	config.dns.reply.blocking.v6.h = "Custom IPv6 address for IP blocking mode";
	config.dns.reply.blocking.v6.a = "<valid IPv6 address> or empty string (\"\")";
	config.dns.reply.blocking.v6.t = CONF_STRUCT_IN6_ADDR;
	memset(&config.dns.reply.blocking.v6.d.in6_addr, 0, sizeof(struct in6_addr));


	// struct dnsmasq
	config.dnsmasq.upstreams.k = "dnsmasq.upstreams";
	config.dnsmasq.upstreams.h = "Array of upstream DNS servers used by Pi-hole";
	config.dnsmasq.upstreams.a = "array of IP addresses and/or hostnames, optionally with a port, e.g. [ \"8.8.8.8\", \"127.0.0.1#5353\", \"docker-resolver\" ]";
	config.dnsmasq.upstreams.t = CONF_JSON_STRING_ARRAY;
	config.dnsmasq.upstreams.d.json = cJSON_CreateArray();
	config.dnsmasq.upstreams.restart_dnsmasq = true;

	config.dnsmasq.domain.k = "dnsmasq.domain";
	config.dnsmasq.domain.h = "The DNS domain used by your Pi-hole";
	config.dnsmasq.domain.a = "<any valid domain>";
	config.dnsmasq.domain.t = CONF_STRING;
	config.dnsmasq.domain.d.s = (char*)"lan";
	config.dnsmasq.domain.restart_dnsmasq = true;

	config.dnsmasq.domain_needed.k = "dnsmasq.domain_needed";
	config.dnsmasq.domain_needed.h = "If set, A and AAAA queries for plain names, without dots or domain parts, are never forwarded to upstream nameservers";
	config.dnsmasq.domain_needed.t = CONF_BOOL;
	config.dnsmasq.domain_needed.d.b = false;
	config.dnsmasq.domain_needed.restart_dnsmasq = true;

	config.dnsmasq.expand_hosts.k = "dnsmasq.expand_hosts";
	config.dnsmasq.expand_hosts.h = "If set, the domain is added to simple names (without a period) in /etc/hosts in the same way as for DHCP-derived names";
	config.dnsmasq.expand_hosts.t = CONF_BOOL;
	config.dnsmasq.expand_hosts.d.b = false;
	config.dnsmasq.expand_hosts.restart_dnsmasq = true;

	config.dnsmasq.bogus_priv.k = "dnsmasq.bogus_priv";
	config.dnsmasq.bogus_priv.h = "Should all reverse lookups for private IP ranges (i.e., 192.168.x.y, etc) which are not found in /etc/hosts or the DHCP leases file be answered with \"no such domain\" rather than being forwarded upstream?";
	config.dnsmasq.bogus_priv.t = CONF_BOOL;
	config.dnsmasq.bogus_priv.d.b = true;
	config.dnsmasq.bogus_priv.restart_dnsmasq = true;

	config.dnsmasq.dnssec.k = "dnsmasq.dnssec";
	config.dnsmasq.dnssec.h = "Validate DNS replies and cache DNSSEC data";
	config.dnsmasq.dnssec.t = CONF_BOOL;
	config.dnsmasq.dnssec.d.b = true;
	config.dnsmasq.dnssec.restart_dnsmasq = true;

	config.dnsmasq.interface.k = "dnsmasq.interface";
	config.dnsmasq.interface.h = "Interface to use for DNS (see also dnsmasq.listening.mode) and DHCP (if enabled)";
	config.dnsmasq.interface.a = "a valid interface name";
	config.dnsmasq.interface.t = CONF_STRING;
	config.dnsmasq.interface.d.s = (char*)"";
	config.dnsmasq.interface.restart_dnsmasq = true;

	config.dnsmasq.host_record.k = "dnsmasq.host_record";
	config.dnsmasq.host_record.h = "Add A, AAAA and PTR records to the DNS. This adds one or more names to the DNS with associated IPv4 (A) and IPv6 (AAAA) records";
	config.dnsmasq.host_record.a = "<name>[,<name>....],[<IPv4-address>],[<IPv6-address>][,<TTL>]";
	config.dnsmasq.host_record.t = CONF_STRING;
	config.dnsmasq.host_record.d.s = (char*)"";
	config.dnsmasq.host_record.restart_dnsmasq = true;

	config.dnsmasq.listening_mode.k = "dnsmasq.listening_mode";
	config.dnsmasq.listening_mode.h = "Pi-hole interface listening modes";
	config.dnsmasq.listening_mode.a = "[ \"LOCAL\", \"ALL\", \"SINGLE\", \"BIND\" ]";
	config.dnsmasq.listening_mode.t = CONF_ENUM_LISTENING_MODE;
	config.dnsmasq.listening_mode.d.listening_mode = LISTEN_LOCAL;
	config.dnsmasq.listening_mode.restart_dnsmasq = true;

	config.dnsmasq.cache_size.k = "dnsmasq.cache_size";
	config.dnsmasq.cache_size.h = "Cache size of the DNS server. Note that expiring cache entries naturally make room for new insertions over time. Setting this number too high will have an adverse effect as not only more space is needed, but also lookup speed gets degraded in the 100,000+ range";
	config.dnsmasq.cache_size.t = CONF_UINT;
	config.dnsmasq.cache_size.d.ui = 10000u;
	config.dnsmasq.cache_size.restart_dnsmasq = true;

	config.dnsmasq.logging.k = "dnsmasq.logging";
	config.dnsmasq.logging.h = "Log DNS queries and replies to pihole.log";
	config.dnsmasq.logging.t = CONF_BOOL;
	config.dnsmasq.logging.d.b = true;
	config.dnsmasq.logging.restart_dnsmasq = true;

	config.dnsmasq.cnames.k = "dnsmasq.cnames";
	config.dnsmasq.cnames.h = "List of CNAME records which indicate that <cname> is really <target>. If the <TTL> is given, it overwrites the value of local-ttl";
	config.dnsmasq.cnames.a = "Array of static leases each on in one of the following forms: \"<cname>,<target>[,<TTL>]\"";
	config.dnsmasq.cnames.t = CONF_JSON_STRING_ARRAY;
	config.dnsmasq.cnames.d.json = cJSON_CreateArray();
	config.dnsmasq.cnames.restart_dnsmasq = true;

	config.dnsmasq.port.k = "dnsmasq.port";
	config.dnsmasq.port.h = "Port used by the DNS server";
	config.dnsmasq.port.t = CONF_UINT16;
	config.dnsmasq.port.d.ui = 53u;
	config.dnsmasq.port.restart_dnsmasq = true;

	// sub-struct rev_server
	config.dnsmasq.rev_server.active.k = "dnsmasq.rev_server.active";
	config.dnsmasq.rev_server.active.h = "Is the reverse server (former also called \"conditional forwarding\") feature enabled?";
	config.dnsmasq.rev_server.active.t = CONF_BOOL;
	config.dnsmasq.rev_server.active.d.b = false;
	config.dnsmasq.rev_server.active.restart_dnsmasq = true;

	config.dnsmasq.rev_server.cidr.k = "dnsmasq.rev_server.cidr";
	config.dnsmasq.rev_server.cidr.h = "Address range for the reverse server feature in CIDR notation. If the prefix length is omitted, either 32 (IPv4) or 128 (IPv6) are substitutet (exact address match). This is almost certainly not what you want here.";
	config.dnsmasq.rev_server.cidr.a = "<ip-address>[/<prefix-len>], e.g., \"192.168.0.0/24\" for the range 192.168.0.1 - 192.168.0.255";
	config.dnsmasq.rev_server.cidr.t = CONF_STRING;
	config.dnsmasq.rev_server.cidr.d.s = (char*)"";
	config.dnsmasq.rev_server.cidr.restart_dnsmasq = true;

	config.dnsmasq.rev_server.target.k = "dnsmasq.rev_server.target";
	config.dnsmasq.rev_server.target.h = "Target server tp be used for the reverse server feature";
	config.dnsmasq.rev_server.target.a = "<server>[#<port>], e.g., \"192.168.0.1\"";
	config.dnsmasq.rev_server.target.t = CONF_STRING;
	config.dnsmasq.rev_server.target.d.s = (char*)"";
	config.dnsmasq.rev_server.target.restart_dnsmasq = true;

	config.dnsmasq.rev_server.domain.k = "dnsmasq.rev_server.domain";
	config.dnsmasq.rev_server.domain.h = "Domain used for the reverse server feature";
	config.dnsmasq.rev_server.domain.a = "<valid domain>, typically set to the same value as dnsmasq.domain";
	config.dnsmasq.rev_server.domain.t = CONF_STRING;
	config.dnsmasq.rev_server.domain.d.s = (char*)"";
	config.dnsmasq.rev_server.domain.restart_dnsmasq = true;

	// sub-struct dhcp
	config.dnsmasq.dhcp.active.k = "dnsmasq.dhcp.active";
	config.dnsmasq.dhcp.active.h = "Is the embedded DHCP server enabled?";
	config.dnsmasq.dhcp.active.t = CONF_BOOL;
	config.dnsmasq.dhcp.active.d.b = false;
	config.dnsmasq.dhcp.active.restart_dnsmasq = true;

	config.dnsmasq.dhcp.start.k = "dnsmasq.dhcp.start";
	config.dnsmasq.dhcp.start.h = "Start address of the DHCP address pool";
	config.dnsmasq.dhcp.start.a = "<ip-addr>, e.g., \"192.168.0.10\"";
	config.dnsmasq.dhcp.start.t = CONF_STRING;
	config.dnsmasq.dhcp.start.d.s = (char*)"";
	config.dnsmasq.dhcp.start.restart_dnsmasq = true;

	config.dnsmasq.dhcp.end.k = "dnsmasq.dhcp.end";
	config.dnsmasq.dhcp.end.h = "End address of the DHCP address pool";
	config.dnsmasq.dhcp.end.a = "<ip-addr>, e.g., \"192.168.0.250\"";
	config.dnsmasq.dhcp.end.t = CONF_STRING;
	config.dnsmasq.dhcp.end.d.s = (char*)"";
	config.dnsmasq.dhcp.end.restart_dnsmasq = true;

	config.dnsmasq.dhcp.router.k = "dnsmasq.dhcp.router";
	config.dnsmasq.dhcp.router.h = "Address of the gateway to be used (typicaly the address of your router in a home installation)";
	config.dnsmasq.dhcp.router.a = "<ip-addr>, e.g., \"192.168.0.1\"";
	config.dnsmasq.dhcp.router.t = CONF_STRING;
	config.dnsmasq.dhcp.router.d.s = (char*)"";
	config.dnsmasq.dhcp.router.restart_dnsmasq = true;

	config.dnsmasq.dhcp.leasetime.k = "dnsmasq.dhcp.leasetime";
	config.dnsmasq.dhcp.leasetime.h = "If the lease time is given, then leases will be given for that length of time. If not given, the default lease time is one hour for IPv4 and one day for IPv6.";
	config.dnsmasq.dhcp.leasetime.a = "The lease time can be in seconds, or minutes (e.g., \"45m\") or hours (e.g., \"1h\") or days (like \"2d\") or even weeks (\"1w\"). You may also use \"infinite\" as string but be aware of the drawbacks";
	config.dnsmasq.dhcp.leasetime.t = CONF_STRING;
	config.dnsmasq.dhcp.leasetime.d.s = (char*)"";
	config.dnsmasq.dhcp.leasetime.restart_dnsmasq = true;

	config.dnsmasq.dhcp.ipv6.k = "dnsmasq.dhcp.ipv6";
	config.dnsmasq.dhcp.ipv6.h = "Should Pi-hole make an attempt to also satisfy IPv6 address requests (be aware that IPv6 works a whole lot different than IPv4)";
	config.dnsmasq.dhcp.ipv6.t = CONF_BOOL;
	config.dnsmasq.dhcp.ipv6.d.b = false;
	config.dnsmasq.dhcp.ipv6.restart_dnsmasq = true;

	config.dnsmasq.dhcp.rapid_commit.k = "dnsmasq.dhcp.rapid_commit";
	config.dnsmasq.dhcp.rapid_commit.h = "Enable DHCPv4 Rapid Commit Option specified in RFC 4039. Should only be enabled if either the server is the only server for the subnet to avoid conflicts";
	config.dnsmasq.dhcp.rapid_commit.t = CONF_BOOL;
	config.dnsmasq.dhcp.rapid_commit.d.b = false;
	config.dnsmasq.dhcp.rapid_commit.restart_dnsmasq = true;

	config.dnsmasq.dhcp.hosts.k = "dnsmasq.dhcp.hosts";
	config.dnsmasq.dhcp.hosts.h = "Per host parameters for the DHCP server. This allows a machine with a particular hardware address to be always allocated the same hostname, IP address and lease time or to specify static DHCP leases";
	config.dnsmasq.dhcp.hosts.a = "Array of static leases each on in one of the following forms: \"[<hwaddr>][,id:<client_id>|*][,set:<tag>][,tag:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]\"";
	config.dnsmasq.dhcp.hosts.t = CONF_JSON_STRING_ARRAY;
	config.dnsmasq.dhcp.hosts.d.json = cJSON_CreateArray();
	config.dnsmasq.dhcp.hosts.restart_dnsmasq = true;


	// struct resolver
	config.resolver.resolveIPv6.k = "resolver.resolveIPv6";
	config.resolver.resolveIPv6.h = "Should FTL try to resolve IPv6 addresses to hostnames?";
	config.resolver.resolveIPv6.t = CONF_BOOL;
	config.resolver.resolveIPv6.d.b = true;

	config.resolver.resolveIPv4.k = "resolver.resolveIPv4";
	config.resolver.resolveIPv4.h = "Should FTL try to resolve IPv4 addresses to hostnames?";
	config.resolver.resolveIPv4.t = CONF_BOOL;
	config.resolver.resolveIPv4.d.b = true;

	config.resolver.networkNames.k = "resolver.networkNames";
	config.resolver.networkNames.h = "Try to obtain client names from the network table?";
	config.resolver.networkNames.t = CONF_BOOL;
	config.resolver.networkNames.d.b = true;

	config.resolver.refreshNames.k = "resolver.refreshNames";
	config.resolver.refreshNames.h = "How (and if) hourly PTR lookups should be made";
	config.resolver.refreshNames.a = "[ \"IPV4_ONLY\", \"ALL\", \"UNKNOWN\", \"NONE\" ]";
	config.resolver.refreshNames.t = CONF_ENUM_REFRESH_HOSTNAMES;
	config.resolver.refreshNames.d.refresh_hostnames = REFRESH_IPV4_ONLY;


	// struct database
	config.database.DBimport.k = "database.DBimport";
	config.database.DBimport.h = "Should FTL load information from the database on startup to be aware of the most recent history?";
	config.database.DBimport.t = CONF_BOOL;
	config.database.DBimport.d.b = true;

	config.database.DBexport.k = "database.DBexport";
	config.database.DBexport.h =  "Should FTL store queries in the long-term database?";
	config.database.DBexport.t = CONF_BOOL;
	config.database.DBexport.d.b = true;

	config.database.maxDBdays.k = "database.maxDBdays";
	config.database.maxDBdays.h = "How long should queries be stored in the database [days]?";
	config.database.maxDBdays.t = CONF_INT;
	config.database.maxDBdays.d.i = 365;

	config.database.maxHistory.k = "database.maxHistory";
	config.database.maxHistory.h = "How much history should be imported from the database [seconds]? (max 24*60*60 = 86400)";
	config.database.maxHistory.t = CONF_UINT;
	config.database.maxHistory.d.ui = MAXLOGAGE*3600;

	config.database.DBinterval.k = "database.DBinterval";
	config.database.DBinterval.h = "How often do we store queries in FTL's database [seconds]?";
	config.database.DBinterval.t = CONF_UINT;
	config.database.DBinterval.d.ui = 60;

	// sub-struct database.network
	config.database.network.parseARPcache.k = "database.network.parseARPcache";
	config.database.network.parseARPcache.h = "Should FTL anaylze the local ARP cache?";
	config.database.network.parseARPcache.t = CONF_BOOL;
	config.database.network.parseARPcache.d.b = true;

	config.database.network.expire.k = "database.network.expire";
	config.database.network.expire.h = "How long should IP addresses be kept in the network_addresses table [days]?";
	config.database.network.expire.t = CONF_UINT;
	config.database.network.expire.d.ui = config.database.maxDBdays.d.ui;


	// struct api
	config.api.localAPIauth.k = "api.localAPIauth";
	config.api.localAPIauth.h = "Does local clients need to authenticate to access the API?";
	config.api.localAPIauth.t = CONF_BOOL;
	config.api.localAPIauth.d.b = true;

	config.api.prettyJSON.k = "api.prettyJSON";
	config.api.prettyJSON.h = "Should FTL prettify the API output?";
	config.api.prettyJSON.t = CONF_BOOL;
	config.api.prettyJSON.d.b = false;

	config.api.sessionTimeout.k = "api.sessionTimeout";
	config.api.sessionTimeout.h = "How long should a session be considered valid after login [seconds]?";
	config.api.sessionTimeout.t = CONF_UINT;
	config.api.sessionTimeout.d.ui = 300;

	config.api.pwhash.k = "api.pwhash";
	config.api.pwhash.h = "API password hash";
	config.api.pwhash.a = "<valid Pi-hole password hash>";
	config.api.pwhash.t = CONF_STRING;
	config.api.pwhash.d.s = (char*)"";

	config.api.exclude_clients.k = "api.exclude_clients";
	config.api.exclude_clients.h = "Array of clients to be excluded from certain API responses";
	config.api.exclude_clients.a = "array of IP addresses and/or hostnames, e.g. [ \"192.168.2.56\", \"fe80::341\", \"localhost\" ]";
	config.api.exclude_clients.t = CONF_JSON_STRING_ARRAY;
	config.api.exclude_clients.d.json = cJSON_CreateArray();

	config.api.exclude_domains.k = "api.exclude_domains";
	config.api.exclude_domains.h = "Array of domains to be excluded from certain API responses";
	config.api.exclude_domains.a = "array of IP addresses and/or hostnames, e.g. [ \"google.de\", \"pi-hole.net\" ]";
	config.api.exclude_domains.t = CONF_JSON_STRING_ARRAY;
	config.api.exclude_domains.d.json = cJSON_CreateArray();


	// struct http
	config.http.domain.k = "http.domain";
	config.http.domain.h = "On which domain is the web interface served?";
	config.http.domain.a = "<valid domain>";
	config.http.domain.t = CONF_STRING;
	config.http.domain.d.s = (char*)"pi.hole";

	config.http.acl.k = "http.acl";
	config.http.acl.h = "Webserver access control list (ACL) allowing for restrictions to be put on the list of IP addresses which have access to the web server. The ACL is a comma separated list of IP subnets, where each subnet is prepended by either a - or a + sign. A plus sign means allow, where a minus sign means deny. If a subnet mask is omitted, such as -1.2.3.4, this means to deny only that single IP address. If this value is not set (empty string), all accesses are allowed. Otherwise, the default setting is to deny all accesses. On each request the full list is traversed, and the last (!) match wins. IPv6 addresses may be specified in CIDR-form [a:b::c]/64.\n\n Example 1: acl = \"+127.0.0.1,+[::1]\"\n ---> deny all access, except from 127.0.0.1 and ::1,\n Example 2: acl = \"+192.168.0.0/16\"\n ---> deny all accesses, except from the 192.168.0.0/16 subnet,\n Example 3: acl = \"+[::]/0\" ---> allow only IPv6 access.";
	config.http.acl.a = "<valid ACL>";
	config.http.acl.t = CONF_STRING;
	config.http.acl.d.s = (char*)"";

	config.http.port.k = "http.port";
	config.http.port.h = "Ports to be used by the webserver";
	config.http.port.a = "comma-separated list of <[ip_address:]port>";
	config.http.port.t = CONF_STRING;
	config.http.port.d.s = (char*)"8080,[::]:8080";

	// sub-struct paths
	config.http.paths.webroot.k = "http.paths.webroot";
	config.http.paths.webroot.h = "Server root on the host";
	config.http.paths.webroot.a = "<valid path>";
	config.http.paths.webroot.t = CONF_STRING;
	config.http.paths.webroot.d.s = (char*)"/var/www/html";

	config.http.paths.webhome.k = "http.paths.webhome";
	config.http.paths.webhome.h = "Sub-directory of the root containing the web interface";
	config.http.paths.webhome.a = "<valid subpath>, both slashes are needed!";
	config.http.paths.webhome.t = CONF_STRING;
	config.http.paths.webhome.d.s = (char*)"/admin/";

	// sub-struct interface
	config.http.interface.boxed.k = "http.interface.boxed";
	config.http.interface.boxed.h = "Should the web interface use the boxed layout?";
	config.http.interface.boxed.t = CONF_BOOL;
	config.http.interface.boxed.d.b = true;

	config.http.interface.theme.k = "http.interface.theme";
	config.http.interface.theme.h = "Theme used by the Pi-hole web interface";
	config.http.interface.theme.a = "<valid themename>";
	config.http.interface.theme.t = CONF_STRING;
	config.http.interface.theme.d.s = (char*)"default";


	// struct files
	config.files.pid.k = "files.pid";
	config.files.pid.h = "The location of FTL's PID file";
	config.files.pid.a = "<any writable file>";
	config.files.pid.t = CONF_STRING;
	config.files.pid.d.s = (char*)"/run/pihole-FTL.pid";

	config.files.database.k = "files.database";
	config.files.database.h = "The location of FTL's long-term database";
	config.files.database.a = "<any FTL database>";
	config.files.database.t = CONF_STRING;
	config.files.database.d.s = (char*)"/etc/pihole/pihole-FTL.db";

	config.files.gravity.k = "files.gravity";
	config.files.gravity.h = "The location of Pi-hole's gravity database";
	config.files.gravity.a = "<any Pi-hole gravity database>";
	config.files.gravity.t = CONF_STRING;
	config.files.gravity.d.s = (char*)"/etc/pihole/gravity.db";

	config.files.macvendor.k = "files.macvendor";
	config.files.macvendor.h = "The database containing MAC -> Vendor information for the network table";
	config.files.macvendor.a = "<any Pi-hole macvendor database>";
	config.files.macvendor.t = CONF_STRING;
	config.files.macvendor.d.s = (char*)"/etc/pihole/macvendor.db";

	config.files.setupVars.k = "files.setupVars";
	config.files.setupVars.h = "The config file of Pi-hole";
	config.files.setupVars.a = "<any Pi-hole setupVars file>";
	config.files.setupVars.t = CONF_STRING;
	config.files.setupVars.d.s = (char*)"/etc/pihole/setupVars.conf";

	config.files.http_info.k = "files.http_info";
	config.files.http_info.h = "The log file used by the webserver";
	config.files.http_info.a = "<any writable file>";
	config.files.http_info.t = CONF_STRING;
	config.files.http_info.d.s = (char*)"/var/log/pihole/HTTP_info.log";

	config.files.ph7_error.k = "files.ph7_error";
	config.files.ph7_error.h = "The log file used by the dynamic interpreter PH7";
	config.files.ph7_error.a = "<any writable file>";
	config.files.ph7_error.t = CONF_STRING;
	config.files.ph7_error.d.s = (char*)"/var/log/pihole/PH7.log";

	// sub-struct files.log
	// config.files.log.ftl is set in a separate function

	config.files.log.dnsmasq.k = "files.log.dnsmasq";
	config.files.log.dnsmasq.h = "The log file used by the embedded dnsmasq DNS server";
	config.files.log.dnsmasq.a = "<any writable file>";
	config.files.log.dnsmasq.t = CONF_STRING;
	config.files.log.dnsmasq.d.s = (char*)"/var/log/pihole/pihole.log";


	// struct misc
	config.misc.nice.k = "misc.nice";
	config.misc.nice.h = "Set niceness of pihole-FTL (can be disabled by setting to -999)";
	config.misc.nice.t = CONF_INT;
	config.misc.nice.d.i = -10;

	config.misc.addr2line.k = "misc.addr2line";
	config.misc.addr2line.h = "The log file used by the dynamic interpreter PH7";
	config.misc.addr2line.t = CONF_BOOL;
	config.misc.addr2line.d.b = true;

	config.misc.privacylevel.k = "misc.privacylevel";
	config.misc.privacylevel.h = "Privacy level";
	config.misc.privacylevel.t = CONF_ENUM_PRIVACY_LEVEL;
	config.misc.privacylevel.d.privacy_level = PRIVACY_SHOW_ALL;

	config.misc.delay_startup.k = "misc.delay_startup";
	config.misc.delay_startup.h = "Should FTL try to call addr2line when generating backtraces?";
	config.misc.delay_startup.t = CONF_UINT;
	config.misc.delay_startup.d.ui = 0;

	// sub-struct misc.temp
	config.misc.temp.limit.k = "misc.temp.limit";
	config.misc.temp.limit.h = "Which upper temperature limit should be used by Pi-hole? Temperatures above this limit will be shown as \"hot\". The number specified here is in the unit defined below";
	config.misc.temp.limit.t = CONF_DOUBLE;
	config.misc.temp.limit.d.d = 60.0; // °C

	config.misc.temp.unit.k = "misc.temp.unit";
	config.misc.temp.unit.h = "Which temperature unit should be used for temperatures processed by FTL?";
	config.misc.temp.unit.a = "[ \"C\", \"F\", \"K\" ]";
	config.misc.temp.unit.t = CONF_STRING;
	config.misc.temp.unit.d.s = (char*)"C";

	// sub-struct misc.check
	config.misc.check.load.k = "misc.check.load";
	config.misc.check.load.h = "Should FTL check the 15 min average of CPU load and complain if the load is larger than the number of available CPU cores?";
	config.misc.check.load.t = CONF_BOOL;
	config.misc.check.load.d.b = true;

	config.misc.check.disk.k = "misc.check.disk";
	config.misc.check.disk.h = "Limit above which FTL should complain about a shared-memory shortage [percent]";
	config.misc.check.disk.t = CONF_UINT;
	config.misc.check.disk.d.ui = 90;

	config.misc.check.shmem.k = "misc.check.shmem";
	config.misc.check.shmem.h = "Limit above which FTL should complain about disk shortage for checked files [percent]";
	config.misc.check.shmem.t = CONF_UINT;
	config.misc.check.shmem.d.ui = 90;


	// struct debug
	config.debug.database.k = "debug.database";
	config.debug.database.h = "Enable extra logging of database actions";
	config.debug.database.t = CONF_BOOL;
	config.debug.database.d.b = false;

	config.debug.networking.k = "debug.networking";
	config.debug.networking.h = "Enable extra logging of detected interfaces";
	config.debug.networking.t = CONF_BOOL;
	config.debug.networking.d.b = false;

	config.debug.locks.k = "debug.locks";
	config.debug.locks.h = "Enable extra logging of shared memory lock actions";
	config.debug.locks.t = CONF_BOOL;
	config.debug.locks.d.b = false;

	config.debug.queries.k = "debug.queries";
	config.debug.queries.h = "Print extensive query information";
	config.debug.queries.t = CONF_BOOL;
	config.debug.queries.d.b = false;

	config.debug.flags.k = "debug.flags";
	config.debug.flags.h = "Print flags of queries received by the DNS hooks";
	config.debug.flags.t = CONF_BOOL;
	config.debug.flags.d.b = false;

	config.debug.shmem.k = "debug.shmem";
	config.debug.shmem.h = "Print information about shared memory buffers";
	config.debug.shmem.t = CONF_BOOL;
	config.debug.shmem.d.b = false;

	config.debug.gc.k = "debug.gc";
	config.debug.gc.h = "Print information about garbage collection";
	config.debug.gc.t = CONF_BOOL;
	config.debug.gc.d.b = false;

	config.debug.arp.k = "debug.arp";
	config.debug.arp.h = "Print information about ARP table processing";
	config.debug.arp.t = CONF_BOOL;
	config.debug.arp.d.b = false;

	config.debug.regex.k = "debug.regex";
	config.debug.regex.h = "Enable extra logging of regex matching details";
	config.debug.regex.t = CONF_BOOL;
	config.debug.regex.d.b = false;

	config.debug.api.k = "debug.api";
	config.debug.api.h = "Enable extra logging of API activities";
	config.debug.api.t = CONF_BOOL;
	config.debug.api.d.b = false;

	config.debug.overtime.k = "debug.overtime";
	config.debug.overtime.h = "Print information about overTime memory operations";
	config.debug.overtime.t = CONF_BOOL;
	config.debug.overtime.d.b = false;

	config.debug.status.k = "debug.status";
	config.debug.status.h = "Enable extra logging of query status changes";
	config.debug.status.t = CONF_BOOL;
	config.debug.status.d.b = false;

	config.debug.caps.k = "debug.caps";
	config.debug.caps.h = "Print information about capabilities granted to the pihole-FTL process";
	config.debug.caps.t = CONF_BOOL;
	config.debug.caps.d.b = false;

	config.debug.dnssec.k = "debug.dnssec";
	config.debug.dnssec.h = "Print information about DNSSEC activity";
	config.debug.dnssec.t = CONF_BOOL;
	config.debug.dnssec.d.b = false;

	config.debug.vectors.k = "debug.vectors";
	config.debug.vectors.h = "Print vector operation details";
	config.debug.vectors.t = CONF_BOOL;
	config.debug.vectors.d.b = false;

	config.debug.resolver.k = "debug.resolver";
	config.debug.resolver.h = "Extensive information about hostname resolution like which DNS servers are used";
	config.debug.resolver.t = CONF_BOOL;
	config.debug.resolver.d.b = false;

	config.debug.edns0.k = "debug.edns0";
	config.debug.edns0.h = "Print EDNS(0) debugging information";
	config.debug.edns0.t = CONF_BOOL;
	config.debug.edns0.d.b = false;

	config.debug.clients.k = "debug.clients";
	config.debug.clients.h = "Enable extra client detail logging";
	config.debug.clients.t = CONF_BOOL;
	config.debug.clients.d.b = false;

	config.debug.aliasclients.k = "debug.aliasclients";
	config.debug.aliasclients.h = "Print aliasclient details";
	config.debug.aliasclients.t = CONF_BOOL;
	config.debug.aliasclients.d.b = false;

	config.debug.events.k = "debug.events";
	config.debug.events.h = "Log information about processed internal events";
	config.debug.events.t = CONF_BOOL;
	config.debug.events.d.b = false;

	config.debug.helper.k = "debug.helper";
	config.debug.helper.h = "Enable logging of script helper activity";
	config.debug.helper.t = CONF_BOOL;
	config.debug.helper.d.b = false;

	config.debug.config.k = "debug.config";
	config.debug.config.h = "Print config parsing details";
	config.debug.config.t = CONF_BOOL;
	config.debug.config.d.b = false;

	config.debug.extra.k = "debug.extra";
	config.debug.extra.h = "Special debug flag that may be used for debugging specific issues";
	config.debug.extra.t = CONF_BOOL;
	config.debug.extra.d.b = false;

	config.debug.reserved.k = "debug.reserved";
	config.debug.reserved.h = "Reserved debug flag";
	config.debug.reserved.t = CONF_BOOL;
	config.debug.reserved.d.b = false;

	// Post-processing:
	// Initialize and verify config data
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(&config, i);

		// Initialize config value with default one for all *except* the log file path
		if(conf_item != &config.files.log.ftl)
		{
			if(conf_item->t == CONF_JSON_STRING_ARRAY)
				// JSON objects really need to be duplicated as the config
				// structure stores only a pointer to memory somewhere else
				conf_item->v.json = cJSON_Duplicate(conf_item->d.json, true);
			else if(conf_item->t == CONF_STRING_ALLOCATED)
				// Allocated string: Make our own copy
				conf_item->v.s = strdup(conf_item->d.s);
			else
				// Ordinary value: Simply copy the union over
				memcpy(&conf_item->v, &conf_item->d, sizeof(conf_item->d));
		}

		// Parse and split paths
		conf_item->p = gen_config_path(conf_item->k, '.');

		// Verify all config options are defined above
		if(!conf_item->p)
			log_err("Config option %u/%u is not set!", i, (unsigned int)CONFIG_ELEMENTS);
		else if(config.debug.config.v.b)
		{
			if(conf_item->p[3])
				log_debug(DEBUG_CONFIG, "Config option %u is %s.%s.%s.%s", i, conf_item->p[0], conf_item->p[1], conf_item->p[2], conf_item->p[3]);
			else if(conf_item->p[2])
				log_debug(DEBUG_CONFIG, "Config option %u is %s.%s.%s", i, conf_item->p[0], conf_item->p[1], conf_item->p[2]);
			else if(conf_item->p[1])
				log_debug(DEBUG_CONFIG, "Config option %u is %s.%s", i, conf_item->p[0], conf_item->p[1]);
			else
				log_debug(DEBUG_CONFIG, "Config option %u is %s", i, conf_item->p[0]);
		}
	}
}

void readFTLconf(const bool rewrite)
{
	// First try to read TOML config file
	if(readFTLtoml(rewrite))
	{
		// If successful, we write the config file back to disk
		// to ensure that all options are present and comments
		// about options deviating from the default are present
		if(rewrite)
		{
			writeFTLtoml(true);
			write_dnsmasq_config(&config, false, NULL);
		}
		return;
	}

	// On error, try to read legacy (pre-v6.0) config file. If successful,
	// we move the legacy config file out of our way
	const char *path = "";
	if((path = readFTLlegacy()) != NULL)
	{
		const char *target = "/etc/pihole/pihole-FTL.conf.bck";
		log_info("Moving %s to %s", path, target);
		if(rename(path, target) != 0)
			log_warn("Unable to move %s to %s: %s", path, target, strerror(errno));
	}
	// Import bits and pieces from legacy config files
	// setupVars.conf
	importsetupVarsConf();
	// 04-pihole-static-dhcp.conf
	read_legacy_dhcp_static_config();
	// 05-pihole-custom-cname.conf
	read_legacy_cnames_config();

	// When we reach this point but the FTL TOML config file exists, it may
	// contain errors such as syntax errors, etc. We move it into a
	// ".broken" location so it can be revisited later
	if(file_exists(GLOBALTOMLPATH))
	{
		const char new_name[] = GLOBALTOMLPATH ".broken";
		rotate_files(new_name, MAX_ROTATION);
		rename(GLOBALTOMLPATH, new_name);
	}

	// Initialize the TOML config file
	writeFTLtoml(true);
	write_dnsmasq_config(&config, false, NULL);
}

bool getLogFilePath(void)
{
	// Initialize memory
	memset(&config, 0, sizeof(config));

	// Initialize the config file path
	config.files.log.ftl.k = "files.log.ftl";
	config.files.log.ftl.h = "The location of FTL's log file";
	config.files.log.ftl.a = "<any writable file>";
	config.files.log.ftl.t = CONF_STRING;
	config.files.log.ftl.d.s = (char*)"/var/log/pihole/FTL.log";
	config.files.log.ftl.v.s = config.files.log.ftl.d.s;

	// Check if the config file contains a different path
	if(!getLogFilePathTOML())
		return getLogFilePathLegacy(NULL);

	return true;
}

bool __attribute__((pure)) get_blockingstatus(void)
{
	return config.dns.blocking.active.v.b;
}

void set_blockingstatus(bool enabled)
{
	config.dns.blocking.active.v.b = enabled;
	writeFTLtoml(true);
	raise(SIGHUP);
}
