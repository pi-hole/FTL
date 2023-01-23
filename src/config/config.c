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
			// config.dns.upstreams.(null) <-> config.dns.upstreams.(null)
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

		// Duplicate allowed values (if defined)
		// Note: This is no necessary as we simply leave the allowed values
		// object living forever and merely copy the pointer to its heap living
		// space around (it is never freed)
		// if(conf_item->a != NULL) copy_item->a = cJSON_Duplicate(conf_item->a, true);

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

// True = Identical, False = Different
bool compare_config_item(const struct conf_item *conf_item1, const struct conf_item *conf_item2)
{
	if(conf_item1->t != conf_item2->t)
		return false;

	// Make a type-dependent copy of the value
	switch(conf_item1->t)
	{
		case CONF_BOOL:
		case CONF_INT:
		case CONF_UINT:
		case CONF_UINT16:
		case CONF_LONG:
		case CONF_ULONG:
		case CONF_DOUBLE:
		case CONF_ENUM_PTR_TYPE:
		case CONF_ENUM_BUSY_TYPE:
		case CONF_ENUM_BLOCKING_MODE:
		case CONF_ENUM_REFRESH_HOSTNAMES:
		case CONF_ENUM_PRIVACY_LEVEL:
		case CONF_ENUM_LISTENING_MODE:
		case CONF_STRUCT_IN_ADDR:
		case CONF_STRUCT_IN6_ADDR:
			// Compare entire union
			return memcmp(&conf_item1->v, &conf_item2->v, sizeof(conf_item1->v)) == 0;
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
			return strcmp(conf_item1->v.s, conf_item2->v.s) == 0;
		case CONF_JSON_STRING_ARRAY:
			return cJSON_Compare(conf_item1->v.json, conf_item2->v.json, true);
	}
	return false;
}


void free_config(struct config *conf)
{
	// Post-processing:
	// Initialize and verify config data
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item (copy)
		struct conf_item *copy_item = get_conf_item(conf, i);

		// Free allowed values (if defined)
		// Note: This is no necessary as we simply leave the allowed values
		// object living forever and merely copy the pointer to its heap living
		// space around (it is never freed)
		// if(conf->a != NULL) cJSON_Delete(conf->a);

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
	config.dns.upstreams.k = "dns.upstreams";
	config.dns.upstreams.h = "Array of upstream DNS servers used by Pi-hole\n Example: [ \"8.8.8.8\", \"127.0.0.1#5353\", \"docker-resolver\" ]";
	config.dns.upstreams.a = cJSON_CreateStringReference("array of IP addresses and/or hostnames, optionally with a port (#...)");
	config.dns.upstreams.t = CONF_JSON_STRING_ARRAY;
	config.dns.upstreams.d.json = cJSON_CreateArray();
	config.dns.upstreams.f = FLAG_RESTART_DNSMASQ;

	config.dns.CNAMEdeepInspect.k = "dns.CNAMEdeepInspect";
	config.dns.CNAMEdeepInspect.h = "Use this option to control deep CNAME inspection. Disabling it might be beneficial for very low-end devices";
	config.dns.CNAMEdeepInspect.t = CONF_BOOL;
	config.dns.CNAMEdeepInspect.f = FLAG_ADVANCED_SETTING;
	config.dns.CNAMEdeepInspect.d.b = true;

	config.dns.blockESNI.k = "dns.blockESNI";
	config.dns.blockESNI.h = "Should _esni. subdomains be blocked by default? Encrypted Server Name Indication (ESNI) is certainly a good step into the right direction to enhance privacy on the web. It prevents on-path observers, including ISPs, coffee shop owners and firewalls, from intercepting the TLS Server Name Indication (SNI) extension by encrypting it. This prevents the SNI from being used to determine which websites users are visiting.\n ESNI will obviously cause issues for pixelserv-tls which will be unable to generate matching certificates on-the-fly when it cannot read the SNI. Cloudflare and Firefox are already enabling ESNI. According to the IEFT draft (link above), we can easily restore piselserv-tls's operation by replying NXDOMAIN to _esni. subdomains of blocked domains as this mimics a \"not configured for this domain\" behavior.";
	config.dns.blockESNI.t = CONF_BOOL;
	config.dns.blockESNI.f = FLAG_ADVANCED_SETTING;
	config.dns.blockESNI.d.b = true;

	config.dns.EDNS0ECS.k = "dns.EDNS0ECS";
	config.dns.EDNS0ECS.h = "Should we overwrite the query source when client information is provided through EDNS0 client subnet (ECS) information? This allows Pi-hole to obtain client IPs even if they are hidden behind the NAT of a router. This feature has been requested and discussed on Discourse where further information how to use it can be found: https://discourse.pi-hole.net/t/support-for-add-subnet-option-from-dnsmasq-ecs-edns0-client-subnet/35940";
	config.dns.EDNS0ECS.t = CONF_BOOL;
	config.dns.EDNS0ECS.f = FLAG_ADVANCED_SETTING;
	config.dns.EDNS0ECS.d.b = true;

	config.dns.ignoreLocalhost.k = "dns.ignoreLocalhost";
	config.dns.ignoreLocalhost.h = "Should FTL hide queries made by localhost?";
	config.dns.ignoreLocalhost.t = CONF_BOOL;
	config.dns.ignoreLocalhost.f = FLAG_ADVANCED_SETTING;
	config.dns.ignoreLocalhost.d.b = false;

	config.dns.showDNSSEC.k = "dns.showDNSSEC";
	config.dns.showDNSSEC.h = "Should FTL should analyze and show internally generated DNSSEC queries?";
	config.dns.showDNSSEC.t = CONF_BOOL;
	config.dns.showDNSSEC.f = FLAG_ADVANCED_SETTING;
	config.dns.showDNSSEC.d.b = true;

	config.dns.analyzeOnlyAandAAAA.k = "dns.analyzeOnlyAandAAAA";
	config.dns.analyzeOnlyAandAAAA.h = "Should FTL analyze *only* A and AAAA queries?";
	config.dns.analyzeOnlyAandAAAA.t = CONF_BOOL;
	config.dns.analyzeOnlyAandAAAA.f = FLAG_ADVANCED_SETTING;
	config.dns.analyzeOnlyAandAAAA.d.b = false;

	config.dns.piholePTR.k = "dns.piholePTR";
	config.dns.piholePTR.h = "Controls whether and how FTL will reply with for address for which a local interface exists.";
	{
		struct enum_options piholePTR[] =
		{
			{ "NONE", "Pi-hole will not respond automatically on PTR requests to local interface addresses. Ensure pi.hole and/or hostname records exist elsewhere." },
			{ "HOSTNAME", "Pi-hole will not respond automatically on PTR requests to local interface addresses. Ensure pi.hole and/or hostname records exist elsewhere." },
			{ "HOSTNAMEFQDN", "Serve the machine's global hostname as fully qualified domain by adding the local suffix. If no local suffix has been defined, FTL appends the local domain .no_fqdn_available. In this case you should either add domain=whatever.com to a custom config file inside /etc/dnsmasq.d/ (to set whatever.com as local domain) or use domain=# which will try to derive the local domain from /etc/resolv.conf (or whatever is set with resolv-file, when multiple search directives exist, the first one is used)." },
			{ "PI.HOLE", "Respond with \"pi.hole\"." }
		};
		CONFIG_ADD_ENUM_OPTIONS(config.dns.piholePTR.a, piholePTR);
	}
	config.dns.piholePTR.t = CONF_ENUM_PTR_TYPE;
	config.dns.piholePTR.f = FLAG_ADVANCED_SETTING;
	config.dns.piholePTR.d.ptr_type = PTR_PIHOLE;

	config.dns.replyWhenBusy.k = "dns.replyWhenBusy";
	config.dns.replyWhenBusy.h = "How should FTL handle queries when the gravity database is not available?";
	{
		struct enum_options replyWhenBusy[] =
		{
			{ "BLOCK", "Block all queries when the database is busy." },
			{ "ALLOW", "Allow all queries when the database is busy." },
			{ "REFUSE", "Refuse all queries which arrive while the database is busy." },
			{ "DROP", "Just drop the queries, i.e., never reply to them at all. Despite \"REFUSE\" sounding similar to \"DROP\", it turned out that many clients will just immediately retry, causing up to several thousands of queries per second. This does not happen in \"DROP\" mode." }
		};
		CONFIG_ADD_ENUM_OPTIONS(config.dns.replyWhenBusy.a, replyWhenBusy);
	}
	config.dns.replyWhenBusy.t = CONF_ENUM_BUSY_TYPE;
	config.dns.replyWhenBusy.f = FLAG_ADVANCED_SETTING;
	config.dns.replyWhenBusy.d.busy_reply = BUSY_ALLOW;

	config.dns.blockTTL.k = "dns.blockTTL";
	config.dns.blockTTL.h = "FTL's internal TTL to be handed out for blocked queries in seconds. This settings allows users to select a value different from the dnsmasq config option local-ttl. This is useful in context of locally used hostnames that are known to stay constant over long times (printers, etc.).\n Note that large values may render whitelisting ineffective due to client-side caching of blocked queries.";
	config.dns.blockTTL.t = CONF_UINT;
	config.dns.blockTTL.f = FLAG_ADVANCED_SETTING;
	config.dns.blockTTL.d.ui = 2;

	config.dns.hosts.k = "dns.hosts";
	config.dns.hosts.h = "Array of custom DNS records\n Example: hosts = [ \"127.0.0.1 mylocal\", \"192.168.0.1 therouter\" ]";
	config.dns.hosts.a = cJSON_CreateStringReference("Array of custom DNS records each one in HOSTS form: \"IP HOSTNAME\"");
	config.dns.hosts.t = CONF_JSON_STRING_ARRAY;
	config.dns.hosts.f = FLAG_ADVANCED_SETTING;
	config.dns.hosts.d.json = cJSON_CreateArray();

	config.dns.domain.k = "dns.domain";
	config.dns.domain.h = "The DNS domain used by your Pi-hole";
	config.dns.domain.a = cJSON_CreateStringReference("<any valid domain>");
	config.dns.domain.t = CONF_STRING;
	config.dns.domain.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.domain.d.s = (char*)"lan";

	config.dns.domain_needed.k = "dns.domain_needed";
	config.dns.domain_needed.h = "If set, A and AAAA queries for plain names, without dots or domain parts, are never forwarded to upstream nameservers";
	config.dns.domain_needed.t = CONF_BOOL;
	config.dns.domain_needed.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.domain_needed.d.b = false;

	config.dns.expand_hosts.k = "dns.expand_hosts";
	config.dns.expand_hosts.h = "If set, the domain is added to simple names (without a period) in /etc/hosts in the same way as for DHCP-derived names";
	config.dns.expand_hosts.t = CONF_BOOL;
	config.dns.expand_hosts.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.expand_hosts.d.b = false;

	config.dns.bogus_priv.k = "dns.bogus_priv";
	config.dns.bogus_priv.h = "Should all reverse lookups for private IP ranges (i.e., 192.168.x.y, etc) which are not found in /etc/hosts or the DHCP leases file be answered with \"no such domain\" rather than being forwarded upstream?";
	config.dns.bogus_priv.t = CONF_BOOL;
	config.dns.bogus_priv.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.bogus_priv.d.b = true;

	config.dns.dnssec.k = "dns.dnssec";
	config.dns.dnssec.h = "Validate DNS replies using DNSSEC?";
	config.dns.dnssec.t = CONF_BOOL;
	config.dns.dnssec.f = FLAG_RESTART_DNSMASQ;
	config.dns.dnssec.d.b = true;

	config.dns.interface.k = "dns.interface";
	config.dns.interface.h = "Interface to use for DNS (see also dnsmasq.listening.mode) and DHCP (if enabled)";
	config.dns.interface.a = cJSON_CreateStringReference("a valid interface name");
	config.dns.interface.t = CONF_STRING;
	config.dns.interface.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.interface.d.s = (char*)"";

	config.dns.host_record.k = "dns.host_record";
	config.dns.host_record.h = "Add A, AAAA and PTR records to the DNS. This adds one or more names to the DNS with associated IPv4 (A) and IPv6 (AAAA) records";
	config.dns.host_record.a = cJSON_CreateStringReference("<name>[,<name>....],[<IPv4-address>],[<IPv6-address>][,<TTL>]");
	config.dns.host_record.t = CONF_STRING;
	config.dns.host_record.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.host_record.d.s = (char*)"";

	config.dns.listening_mode.k = "dns.listening_mode";
	config.dns.listening_mode.h = "Pi-hole interface listening modes";
	{
		struct enum_options listening_mode[] =
		{
			{ "LOCAL", "Allow only local requests. This setting accepts DNS queries only from hosts whose address is on a local subnet, i.e., a subnet for which an interface exists on the server. It is intended to be set as a default on installation, to allow unconfigured installations to be useful but also safe from being used for DNS amplification attacks if (accidentally) running public." },
			{ "SINGLE", "Permit all origins, accept only on the specified interface. Respond only to queries arriving on the specified interface. The loopback (lo) interface is automatically added to the list of interfaces to use when this option is used. Make sure your Pi-hole is properly firewalled!" },
			{ "BIND", "By default, FTL binds the wildcard address. If this is not what you want, you can use this option as it forces FTL to really bind only the interfaces it is listening on. Note that this may result in issues when the interface may go down (cable unplugged, etc.). About the only time when this is useful is when running another nameserver on the same port on the same machine. This may also happen if you run a virtualization API such as libvirt. When this option is used, IP alias interface labels (e.g. enp2s0:0) are checked rather than interface names." },
			{ "ALL", "Permit all origins, accept on all interfaces. Make sure your Pi-hole is properly firewalled! This truly allows any traffic to be replied to and is a dangerous thing to do as your Pi-hole could become an open resolver. You should always ask yourself if the first option doesn't work for you as well." }
		};
		CONFIG_ADD_ENUM_OPTIONS(config.dns.listening_mode.a, listening_mode);
	}
	config.dns.listening_mode.t = CONF_ENUM_LISTENING_MODE;
	config.dns.listening_mode.f = FLAG_RESTART_DNSMASQ;
	config.dns.listening_mode.d.listening_mode = LISTEN_LOCAL;

	config.dns.cache_size.k = "dns.cache_size";
	config.dns.cache_size.h = "Cache size of the DNS server. Note that expiring cache entries naturally make room for new insertions over time. Setting this number too high will have an adverse effect as not only more space is needed, but also lookup speed gets degraded in the 10,000+ range. dnsmasq may issue a warning when you go beyond 10,000+ cache entries.";
	config.dns.cache_size.t = CONF_UINT;
	config.dns.cache_size.f = FLAG_RESTART_DNSMASQ;
	config.dns.cache_size.d.ui = 2000u;

	config.dns.query_logging.k = "dns.query_logging";
	config.dns.query_logging.h = "Log DNS queries and replies to pihole.log";
	config.dns.query_logging.t = CONF_BOOL;
	config.dns.query_logging.f = FLAG_RESTART_DNSMASQ;
	config.dns.query_logging.d.b = true;

	config.dns.cnames.k = "dns.cnames";
	config.dns.cnames.h = "List of CNAME records which indicate that <cname> is really <target>. If the <TTL> is given, it overwrites the value of local-ttl";
	config.dns.cnames.a = cJSON_CreateStringReference("Array of static leases each on in one of the following forms: \"<cname>,<target>[,<TTL>]\"");
	config.dns.cnames.t = CONF_JSON_STRING_ARRAY;
	config.dns.cnames.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.cnames.d.json = cJSON_CreateArray();

	config.dns.port.k = "dns.port";
	config.dns.port.h = "Port used by the DNS server";
	config.dns.port.t = CONF_UINT16;
	config.dns.port.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dns.port.d.ui = 53u;

	// sub-struct dns.blocking
	config.dns.blocking.active.k = "dns.blocking.active";
	config.dns.blocking.active.h = "Should FTL block queries?";
	config.dns.blocking.active.t = CONF_BOOL;
	config.dns.blocking.active.d.b = true;

	config.dns.blocking.mode.k = "dns.blocking.mode";
	config.dns.blocking.mode.h = "How should FTL reply to blocked queries?";
	config.dns.blocking.mode.a = cJSON_CreateStringReference("[ \"NULL\", \"IP-NODATA-AAAA\", \"IP\", \"NXDOMAIN\", \"NODATA\" ]");
	{
		struct enum_options blockingmode[] =
		{
			{ "NULL", "In NULL mode, which is both the default and recommended mode for Pi-hole FTLDNS, blocked queries will be answered with the \"unspecified address\" (0.0.0.0 or ::). The \"unspecified address\" is a reserved IP address specified by RFC 3513 - Internet Protocol Version 6 (IPv6) Addressing Architecture, section 2.5.2." },
			{ "IP-NODATA-AAAA", "In IP-NODATA-AAAA mode, blocked queries will be answered with the local IPv4 addresses of your Pi-hole. Blocked AAAA queries will be answered with NODATA-IPV6 and clients will only try to reach your Pi-hole over its static IPv4 address." },
			{ "IP", "In IP mode, blocked queries will be answered with the local IP addresses of your Pi-hole." },
			{ "NXDOMAIN", "In NXDOMAIN mode, blocked queries will be answered with an empty response (i.e., there won't be an answer section) and status NXDOMAIN. A NXDOMAIN response should indicate that there is no such domain to the client making the query." },
			{ "NODATA", "In NODATA mode, blocked queries will be answered with an empty response (no answer section) and status NODATA. A NODATA response indicates that the domain exists, but there is no record for the requested query type." }
		};
		CONFIG_ADD_ENUM_OPTIONS(config.dns.blocking.mode.a, blockingmode);
	}
	config.dns.blocking.mode.t = CONF_ENUM_BLOCKING_MODE;
	config.dns.blocking.mode.d.blocking_mode = MODE_NULL;

	// sub-struct dns.rate_limit
	config.dns.rateLimit.count.k = "dns.rateLimit.count";
	config.dns.rateLimit.count.h = "Rate-limited queries are answered with a REFUSED reply and not further processed by FTL.\nThe default settings for FTL's rate-limiting are to permit no more than 1000 queries in 60 seconds. Both numbers can be customized independently. It is important to note that rate-limiting is happening on a per-client basis. Other clients can continue to use FTL while rate-limited clients are short-circuited at the same time.\n For this setting, both numbers, the maximum number of queries within a given time, and the length of the time interval (seconds) have to be specified. For instance, if you want to set a rate limit of 1 query per hour, the option should look like RATE_LIMIT=1/3600. The time interval is relative to when FTL has finished starting (start of the daemon + possible delay by DELAY_STARTUP) then it will advance in steps of the rate-limiting interval. If a client reaches the maximum number of queries it will be blocked until the end of the current interval. This will be logged to /var/log/pihole/FTL.log, e.g. Rate-limiting 10.0.1.39 for at least 44 seconds. If the client continues to send queries while being blocked already and this number of queries during the blocking exceeds the limit the client will continue to be blocked until the end of the next interval (FTL.log will contain lines like Still rate-limiting 10.0.1.39 as it made additional 5007 queries). As soon as the client requests less than the set limit, it will be unblocked (Ending rate-limitation of 10.0.1.39).\n Rate-limiting may be disabled altogether by setting both values to zero (this results in the same behavior as before FTL v5.7).\n How many queries are permitted...";
	config.dns.rateLimit.count.t = CONF_UINT;
	config.dns.rateLimit.count.d.ui = 1000;

	config.dns.rateLimit.interval.k = "dns.rateLimit.interval";
	config.dns.rateLimit.interval.h = "... in the set interval before rate-limiting?";
	config.dns.rateLimit.interval.t = CONF_UINT;
	config.dns.rateLimit.interval.d.ui = 60;

	// sub-struct dns.special_domains
	config.dns.specialDomains.mozillaCanary.k = "dns.specialDomains.mozillaCanary";
	config.dns.specialDomains.mozillaCanary.h = "Should Pi-hole always replies with NXDOMAIN to A and AAAA queries of use-application-dns.net to disable Firefox automatic DNS-over-HTTP? This is following the recommendation on https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https";
	config.dns.specialDomains.mozillaCanary.t = CONF_BOOL;
	config.dns.specialDomains.mozillaCanary.d.b = true;

	config.dns.specialDomains.iCloudPrivateRelay.k = "dns.specialDomains.iCloudPrivateRelay";
	config.dns.specialDomains.iCloudPrivateRelay.h = "Should Pi-hole always replies with NXDOMAIN to A and AAAA queries of mask.icloud.com and mask-h2.icloud.com to disable Apple's iCloud Private Relay to prevent Apple devices from bypassing Pi-hole? This is following the recommendation on https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay";
	config.dns.specialDomains.iCloudPrivateRelay.t = CONF_BOOL;
	config.dns.specialDomains.iCloudPrivateRelay.d.b = true;

	// sub-struct dns.reply_addr
	config.dns.reply.host.overwrite_v4.k = "dns.reply.host.overwrite_v4";
	config.dns.reply.host.overwrite_v4.h = "Use a specific IPv4 address for the Pi-hole host? By default, FTL determines the address of the interface a query arrived on and uses this address for replying to A queries with the most suitable address for the requesting client. This setting can be used to use a fixed, rather than the dynamically obtained, address when Pi-hole responds to the following names: [ \"pi.hole\", \"<the device's hostname>\", \"pi.hole.<local domain>\", \"<the device's hostname>.<local domain>\" ]";
	config.dns.reply.host.overwrite_v4.t = CONF_BOOL;
	config.dns.reply.host.overwrite_v4.f = FLAG_ADVANCED_SETTING;
	config.dns.reply.host.overwrite_v4.d.b = false;

	config.dns.reply.host.v4.k = "dns.reply.host.IPv4";
	config.dns.reply.host.v4.h = "Custom IPv4 address for the Pi-hole host";
	config.dns.reply.host.v4.a = cJSON_CreateStringReference("<valid IPv4 address> or empty string (\"\")");
	config.dns.reply.host.v4.t = CONF_STRUCT_IN_ADDR;
	config.dns.reply.host.v4.f = FLAG_ADVANCED_SETTING;
	memset(&config.dns.reply.host.v4.d.in_addr, 0, sizeof(struct in_addr));

	config.dns.reply.host.overwrite_v6.k = "dns.reply.host.overwrite_v6";
	config.dns.reply.host.overwrite_v6.h = "Use a specific IPv6 address for the Pi-hole host? See description for the IPv4 variant above for further details.";
	config.dns.reply.host.overwrite_v6.t = CONF_BOOL;
	config.dns.reply.host.overwrite_v6.f = FLAG_ADVANCED_SETTING;
	config.dns.reply.host.overwrite_v6.d.b = false;

	config.dns.reply.host.v6.k = "dns.reply.host.IPv6";
	config.dns.reply.host.v6.h = "Custom IPv6 address for the Pi-hole host";
	config.dns.reply.host.v6.a = cJSON_CreateStringReference("<valid IPv6 address> or empty string (\"\")");
	config.dns.reply.host.v6.t = CONF_STRUCT_IN6_ADDR;
	config.dns.reply.host.v6.f = FLAG_ADVANCED_SETTING;
	memset(&config.dns.reply.host.v6.d.in6_addr, 0, sizeof(struct in6_addr));

	config.dns.reply.blocking.overwrite_v4.k = "dns.reply.blocking.overwrite_v4";
	config.dns.reply.blocking.overwrite_v4.h = "Use a specific IPv4 address in IP blocking mode? By default, FTL determines the address of the interface a query arrived on and uses this address for replying to A queries with the most suitable address for the requesting client. This setting can be used to use a fixed, rather than the dynamically obtained, address when Pi-hole responds in the following cases: IP blocking mode is used and this query is to be blocked, regular expressions with the ;reply=IP regex extension.";
	config.dns.reply.blocking.overwrite_v4.t = CONF_BOOL;
	config.dns.reply.blocking.overwrite_v4.f = FLAG_ADVANCED_SETTING;
	config.dns.reply.blocking.overwrite_v4.d.b = false;

	config.dns.reply.blocking.v4.k = "dns.reply.blocking.IPv4";
	config.dns.reply.blocking.v4.h = "Custom IPv4 address for IP blocking mode";
	config.dns.reply.blocking.v4.a = cJSON_CreateStringReference("<valid IPv4 address> or empty string (\"\")");
	config.dns.reply.blocking.v4.t = CONF_STRUCT_IN_ADDR;
	config.dns.reply.blocking.v4.f = FLAG_ADVANCED_SETTING;
	memset(&config.dns.reply.blocking.v4.d.in_addr, 0, sizeof(struct in_addr));

	config.dns.reply.blocking.overwrite_v6.k = "dns.reply.blocking.overwrite_v6";
	config.dns.reply.blocking.overwrite_v6.h = "Use a specific IPv6 address in IP blocking mode? See description for the IPv4 variant above for further details.";
	config.dns.reply.blocking.overwrite_v6.t = CONF_BOOL;
	config.dns.reply.blocking.overwrite_v6.f = FLAG_ADVANCED_SETTING;
	config.dns.reply.blocking.overwrite_v6.d.b = false;

	config.dns.reply.blocking.v6.k = "dns.reply.blocking.IPv6";
	config.dns.reply.blocking.v6.h = "Custom IPv6 address for IP blocking mode";
	config.dns.reply.blocking.v6.a = cJSON_CreateStringReference("<valid IPv6 address> or empty string (\"\")");
	config.dns.reply.blocking.v6.t = CONF_STRUCT_IN6_ADDR;
	config.dns.reply.blocking.v6.f = FLAG_ADVANCED_SETTING;
	memset(&config.dns.reply.blocking.v6.d.in6_addr, 0, sizeof(struct in6_addr));

	// sub-struct rev_server
	config.dns.rev_server.active.k = "dns.rev_server.active";
	config.dns.rev_server.active.h = "Is the reverse server (former also called \"conditional forwarding\") feature enabled?";
	config.dns.rev_server.active.t = CONF_BOOL;
	config.dns.rev_server.active.d.b = false;
	config.dns.rev_server.active.f = FLAG_RESTART_DNSMASQ;

	config.dns.rev_server.cidr.k = "dns.rev_server.cidr";
	config.dns.rev_server.cidr.h = "Address range for the reverse server feature in CIDR notation. If the prefix length is omitted, either 32 (IPv4) or 128 (IPv6) are substitutet (exact address match). This is almost certainly not what you want here.";
	config.dns.rev_server.cidr.a = cJSON_CreateStringReference("<ip-address>[/<prefix-len>], e.g., \"192.168.0.0/24\" for the range 192.168.0.1 - 192.168.0.255");
	config.dns.rev_server.cidr.t = CONF_STRING;
	config.dns.rev_server.cidr.d.s = (char*)"";
	config.dns.rev_server.cidr.f = FLAG_RESTART_DNSMASQ;

	config.dns.rev_server.target.k = "dns.rev_server.target";
	config.dns.rev_server.target.h = "Target server tp be used for the reverse server feature";
	config.dns.rev_server.target.a = cJSON_CreateStringReference("<server>[#<port>], e.g., \"192.168.0.1\"");
	config.dns.rev_server.target.t = CONF_STRING;
	config.dns.rev_server.target.d.s = (char*)"";
	config.dns.rev_server.target.f = FLAG_RESTART_DNSMASQ;

	config.dns.rev_server.domain.k = "dns.rev_server.domain";
	config.dns.rev_server.domain.h = "Domain used for the reverse server feature";
	config.dns.rev_server.domain.a = cJSON_CreateStringReference("<valid domain>, typically set to the same value as dns.domain");
	config.dns.rev_server.domain.t = CONF_STRING;
	config.dns.rev_server.domain.d.s = (char*)"";
	config.dns.rev_server.domain.f = FLAG_RESTART_DNSMASQ;

	// sub-struct dhcp
	config.dhcp.active.k = "dhcp.active";
	config.dhcp.active.h = "Is the embedded DHCP server enabled?";
	config.dhcp.active.t = CONF_BOOL;
	config.dhcp.active.f = FLAG_RESTART_DNSMASQ;
	config.dhcp.active.d.b = false;

	config.dhcp.start.k = "dhcp.start";
	config.dhcp.start.h = "Start address of the DHCP address pool";
	config.dhcp.start.a = cJSON_CreateStringReference("<ip-addr>, e.g., \"192.168.0.10\"");
	config.dhcp.start.t = CONF_STRING;
	config.dhcp.start.f = FLAG_RESTART_DNSMASQ;
	config.dhcp.start.d.s = (char*)"";

	config.dhcp.end.k = "dhcp.end";
	config.dhcp.end.h = "End address of the DHCP address pool";
	config.dhcp.end.a = cJSON_CreateStringReference("<ip-addr>, e.g., \"192.168.0.250\"");
	config.dhcp.end.t = CONF_STRING;
	config.dhcp.end.f = FLAG_RESTART_DNSMASQ;
	config.dhcp.end.d.s = (char*)"";

	config.dhcp.router.k = "dhcp.router";
	config.dhcp.router.h = "Address of the gateway to be used (typicaly the address of your router in a home installation)";
	config.dhcp.router.a = cJSON_CreateStringReference("<ip-addr>, e.g., \"192.168.0.1\"");
	config.dhcp.router.t = CONF_STRING;
	config.dhcp.router.f = FLAG_RESTART_DNSMASQ;
	config.dhcp.router.d.s = (char*)"";

	config.dhcp.leasetime.k = "dhcp.leasetime";
	config.dhcp.leasetime.h = "If the lease time is given, then leases will be given for that length of time. If not given, the default lease time is one hour for IPv4 and one day for IPv6.";
	config.dhcp.leasetime.a = cJSON_CreateStringReference("The lease time can be in seconds, or minutes (e.g., \"45m\") or hours (e.g., \"1h\") or days (like \"2d\") or even weeks (\"1w\"). You may also use \"infinite\" as string but be aware of the drawbacks");
	config.dhcp.leasetime.t = CONF_STRING;
	config.dhcp.leasetime.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dhcp.leasetime.d.s = (char*)"";

	config.dhcp.ipv6.k = "dhcp.ipv6";
	config.dhcp.ipv6.h = "Should Pi-hole make an attempt to also satisfy IPv6 address requests (be aware that IPv6 works a whole lot different than IPv4)";
	config.dhcp.ipv6.t = CONF_BOOL;
	config.dhcp.ipv6.f = FLAG_RESTART_DNSMASQ;
	config.dhcp.ipv6.d.b = false;

	config.dhcp.rapid_commit.k = "dhcp.rapid_commit";
	config.dhcp.rapid_commit.h = "Enable DHCPv4 Rapid Commit Option specified in RFC 4039. Should only be enabled if either the server is the only server for the subnet to avoid conflicts";
	config.dhcp.rapid_commit.t = CONF_BOOL;
	config.dhcp.rapid_commit.f = FLAG_RESTART_DNSMASQ;
	config.dhcp.rapid_commit.d.b = false;

	config.dhcp.hosts.k = "dhcp.hosts";
	config.dhcp.hosts.h = "Per host parameters for the DHCP server. This allows a machine with a particular hardware address to be always allocated the same hostname, IP address and lease time or to specify static DHCP leases";
	config.dhcp.hosts.a = cJSON_CreateStringReference("Array of static leases each on in one of the following forms: \"[<hwaddr>][,id:<client_id>|*][,set:<tag>][,tag:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]\"");
	config.dhcp.hosts.t = CONF_JSON_STRING_ARRAY;
	config.dhcp.hosts.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	config.dhcp.hosts.d.json = cJSON_CreateArray();


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
	config.resolver.networkNames.h = "Control whether FTL should use the fallback option to try to obtain client names from checking the network table. This behavior can be disabled with this option.\nAssume an IPv6 client without a host names. However, the network table knows - though the client's MAC address - that this is the same device where we have a host name for another IP address (e.g., a DHCP server managed IPv4 address). In this case, we use the host name associated to the other address as this is the same device.";
	config.resolver.networkNames.t = CONF_BOOL;
	config.resolver.networkNames.f = FLAG_ADVANCED_SETTING;
	config.resolver.networkNames.d.b = true;

	config.resolver.refreshNames.k = "resolver.refreshNames";
	config.resolver.refreshNames.h = "With this option, you can change how (and if) hourly PTR requests are made to check for changes in client and upstream server hostnames.";
	{
		struct enum_options refreshNames[] =
		{
			{ "IPV4_ONLY", "Do hourly PTR lookups only for IPv4 addresses. This is the new default since Pi-hole FTL v5.3.2. It should resolve issues with more and more very short-lived PE IPv6 addresses coming up in a lot of networks." },
			{ "ALL", "Do hourly PTR lookups for all addresses. This was the default until FTL v5.3(.1). It has been replaced as it can create a lot of PTR queries for those with many IPv6 addresses in their networks." },
			{ "UNKNOWN", "Only resolve unknown hostnames. Already existing hostnames are never refreshed, i.e., there will be no PTR queries made for clients where hostnames are known. This also means that known hostnames will not be updated once known." },
			{ "NONE", "Don't do any hourly PTR lookups. This means we look host names up exactly once (when we first see a client) and never again. You may miss future changes of host names." }
		};
		CONFIG_ADD_ENUM_OPTIONS(config.resolver.refreshNames.a, refreshNames);
	}
	config.resolver.refreshNames.t = CONF_ENUM_REFRESH_HOSTNAMES;
	config.resolver.refreshNames.f = FLAG_ADVANCED_SETTING;
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
	config.database.network.parseARPcache.h = "Should FTL anaylze the local ARP cache? When disabled, client identification and the network table will stop working reliably.";
	config.database.network.parseARPcache.t = CONF_BOOL;
	config.database.network.parseARPcache.f = FLAG_ADVANCED_SETTING;
	config.database.network.parseARPcache.d.b = true;

	config.database.network.expire.k = "database.network.expire";
	config.database.network.expire.h = "How long should IP addresses be kept in the network_addresses table [days]? IP addresses (and associated host names) older than the specified number of days are removed to avoid dead entries in the network overview table.";
	config.database.network.expire.t = CONF_UINT;
	config.database.network.expire.f = FLAG_ADVANCED_SETTING;
	config.database.network.expire.d.ui = config.database.maxDBdays.d.ui;


	// struct http
	config.webserver.domain.k = "webserver.domain";
	config.webserver.domain.h = "On which domain is the web interface served?";
	config.webserver.domain.a = cJSON_CreateStringReference("<valid domain>");
	config.webserver.domain.t = CONF_STRING;
	config.webserver.domain.d.s = (char*)"pi.hole";

	config.webserver.acl.k = "webserver.acl";
	config.webserver.acl.h = "Webserver access control list (ACL) allowing for restrictions to be put on the list of IP addresses which have access to the web server. The ACL is a comma separated list of IP subnets, where each subnet is prepended by either a - or a + sign. A plus sign means allow, where a minus sign means deny. If a subnet mask is omitted, such as -1.2.3.4, this means to deny only that single IP address. If this value is not set (empty string), all accesses are allowed. Otherwise, the default setting is to deny all accesses. On each request the full list is traversed, and the last (!) match wins. IPv6 addresses may be specified in CIDR-form [a:b::c]/64.\n\n Example 1: acl = \"+127.0.0.1,+[::1]\"\n ---> deny all access, except from 127.0.0.1 and ::1,\n Example 2: acl = \"+192.168.0.0/16\"\n ---> deny all accesses, except from the 192.168.0.0/16 subnet,\n Example 3: acl = \"+[::]/0\" ---> allow only IPv6 access.";
	config.webserver.acl.a = cJSON_CreateStringReference("<valid ACL>");
	config.webserver.acl.f = FLAG_ADVANCED_SETTING;
	config.webserver.acl.t = CONF_STRING;
	config.webserver.acl.d.s = (char*)"";

	config.webserver.port.k = "webserver.port";
	config.webserver.port.h = "Ports to be used by the webserver. Comma-separated list of ports to listen on. It is possible to specify an IP address to bind to. In this case, an IP address and a colon must be prepended to the port number. For example, to bind to the loopback interface on port 80 (IPv4) and to all interfaces port 8080 (IPv4), use \"127.0.0.1:80,8080\". \"[::]:8080\" can be used to listen to IPv6 connections to port 8080. IPv6 addresses of network interfaces can be specified as well, e.g. \"[::1]:8080\" for the IPv6 loopback interface. [::]:80 will bind to port 80 IPv6 only.\n In order to use port 8080 for all interfaces, both IPv4 and IPv6, use either the configuration \"8080,[::]:8080\" (create one socket for IPv4 and one for IPv6 only), or \"+8080\" (create one socket for both, IPv4 and IPv6). The + notation to use IPv4 and IPv6 will only work if no network interface is specified. Depending on your operating system version and IPv6 network environment, some configurations might not work as expected, so you have to test to find the configuration most suitable for your needs. In case \"+8080\" does not work for your environment, you need to use \"8080,[::]:8080\".";
	config.webserver.port.a = cJSON_CreateStringReference("comma-separated list of <[ip_address:]port>");
	config.webserver.port.t = CONF_STRING;
	config.webserver.port.d.s = (char*)"8080,[::]:8080";

	// sub-struct paths
	config.webserver.paths.webroot.k = "webserver.paths.webroot";
	config.webserver.paths.webroot.h = "Server root on the host";
	config.webserver.paths.webroot.a = cJSON_CreateStringReference("<valid path>");
	config.webserver.paths.webroot.t = CONF_STRING;
	config.webserver.paths.webroot.f = FLAG_ADVANCED_SETTING;
	config.webserver.paths.webroot.d.s = (char*)"/var/www/html";

	config.webserver.paths.webhome.k = "webserver.paths.webhome";
	config.webserver.paths.webhome.h = "Sub-directory of the root containing the web interface";
	config.webserver.paths.webhome.a = cJSON_CreateStringReference("<valid subpath>, both slashes are needed!");
	config.webserver.paths.webhome.t = CONF_STRING;
	config.webserver.paths.webhome.f = FLAG_ADVANCED_SETTING;
	config.webserver.paths.webhome.d.s = (char*)"/admin/";

	// sub-struct interface
	config.webserver.interface.boxed.k = "webserver.interface.boxed";
	config.webserver.interface.boxed.h = "Should the web interface use the boxed layout?";
	config.webserver.interface.boxed.t = CONF_BOOL;
	config.webserver.interface.boxed.d.b = true;

	config.webserver.interface.theme.k = "webserver.interface.theme";
	config.webserver.interface.theme.h = "Theme used by the Pi-hole web interface";
	config.webserver.interface.theme.a = cJSON_CreateStringReference("<valid themename>");
	config.webserver.interface.theme.t = CONF_STRING;
	config.webserver.interface.theme.d.s = (char*)"default";

	// sub-struct api
	config.webserver.api.localAPIauth.k = "webserver.api.localAPIauth";
	config.webserver.api.localAPIauth.h = "Does local clients need to authenticate to access the API?";
	config.webserver.api.localAPIauth.t = CONF_BOOL;
	config.webserver.api.localAPIauth.d.b = true;

	config.webserver.api.prettyJSON.k = "webserver.api.prettyJSON";
	config.webserver.api.prettyJSON.h = "Should FTL prettify the API output (add extra spaces, newlines and indentation)?";
	config.webserver.api.prettyJSON.t = CONF_BOOL;
	config.webserver.api.prettyJSON.f = FLAG_ADVANCED_SETTING;
	config.webserver.api.prettyJSON.d.b = false;

	config.webserver.api.sessionTimeout.k = "webserver.api.sessionTimeout";
	config.webserver.api.sessionTimeout.h = "How long should a session be considered valid after login [seconds]?";
	config.webserver.api.sessionTimeout.t = CONF_UINT;
	config.webserver.api.sessionTimeout.d.ui = 300;

	config.webserver.api.pwhash.k = "webserver.api.pwhash";
	config.webserver.api.pwhash.h = "API password hash";
	config.webserver.api.pwhash.a = cJSON_CreateStringReference("<valid Pi-hole password hash>");
	config.webserver.api.pwhash.t = CONF_STRING;
	config.webserver.api.pwhash.d.s = (char*)"";

	config.webserver.api.exclude_clients.k = "webserver.api.exclude_clients";
	config.webserver.api.exclude_clients.h = "Array of clients to be excluded from certain API responses\n Example: [ \"192.168.2.56\", \"fe80::341\", \"localhost\" ]";
	config.webserver.api.exclude_clients.a = cJSON_CreateStringReference("array of IP addresses and/or hostnames");
	config.webserver.api.exclude_clients.t = CONF_JSON_STRING_ARRAY;
	config.webserver.api.exclude_clients.d.json = cJSON_CreateArray();

	config.webserver.api.exclude_domains.k = "webserver.api.exclude_domains";
	config.webserver.api.exclude_domains.h = "Array of domains to be excluded from certain API responses\n Example: [ \"google.de\", \"pi-hole.net\" ]";
	config.webserver.api.exclude_domains.a = cJSON_CreateStringReference("array of IP addresses and/or hostnames");
	config.webserver.api.exclude_domains.t = CONF_JSON_STRING_ARRAY;
	config.webserver.api.exclude_domains.d.json = cJSON_CreateArray();

	// sub-struct webserver.api.temp
	config.webserver.api.temp.limit.k = "webserver.api.temp.limit";
	config.webserver.api.temp.limit.h = "Which upper temperature limit should be used by Pi-hole? Temperatures above this limit will be shown as \"hot\". The number specified here is in the unit defined below";
	config.webserver.api.temp.limit.t = CONF_DOUBLE;
	config.webserver.api.temp.limit.d.d = 60.0; // °C

	config.webserver.api.temp.unit.k = "webserver.api.temp.unit";
	config.webserver.api.temp.unit.h = "Which temperature unit should be used for temperatures processed by FTL?";
	{
		struct enum_options temp_unit[] =
		{
			{ "C", "Celsius" },
			{ "F", "Fahrenheit" },
			{ "K", "Kelvin" },
		};
		CONFIG_ADD_ENUM_OPTIONS(config.webserver.api.temp.unit.a, temp_unit);
	}
	config.webserver.api.temp.unit.t = CONF_STRING;
	config.webserver.api.temp.unit.d.s = (char*)"C";


	// struct files
	config.files.pid.k = "files.pid";
	config.files.pid.h = "The file which contains the PID of FTL's main process.";
	config.files.pid.a = cJSON_CreateStringReference("<any writable file>");
	config.files.pid.t = CONF_STRING;
	config.files.pid.f = FLAG_ADVANCED_SETTING;
	config.files.pid.d.s = (char*)"/run/pihole-FTL.pid";

	config.files.database.k = "files.database";
	config.files.database.h = "The location of FTL's long-term database";
	config.files.database.a = cJSON_CreateStringReference("<any FTL database>");
	config.files.database.t = CONF_STRING;
	config.files.database.f = FLAG_ADVANCED_SETTING;
	config.files.database.d.s = (char*)"/etc/pihole/pihole-FTL.db";

	config.files.gravity.k = "files.gravity";
	config.files.gravity.h = "The location of Pi-hole's gravity database";
	config.files.gravity.a = cJSON_CreateStringReference("<any Pi-hole gravity database>");
	config.files.gravity.t = CONF_STRING;
	config.files.gravity.f = FLAG_ADVANCED_SETTING;
	config.files.gravity.d.s = (char*)"/etc/pihole/gravity.db";

	config.files.macvendor.k = "files.macvendor";
	config.files.macvendor.h = "The database containing MAC -> Vendor information for the network table";
	config.files.macvendor.a = cJSON_CreateStringReference("<any Pi-hole macvendor database>");
	config.files.macvendor.t = CONF_STRING;
	config.files.macvendor.f = FLAG_ADVANCED_SETTING;
	config.files.macvendor.d.s = (char*)"/etc/pihole/macvendor.db";

	config.files.setupVars.k = "files.setupVars";
	config.files.setupVars.h = "The config file of Pi-hole";
	config.files.setupVars.a = cJSON_CreateStringReference("<any Pi-hole setupVars file>");
	config.files.setupVars.t = CONF_STRING;
	config.files.setupVars.f = FLAG_ADVANCED_SETTING;
	config.files.setupVars.d.s = (char*)"/etc/pihole/setupVars.conf";

	config.files.http_info.k = "files.http_info";
	config.files.http_info.h = "The log file used by the webserver";
	config.files.http_info.a = cJSON_CreateStringReference("<any writable file>");
	config.files.http_info.t = CONF_STRING;
	config.files.http_info.f = FLAG_ADVANCED_SETTING;
	config.files.http_info.d.s = (char*)"/var/log/pihole/HTTP_info.log";

	config.files.ph7_error.k = "files.ph7_error";
	config.files.ph7_error.h = "The log file used by the dynamic interpreter PH7";
	config.files.ph7_error.a = cJSON_CreateStringReference("<any writable file>");
	config.files.ph7_error.t = CONF_STRING;
	config.files.ph7_error.f = FLAG_ADVANCED_SETTING;
	config.files.ph7_error.d.s = (char*)"/var/log/pihole/PH7.log";

	// sub-struct files.log
	// config.files.log.ftl is set in a separate function

	config.files.log.dnsmasq.k = "files.log.dnsmasq";
	config.files.log.dnsmasq.h = "The log file used by the embedded dnsmasq DNS server";
	config.files.log.dnsmasq.a = cJSON_CreateStringReference("<any writable file>");
	config.files.log.dnsmasq.t = CONF_STRING;
	config.files.log.dnsmasq.f = FLAG_ADVANCED_SETTING;
	config.files.log.dnsmasq.d.s = (char*)"/var/log/pihole/pihole.log";


	// struct misc
	config.misc.privacylevel.k = "misc.privacylevel";
	config.misc.privacylevel.h = "Using privacy levels you can specify which level of detail you want to see in your Pi-hole statistics.";
	{
		struct enum_options privacylevel[] =
		{
			{ "0", "Doesn't hide anything, all statistics are available." },
			{ "1", "Hide domains. This setting disables Top Domains and Top Ads" },
			{ "2", "Hide domains and clients. This setting disables Top Domains, Top Ads, Top Clients and Clients over time." },
			{ "3", "Anonymize everything. This setting disabled almost any statistics and query analysis. There will be no long-term database logging and no Query Log. You will also loose most regex features." }
		};
		CONFIG_ADD_ENUM_OPTIONS(config.misc.privacylevel.a, privacylevel);
	}
	config.misc.privacylevel.t = CONF_ENUM_PRIVACY_LEVEL;
	config.misc.privacylevel.d.privacy_level = PRIVACY_SHOW_ALL;

	config.misc.delay_startup.k = "misc.delay_startup";
	config.misc.delay_startup.h = "During startup, in some configurations, network interfaces appear only late during system startup and are not ready when FTL tries to bind to them. Therefore, you may want FTL to wait a given amount of time before trying to start the DNS revolver. This setting takes any integer value between 0 and 300 seconds. To prevent delayed startup while the system is already running and FTL is restarted, the delay only takes place within the first 180 seconds (hard-coded) after booting.";
	config.misc.delay_startup.t = CONF_UINT;
	config.misc.delay_startup.d.ui = 0;

	config.misc.nice.k = "misc.nice";
	config.misc.nice.h = "Set niceness of pihole-FTL. Defaults to -10 and can be disabled altogether by setting a value of -999. The nice value is an attribute that can be used to influence the CPU scheduler to favor or disfavor a process in scheduling decisions. The range of the nice value varies across UNIX systems. On modern Linux, the range is -20 (high priority = not very nice to other processes) to +19 (low priority).";
	config.misc.nice.t = CONF_INT;
	config.misc.nice.f = FLAG_ADVANCED_SETTING;
	config.misc.nice.d.i = -10;

	config.misc.addr2line.k = "misc.addr2line";
	config.misc.addr2line.h = "Should FTL translate its own stack addresses into code lines during the bug backtrace? This improves the analysis of crashed significantly. It is recommended to leave the option enabled. This option should only be disabled when addr2line is known to not be working correctly on the machine because, in this case, the malfunctioning addr2line can prevent from generating any backtrace at all.";
	config.misc.addr2line.t = CONF_BOOL;
	config.misc.addr2line.f = FLAG_ADVANCED_SETTING;
	config.misc.addr2line.d.b = true;

	// sub-struct misc.check
	config.misc.check.load.k = "misc.check.load";
	config.misc.check.load.h = "Pi-hole is very lightweight on resources. Nevertheless, this does not mean that you should run Pi-hole on a server that is otherwise extremely busy as queuing on the system can lead to unnecessary delays in DNS operation as the system becomes less and less usable as the system load increases because all resources are permanently in use. To account for this, FTL regularly checks the system load. To bring this to your attention, FTL warns about excessive load when the 15 minute system load average exceeds the number of cores.\n This check can be disabled with this setting.";
	config.misc.check.load.t = CONF_BOOL;
	config.misc.check.load.d.b = true;

	config.misc.check.disk.k = "misc.check.disk";
	config.misc.check.disk.h = "FTL stores its long-term history in a database file on disk. Furthermore, FTL stores log files. By default, FTL warns if usage of the disk holding any crucial file exceeds 90%. You can set any integer limit between 0 to 100 (interpreted as percentages) where 0 means that checking of disk usage is disabled.";
	config.misc.check.disk.t = CONF_UINT;
	config.misc.check.disk.d.ui = 90;

	config.misc.check.shmem.k = "misc.check.shmem";
	config.misc.check.shmem.h = "FTL stores history in shared memory to allow inter-process communication with forked dedicated TCP workers. If FTL runs out of memory, it cannot continue to work as queries cannot be analyzed any further. Hence, FTL checks if enough shared memory is available on your system and warns you if this is not the case.\n By default, FTL warns if the shared-memory usage exceeds 90%. You can set any integer limit between 0 to 100 (interpreted as percentages) where 0 means that checking of shared-memory usage is disabled.";
	config.misc.check.shmem.t = CONF_UINT;
	config.misc.check.shmem.d.ui = 90;


	// struct debug
	config.debug.database.k = "debug.database";
	config.debug.database.h = "Print debugging information about database actions. This prints performed SQL statements as well as some general information such as the time it took to store the queries and how many have been saved to the database.";
	config.debug.database.t = CONF_BOOL;
	config.debug.database.f = FLAG_ADVANCED_SETTING;
	config.debug.database.d.b = false;

	config.debug.networking.k = "debug.networking";
	config.debug.networking.h = "Prints a list of the detected interfaces on the startup of pihole-FTL. Also, prints whether these interfaces are IPv4 or IPv6 interfaces.";
	config.debug.networking.t = CONF_BOOL;
	config.debug.networking.f = FLAG_ADVANCED_SETTING;
	config.debug.networking.d.b = false;

	config.debug.locks.k = "debug.locks";
	config.debug.locks.h = "Print information about shared memory locks. Messages will be generated when waiting, obtaining, and releasing a lock.";
	config.debug.locks.t = CONF_BOOL;
	config.debug.locks.f = FLAG_ADVANCED_SETTING;
	config.debug.locks.d.b = false;

	config.debug.queries.k = "debug.queries";
	config.debug.queries.h = "Print extensive query information (domains, types, replies, etc.). This has always been part of the legacy debug mode of pihole-FTL.";
	config.debug.queries.t = CONF_BOOL;
	config.debug.queries.f = FLAG_ADVANCED_SETTING;
	config.debug.queries.d.b = false;

	config.debug.flags.k = "debug.flags";
	config.debug.flags.h = "Print flags of queries received by the DNS hooks. Only effective when DEBUG_QUERIES is enabled as well.";
	config.debug.flags.t = CONF_BOOL;
	config.debug.flags.f = FLAG_ADVANCED_SETTING;
	config.debug.flags.d.b = false;

	config.debug.shmem.k = "debug.shmem";
	config.debug.shmem.h = "Print information about shared memory buffers. Messages are either about creating or enlarging shmem objects or string injections.";
	config.debug.shmem.t = CONF_BOOL;
	config.debug.shmem.f = FLAG_ADVANCED_SETTING;
	config.debug.shmem.d.b = false;

	config.debug.gc.k = "debug.gc";
	config.debug.gc.h = "Print information about garbage collection (GC): What is to be removed, how many have been removed and how long did GC take.";
	config.debug.gc.t = CONF_BOOL;
	config.debug.gc.f = FLAG_ADVANCED_SETTING;
	config.debug.gc.d.b = false;

	config.debug.arp.k = "debug.arp";
	config.debug.arp.h = "Print information about ARP table processing: How long did parsing take, whether read MAC addresses are valid, and if the macvendor.db file exists.";
	config.debug.arp.t = CONF_BOOL;
	config.debug.arp.f = FLAG_ADVANCED_SETTING;
	config.debug.arp.d.b = false;

	config.debug.regex.k = "debug.regex";
	config.debug.regex.h = "Controls if FTLDNS should print extended details about regex matching into FTL.log.";
	config.debug.regex.t = CONF_BOOL;
	config.debug.regex.f = FLAG_ADVANCED_SETTING;
	config.debug.regex.d.b = false;

	config.debug.api.k = "debug.api";
	config.debug.api.h = "Print extra debugging information during telnet API calls. Currently only used to send extra information when getting all queries.";
	config.debug.api.t = CONF_BOOL;
	config.debug.api.f = FLAG_ADVANCED_SETTING;
	config.debug.api.d.b = false;

	config.debug.overtime.k = "debug.overtime";
	config.debug.overtime.h = "Print information about overTime memory operations, such as initializing or moving overTime slots.";
	config.debug.overtime.t = CONF_BOOL;
	config.debug.overtime.f = FLAG_ADVANCED_SETTING;
	config.debug.overtime.d.b = false;

	config.debug.status.k = "debug.status";
	config.debug.status.h = "Print information about status changes for individual queries. This can be useful to identify unexpected unknown queries.";
	config.debug.status.t = CONF_BOOL;
	config.debug.status.f = FLAG_ADVANCED_SETTING;
	config.debug.status.d.b = false;

	config.debug.caps.k = "debug.caps";
	config.debug.caps.h = "Print information about capabilities granted to the pihole-FTL process. The current capabilities are printed on receipt of SIGHUP, i.e., the current set of capabilities can be queried without restarting pihole-FTL (by setting DEBUG_CAPS=true and thereafter sending killall -HUP pihole-FTL).";
	config.debug.caps.t = CONF_BOOL;
	config.debug.caps.f = FLAG_ADVANCED_SETTING;
	config.debug.caps.d.b = false;

	config.debug.dnssec.k = "debug.dnssec";
	config.debug.dnssec.h = "Print information about DNSSEC activity";
	config.debug.dnssec.t = CONF_BOOL;
	config.debug.dnssec.f = FLAG_ADVANCED_SETTING;
	config.debug.dnssec.d.b = false;

	config.debug.vectors.k = "debug.vectors";
	config.debug.vectors.h = "FTL uses dynamically allocated vectors for various tasks. This config option enables extensive debugging information such as information about allocation, referencing, deletion, and appending.";
	config.debug.vectors.t = CONF_BOOL;
	config.debug.vectors.f = FLAG_ADVANCED_SETTING;
	config.debug.vectors.d.b = false;

	config.debug.resolver.k = "debug.resolver";
	config.debug.resolver.h = "Extensive information about hostname resolution like which DNS servers are used in the first and second hostname resolving tries (only affecting internally generated PTR queries).";
	config.debug.resolver.t = CONF_BOOL;
	config.debug.resolver.f = FLAG_ADVANCED_SETTING;
	config.debug.resolver.d.b = false;

	config.debug.edns0.k = "debug.edns0";
	config.debug.edns0.h = "Print debugging information about received EDNS(0) data.";
	config.debug.edns0.t = CONF_BOOL;
	config.debug.edns0.f = FLAG_ADVANCED_SETTING;
	config.debug.edns0.d.b = false;

	config.debug.clients.k = "debug.clients";
	config.debug.clients.h = "Log various important client events such as change of interface (e.g., client switching from WiFi to wired or VPN connection), as well as extensive reporting about how clients were assigned to its groups.";
	config.debug.clients.t = CONF_BOOL;
	config.debug.clients.f = FLAG_ADVANCED_SETTING;
	config.debug.clients.d.b = false;

	config.debug.aliasclients.k = "debug.aliasclients";
	config.debug.aliasclients.h = "Log information related to alias-client processing.";
	config.debug.aliasclients.t = CONF_BOOL;
	config.debug.aliasclients.f = FLAG_ADVANCED_SETTING;
	config.debug.aliasclients.d.b = false;

	config.debug.events.k = "debug.events";
	config.debug.events.h = "Log information regarding FTL's embedded event handling queue.";
	config.debug.events.t = CONF_BOOL;
	config.debug.events.f = FLAG_ADVANCED_SETTING;
	config.debug.events.d.b = false;

	config.debug.helper.k = "debug.helper";
	config.debug.helper.h = "Log information about script helpers, e.g., due to dhcp-script.";
	config.debug.helper.t = CONF_BOOL;
	config.debug.helper.f = FLAG_ADVANCED_SETTING;
	config.debug.helper.d.b = false;

	config.debug.config.k = "debug.config";
	config.debug.config.h = "Print config parsing details";
	config.debug.config.t = CONF_BOOL;
	config.debug.config.f = FLAG_ADVANCED_SETTING;
	config.debug.config.d.b = false;

	config.debug.extra.k = "debug.extra";
	config.debug.extra.h = "Temporary flag that may print additional information. This debug flag is meant to be used whenever needed for temporary investigations. The logged content may change without further notice at any time.";
	config.debug.extra.t = CONF_BOOL;
	config.debug.extra.f = FLAG_ADVANCED_SETTING;
	config.debug.extra.d.b = false;

	config.debug.reserved.k = "debug.reserved";
	config.debug.reserved.h = "Reserved debug flag";
	config.debug.reserved.t = CONF_BOOL;
	config.debug.reserved.f = FLAG_ADVANCED_SETTING;
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
		if(!conf_item->p || !conf_item->k || !conf_item->h)
		{
			log_err("Config option %u/%u is not set!", i, (unsigned int)CONFIG_ELEMENTS);
			continue;
		}

		// Verify that all config options have a type
		if(conf_item->t == 0)
		{
			log_err("Config option %s has no type!", conf_item->k);
			continue;
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
			write_custom_list();
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
	// custom.list
	read_legacy_custom_hosts_config();

	// When we reach this point but the FTL TOML config file exists, it may
	// contain errors such as syntax errors, etc. We move it into a
	// ".broken" location so it can be revisited later
	if(file_exists(GLOBALTOMLPATH))
	{
		const char new_name[] = GLOBALTOMLPATH ".broken";
		rotate_files(new_name);
		rename(GLOBALTOMLPATH, new_name);
	}

	// Initialize the TOML config file
	writeFTLtoml(true);
	write_dnsmasq_config(&config, false, NULL);
	write_custom_list();
}

bool getLogFilePath(void)
{
	// Initialize memory
	memset(&config, 0, sizeof(config));

	// Initialize the config file path
	config.files.log.ftl.k = "files.log.ftl";
	config.files.log.ftl.h = "The location of FTL's log file";
	config.files.log.ftl.a = cJSON_CreateStringReference("<any writable file>");
	config.files.log.ftl.t = CONF_STRING;
	config.files.log.ftl.f = FLAG_ADVANCED_SETTING;
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

const char * __attribute__ ((const)) get_conf_type_str(const enum conf_type type)
{
	switch(type)
	{
		case CONF_BOOL:
			return "boolean";
		case CONF_INT:
			return "integer";
		case CONF_UINT: // fall through
		case CONF_ENUM_PRIVACY_LEVEL:
			return "unsigned integer";
		case CONF_UINT16:
			return "unsigned integer (16 bit)";
		case CONF_LONG:
			return "long integer";
		case CONF_ULONG:
			return "unsigned long integer";
		case CONF_DOUBLE:
			return "double";
		case CONF_STRING: // fall through
		case CONF_STRING_ALLOCATED:
			return "string";
		case CONF_ENUM_PTR_TYPE:
		case CONF_ENUM_BUSY_TYPE:
		case CONF_ENUM_BLOCKING_MODE:
		case CONF_ENUM_REFRESH_HOSTNAMES:
		case CONF_ENUM_LISTENING_MODE:
			return "enum (string)";
		case CONF_STRUCT_IN_ADDR:
			return "IPv4 address";
		case CONF_STRUCT_IN6_ADDR:
			return "IPv6 address";
		case CONF_JSON_STRING_ARRAY:
			return "string array";
		default:
			return "unknown";
	}
}