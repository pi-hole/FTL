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
// lock_shm(), unlock_shm()
#include "shmem.h"
// dnsmasq_failed
#include "daemon.h"

struct config config = { 0 };
static bool config_initialized = false;

// Set debug flags from config struct to global debug_flags array
// This is called whenever the config is reloaded and debug flags may have
// changed
void set_debug_flags(struct config *conf)
{
	// Reset debug flags
	memset(debug_flags, false, sizeof(debug_flags));

	// Loop over all debug options and check if at least one is enabled
	unsigned int elements_set = 0u;
	for(unsigned int i = 0; i < DEBUG_ELEMENTS-1; i++)
	{
		struct conf_item *debug_item = get_debug_item(conf, i);
		if(debug_item->v.b)
		{
			// Add offset of 1 as the first element is "ANY"
			debug_flags[i + 1] = true;
			debug_flags[DEBUG_ANY] = true;
			elements_set++;
		}
	}

	// If all debug flags are set, we set the "ALL" flag. We subtract 1 from
	// DEBUG_ELEMENTS as the last element is "ALL" itself
	conf->debug.all.v.b = elements_set == DEBUG_ELEMENTS-1;
}

void set_all_debug(struct config *conf, const bool status)
{
	// Loop over all debug options and check if all are enabled
	unsigned int elements_set = 0u;
	for(unsigned int i = 0; i < DEBUG_ELEMENTS-1; i++)
	{
		struct conf_item *debug_item = get_debug_item(conf, i);
		if(debug_item->v.b)
			elements_set++;
	}

	const bool all_set = elements_set == DEBUG_ELEMENTS-1;

	// If ALL is false and not all debug flags are set, we do not manipulate
	// the debug flags at all. This is necessary to avoid overwriting individual
	// debug flag settings when the user has set some of them to true and
	// "ALL" to false.
	if(status == false && !all_set)
		return;

	// Loop over all debug options and set them to the desired status
	// We do not set the last element as this is "ALL" itself
	for(unsigned int i = 0; i < DEBUG_ELEMENTS-1; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *debug_item = get_debug_item(conf, i);

		// Set status
		debug_item->v.b = status;
	}
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

		// Safety measure: Exit if this path is too deep
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

struct conf_item *get_debug_item(struct config *conf, const enum debug_flag debug)
{
	// Sanity check
	if(debug > DEBUG_MAX-1)
	{
		log_err("Debug config item with index %u requested but we have only %i debug elements", debug, DEBUG_MAX-1);
		return NULL;
	}

	// Return n-th config element
	return (void*)&conf->debug + debug*sizeof(struct conf_item);
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

void duplicate_config(struct config *dst, struct config *src)
{
	// Post-processing:
	// Initialize and verify config data
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item (original)
		struct conf_item *conf_item = get_conf_item(src, i);

		// Get pointer to memory location of this conf_item (copy)
		struct conf_item *copy_item = get_conf_item(dst, i);

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
			case CONF_PASSWORD: // This is a pseudo-type, it is read-only and cannot be read
			case CONF_ENUM_PTR_TYPE:
			case CONF_ENUM_BUSY_TYPE:
			case CONF_ENUM_BLOCKING_MODE:
			case CONF_ENUM_REFRESH_HOSTNAMES:
			case CONF_ENUM_PRIVACY_LEVEL:
			case CONF_ENUM_LISTENING_MODE:
			case CONF_ENUM_WEB_THEME:
			case CONF_ENUM_TEMP_UNIT:
			case CONF_STRUCT_IN_ADDR:
			case CONF_STRUCT_IN6_ADDR:
			case CONF_ALL_DEBUG_BOOL:
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
bool compare_config_item(const enum conf_type t, const union conf_value *val1, const union conf_value *val2)
{
	// Make a type-dependent copy of the value
	switch(t)
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
		case CONF_ENUM_WEB_THEME:
		case CONF_ENUM_TEMP_UNIT:
		case CONF_STRUCT_IN_ADDR:
		case CONF_STRUCT_IN6_ADDR:
		case CONF_ALL_DEBUG_BOOL:
			// Compare entire union
			return memcmp(val1, val2, sizeof(*val1)) == 0;
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
			// Compare strings
			return strcmp(val1->s, val2->s) == 0;
		case CONF_JSON_STRING_ARRAY:
			// Compare JSON object/array
			return cJSON_Compare(val1->json, val2->json, true);
		case CONF_PASSWORD:
			// This is a pseudo item, we assume it has always been changed when
			// it is specified
			return strcmp(val2->s, PASSWORD_VALUE) != 0;
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
			case CONF_PASSWORD: // This is a pseudo item, it cannot be freed
			case CONF_ENUM_PTR_TYPE:
			case CONF_ENUM_BUSY_TYPE:
			case CONF_ENUM_BLOCKING_MODE:
			case CONF_ENUM_REFRESH_HOSTNAMES:
			case CONF_ENUM_PRIVACY_LEVEL:
			case CONF_ENUM_LISTENING_MODE:
			case CONF_ENUM_WEB_THEME:
			case CONF_ENUM_TEMP_UNIT:
			case CONF_STRUCT_IN_ADDR:
			case CONF_STRUCT_IN6_ADDR:
			case CONF_ALL_DEBUG_BOOL:
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

void initConfig(struct config *conf)
{
	if(config_initialized)
		return;
	config_initialized = true;

	// struct dns
	conf->dns.upstreams.k = "dns.upstreams";
	conf->dns.upstreams.h = "Array of upstream DNS servers used by Pi-hole\n Example: [ \"8.8.8.8\", \"127.0.0.1#5353\", \"docker-resolver\" ]";
	conf->dns.upstreams.a = cJSON_CreateStringReference("array of IP addresses and/or hostnames, optionally with a port (#...)");
	conf->dns.upstreams.t = CONF_JSON_STRING_ARRAY;
	conf->dns.upstreams.d.json = cJSON_CreateArray();
	conf->dns.upstreams.f = FLAG_RESTART_DNSMASQ;

	conf->dns.CNAMEdeepInspect.k = "dns.CNAMEdeepInspect";
	conf->dns.CNAMEdeepInspect.h = "Use this option to control deep CNAME inspection. Disabling it might be beneficial for very low-end devices";
	conf->dns.CNAMEdeepInspect.t = CONF_BOOL;
	conf->dns.CNAMEdeepInspect.f = FLAG_ADVANCED_SETTING;
	conf->dns.CNAMEdeepInspect.d.b = true;

	conf->dns.blockESNI.k = "dns.blockESNI";
	conf->dns.blockESNI.h = "Should _esni. subdomains be blocked by default? Encrypted Server Name Indication (ESNI) is certainly a good step into the right direction to enhance privacy on the web. It prevents on-path observers, including ISPs, coffee shop owners and firewalls, from intercepting the TLS Server Name Indication (SNI) extension by encrypting it. This prevents the SNI from being used to determine which websites users are visiting.\n ESNI will obviously cause issues for pixelserv-tls which will be unable to generate matching certificates on-the-fly when it cannot read the SNI. Cloudflare and Firefox are already enabling ESNI. According to the IEFT draft (link above), we can easily restore piselserv-tls's operation by replying NXDOMAIN to _esni. subdomains of blocked domains as this mimics a \"not configured for this domain\" behavior.";
	conf->dns.blockESNI.t = CONF_BOOL;
	conf->dns.blockESNI.f = FLAG_ADVANCED_SETTING;
	conf->dns.blockESNI.d.b = true;

	conf->dns.EDNS0ECS.k = "dns.EDNS0ECS";
	conf->dns.EDNS0ECS.h = "Should we overwrite the query source when client information is provided through EDNS0 client subnet (ECS) information? This allows Pi-hole to obtain client IPs even if they are hidden behind the NAT of a router. This feature has been requested and discussed on Discourse where further information how to use it can be found: https://discourse.pi-hole.net/t/support-for-add-subnet-option-from-dnsmasq-ecs-edns0-client-subnet/35940";
	conf->dns.EDNS0ECS.t = CONF_BOOL;
	conf->dns.EDNS0ECS.f = FLAG_ADVANCED_SETTING;
	conf->dns.EDNS0ECS.d.b = true;

	conf->dns.ignoreLocalhost.k = "dns.ignoreLocalhost";
	conf->dns.ignoreLocalhost.h = "Should FTL hide queries made by localhost?";
	conf->dns.ignoreLocalhost.t = CONF_BOOL;
	conf->dns.ignoreLocalhost.f = FLAG_ADVANCED_SETTING;
	conf->dns.ignoreLocalhost.d.b = false;

	conf->dns.showDNSSEC.k = "dns.showDNSSEC";
	conf->dns.showDNSSEC.h = "Should FTL should analyze and show internally generated DNSSEC queries?";
	conf->dns.showDNSSEC.t = CONF_BOOL;
	conf->dns.showDNSSEC.f = FLAG_ADVANCED_SETTING;
	conf->dns.showDNSSEC.d.b = true;

	conf->dns.analyzeOnlyAandAAAA.k = "dns.analyzeOnlyAandAAAA";
	conf->dns.analyzeOnlyAandAAAA.h = "Should FTL analyze *only* A and AAAA queries?";
	conf->dns.analyzeOnlyAandAAAA.t = CONF_BOOL;
	conf->dns.analyzeOnlyAandAAAA.f = FLAG_ADVANCED_SETTING;
	conf->dns.analyzeOnlyAandAAAA.d.b = false;

	conf->dns.piholePTR.k = "dns.piholePTR";
	conf->dns.piholePTR.h = "Controls whether and how FTL will reply with for address for which a local interface exists.";
	{
		struct enum_options piholePTR[] =
		{
			{ "NONE", "Pi-hole will not respond automatically on PTR requests to local interface addresses. Ensure pi.hole and/or hostname records exist elsewhere." },
			{ "HOSTNAME", "Pi-hole will not respond automatically on PTR requests to local interface addresses. Ensure pi.hole and/or hostname records exist elsewhere." },
			{ "HOSTNAMEFQDN", "Serve the machine's global hostname as fully qualified domain by adding the local suffix. If no local suffix has been defined, FTL appends the local domain .no_fqdn_available. In this case you should either add domain=whatever.com to a custom config file inside /etc/dnsmasq.d/ (to set whatever.com as local domain) or use domain=# which will try to derive the local domain from /etc/resolv.conf (or whatever is set with resolv-file, when multiple search directives exist, the first one is used)." },
			{ "PI.HOLE", "Respond with \"pi.hole\"." }
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->dns.piholePTR.a, piholePTR);
	}
	conf->dns.piholePTR.t = CONF_ENUM_PTR_TYPE;
	conf->dns.piholePTR.f = FLAG_ADVANCED_SETTING;
	conf->dns.piholePTR.d.ptr_type = PTR_PIHOLE;

	conf->dns.replyWhenBusy.k = "dns.replyWhenBusy";
	conf->dns.replyWhenBusy.h = "How should FTL handle queries when the gravity database is not available?";
	{
		struct enum_options replyWhenBusy[] =
		{
			{ "BLOCK", "Block all queries when the database is busy." },
			{ "ALLOW", "Allow all queries when the database is busy." },
			{ "REFUSE", "Refuse all queries which arrive while the database is busy." },
			{ "DROP", "Just drop the queries, i.e., never reply to them at all. Despite \"REFUSE\" sounding similar to \"DROP\", it turned out that many clients will just immediately retry, causing up to several thousands of queries per second. This does not happen in \"DROP\" mode." }
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->dns.replyWhenBusy.a, replyWhenBusy);
	}
	conf->dns.replyWhenBusy.t = CONF_ENUM_BUSY_TYPE;
	conf->dns.replyWhenBusy.f = FLAG_ADVANCED_SETTING;
	conf->dns.replyWhenBusy.d.busy_reply = BUSY_ALLOW;

	conf->dns.blockTTL.k = "dns.blockTTL";
	conf->dns.blockTTL.h = "FTL's internal TTL to be handed out for blocked queries in seconds. This settings allows users to select a value different from the dnsmasq config option local-ttl. This is useful in context of locally used hostnames that are known to stay constant over long times (printers, etc.).\n Note that large values may render whitelisting ineffective due to client-side caching of blocked queries.";
	conf->dns.blockTTL.t = CONF_UINT;
	conf->dns.blockTTL.f = FLAG_ADVANCED_SETTING;
	conf->dns.blockTTL.d.ui = 2;

	conf->dns.hosts.k = "dns.hosts";
	conf->dns.hosts.h = "Array of custom DNS records\n Example: hosts = [ \"127.0.0.1 mylocal\", \"192.168.0.1 therouter\" ]";
	conf->dns.hosts.a = cJSON_CreateStringReference("Array of custom DNS records each one in HOSTS form: \"IP HOSTNAME\"");
	conf->dns.hosts.t = CONF_JSON_STRING_ARRAY;
	conf->dns.hosts.f = FLAG_ADVANCED_SETTING | FLAG_RESTART_DNSMASQ;
	conf->dns.hosts.d.json = cJSON_CreateArray();

	conf->dns.domainNeeded.k = "dns.domainNeeded";
	conf->dns.domainNeeded.h = "If set, A and AAAA queries for plain names, without dots or domain parts, are never forwarded to upstream nameservers";
	conf->dns.domainNeeded.t = CONF_BOOL;
	conf->dns.domainNeeded.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.domainNeeded.d.b = false;

	conf->dns.expandHosts.k = "dns.expandHosts";
	conf->dns.expandHosts.h = "If set, the domain is added to simple names (without a period) in /etc/hosts in the same way as for DHCP-derived names";
	conf->dns.expandHosts.t = CONF_BOOL;
	conf->dns.expandHosts.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.expandHosts.d.b = false;

	conf->dns.bogusPriv.k = "dns.bogusPriv";
	conf->dns.bogusPriv.h = "Should all reverse lookups for private IP ranges (i.e., 192.168.x.y, etc) which are not found in /etc/hosts or the DHCP leases file be answered with \"no such domain\" rather than being forwarded upstream?";
	conf->dns.bogusPriv.t = CONF_BOOL;
	conf->dns.bogusPriv.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.bogusPriv.d.b = true;

	conf->dns.dnssec.k = "dns.dnssec";
	conf->dns.dnssec.h = "Validate DNS replies using DNSSEC?";
	conf->dns.dnssec.t = CONF_BOOL;
	conf->dns.dnssec.f = FLAG_RESTART_DNSMASQ;
	conf->dns.dnssec.d.b = true;

	conf->dns.interface.k = "dns.interface";
	conf->dns.interface.h = "Interface to use for DNS (see also dnsmasq.listening.mode) and DHCP (if enabled)";
	conf->dns.interface.a = cJSON_CreateStringReference("a valid interface name");
	conf->dns.interface.t = CONF_STRING;
	conf->dns.interface.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.interface.d.s = (char*)"";

	conf->dns.hostRecord.k = "dns.hostRecord";
	conf->dns.hostRecord.h = "Add A, AAAA and PTR records to the DNS. This adds one or more names to the DNS with associated IPv4 (A) and IPv6 (AAAA) records";
	conf->dns.hostRecord.a = cJSON_CreateStringReference("<name>[,<name>....],[<IPv4-address>],[<IPv6-address>][,<TTL>]");
	conf->dns.hostRecord.t = CONF_STRING;
	conf->dns.hostRecord.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.hostRecord.d.s = (char*)"";

	conf->dns.listeningMode.k = "dns.listeningMode";
	conf->dns.listeningMode.h = "Pi-hole interface listening modes";
	{
		struct enum_options listeningMode[] =
		{
			{ "LOCAL", "Allow only local requests. This setting accepts DNS queries only from hosts whose address is on a local subnet, i.e., a subnet for which an interface exists on the server. It is intended to be set as a default on installation, to allow unconfigured installations to be useful but also safe from being used for DNS amplification attacks if (accidentally) running public." },
			{ "SINGLE", "Permit all origins, accept only on the specified interface. Respond only to queries arriving on the specified interface. The loopback (lo) interface is automatically added to the list of interfaces to use when this option is used. Make sure your Pi-hole is properly firewalled!" },
			{ "BIND", "By default, FTL binds the wildcard address. If this is not what you want, you can use this option as it forces FTL to really bind only the interfaces it is listening on. Note that this may result in issues when the interface may go down (cable unplugged, etc.). About the only time when this is useful is when running another nameserver on the same port on the same machine. This may also happen if you run a virtualization API such as libvirt. When this option is used, IP alias interface labels (e.g. enp2s0:0) are checked rather than interface names." },
			{ "ALL", "Permit all origins, accept on all interfaces. Make sure your Pi-hole is properly firewalled! This truly allows any traffic to be replied to and is a dangerous thing to do as your Pi-hole could become an open resolver. You should always ask yourself if the first option doesn't work for you as well." }
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->dns.listeningMode.a, listeningMode);
	}
	conf->dns.listeningMode.t = CONF_ENUM_LISTENING_MODE;
	conf->dns.listeningMode.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.listeningMode.d.listeningMode = LISTEN_LOCAL;

	conf->dns.queryLogging.k = "dns.queryLogging";
	conf->dns.queryLogging.h = "Log DNS queries and replies to pihole.log";
	conf->dns.queryLogging.t = CONF_BOOL;
	conf->dns.queryLogging.f = FLAG_RESTART_DNSMASQ;
	conf->dns.queryLogging.d.b = true;

	conf->dns.cnameRecords.k = "dns.cnameRecords";
	conf->dns.cnameRecords.h = "List of CNAME records which indicate that <cname> is really <target>. If the <TTL> is given, it overwrites the value of local-ttl";
	conf->dns.cnameRecords.a = cJSON_CreateStringReference("Array of static leases each on in one of the following forms: \"<cname>,<target>[,<TTL>]\"");
	conf->dns.cnameRecords.t = CONF_JSON_STRING_ARRAY;
	conf->dns.cnameRecords.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.cnameRecords.d.json = cJSON_CreateArray();

	conf->dns.port.k = "dns.port";
	conf->dns.port.h = "Port used by the DNS server";
	conf->dns.port.t = CONF_UINT16;
	conf->dns.port.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.port.d.ui = 53u;

	// sub-struct dns.cache
	conf->dns.cache.size.k = "dns.cache.size";
	conf->dns.cache.size.h = "Cache size of the DNS server. Note that expiring cache entries naturally make room for new insertions over time. Setting this number too high will have an adverse effect as not only more space is needed, but also lookup speed gets degraded in the 10,000+ range. dnsmasq may issue a warning when you go beyond 10,000+ cache entries.";
	conf->dns.cache.size.t = CONF_UINT;
	conf->dns.cache.size.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.cache.size.d.ui = 10000u;

	conf->dns.cache.optimizer.k = "dns.cache.optimizer";
	conf->dns.cache.optimizer.h = "Query cache optimizer: If a DNS name exists in the cache, but its time-to-live has expired only recently, the data will be used anyway (a refreshing from upstream is triggered). This can improve DNS query delays especially over unreliable Internet connections. This feature comes at the expense of possibly sometimes returning out-of-date data and less efficient cache utilisation, since old data cannot be flushed when its TTL expires, so the cache becomes mostly least-recently-used. To mitigate issues caused by massively outdated DNS replies, the maximum overaging of cached records is limited. We strongly recommend staying below 86400 (1 day) with this option.";
	conf->dns.cache.optimizer.t = CONF_UINT;
	conf->dns.cache.optimizer.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dns.cache.optimizer.d.ui = 3600u;

	// sub-struct dns.blocking
	conf->dns.blocking.active.k = "dns.blocking.active";
	conf->dns.blocking.active.h = "Should FTL block queries?";
	conf->dns.blocking.active.t = CONF_BOOL;
	conf->dns.blocking.active.d.b = true;

	conf->dns.blocking.mode.k = "dns.blocking.mode";
	conf->dns.blocking.mode.h = "How should FTL reply to blocked queries?";
	{
		struct enum_options blockingmode[] =
		{
			{ "NULL", "In NULL mode, which is both the default and recommended mode for Pi-hole FTLDNS, blocked queries will be answered with the \"unspecified address\" (0.0.0.0 or ::). The \"unspecified address\" is a reserved IP address specified by RFC 3513 - Internet Protocol Version 6 (IPv6) Addressing Architecture, section 2.5.2." },
			{ "IP-NODATA-AAAA", "In IP-NODATA-AAAA mode, blocked queries will be answered with the local IPv4 addresses of your Pi-hole. Blocked AAAA queries will be answered with NODATA-IPV6 and clients will only try to reach your Pi-hole over its static IPv4 address." },
			{ "IP", "In IP mode, blocked queries will be answered with the local IP addresses of your Pi-hole." },
			{ "NXDOMAIN", "In NXDOMAIN mode, blocked queries will be answered with an empty response (i.e., there won't be an answer section) and status NXDOMAIN. A NXDOMAIN response should indicate that there is no such domain to the client making the query." },
			{ "NODATA", "In NODATA mode, blocked queries will be answered with an empty response (no answer section) and status NODATA. A NODATA response indicates that the domain exists, but there is no record for the requested query type." }
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->dns.blocking.mode.a, blockingmode);
	}
	conf->dns.blocking.mode.t = CONF_ENUM_BLOCKING_MODE;
	conf->dns.blocking.mode.d.blocking_mode = MODE_NULL;

	// sub-struct dns.rate_limit
	conf->dns.rateLimit.count.k = "dns.rateLimit.count";
	conf->dns.rateLimit.count.h = "Rate-limited queries are answered with a REFUSED reply and not further processed by FTL.\n The default settings for FTL's rate-limiting are to permit no more than 1000 queries in 60 seconds. Both numbers can be customized independently. It is important to note that rate-limiting is happening on a per-client basis. Other clients can continue to use FTL while rate-limited clients are short-circuited at the same time.\n For this setting, both numbers, the maximum number of queries within a given time, and the length of the time interval (seconds) have to be specified. For instance, if you want to set a rate limit of 1 query per hour, the option should look like RATE_LIMIT=1/3600. The time interval is relative to when FTL has finished starting (start of the daemon + possible delay by DELAY_STARTUP) then it will advance in steps of the rate-limiting interval. If a client reaches the maximum number of queries it will be blocked until the end of the current interval. This will be logged to /var/log/pihole/FTL.log, e.g. Rate-limiting 10.0.1.39 for at least 44 seconds. If the client continues to send queries while being blocked already and this number of queries during the blocking exceeds the limit the client will continue to be blocked until the end of the next interval (FTL.log will contain lines like Still rate-limiting 10.0.1.39 as it made additional 5007 queries). As soon as the client requests less than the set limit, it will be unblocked (Ending rate-limitation of 10.0.1.39).\n Rate-limiting may be disabled altogether by setting both values to zero (this results in the same behavior as before FTL v5.7).\n How many queries are permitted...";
	conf->dns.rateLimit.count.t = CONF_UINT;
	conf->dns.rateLimit.count.d.ui = 1000;

	conf->dns.rateLimit.interval.k = "dns.rateLimit.interval";
	conf->dns.rateLimit.interval.h = "... in the set interval before rate-limiting?";
	conf->dns.rateLimit.interval.t = CONF_UINT;
	conf->dns.rateLimit.interval.d.ui = 60;

	// sub-struct dns.special_domains
	conf->dns.specialDomains.mozillaCanary.k = "dns.specialDomains.mozillaCanary";
	conf->dns.specialDomains.mozillaCanary.h = "Should Pi-hole always replies with NXDOMAIN to A and AAAA queries of use-application-dns.net to disable Firefox automatic DNS-over-HTTP? This is following the recommendation on https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https";
	conf->dns.specialDomains.mozillaCanary.t = CONF_BOOL;
	conf->dns.specialDomains.mozillaCanary.d.b = true;

	conf->dns.specialDomains.iCloudPrivateRelay.k = "dns.specialDomains.iCloudPrivateRelay";
	conf->dns.specialDomains.iCloudPrivateRelay.h = "Should Pi-hole always replies with NXDOMAIN to A and AAAA queries of mask.icloud.com and mask-h2.icloud.com to disable Apple's iCloud Private Relay to prevent Apple devices from bypassing Pi-hole? This is following the recommendation on https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay";
	conf->dns.specialDomains.iCloudPrivateRelay.t = CONF_BOOL;
	conf->dns.specialDomains.iCloudPrivateRelay.d.b = true;

	// sub-struct dns.reply_addr
	conf->dns.reply.host.force4.k = "dns.reply.host.force4";
	conf->dns.reply.host.force4.h = "Use a specific IPv4 address for the Pi-hole host? By default, FTL determines the address of the interface a query arrived on and uses this address for replying to A queries with the most suitable address for the requesting client. This setting can be used to use a fixed, rather than the dynamically obtained, address when Pi-hole responds to the following names: [ \"pi.hole\", \"<the device's hostname>\", \"pi.hole.<local domain>\", \"<the device's hostname>.<local domain>\" ]";
	conf->dns.reply.host.force4.t = CONF_BOOL;
	conf->dns.reply.host.force4.f = FLAG_ADVANCED_SETTING;
	conf->dns.reply.host.force4.d.b = false;

	conf->dns.reply.host.v4.k = "dns.reply.host.IPv4";
	conf->dns.reply.host.v4.h = "Custom IPv4 address for the Pi-hole host";
	conf->dns.reply.host.v4.a = cJSON_CreateStringReference("<valid IPv4 address> or empty string (\"\")");
	conf->dns.reply.host.v4.t = CONF_STRUCT_IN_ADDR;
	conf->dns.reply.host.v4.f = FLAG_ADVANCED_SETTING;
	memset(&conf->dns.reply.host.v4.d.in_addr, 0, sizeof(struct in_addr));

	conf->dns.reply.host.force6.k = "dns.reply.host.force6";
	conf->dns.reply.host.force6.h = "Use a specific IPv6 address for the Pi-hole host? See description for the IPv4 variant above for further details.";
	conf->dns.reply.host.force6.t = CONF_BOOL;
	conf->dns.reply.host.force6.f = FLAG_ADVANCED_SETTING;
	conf->dns.reply.host.force6.d.b = false;

	conf->dns.reply.host.v6.k = "dns.reply.host.IPv6";
	conf->dns.reply.host.v6.h = "Custom IPv6 address for the Pi-hole host";
	conf->dns.reply.host.v6.a = cJSON_CreateStringReference("<valid IPv6 address> or empty string (\"\")");
	conf->dns.reply.host.v6.t = CONF_STRUCT_IN6_ADDR;
	conf->dns.reply.host.v6.f = FLAG_ADVANCED_SETTING;
	memset(&conf->dns.reply.host.v6.d.in6_addr, 0, sizeof(struct in6_addr));

	conf->dns.reply.blocking.force4.k = "dns.reply.blocking.force4";
	conf->dns.reply.blocking.force4.h = "Use a specific IPv4 address in IP blocking mode? By default, FTL determines the address of the interface a query arrived on and uses this address for replying to A queries with the most suitable address for the requesting client. This setting can be used to use a fixed, rather than the dynamically obtained, address when Pi-hole responds in the following cases: IP blocking mode is used and this query is to be blocked, regular expressions with the ;reply=IP regex extension.";
	conf->dns.reply.blocking.force4.t = CONF_BOOL;
	conf->dns.reply.blocking.force4.f = FLAG_ADVANCED_SETTING;
	conf->dns.reply.blocking.force4.d.b = false;

	conf->dns.reply.blocking.v4.k = "dns.reply.blocking.IPv4";
	conf->dns.reply.blocking.v4.h = "Custom IPv4 address for IP blocking mode";
	conf->dns.reply.blocking.v4.a = cJSON_CreateStringReference("<valid IPv4 address> or empty string (\"\")");
	conf->dns.reply.blocking.v4.t = CONF_STRUCT_IN_ADDR;
	conf->dns.reply.blocking.v4.f = FLAG_ADVANCED_SETTING;
	memset(&conf->dns.reply.blocking.v4.d.in_addr, 0, sizeof(struct in_addr));

	conf->dns.reply.blocking.force6.k = "dns.reply.blocking.force6";
	conf->dns.reply.blocking.force6.h = "Use a specific IPv6 address in IP blocking mode? See description for the IPv4 variant above for further details.";
	conf->dns.reply.blocking.force6.t = CONF_BOOL;
	conf->dns.reply.blocking.force6.f = FLAG_ADVANCED_SETTING;
	conf->dns.reply.blocking.force6.d.b = false;

	conf->dns.reply.blocking.v6.k = "dns.reply.blocking.IPv6";
	conf->dns.reply.blocking.v6.h = "Custom IPv6 address for IP blocking mode";
	conf->dns.reply.blocking.v6.a = cJSON_CreateStringReference("<valid IPv6 address> or empty string (\"\")");
	conf->dns.reply.blocking.v6.t = CONF_STRUCT_IN6_ADDR;
	conf->dns.reply.blocking.v6.f = FLAG_ADVANCED_SETTING;
	memset(&conf->dns.reply.blocking.v6.d.in6_addr, 0, sizeof(struct in6_addr));

	// sub-struct revServer
	conf->dns.revServer.active.k = "dns.revServer.active";
	conf->dns.revServer.active.h = "Is the reverse server (former also called \"conditional forwarding\") feature enabled?";
	conf->dns.revServer.active.t = CONF_BOOL;
	conf->dns.revServer.active.d.b = false;
	conf->dns.revServer.active.f = FLAG_RESTART_DNSMASQ;

	conf->dns.revServer.cidr.k = "dns.revServer.cidr";
	conf->dns.revServer.cidr.h = "Address range for the reverse server feature in CIDR notation. If the prefix length is omitted, either 32 (IPv4) or 128 (IPv6) are substitutet (exact address match). This is almost certainly not what you want here.";
	conf->dns.revServer.cidr.a = cJSON_CreateStringReference("<ip-address>[/<prefix-len>], e.g., \"192.168.0.0/24\" for the range 192.168.0.1 - 192.168.0.255");
	conf->dns.revServer.cidr.t = CONF_STRING;
	conf->dns.revServer.cidr.d.s = (char*)"";
	conf->dns.revServer.cidr.f = FLAG_RESTART_DNSMASQ;

	conf->dns.revServer.target.k = "dns.revServer.target";
	conf->dns.revServer.target.h = "Target server tp be used for the reverse server feature";
	conf->dns.revServer.target.a = cJSON_CreateStringReference("<server>[#<port>], e.g., \"192.168.0.1\"");
	conf->dns.revServer.target.t = CONF_STRING;
	conf->dns.revServer.target.d.s = (char*)"";
	conf->dns.revServer.target.f = FLAG_RESTART_DNSMASQ;

	conf->dns.revServer.domain.k = "dns.revServer.domain";
	conf->dns.revServer.domain.h = "Domain used for the reverse server feature";
	conf->dns.revServer.domain.a = cJSON_CreateStringReference("<valid domain>, typically set to the same value as dhcp.domain");
	conf->dns.revServer.domain.t = CONF_STRING;
	conf->dns.revServer.domain.d.s = (char*)"";
	conf->dns.revServer.domain.f = FLAG_RESTART_DNSMASQ;

	// sub-struct dhcp
	conf->dhcp.active.k = "dhcp.active";
	conf->dhcp.active.h = "Is the embedded DHCP server enabled?";
	conf->dhcp.active.t = CONF_BOOL;
	conf->dhcp.active.f = FLAG_RESTART_DNSMASQ;
	conf->dhcp.active.d.b = false;

	conf->dhcp.start.k = "dhcp.start";
	conf->dhcp.start.h = "Start address of the DHCP address pool";
	conf->dhcp.start.a = cJSON_CreateStringReference("<ip-addr>, e.g., \"192.168.0.10\"");
	conf->dhcp.start.t = CONF_STRING;
	conf->dhcp.start.f = FLAG_RESTART_DNSMASQ;
	conf->dhcp.start.d.s = (char*)"";

	conf->dhcp.end.k = "dhcp.end";
	conf->dhcp.end.h = "End address of the DHCP address pool";
	conf->dhcp.end.a = cJSON_CreateStringReference("<ip-addr>, e.g., \"192.168.0.250\"");
	conf->dhcp.end.t = CONF_STRING;
	conf->dhcp.end.f = FLAG_RESTART_DNSMASQ;
	conf->dhcp.end.d.s = (char*)"";

	conf->dhcp.router.k = "dhcp.router";
	conf->dhcp.router.h = "Address of the gateway to be used (typically the address of your router in a home installation)";
	conf->dhcp.router.a = cJSON_CreateStringReference("<ip-addr>, e.g., \"192.168.0.1\"");
	conf->dhcp.router.t = CONF_STRING;
	conf->dhcp.router.f = FLAG_RESTART_DNSMASQ;
	conf->dhcp.router.d.s = (char*)"";

	conf->dhcp.domain.k = "dhcp.domain";
	conf->dhcp.domain.h = "The DNS domain used by your Pi-hole";
	conf->dhcp.domain.a = cJSON_CreateStringReference("<any valid domain>");
	conf->dhcp.domain.t = CONF_STRING;
	conf->dhcp.domain.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dhcp.domain.d.s = (char*)"lan";

	conf->dhcp.leaseTime.k = "dhcp.leaseTime";
	conf->dhcp.leaseTime.h = "If the lease time is given, then leases will be given for that length of time. If not given, the default lease time is one hour for IPv4 and one day for IPv6.";
	conf->dhcp.leaseTime.a = cJSON_CreateStringReference("The lease time can be in seconds, or minutes (e.g., \"45m\") or hours (e.g., \"1h\") or days (like \"2d\") or even weeks (\"1w\"). You may also use \"infinite\" as string but be aware of the drawbacks");
	conf->dhcp.leaseTime.t = CONF_STRING;
	conf->dhcp.leaseTime.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dhcp.leaseTime.d.s = (char*)"";

	conf->dhcp.ipv6.k = "dhcp.ipv6";
	conf->dhcp.ipv6.h = "Should Pi-hole make an attempt to also satisfy IPv6 address requests (be aware that IPv6 works a whole lot different than IPv4)";
	conf->dhcp.ipv6.t = CONF_BOOL;
	conf->dhcp.ipv6.f = FLAG_RESTART_DNSMASQ;
	conf->dhcp.ipv6.d.b = false;

	conf->dhcp.multiDNS.k = "dhcp.multiDNS";
	conf->dhcp.multiDNS.h = "Advertise DNS server multiple times to clients. Some devices will add their own proprietary DNS servers to the list of DNS servers, which can cause issues with Pi-hole. This option will advertise the Pi-hole DNS server multiple times to clients, which should prevent this from happening.";
	conf->dhcp.multiDNS.t = CONF_BOOL;
	conf->dhcp.multiDNS.f = FLAG_RESTART_DNSMASQ;
	conf->dhcp.multiDNS.d.b = false;

	conf->dhcp.rapidCommit.k = "dhcp.rapidCommit";
	conf->dhcp.rapidCommit.h = "Enable DHCPv4 Rapid Commit Option specified in RFC 4039. Should only be enabled if either the server is the only server for the subnet to avoid conflicts";
	conf->dhcp.rapidCommit.t = CONF_BOOL;
	conf->dhcp.rapidCommit.f = FLAG_RESTART_DNSMASQ;
	conf->dhcp.rapidCommit.d.b = false;

	conf->dhcp.hosts.k = "dhcp.hosts";
	conf->dhcp.hosts.h = "Per host parameters for the DHCP server. This allows a machine with a particular hardware address to be always allocated the same hostname, IP address and lease time or to specify static DHCP leases";
	conf->dhcp.hosts.a = cJSON_CreateStringReference("Array of static leases each on in one of the following forms: \"[<hwaddr>][,id:<client_id>|*][,set:<tag>][,tag:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]\"");
	conf->dhcp.hosts.t = CONF_JSON_STRING_ARRAY;
	conf->dhcp.hosts.f = FLAG_RESTART_DNSMASQ | FLAG_ADVANCED_SETTING;
	conf->dhcp.hosts.d.json = cJSON_CreateArray();


	// struct resolver
	conf->resolver.resolveIPv6.k = "resolver.resolveIPv6";
	conf->resolver.resolveIPv6.h = "Should FTL try to resolve IPv6 addresses to hostnames?";
	conf->resolver.resolveIPv6.t = CONF_BOOL;
	conf->resolver.resolveIPv6.d.b = true;

	conf->resolver.resolveIPv4.k = "resolver.resolveIPv4";
	conf->resolver.resolveIPv4.h = "Should FTL try to resolve IPv4 addresses to hostnames?";
	conf->resolver.resolveIPv4.t = CONF_BOOL;
	conf->resolver.resolveIPv4.d.b = true;

	conf->resolver.networkNames.k = "resolver.networkNames";
	conf->resolver.networkNames.h = "Control whether FTL should use the fallback option to try to obtain client names from checking the network table. This behavior can be disabled with this option.\n Assume an IPv6 client without a host names. However, the network table knows - though the client's MAC address - that this is the same device where we have a host name for another IP address (e.g., a DHCP server managed IPv4 address). In this case, we use the host name associated to the other address as this is the same device.";
	conf->resolver.networkNames.t = CONF_BOOL;
	conf->resolver.networkNames.f = FLAG_ADVANCED_SETTING;
	conf->resolver.networkNames.d.b = true;

	conf->resolver.refreshNames.k = "resolver.refreshNames";
	conf->resolver.refreshNames.h = "With this option, you can change how (and if) hourly PTR requests are made to check for changes in client and upstream server hostnames.";
	{
		struct enum_options refreshNames[] =
		{
			{ "IPV4_ONLY", "Do hourly PTR lookups only for IPv4 addresses. This is the new default since Pi-hole FTL v5.3.2. It should resolve issues with more and more very short-lived PE IPv6 addresses coming up in a lot of networks." },
			{ "ALL", "Do hourly PTR lookups for all addresses. This was the default until FTL v5.3(.1). It has been replaced as it can create a lot of PTR queries for those with many IPv6 addresses in their networks." },
			{ "UNKNOWN", "Only resolve unknown hostnames. Already existing hostnames are never refreshed, i.e., there will be no PTR queries made for clients where hostnames are known. This also means that known hostnames will not be updated once known." },
			{ "NONE", "Don't do any hourly PTR lookups. This means we look host names up exactly once (when we first see a client) and never again. You may miss future changes of host names." }
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->resolver.refreshNames.a, refreshNames);
	}
	conf->resolver.refreshNames.t = CONF_ENUM_REFRESH_HOSTNAMES;
	conf->resolver.refreshNames.f = FLAG_ADVANCED_SETTING;
	conf->resolver.refreshNames.d.refresh_hostnames = REFRESH_IPV4_ONLY;


	// struct database
	conf->database.DBimport.k = "database.DBimport";
	conf->database.DBimport.h = "Should FTL load information from the database on startup to be aware of the most recent history?";
	conf->database.DBimport.t = CONF_BOOL;
	conf->database.DBimport.d.b = true;

	conf->database.DBexport.k = "database.DBexport";
	conf->database.DBexport.h =  "Should FTL store queries in the long-term database?";
	conf->database.DBexport.t = CONF_BOOL;
	conf->database.DBexport.d.b = true;

	conf->database.maxDBdays.k = "database.maxDBdays";
	conf->database.maxDBdays.h = "How long should queries be stored in the database [days]?";
	conf->database.maxDBdays.t = CONF_INT;
	conf->database.maxDBdays.d.i = (365/4);

	conf->database.DBinterval.k = "database.DBinterval";
	conf->database.DBinterval.h = "How often do we store queries in FTL's database [seconds]?";
	conf->database.DBinterval.t = CONF_UINT;
	conf->database.DBinterval.d.ui = 60;

	// sub-struct database.network
	conf->database.network.parseARPcache.k = "database.network.parseARPcache";
	conf->database.network.parseARPcache.h = "Should FTL analyze the local ARP cache? When disabled, client identification and the network table will stop working reliably.";
	conf->database.network.parseARPcache.t = CONF_BOOL;
	conf->database.network.parseARPcache.f = FLAG_ADVANCED_SETTING;
	conf->database.network.parseARPcache.d.b = true;

	conf->database.network.expire.k = "database.network.expire";
	conf->database.network.expire.h = "How long should IP addresses be kept in the network_addresses table [days]? IP addresses (and associated host names) older than the specified number of days are removed to avoid dead entries in the network overview table.";
	conf->database.network.expire.t = CONF_UINT;
	conf->database.network.expire.f = FLAG_ADVANCED_SETTING;
	conf->database.network.expire.d.ui = conf->database.maxDBdays.d.ui;


	// struct http
	conf->webserver.domain.k = "webserver.domain";
	conf->webserver.domain.h = "On which domain is the web interface served?";
	conf->webserver.domain.a = cJSON_CreateStringReference("<valid domain>");
	conf->webserver.domain.t = CONF_STRING;
	conf->webserver.domain.d.s = (char*)"pi.hole";

	conf->webserver.acl.k = "webserver.acl";
	conf->webserver.acl.h = "Webserver access control list (ACL) allowing for restrictions to be put on the list of IP addresses which have access to the web server. The ACL is a comma separated list of IP subnets, where each subnet is prepended by either a - or a + sign. A plus sign means allow, where a minus sign means deny. If a subnet mask is omitted, such as -1.2.3.4, this means to deny only that single IP address. If this value is not set (empty string), all accesses are allowed. Otherwise, the default setting is to deny all accesses. On each request the full list is traversed, and the last (!) match wins. IPv6 addresses may be specified in CIDR-form [a:b::c]/64.\n\n Example 1: acl = \"+127.0.0.1,+[::1]\"\n ---> deny all access, except from 127.0.0.1 and ::1,\n Example 2: acl = \"+192.168.0.0/16\"\n ---> deny all accesses, except from the 192.168.0.0/16 subnet,\n Example 3: acl = \"+[::]/0\" ---> allow only IPv6 access.";
	conf->webserver.acl.a = cJSON_CreateStringReference("<valid ACL>");
	conf->webserver.acl.f = FLAG_ADVANCED_SETTING;
	conf->webserver.acl.t = CONF_STRING;
	conf->webserver.acl.d.s = (char*)"";

	conf->webserver.port.k = "webserver.port";
	conf->webserver.port.h = "Ports to be used by the webserver.\n Comma-separated list of ports to listen on. It is possible to specify an IP address to bind to. In this case, an IP address and a colon must be prepended to the port number. For example, to bind to the loopback interface on port 80 (IPv4) and to all interfaces port 8080 (IPv4), use \"127.0.0.1:80,8080\". \"[::]:80\" can be used to listen to IPv6 connections to port 80. IPv6 addresses of network interfaces can be specified as well, e.g. \"[::1]:80\" for the IPv6 loopback interface. [::]:80 will bind to port 80 IPv6 only.\n In order to use port 80 for all interfaces, both IPv4 and IPv6, use either the configuration \"80,[::]:80\" (create one socket for IPv4 and one for IPv6 only), or \"+80\" (create one socket for both, IPv4 and IPv6). The + notation to use IPv4 and IPv6 will only work if no network interface is specified. Depending on your operating system version and IPv6 network environment, some configurations might not work as expected, so you have to test to find the configuration most suitable for your needs. In case \"+80\" does not work for your environment, you need to use \"80,[::]:80\".\n If the port is TLS/SSL, a letter 's' must be appended, for example, \"80,443s\" will open port 80 and port 443, and connections on port 443 will be encrypted. For non-encrypted ports, it is allowed to append letter 'r' (as in redirect). Redirected ports will redirect all their traffic to the first configured SSL port. For example, if webserver.port is \"80r,443s\", then all HTTP traffic coming at port 80 will be redirected to HTTPS port 443.";
	conf->webserver.port.a = cJSON_CreateStringReference("comma-separated list of <[ip_address:]port>");
	conf->webserver.port.t = CONF_STRING;
	conf->webserver.port.d.s = (char*)"80,[::]:80";

	conf->webserver.tls.rev_proxy.k = "webserver.tls.rev_proxy";
	conf->webserver.tls.rev_proxy.h = "Is Pi-hole running behind a reverse proxy? If yes, Pi-hole will not consider HTTP-only connections being insecure. This is useful if you are running Pi-hole in a trusted environment, for example, in a local network, and you are using a reverse proxy to provide TLS encryption, e.g., by using Traefik (docker). If you are using a reverse proxy, you can alternatively set webserver.tls.cert to the path of the TLS certificate file and let Pi-hole handle true end-to-end encryption.";
	conf->webserver.tls.rev_proxy.f = FLAG_ADVANCED_SETTING;
	conf->webserver.tls.rev_proxy.t = CONF_BOOL;
	conf->webserver.tls.rev_proxy.d.b = false;

	conf->webserver.tls.cert.k = "webserver.tls.cert";
	conf->webserver.tls.cert.h = "Path to the TLS (SSL) certificate file. This option is only required when at least one of webserver.port is TLS. The file must be in PEM format, and it must have both, private key and certificate (the *.pem file created must contain a 'CERTIFICATE' section as well as a 'RSA PRIVATE KEY' section).\n The *.pem file can be created using\n     cp server.crt server.pem\n     cat server.key >> server.pem\n if you have these files instead";
	conf->webserver.tls.cert.a = cJSON_CreateStringReference("<valid TLS certificate file (*.pem)>");
	conf->webserver.tls.cert.f = FLAG_ADVANCED_SETTING | FLAG_RESTART_DNSMASQ;
	conf->webserver.tls.cert.t = CONF_STRING;
	conf->webserver.tls.cert.d.s = (char*)"/etc/pihole/tls.pem";

	conf->webserver.sessionTimeout.k = "webserver.sessionTimeout";
	conf->webserver.sessionTimeout.h = "Session timeout in seconds. If a session is inactive for more than this time, it will be terminated. Sessions are continuously refreshed by the web interface, preventing sessions from timing out while the web interface is open.\n This option may also be used to make logins persistent for long times, e.g. 86400 seconds (24 hours), 604800 seconds (7 days) or 2592000 seconds (30 days). Note that the total number of concurrent sessions is limited so setting this value too high may result in users being rejected and unable to log in if there are already too many sessions active.";
	conf->webserver.sessionTimeout.t = CONF_UINT;
	conf->webserver.sessionTimeout.d.ui = 300u;

	// sub-struct paths
	conf->webserver.paths.webroot.k = "webserver.paths.webroot";
	conf->webserver.paths.webroot.h = "Server root on the host";
	conf->webserver.paths.webroot.a = cJSON_CreateStringReference("<valid path>");
	conf->webserver.paths.webroot.t = CONF_STRING;
	conf->webserver.paths.webroot.f = FLAG_ADVANCED_SETTING;
	conf->webserver.paths.webroot.d.s = (char*)"/var/www/html";

	conf->webserver.paths.webhome.k = "webserver.paths.webhome";
	conf->webserver.paths.webhome.h = "Sub-directory of the root containing the web interface";
	conf->webserver.paths.webhome.a = cJSON_CreateStringReference("<valid subpath>, both slashes are needed!");
	conf->webserver.paths.webhome.t = CONF_STRING;
	conf->webserver.paths.webhome.f = FLAG_ADVANCED_SETTING;
	conf->webserver.paths.webhome.d.s = (char*)"/admin/";

	// sub-struct interface
	conf->webserver.interface.boxed.k = "webserver.interface.boxed";
	conf->webserver.interface.boxed.h = "Should the web interface use the boxed layout?";
	conf->webserver.interface.boxed.t = CONF_BOOL;
	conf->webserver.interface.boxed.d.b = true;

	conf->webserver.interface.theme.k = "webserver.interface.theme";
	conf->webserver.interface.theme.h = "Theme used by the Pi-hole web interface";
	{
		struct enum_options themes[] =
		{
			// Remember to adjust enum web_theme when adding more themes!
			{ "default-auto", "Pi-hole auto theme (light/dark, default)" },
			{ "default-light", "Pi-hole day theme (light)" },
			{ "default-dark", "Pi-hole midnight theme (dark)" },
			{ "default-darker", "Pi-hole deep-midnight theme (dark)" },
			{ "high-contrast", "High Contrast theme (light)" },
			{ "high-contrast-dark", "High Contrast theme (dark)" },
			{ "lcars", "Star Trek LCARS theme (dark)" }
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->webserver.interface.theme.a, themes);
	}
	conf->webserver.interface.theme.t = CONF_ENUM_WEB_THEME;
	conf->webserver.interface.theme.d.web_theme = THEME_DEFAULT_AUTO;

	// sub-struct api
	conf->webserver.api.localAPIauth.k = "webserver.api.localAPIauth";
	conf->webserver.api.localAPIauth.h = "Do local clients need to authenticate to access the API?";
	conf->webserver.api.localAPIauth.t = CONF_BOOL;
	conf->webserver.api.localAPIauth.d.b = true;

	conf->webserver.api.prettyJSON.k = "webserver.api.prettyJSON";
	conf->webserver.api.prettyJSON.h = "Should FTL prettify the API output (add extra spaces, newlines and indentation)?";
	conf->webserver.api.prettyJSON.t = CONF_BOOL;
	conf->webserver.api.prettyJSON.f = FLAG_ADVANCED_SETTING;
	conf->webserver.api.prettyJSON.d.b = false;

	conf->webserver.api.pwhash.k = "webserver.api.pwhash";
	conf->webserver.api.pwhash.h = "API password hash";
	conf->webserver.api.pwhash.a = cJSON_CreateStringReference("<valid Pi-hole password hash>");
	conf->webserver.api.pwhash.t = CONF_STRING;
	conf->webserver.api.pwhash.f = FLAG_INVALIDATE_SESSIONS;
	conf->webserver.api.pwhash.d.s = (char*)"";

	conf->webserver.api.password.k = "webserver.api.password";
	conf->webserver.api.password.h = "Pi-hole web interface and API password. When set to something different than \""PASSWORD_VALUE"\", this property will compute the corresponding password hash to set webserver.api.pwhash";
	conf->webserver.api.password.a = cJSON_CreateStringReference("<valid Pi-hole password>");
	conf->webserver.api.password.t = CONF_PASSWORD;
	conf->webserver.api.password.f = FLAG_PSEUDO_ITEM | FLAG_INVALIDATE_SESSIONS;
	conf->webserver.api.password.d.s = (char*)"";

	conf->webserver.api.totp_secret.k = "webserver.api.totp_secret";
	conf->webserver.api.totp_secret.h = "Pi-hole 2FA TOTP secret. When set to something different than \"""\", 2FA authentication will be enforced for the API and the web interface. This setting is write-only, you can not read the secret back.";
	conf->webserver.api.totp_secret.a = cJSON_CreateStringReference("<valid TOTP secret (20 Bytes in Base32 encoding)>");
	conf->webserver.api.totp_secret.t = CONF_STRING;
	conf->webserver.api.totp_secret.f = FLAG_WRITE_ONLY | FLAG_INVALIDATE_SESSIONS;
	conf->webserver.api.totp_secret.d.s = (char*)"";

	conf->webserver.api.excludeClients.k = "webserver.api.excludeClients";
	conf->webserver.api.excludeClients.h = "Array of clients to be excluded from certain API responses\n Example: [ \"192.168.2.56\", \"fe80::341\", \"localhost\" ]";
	conf->webserver.api.excludeClients.a = cJSON_CreateStringReference("array of IP addresses and/or hostnames");
	conf->webserver.api.excludeClients.t = CONF_JSON_STRING_ARRAY;
	conf->webserver.api.excludeClients.d.json = cJSON_CreateArray();

	conf->webserver.api.excludeDomains.k = "webserver.api.excludeDomains";
	conf->webserver.api.excludeDomains.h = "Array of domains to be excluded from certain API responses\n Example: [ \"google.de\", \"pi-hole.net\" ]";
	conf->webserver.api.excludeDomains.a = cJSON_CreateStringReference("array of IP addresses and/or hostnames");
	conf->webserver.api.excludeDomains.t = CONF_JSON_STRING_ARRAY;
	conf->webserver.api.excludeDomains.d.json = cJSON_CreateArray();

	conf->webserver.api.maxHistory.k = "webserver.api.maxHistory";
	conf->webserver.api.maxHistory.h = "How much history should be imported from the database and returned by the API [seconds]? (max 24*60*60 = 86400)";
	conf->webserver.api.maxHistory.t = CONF_UINT;
	conf->webserver.api.maxHistory.d.ui = MAXLOGAGE*3600;

	conf->webserver.api.allow_destructive.k = "webserver.api.allow_destructive";
	conf->webserver.api.allow_destructive.h = "Allow destructive API calls (e.g. deleting all queries, powering off the system, ...)";
	conf->webserver.api.allow_destructive.t = CONF_BOOL;
	conf->webserver.api.allow_destructive.d.b = true;

	// sub-struct webserver.api.temp
	conf->webserver.api.temp.limit.k = "webserver.api.temp.limit";
	conf->webserver.api.temp.limit.h = "Which upper temperature limit should be used by Pi-hole? Temperatures above this limit will be shown as \"hot\". The number specified here is in the unit defined below";
	conf->webserver.api.temp.limit.t = CONF_DOUBLE;
	conf->webserver.api.temp.limit.d.d = 60.0; // °C

	conf->webserver.api.temp.unit.k = "webserver.api.temp.unit";
	conf->webserver.api.temp.unit.h = "Which temperature unit should be used for temperatures processed by FTL?";
	{
		struct enum_options temp_unit[] =
		{
			{ "C", "Celsius" },
			{ "F", "Fahrenheit" },
			{ "K", "Kelvin" },
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->webserver.api.temp.unit.a, temp_unit);
	}
	conf->webserver.api.temp.unit.t = CONF_ENUM_TEMP_UNIT;
	conf->webserver.api.temp.unit.d.temp_unit = TEMP_UNIT_C;


	// struct files
	conf->files.pid.k = "files.pid";
	conf->files.pid.h = "The file which contains the PID of FTL's main process.";
	conf->files.pid.a = cJSON_CreateStringReference("<any writable file>");
	conf->files.pid.t = CONF_STRING;
	conf->files.pid.f = FLAG_ADVANCED_SETTING;
	conf->files.pid.d.s = (char*)"/run/pihole-FTL.pid";

	conf->files.database.k = "files.database";
	conf->files.database.h = "The location of FTL's long-term database";
	conf->files.database.a = cJSON_CreateStringReference("<any FTL database>");
	conf->files.database.t = CONF_STRING;
	conf->files.database.f = FLAG_ADVANCED_SETTING;
	conf->files.database.d.s = (char*)"/etc/pihole/pihole-FTL.db";

	conf->files.gravity.k = "files.gravity";
	conf->files.gravity.h = "The location of Pi-hole's gravity database";
	conf->files.gravity.a = cJSON_CreateStringReference("<any Pi-hole gravity database>");
	conf->files.gravity.t = CONF_STRING;
	conf->files.gravity.f = FLAG_ADVANCED_SETTING;
	conf->files.gravity.d.s = (char*)"/etc/pihole/gravity.db";

	conf->files.macvendor.k = "files.macvendor";
	conf->files.macvendor.h = "The database containing MAC -> Vendor information for the network table";
	conf->files.macvendor.a = cJSON_CreateStringReference("<any Pi-hole macvendor database>");
	conf->files.macvendor.t = CONF_STRING;
	conf->files.macvendor.f = FLAG_ADVANCED_SETTING;
	conf->files.macvendor.d.s = (char*)"/etc/pihole/macvendor.db";

	conf->files.setupVars.k = "files.setupVars";
	conf->files.setupVars.h = "The config file of Pi-hole";
	conf->files.setupVars.a = cJSON_CreateStringReference("<any Pi-hole setupVars file>");
	conf->files.setupVars.t = CONF_STRING;
	conf->files.setupVars.f = FLAG_ADVANCED_SETTING;
	conf->files.setupVars.d.s = (char*)"/etc/pihole/setupVars.conf";

	conf->files.log.webserver.k = "files.log.webserver";
	conf->files.log.webserver.h = "The log file used by the webserver";
	conf->files.log.webserver.a = cJSON_CreateStringReference("<any writable file>");
	conf->files.log.webserver.t = CONF_STRING;
	conf->files.log.webserver.f = FLAG_ADVANCED_SETTING;
	conf->files.log.webserver.d.s = (char*)"/var/log/pihole/webserver.log";

	// sub-struct files.log
	// conf->files.log.ftl is set in a separate function

	conf->files.log.dnsmasq.k = "files.log.dnsmasq";
	conf->files.log.dnsmasq.h = "The log file used by the embedded dnsmasq DNS server";
	conf->files.log.dnsmasq.a = cJSON_CreateStringReference("<any writable file>");
	conf->files.log.dnsmasq.t = CONF_STRING;
	conf->files.log.dnsmasq.f = FLAG_ADVANCED_SETTING;
	conf->files.log.dnsmasq.d.s = (char*)"/var/log/pihole/pihole.log";


	// struct misc
	conf->misc.privacylevel.k = "misc.privacylevel";
	conf->misc.privacylevel.h = "Using privacy levels you can specify which level of detail you want to see in your Pi-hole statistics.";
	{
		struct enum_options privacylevel[] =
		{
			{ "0", "Doesn't hide anything, all statistics are available." },
			{ "1", "Hide domains. This setting disables Top Domains and Top Ads" },
			{ "2", "Hide domains and clients. This setting disables Top Domains, Top Ads, Top Clients and Clients over time." },
			{ "3", "Anonymize everything. This setting disabled almost any statistics and query analysis. There will be no long-term database logging and no Query Log. You will also loose most regex features." }
		};
		CONFIG_ADD_ENUM_OPTIONS(conf->misc.privacylevel.a, privacylevel);
	}
	conf->misc.privacylevel.t = CONF_ENUM_PRIVACY_LEVEL;
	conf->misc.privacylevel.d.privacy_level = PRIVACY_SHOW_ALL;

	conf->misc.delay_startup.k = "misc.delay_startup";
	conf->misc.delay_startup.h = "During startup, in some configurations, network interfaces appear only late during system startup and are not ready when FTL tries to bind to them. Therefore, you may want FTL to wait a given amount of time before trying to start the DNS revolver. This setting takes any integer value between 0 and 300 seconds. To prevent delayed startup while the system is already running and FTL is restarted, the delay only takes place within the first 180 seconds (hard-coded) after booting.";
	conf->misc.delay_startup.t = CONF_UINT;
	conf->misc.delay_startup.d.ui = 0;

	conf->misc.nice.k = "misc.nice";
	conf->misc.nice.h = "Set niceness of pihole-FTL. Defaults to -10 and can be disabled altogether by setting a value of -999. The nice value is an attribute that can be used to influence the CPU scheduler to favor or disfavor a process in scheduling decisions. The range of the nice value varies across UNIX systems. On modern Linux, the range is -20 (high priority = not very nice to other processes) to +19 (low priority).";
	conf->misc.nice.t = CONF_INT;
	conf->misc.nice.f = FLAG_ADVANCED_SETTING;
	conf->misc.nice.d.i = -10;

	conf->misc.addr2line.k = "misc.addr2line";
	conf->misc.addr2line.h = "Should FTL translate its own stack addresses into code lines during the bug backtrace? This improves the analysis of crashed significantly. It is recommended to leave the option enabled. This option should only be disabled when addr2line is known to not be working correctly on the machine because, in this case, the malfunctioning addr2line can prevent from generating any backtrace at all.";
	conf->misc.addr2line.t = CONF_BOOL;
	conf->misc.addr2line.f = FLAG_ADVANCED_SETTING;
	conf->misc.addr2line.d.b = true;

	conf->misc.dnsmasq_lines.k = "misc.dnsmasq_lines";
	conf->misc.dnsmasq_lines.h = "Additional lines to inject into the generated dnsmasq configuration.\n Warning: This is an advanced setting and should only be used with care. Incorrectly formatted or duplicated lines as well as lines conflicting with the automatic configuration of Pi-hole can break the embedded dnsmasq and will stop DNS resolution from working.\n Use this option with extra care.";
	conf->misc.dnsmasq_lines.a = cJSON_CreateStringReference("array of valid dnsmasq config line options");
	conf->misc.dnsmasq_lines.t = CONF_JSON_STRING_ARRAY;
	conf->misc.dnsmasq_lines.f = FLAG_RESTART_DNSMASQ;
	conf->misc.dnsmasq_lines.d.json = cJSON_CreateArray();

	// sub-struct misc.check
	conf->misc.check.load.k = "misc.check.load";
	conf->misc.check.load.h = "Pi-hole is very lightweight on resources. Nevertheless, this does not mean that you should run Pi-hole on a server that is otherwise extremely busy as queuing on the system can lead to unnecessary delays in DNS operation as the system becomes less and less usable as the system load increases because all resources are permanently in use. To account for this, FTL regularly checks the system load. To bring this to your attention, FTL warns about excessive load when the 15 minute system load average exceeds the number of cores.\n This check can be disabled with this setting.";
	conf->misc.check.load.t = CONF_BOOL;
	conf->misc.check.load.d.b = true;

	conf->misc.check.disk.k = "misc.check.disk";
	conf->misc.check.disk.h = "FTL stores its long-term history in a database file on disk. Furthermore, FTL stores log files. By default, FTL warns if usage of the disk holding any crucial file exceeds 90%. You can set any integer limit between 0 to 100 (interpreted as percentages) where 0 means that checking of disk usage is disabled.";
	conf->misc.check.disk.t = CONF_UINT;
	conf->misc.check.disk.d.ui = 90;

	conf->misc.check.shmem.k = "misc.check.shmem";
	conf->misc.check.shmem.h = "FTL stores history in shared memory to allow inter-process communication with forked dedicated TCP workers. If FTL runs out of memory, it cannot continue to work as queries cannot be analyzed any further. Hence, FTL checks if enough shared memory is available on your system and warns you if this is not the case.\n By default, FTL warns if the shared-memory usage exceeds 90%. You can set any integer limit between 0 to 100 (interpreted as percentages) where 0 means that checking of shared-memory usage is disabled.";
	conf->misc.check.shmem.t = CONF_UINT;
	conf->misc.check.shmem.d.ui = 90;


	// struct debug
	conf->debug.database.k = "debug.database";
	conf->debug.database.h = "Print debugging information about database actions. This prints performed SQL statements as well as some general information such as the time it took to store the queries and how many have been saved to the database.";
	conf->debug.database.t = CONF_BOOL;
	conf->debug.database.f = FLAG_ADVANCED_SETTING;
	conf->debug.database.d.b = false;

	conf->debug.networking.k = "debug.networking";
	conf->debug.networking.h = "Prints a list of the detected interfaces on the startup of pihole-FTL. Also, prints whether these interfaces are IPv4 or IPv6 interfaces.";
	conf->debug.networking.t = CONF_BOOL;
	conf->debug.networking.f = FLAG_ADVANCED_SETTING;
	conf->debug.networking.d.b = false;

	conf->debug.locks.k = "debug.locks";
	conf->debug.locks.h = "Print information about shared memory locks. Messages will be generated when waiting, obtaining, and releasing a lock.";
	conf->debug.locks.t = CONF_BOOL;
	conf->debug.locks.f = FLAG_ADVANCED_SETTING;
	conf->debug.locks.d.b = false;

	conf->debug.queries.k = "debug.queries";
	conf->debug.queries.h = "Print extensive query information (domains, types, replies, etc.). This has always been part of the legacy debug mode of pihole-FTL.";
	conf->debug.queries.t = CONF_BOOL;
	conf->debug.queries.f = FLAG_ADVANCED_SETTING;
	conf->debug.queries.d.b = false;

	conf->debug.flags.k = "debug.flags";
	conf->debug.flags.h = "Print flags of queries received by the DNS hooks. Only effective when DEBUG_QUERIES is enabled as well.";
	conf->debug.flags.t = CONF_BOOL;
	conf->debug.flags.f = FLAG_ADVANCED_SETTING;
	conf->debug.flags.d.b = false;

	conf->debug.shmem.k = "debug.shmem";
	conf->debug.shmem.h = "Print information about shared memory buffers. Messages are either about creating or enlarging shmem objects or string injections.";
	conf->debug.shmem.t = CONF_BOOL;
	conf->debug.shmem.f = FLAG_ADVANCED_SETTING;
	conf->debug.shmem.d.b = false;

	conf->debug.gc.k = "debug.gc";
	conf->debug.gc.h = "Print information about garbage collection (GC): What is to be removed, how many have been removed and how long did GC take.";
	conf->debug.gc.t = CONF_BOOL;
	conf->debug.gc.f = FLAG_ADVANCED_SETTING;
	conf->debug.gc.d.b = false;

	conf->debug.arp.k = "debug.arp";
	conf->debug.arp.h = "Print information about ARP table processing: How long did parsing take, whether read MAC addresses are valid, and if the macvendor.db file exists.";
	conf->debug.arp.t = CONF_BOOL;
	conf->debug.arp.f = FLAG_ADVANCED_SETTING;
	conf->debug.arp.d.b = false;

	conf->debug.regex.k = "debug.regex";
	conf->debug.regex.h = "Controls if FTLDNS should print extended details about regex matching into FTL.log.";
	conf->debug.regex.t = CONF_BOOL;
	conf->debug.regex.f = FLAG_ADVANCED_SETTING;
	conf->debug.regex.d.b = false;

	conf->debug.api.k = "debug.api";
	conf->debug.api.h = "Print extra debugging information during telnet API calls. Currently only used to send extra information when getting all queries.";
	conf->debug.api.t = CONF_BOOL;
	conf->debug.api.f = FLAG_ADVANCED_SETTING;
	conf->debug.api.d.b = false;

	conf->debug.tls.k = "debug.tls";
	conf->debug.tls.h = "Print extra debugging information about TLS connections. This includes the TLS version, the cipher suite, the certificate chain and much more. This very verbose output should only be used when debugging specific TLS issues and can be helpful, e.g., when a client cannot connect due to an obscure TLS error as modern browsers do not provide much information about the underlying TLS connection and most often give only very generic error messages without much/any underlying technical information.";
	conf->debug.tls.t = CONF_BOOL;
	conf->debug.tls.f = FLAG_ADVANCED_SETTING;
	conf->debug.tls.d.b = false;

	conf->debug.overtime.k = "debug.overtime";
	conf->debug.overtime.h = "Print information about overTime memory operations, such as initializing or moving overTime slots.";
	conf->debug.overtime.t = CONF_BOOL;
	conf->debug.overtime.f = FLAG_ADVANCED_SETTING;
	conf->debug.overtime.d.b = false;

	conf->debug.status.k = "debug.status";
	conf->debug.status.h = "Print information about status changes for individual queries. This can be useful to identify unexpected unknown queries.";
	conf->debug.status.t = CONF_BOOL;
	conf->debug.status.f = FLAG_ADVANCED_SETTING;
	conf->debug.status.d.b = false;

	conf->debug.caps.k = "debug.caps";
	conf->debug.caps.h = "Print information about capabilities granted to the pihole-FTL process. The current capabilities are printed on receipt of SIGHUP, i.e., the current set of capabilities can be queried without restarting pihole-FTL (by setting DEBUG_CAPS=true and thereafter sending killall -HUP pihole-FTL).";
	conf->debug.caps.t = CONF_BOOL;
	conf->debug.caps.f = FLAG_ADVANCED_SETTING;
	conf->debug.caps.d.b = false;

	conf->debug.dnssec.k = "debug.dnssec";
	conf->debug.dnssec.h = "Print information about DNSSEC activity";
	conf->debug.dnssec.t = CONF_BOOL;
	conf->debug.dnssec.f = FLAG_ADVANCED_SETTING;
	conf->debug.dnssec.d.b = false;

	conf->debug.vectors.k = "debug.vectors";
	conf->debug.vectors.h = "FTL uses dynamically allocated vectors for various tasks. This config option enables extensive debugging information such as information about allocation, referencing, deletion, and appending.";
	conf->debug.vectors.t = CONF_BOOL;
	conf->debug.vectors.f = FLAG_ADVANCED_SETTING;
	conf->debug.vectors.d.b = false;

	conf->debug.resolver.k = "debug.resolver";
	conf->debug.resolver.h = "Extensive information about hostname resolution like which DNS servers are used in the first and second hostname resolving tries (only affecting internally generated PTR queries).";
	conf->debug.resolver.t = CONF_BOOL;
	conf->debug.resolver.f = FLAG_ADVANCED_SETTING;
	conf->debug.resolver.d.b = false;

	conf->debug.edns0.k = "debug.edns0";
	conf->debug.edns0.h = "Print debugging information about received EDNS(0) data.";
	conf->debug.edns0.t = CONF_BOOL;
	conf->debug.edns0.f = FLAG_ADVANCED_SETTING;
	conf->debug.edns0.d.b = false;

	conf->debug.clients.k = "debug.clients";
	conf->debug.clients.h = "Log various important client events such as change of interface (e.g., client switching from WiFi to wired or VPN connection), as well as extensive reporting about how clients were assigned to its groups.";
	conf->debug.clients.t = CONF_BOOL;
	conf->debug.clients.f = FLAG_ADVANCED_SETTING;
	conf->debug.clients.d.b = false;

	conf->debug.aliasclients.k = "debug.aliasclients";
	conf->debug.aliasclients.h = "Log information related to alias-client processing.";
	conf->debug.aliasclients.t = CONF_BOOL;
	conf->debug.aliasclients.f = FLAG_ADVANCED_SETTING;
	conf->debug.aliasclients.d.b = false;

	conf->debug.events.k = "debug.events";
	conf->debug.events.h = "Log information regarding FTL's embedded event handling queue.";
	conf->debug.events.t = CONF_BOOL;
	conf->debug.events.f = FLAG_ADVANCED_SETTING;
	conf->debug.events.d.b = false;

	conf->debug.helper.k = "debug.helper";
	conf->debug.helper.h = "Log information about script helpers, e.g., due to dhcp-script.";
	conf->debug.helper.t = CONF_BOOL;
	conf->debug.helper.f = FLAG_ADVANCED_SETTING;
	conf->debug.helper.d.b = false;

	conf->debug.config.k = "debug.config";
	conf->debug.config.h = "Print config parsing details";
	conf->debug.config.t = CONF_BOOL;
	conf->debug.config.f = FLAG_ADVANCED_SETTING;
	conf->debug.config.d.b = false;

	conf->debug.inotify.k = "debug.inotify";
	conf->debug.inotify.h = "Debug monitoring of /etc/pihole filesystem events";
	conf->debug.inotify.t = CONF_BOOL;
	conf->debug.inotify.f = FLAG_ADVANCED_SETTING;
	conf->debug.inotify.d.b = false;

	conf->debug.extra.k = "debug.extra";
	conf->debug.extra.h = "Temporary flag that may print additional information. This debug flag is meant to be used whenever needed for temporary investigations. The logged content may change without further notice at any time.";
	conf->debug.extra.t = CONF_BOOL;
	conf->debug.extra.f = FLAG_ADVANCED_SETTING;
	conf->debug.extra.d.b = false;

	conf->debug.reserved.k = "debug.reserved";
	conf->debug.reserved.h = "Reserved debug flag";
	conf->debug.reserved.t = CONF_BOOL;
	conf->debug.reserved.f = FLAG_ADVANCED_SETTING;
	conf->debug.reserved.d.b = false;

	conf->debug.all.k = "debug.all";
	conf->debug.all.h = "Set all debug flags at once. This is a convenience option to enable all debug flags at once. Note that this option is not persistent, setting it to true will enable all *remaining* debug flags but unsetting it will disable *all* debug flags.";
	conf->debug.all.t = CONF_ALL_DEBUG_BOOL;
	conf->debug.all.f = FLAG_ADVANCED_SETTING;
	conf->debug.all.d.b = false;

	// Post-processing:
	// Initialize and verify config data
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		struct conf_item *conf_item = get_conf_item(&config, i);

		// Initialize config value with default one for all *except* the log file path
		if(conf_item != &conf->files.log.ftl)
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

void readFTLconf(struct config *conf, const bool rewrite)
{
	// Initialize config with default values
	initConfig(conf);

	// First try to read TOML config file
	if(readFTLtoml(conf, NULL, rewrite))
	{
		// If successful, we write the config file back to disk
		// to ensure that all options are present and comments
		// about options deviating from the default are present
		if(rewrite)
		{
			writeFTLtoml(true);
			write_dnsmasq_config(conf, false, NULL);
			write_custom_list();
		}
		return;
	}

	// On error, try to read legacy (pre-v6.0) config file. If successful,
	// we move the legacy config file out of our way
	const char *path = "";
	if((path = readFTLlegacy(conf)) != NULL)
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
		rotate_files(new_name, NULL);
		rename(GLOBALTOMLPATH, new_name);
	}

	// Initialize the TOML config file
	writeFTLtoml(true);
	write_dnsmasq_config(conf, false, NULL);
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
		return getLogFilePathLegacy(&config, NULL);

	return true;
}

enum blocking_status __attribute__((pure)) get_blockingstatus(void)
{
	if(dnsmasq_failed)
		return DNS_FAILED;

	return config.dns.blocking.active.v.b ? BLOCKING_ENABLED : BLOCKING_DISABLED;
}

void set_blockingstatus(bool enabled)
{
	// If dnsmasq failed to start, we do not allow to change the blocking status
	if(dnsmasq_failed)
		return;

	config.dns.blocking.active.v.b = enabled;
	writeFTLtoml(true);
	raise(SIGHUP);
}

const char * __attribute__ ((const)) get_conf_type_str(const enum conf_type type)
{
	switch(type)
	{
		case CONF_BOOL:
		case CONF_ALL_DEBUG_BOOL:
			return "boolean";
		case CONF_INT:
			return "integer";
		case CONF_UINT: // fall through
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
		case CONF_ENUM_WEB_THEME:
		case CONF_ENUM_TEMP_UNIT:
			return "enum (string)";
		case CONF_ENUM_PRIVACY_LEVEL:
			return "enum (unsigned integer)";
		case CONF_STRUCT_IN_ADDR:
			return "IPv4 address";
		case CONF_STRUCT_IN6_ADDR:
			return "IPv6 address";
		case CONF_JSON_STRING_ARRAY:
			return "string array";
		case CONF_PASSWORD:
			return "password (write-only string)";
		default:
			return "unknown";
	}
}

void replace_config(struct config *newconf)
{
	// Lock shared memory
	lock_shm();

	// Backup old config struct (so we can free it)
	struct config old_conf;
	memcpy(&old_conf, &config, sizeof(struct config));

	// Replace old config struct by changed one atomically
	memcpy(&config, newconf, sizeof(struct config));

	// Free old backup struct
	free_config(&old_conf);

	// Unlock shared memory
	unlock_shm();
}

void reread_config(void)
{
	struct config conf_copy;
	duplicate_config(&conf_copy, &config);

	// Read TOML config file
	if(readFTLtoml(&conf_copy, NULL, true))
	{
		// Install new configuration
		log_debug(DEBUG_CONFIG, "Loaded configuration is valid, installing it");
		replace_config(&conf_copy);
	}
	else
	{
		// New configuration is invalid, restore old one
		log_debug(DEBUG_CONFIG, "Loaded configuration is invalid, restoring old one");
		free_config(&conf_copy);
	}

	// Write the config file back to disk to ensure that all options and
	// comments about options deviating from the default are present
	writeFTLtoml(true);

	// We do not write the dnsmasq config file here as this is done on every
	// restart and changes would have no effect here

	// However, we do need to write the custom.list file as this file can change
	// at any time and is automatically reloaded by dnsmasq
	write_custom_list();
}
