/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/dns
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
// lock_shm() and unlock_shm()
#include "shmem.h"
// counters
#include "datastructure.h"
// get_dnsmasq_metrics(&metrics)
#include "metrics.h"
// get_blockingstatus()
#include "config/config.h"
// uname()
#include <sys/utsname.h>
// struct proc_mem, getProcessMemory()
#include "procps.h"
// getcpu_percentage()
#include "daemon.h"

int api_padd(struct ftl_conn *api)
{
	// Parse parameters
	bool full = true;
	if(api->request->query_string != NULL)
		get_bool_var(api->request->query_string, "full", &full);

	cJSON *json = JSON_NEW_OBJECT();
	// Lock shared memory
	lock_shm();

	const int total = counters->queries;
	const int blocked = get_blocked_count();
	const unsigned int active_clients = get_active_clients();
	const int num_gravity = counters->database.gravity;

	// If privacy level is set to hide domains, do not return the most
	// recent blocked domain
	if(config.misc.privacylevel.v.privacy_level < PRIVACY_HIDE_DOMAINS)
	{
		// Find most recently blocked query
		for(int queryID = counters->queries - 1; queryID > 0 ; queryID--)
		{
			const queriesData *query = getQuery(queryID, true);
			if(query == NULL)
				continue;

			if(query->flags.blocked)
			{
				// Ask subroutine for domain. It may return "hidden" depending on
				// the privacy settings at the time the query was made
				const char *domain = getDomainString(query);
				if(domain == NULL)
					continue;

				JSON_COPY_STR_TO_OBJECT(json, "recent_blocked", domain);
				break;
			}
		}
	}

	// Unlock shared memory
	unlock_shm();

	// Add the number of active clients, the size of the gravity list
	JSON_ADD_NUMBER_TO_OBJECT(json, "active_clients", active_clients);
	JSON_ADD_NUMBER_TO_OBJECT(json, "gravity_size", num_gravity);

	cJSON *top_domains = get_top_domains(api, 1, false, true);
	if(cJSON_GetArraySize(top_domains) == 0)
	{
		JSON_ADD_NULL_TO_OBJECT(json, "top_domain");
	}
	else
	{
		cJSON *top_domain = cJSON_GetArrayItem(top_domains, 0);
		const char *domain = cJSON_GetStringValue(top_domain);
		JSON_COPY_STR_TO_OBJECT(json, "top_domain", domain);
	}
	cJSON_Delete(top_domains);
	cJSON *top_blocked = get_top_domains(api, 1, true, true);
	if(cJSON_GetArraySize(top_blocked) == 0)
	{
		JSON_ADD_NULL_TO_OBJECT(json, "top_blocked");
	}
	else
	{
		cJSON *top_block = cJSON_GetArrayItem(top_blocked, 0);
		const char *domain = cJSON_GetStringValue(top_block);
		JSON_COPY_STR_TO_OBJECT(json, "top_blocked", domain);
	}
	cJSON *top_clients = get_top_clients(api, 1, false, true, false, true);
	if(cJSON_GetArraySize(top_clients) == 0)
	{
		JSON_ADD_NULL_TO_OBJECT(json, "top_client");
	}
	else
	{
		cJSON *top_client = cJSON_GetArrayItem(top_clients, 0);
		const char *client = cJSON_GetStringValue(top_client);
		JSON_COPY_STR_TO_OBJECT(json, "top_client", client);
	}

	// Add a null entry if the domain is hidden or there is no recent
	// blocked domain (e.g. when blocking is disabled)
	JSON_ADD_NULL_IF_NOT_EXISTS(json, "recent_blocked");

	// Calculate percentage of blocked queries
	float percent_blocked = 0.0f;
	// Avoid 1/0 condition
	if(total > 0)
		percent_blocked = 1e2f*blocked/total;

	// Add the blocking status
	const char *blocking = get_blocking_status_str(get_blockingstatus());
	JSON_REF_STR_IN_OBJECT(json, "blocking", blocking);

	// Add query statistics
	cJSON *queries = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(queries, "total", total);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "blocked", blocked);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "percent_blocked", percent_blocked);
	JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);

	// Add cache statistics
	cJSON *cache = JSON_NEW_OBJECT();
	struct metrics metrics = { 0 };
	get_dnsmasq_metrics(&metrics);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "size", metrics.dns.cache.size);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "inserted", metrics.dns.cache.inserted);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "evicted", metrics.dns.cache.live_freed);
	JSON_ADD_ITEM_TO_OBJECT(json, "cache", cache);

	// info/system
	cJSON *system = JSON_NEW_OBJECT();
	get_system_obj(api, system);
	JSON_ADD_ITEM_TO_OBJECT(json, "system", system);

	// info/host
	struct utsname un = { 0 };
	uname(&un);
	JSON_COPY_STR_TO_OBJECT(json, "node_name", un.nodename);
	JSON_ADD_ITEM_TO_OBJECT(json, "host_model", read_sys_property("/sys/firmware/devicetree/base/model"));

	// Expensive calls, do only if full is requested
	if(full)
	{
		// network/gateway
		cJSON *gateway_ = JSON_NEW_OBJECT();
		get_gateway(api, gateway_, true);

		cJSON *gateway = cJSON_GetObjectItemCaseSensitive(gateway_, "gateway");
		cJSON *interfaces = cJSON_GetObjectItemCaseSensitive(gateway_, "interfaces");

		// Loop over gateway and find first entry with family == "inet"
		cJSON *entry = NULL;
		const char *gw_v4_name = NULL, *gw_v6_name = NULL;
		const char *gw_v4_addr = NULL, *gw_v6_addr = NULL;
		cJSON_ArrayForEach(entry, gateway)
		{
			cJSON *family = cJSON_GetObjectItemCaseSensitive(entry, "family");
			if(gw_v4_name == NULL && strcmp(cJSON_GetStringValue(family), "inet") == 0)
			{
				gw_v4_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "interface"));
				gw_v4_addr = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "address"));
			}
			if(gw_v6_name == NULL && strcmp(cJSON_GetStringValue(family), "inet6") == 0)
			{
				gw_v6_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "interface"));
				gw_v6_addr = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "address"));
			}

			// Break if both addresses are found
			if(gw_v4_name && gw_v6_name)
				break;
		}

		// If no IPv6 gateway is found, use the IPv4 gateway
		if(gw_v6_name == NULL)
			gw_v6_name = gw_v4_name;

		// Iterate over all interfaces until we find the one associated
		// with the IPv4 gateway
		cJSON *iface_v4 = JSON_NEW_OBJECT();
		cJSON *iface_v6 = JSON_NEW_OBJECT();
		unsigned int v4_addrs = 0, v6_addrs = 0;
		cJSON_ArrayForEach(entry, interfaces)
		{
			if(strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "name")), gw_v4_name) == 0)
			{
				// Add first interface address with family == inet
				cJSON *addr = NULL;
				cJSON *addrs = cJSON_GetObjectItemCaseSensitive(entry, "addresses");
				cJSON_ArrayForEach(addr, addrs)
				{
					cJSON *family = cJSON_GetObjectItemCaseSensitive(addr, "family");
					if(strcmp(cJSON_GetStringValue(family), "inet") == 0)
					{
						if(v4_addrs == 0)
						{
							cJSON *_addr = cJSON_GetObjectItemCaseSensitive(addr, "address");
							JSON_COPY_STR_TO_OBJECT(iface_v4, "addr", cJSON_GetStringValue(_addr));
						}
						v4_addrs++;
					}
				}

				// Add NULL if no IPv4 address is found
				if(v4_addrs == 0)
					JSON_ADD_NULL_TO_OBJECT(iface_v4, "addr");

				// Also add IPv4 interface statistics
				cJSON *stats = cJSON_GetObjectItemCaseSensitive(entry, "stats");
				cJSON *rx_bytes = cJSON_GetObjectItemCaseSensitive(stats, "rx_bytes");
				JSON_ADD_ITEM_TO_OBJECT(iface_v4, "rx_bytes", cJSON_Duplicate(rx_bytes, true));
				cJSON *tx_bytes = cJSON_GetObjectItemCaseSensitive(stats, "tx_bytes");
				JSON_ADD_ITEM_TO_OBJECT(iface_v4, "tx_bytes", cJSON_Duplicate(tx_bytes, true));
			}
			if(strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "name")), gw_v6_name) == 0)
			{
				// Add first interface address with family == inet
				cJSON *addr = NULL;
				cJSON *addrs = cJSON_GetObjectItemCaseSensitive(entry, "addresses");
				cJSON_ArrayForEach(addr, addrs)
				{
					cJSON *family = cJSON_GetObjectItemCaseSensitive(addr, "family");
					if(strcmp(cJSON_GetStringValue(family), "inet6") == 0)
					{
						if(v6_addrs == 0)
						{
							cJSON *_addr = cJSON_GetObjectItemCaseSensitive(addr, "address");
							JSON_COPY_STR_TO_OBJECT(iface_v6, "addr", cJSON_GetStringValue(_addr));
						}
						v6_addrs++;
					}
				}

				// Add NULL if no IPv6 address is found
				if(v6_addrs == 0)
					JSON_ADD_NULL_TO_OBJECT(iface_v6, "addr");
			}
		}

		// Add the number of addresses found
		JSON_ADD_NUMBER_TO_OBJECT(iface_v4, "num_addrs", v4_addrs);
		JSON_ADD_NUMBER_TO_OBJECT(iface_v6, "num_addrs", v6_addrs);

		// Add the interfaces to the gateway object
		JSON_COPY_STR_TO_OBJECT(iface_v4, "name", gw_v4_name);
		JSON_COPY_STR_TO_OBJECT(iface_v4, "gw_addr", gw_v4_addr);
		JSON_COPY_STR_TO_OBJECT(iface_v6, "name", gw_v6_name);
		JSON_COPY_STR_TO_OBJECT(iface_v6, "gw_addr", gw_v6_addr);

		// Create interface object
		cJSON *iface = JSON_NEW_OBJECT();
		JSON_ADD_ITEM_TO_OBJECT(iface, "v4", iface_v4);
		JSON_ADD_ITEM_TO_OBJECT(iface, "v6", iface_v6);
		JSON_ADD_ITEM_TO_OBJECT(json, "iface", iface);

		// Free memory
		cJSON_Delete(gateway_);

		// info/version
		cJSON *version = JSON_NEW_OBJECT();
		get_version_obj(api, version);
		JSON_ADD_ITEM_TO_OBJECT(json, "version", version);
	}

	// subset of config
	cJSON *jconfig = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(jconfig, "dhcp_active", config.dhcp.active.v.b);
	JSON_ADD_ITEM_TO_OBJECT(jconfig, "dhcp_start", addJSONConfValue(config.dhcp.start.t, &config.dhcp.start.v));
	JSON_ADD_ITEM_TO_OBJECT(jconfig, "dhcp_end", addJSONConfValue(config.dhcp.end.t, &config.dhcp.end.v));
	JSON_ADD_BOOL_TO_OBJECT(jconfig, "dhcp_ipv6", config.dhcp.ipv6.v.b);
	JSON_COPY_STR_TO_OBJECT(jconfig, "dns_domain", config.dns.domain.name.v.s);
	JSON_ADD_NUMBER_TO_OBJECT(jconfig, "dns_port", config.dns.port.v.u16);
	JSON_ADD_NUMBER_TO_OBJECT(jconfig, "dns_num_upstreams", cJSON_GetArraySize(config.dns.upstreams.v.json));
	JSON_ADD_BOOL_TO_OBJECT(jconfig, "dns_dnssec", config.dns.dnssec.v.b);
	JSON_ADD_BOOL_TO_OBJECT(jconfig, "dns_revServer_active", cJSON_GetArraySize(config.dns.revServers.v.json) > 0);
	JSON_ADD_NUMBER_TO_OBJECT(jconfig, "privacy_level", config.misc.privacylevel.v.privacy_level);
	JSON_ADD_ITEM_TO_OBJECT(json, "config", jconfig);

	// subset of info/ftl
	struct proc_mem pmem = { 0 };
	struct proc_meminfo mem = { 0 };
	parse_proc_meminfo(&mem);
	getProcessMemory(&pmem, mem.total);
	JSON_ADD_NUMBER_TO_OBJECT(json, "%mem", pmem.VmRSS_percent);
	JSON_ADD_NUMBER_TO_OBJECT(json, "%cpu", get_ftl_cpu_percentage());
	JSON_ADD_NUMBER_TO_OBJECT(json, "pid", getpid());

	// info/sensors -> CPU temp sensor
	cJSON *sensors = JSON_NEW_OBJECT();
	get_sensors_obj(api, sensors, false);
	JSON_ADD_ITEM_TO_OBJECT(json, "sensors", sensors);

	JSON_SEND_OBJECT(json);
}
