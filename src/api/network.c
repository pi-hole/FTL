/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/network
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// Routing information and flags
#include <net/route.h>
// Interate through directories
#include <dirent.h>
// networkrecord
#include "database/network-table.h"
// dbopen()
#include "database/common.h"

static bool getDefaultInterface(char iface[IF_NAMESIZE], in_addr_t *gw)
{
	// Get IPv4 default route gateway and associated interface
	long dest_r = 0, gw_r = 0;
	int flags = 0, metric = 0, minmetric = __INT_MAX__;
	char iface_r[IF_NAMESIZE] = { 0 };
	char buf[1024] = { 0 };

	FILE *file;
	if((file = fopen("/proc/net/route", "r")))
	{
		// Parse /proc/net/route - the kernel's IPv4 routing table
		while(fgets(buf, sizeof(buf), file))
		{
			if(sscanf(buf, "%s %lx %lx %x %*i %*i %i", iface_r, &dest_r, &gw_r, &flags, &metric) != 5)
				continue;

			// Only anaylze routes which are UP and whose
			// destinations are a gateway
			if(!(flags & RTF_UP) || !(flags & RTF_GATEWAY))
				continue;

			// Only analyze "catch all" routes (destination 0.0.0.0)
			if(dest_r != 0)
				continue;

			// Store default gateway, overwrite if we find a route with
			// a lower metric
			if(metric < minmetric)
			{
				minmetric = metric;
				*gw = gw_r;
				strcpy(iface, iface_r);

				log_debug(DEBUG_API, "Reading interfaces: flags: %i, addr: %s, iface: %s, metric: %i, minmetric: %i",
				          flags, inet_ntoa(*(struct in_addr *) gw), iface, metric, minmetric);
			}
		}
		fclose(file);
	}
	else
		log_err("Cannot read /proc/net/route: %s", strerror(errno));

	// Return success based on having found the default gateway's address
	return gw != 0;
}

int api_network_gateway(struct ftl_conn *api)
{
	in_addr_t gw = 0;
	char iface[IF_NAMESIZE] = { 0 };

	// Get default interface
	getDefaultInterface(iface, &gw);

	// Generate JSON response
	cJSON *json = JSON_NEW_OBJECT();
	const char *gwaddr = inet_ntoa(*(struct in_addr *) &gw);
	JSON_COPY_STR_TO_OBJECT(json, "address", gwaddr);
	JSON_REF_STR_IN_OBJECT(json, "interface", iface);
	JSON_SEND_OBJECT(json);
}

int api_network_interfaces(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();

	// Get interface with default route
	in_addr_t gw = 0;
	char default_iface[IF_NAMESIZE] = { 0 };
	getDefaultInterface(default_iface, &gw);

	// Enumerate and list interfaces
	// Loop over interfaces and extract information
	DIR *dfd;
	FILE *f;
	struct dirent *dp;
	size_t tx_sum = 0, rx_sum = 0;
	char fname[64 + IF_NAMESIZE] = { 0 };
	char readbuffer[1024] = { 0 };

	// Open /sys/class/net directory
	if ((dfd = opendir("/sys/class/net")) == NULL)
	{
		log_err("API: Cannot access /sys/class/net");
		return 500;
	}

	// Get IP addresses of all interfaces on this machine
	struct ifaddrs *ifap = NULL;
	if(getifaddrs(&ifap) == -1)
		log_err("API: Cannot get interface addresses: %s", strerror(errno));

	cJSON *interfaces = JSON_NEW_ARRAY();
	// Walk /sys/class/net directory
	while ((dp = readdir(dfd)) != NULL)
	{
		// Skip "." and ".."
		if(!dp->d_name || strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		// Create new interface record
		cJSON *iface = JSON_NEW_OBJECT();

		// Extract interface name
		const char *iface_name = dp->d_name;
		JSON_COPY_STR_TO_OBJECT(iface, "name", iface_name);

		// Is this the default interface?
		const bool is_default_iface = strcmp(iface_name, default_iface) == 0;
		JSON_ADD_BOOL_TO_OBJECT(iface, "default", is_default_iface);

		// Extract carrier status
		bool carrier = false;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/carrier", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fgets(readbuffer, sizeof(readbuffer)-1, f) != NULL)
				carrier = readbuffer[0] == '1';
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));
		JSON_ADD_BOOL_TO_OBJECT(iface, "carrier", carrier);

		// Extract link speed (may not be possible, e.g., for WiFi devices with dynamic link speeds)
		int speed = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/speed", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%i", &(speed)) != 1)
				speed = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));
		JSON_ADD_NUMBER_TO_OBJECT(iface, "speed", speed);

		// Get total transmitted bytes
		ssize_t tx_bytes = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/tx_bytes", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(tx_bytes)) != 1)
				tx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Format transmitted bytes
		double tx = 0.0;
		char tx_unit[3] = { 0 };
		format_memory_size(tx_unit, tx_bytes, &tx);
		if(tx_unit[0] != '\0')
			tx_unit[1] = 'B';

		// Add transmitted bytes to interface record
		cJSON *tx_json = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(tx_json, "num", tx);
		JSON_COPY_STR_TO_OBJECT(tx_json, "unit", tx_unit);
		JSON_ADD_ITEM_TO_OBJECT(iface, "tx", tx_json);

		// Get total received bytes
		ssize_t rx_bytes = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/rx_bytes", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(rx_bytes)) != 1)
				rx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Format received bytes
		double rx = 0.0;
		char rx_unit[3] = { 0 };
		format_memory_size(rx_unit, rx_bytes, &rx);
		if(rx_unit[0] != '\0')
			rx_unit[1] = 'B';

		// Add received bytes to JSON object
		cJSON *rx_json = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(rx_json, "num", rx);
		JSON_COPY_STR_TO_OBJECT(rx_json, "unit", rx_unit);
		JSON_ADD_ITEM_TO_OBJECT(iface, "rx", rx_json);

		// Get IP address(es) of this interface
		if(ifap)
		{
			// Walk through linked list of interface addresses
			cJSON *ipv4 = JSON_NEW_ARRAY();
			cJSON *ipv6 = JSON_NEW_ARRAY();
			for(struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
			{
				// Skip interfaces without an address and those
				// not matching the current interface
				if(ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, iface_name) != 0)
					continue;

				// If we reach this point, we found the correct interface
				const sa_family_t family = ifa->ifa_addr->sa_family;
				char host[NI_MAXHOST] = { 0 };
				if(family == AF_INET || family == AF_INET6)
				{
					// Get IP address
					const int s = getnameinfo(ifa->ifa_addr,
					                          (family == AF_INET) ?
					                               sizeof(struct sockaddr_in) :
					                               sizeof(struct sockaddr_in6),
					                          host, NI_MAXHOST,
					                          NULL, 0, NI_NUMERICHOST);
					if (s != 0)
					{
						log_warn("API: getnameinfo() failed: %s\n", gai_strerror(s));
						continue;
					}

					if(family == AF_INET)
					{
						JSON_COPY_STR_TO_ARRAY(ipv4, host);
					}
					else if(family == AF_INET6)
					{
						JSON_COPY_STR_TO_ARRAY(ipv6, host);
					}
				}
			}
			JSON_ADD_ITEM_TO_OBJECT(iface, "ipv4", ipv4);
			JSON_ADD_ITEM_TO_OBJECT(iface, "ipv6", ipv6);
		}

		// Sum up transmitted and received bytes
		tx_sum += tx_bytes;
		rx_sum += rx_bytes;

		// Add interface to array
		JSON_ADD_ITEM_TO_ARRAY(interfaces, iface);
	}

	freeifaddrs(ifap);
	closedir(dfd);

	cJSON *sum = JSON_NEW_OBJECT();
	JSON_COPY_STR_TO_OBJECT(sum, "name", "sum");
	JSON_ADD_BOOL_TO_OBJECT(sum, "carrier", true);
	JSON_ADD_NUMBER_TO_OBJECT(sum, "speed", 0);

	// Format transmitted bytes
	double tx = 0.0;
	char tx_unit[3] = { 0 };
	format_memory_size(tx_unit, tx_sum, &tx);
	if(tx_unit[0] != '\0')
		tx_unit[1] = 'B';

	// Add transmitted bytes to interface record
	cJSON *tx_json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(tx_json, "num", tx);
	JSON_COPY_STR_TO_OBJECT(tx_json, "unit", tx_unit);
	JSON_ADD_ITEM_TO_OBJECT(sum, "tx", tx_json);

	// Format received bytes
	double rx = 0.0;
	char rx_unit[3] = { 0 };
	format_memory_size(rx_unit, rx_sum, &rx);
	if(rx_unit[0] != '\0')
		rx_unit[1] = 'B';

	// Add received bytes to JSON object
	cJSON *rx_json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(rx_json, "num", rx);
	JSON_COPY_STR_TO_OBJECT(rx_json, "unit", rx_unit);
	JSON_ADD_ITEM_TO_OBJECT(sum, "rx", rx_json);

	cJSON *ipv4 = JSON_NEW_ARRAY();
	cJSON *ipv6 = JSON_NEW_ARRAY();
	JSON_ADD_ITEM_TO_OBJECT(sum, "ipv4", ipv4);
	JSON_ADD_ITEM_TO_OBJECT(sum, "ipv6", ipv6);

	// Add interface to array
	JSON_ADD_ITEM_TO_ARRAY(interfaces, sum);
	JSON_ADD_ITEM_TO_OBJECT(json, "interfaces", interfaces);
	JSON_SEND_OBJECT(json);
}

int api_network_devices(struct ftl_conn *api)
{
	// Does the user request a custom number of devices to be included?
	unsigned int device_count = 10;
	get_uint_var(api->request->query_string, "device_count", &device_count);

	// Does the user request a custom number of addresses per device to be included?
	unsigned int address_count = 3;
	get_uint_var(api->request->query_string, "address_count", &address_count);

	// Open pihole-FTL.db database file
	sqlite3_stmt *device_stmt = NULL, *ip_stmt = NULL;
	sqlite3 *db = dbopen(false);
	if(db == NULL)
	{
		log_warn("Failed to open database in networkTable_readDevices()");
		return false;
	}

	const char *sql_msg = NULL;
	if(!networkTable_readDevices(db, &device_stmt, &sql_msg))
	{
		// Add SQL message (may be NULL = not available)
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not read network details from database table",
		                       sql_msg);
	}

	// Read record for a single device
	cJSON *devices = JSON_NEW_ARRAY();
	network_record network;
	unsigned int device_counter = 0;
	while(networkTable_readDevicesGetRecord(device_stmt, &network, &sql_msg) &&
	      ++device_counter > device_count)
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(item, "id", network.id);
		JSON_COPY_STR_TO_OBJECT(item, "hwaddr", network.hwaddr);
		JSON_COPY_STR_TO_OBJECT(item, "interface", network.iface);
		JSON_ADD_NUMBER_TO_OBJECT(item, "firstSeen", network.firstSeen);
		JSON_ADD_NUMBER_TO_OBJECT(item, "lastQuery", network.lastQuery);
		JSON_ADD_NUMBER_TO_OBJECT(item, "numQueries", network.numQueries);
		JSON_COPY_STR_TO_OBJECT(item, "macVendor", network.macVendor);

		// Build array of all IP addresses known associated to this client
		cJSON *ips = JSON_NEW_ARRAY();
		if(networkTable_readIPs(db, &ip_stmt, network.id, &sql_msg))
		{
			// Walk known IP addresses + names
			network_addresses_record network_address;
			unsigned int address_counter = 0;
			while(networkTable_readIPsGetRecord(ip_stmt, &network_address, &sql_msg) &&
			      ++address_counter > address_count)
			{
				cJSON *ip = JSON_NEW_OBJECT();
				JSON_COPY_STR_TO_OBJECT(ip, "ip", network_address.ip);
				JSON_COPY_STR_TO_OBJECT(ip, "name", network_address.name);
				JSON_ADD_NUMBER_TO_OBJECT(ip, "lastSeen", network_address.lastSeen);
				JSON_ADD_NUMBER_TO_OBJECT(ip, "nameUpdated", network_address.nameUpdated);
				JSON_ADD_ITEM_TO_ARRAY(ips, ip);
			}

			// Possible error handling
			if(sql_msg != NULL)
			{
				cJSON_Delete(ips);
				cJSON_Delete(devices);
				return send_json_error(api, 500,
				                       "database_error",
				                       "Could not read network details from database table (getting IP records)",
				                       sql_msg);
			}

			// Finalize sub-query
			networkTable_readIPsFinalize(ip_stmt);
		}

		// Add array of IP addresses to device
		JSON_ADD_ITEM_TO_OBJECT(item, "ips", ips);

		// Add device to array of all devices
		JSON_ADD_ITEM_TO_ARRAY(devices, item);
	}

	if(sql_msg != NULL)
	{
		cJSON_Delete(devices);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not read network details from database table (step)",
		                       sql_msg);
	}

	// Finalize query
	networkTable_readDevicesFinalize(device_stmt);
	dbclose(&db);

	// Return data to user
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "devices", devices);
	JSON_SEND_OBJECT(json);
}
