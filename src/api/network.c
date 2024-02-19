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
// Iterate through directories
#include <dirent.h>
// networkrecord
#include "database/network-table.h"
// dbopen(false, )
#include "database/common.h"
// attach_database()
#include "database/query-table.h"
// config struct
#include "config/config.h"

static bool getDefaultInterface(char iface[IF_NAMESIZE], in_addr_t *gw)
{
	// Get IPv4 default route gateway and associated interface
	unsigned long dest_r = 0, gw_r = 0;
	unsigned int flags = 0u;
	int metric = 0, minmetric = __INT_MAX__;

	FILE *file;
	if((file = fopen("/proc/net/route", "r")))
	{
		// Parse /proc/net/route - the kernel's IPv4 routing table
		char buf[1024] = { 0 };
		while(fgets(buf, sizeof(buf), file))
		{
			char iface_r[IF_NAMESIZE] = { 0 };
			if(sscanf(buf, "%15s %lx %lx %x %*i %*i %i", iface_r, &dest_r, &gw_r, &flags, &metric) != 5)
				continue;

			// Only analyze routes which are UP and whose
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

				log_debug(DEBUG_API, "Reading interfaces: flags: %u, addr: %s, iface: %s, metric: %i, minmetric: %i",
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
		if(strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
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
		if(tx_bytes > 0)
			tx_sum += tx_bytes;
		if(rx_bytes > 0)
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

static int api_network_devices_GET(struct ftl_conn *api)
{
	// Does the user request a custom number of devices to be included?
	unsigned int device_count = 10;
	get_uint_var(api->request->query_string, "max_devices", &device_count);

	// Does the user request a custom number of addresses per device to be included?
	unsigned int address_count = 3;
	get_uint_var(api->request->query_string, "max_addresses", &address_count);

	// Open pihole-FTL.db database file
	sqlite3_stmt *device_stmt = NULL, *ip_stmt = NULL;
	sqlite3 *db = dbopen(true, false);
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
	      device_counter++ < device_count)
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
			      address_counter++ < address_count)
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

static int api_network_devices_DELETE(struct ftl_conn *api)
{
	// Get device ID
	int device_id = 0;
	if(sscanf(api->item, "%i", &device_id) != 1)
	{
		return send_json_error(api, 400,
		                       "invalid_request",
		                       "Missing or invalid {id} parameter",
		                       NULL);
	}

	// Open pihole-FTL.db database file
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
	{
		log_warn("Failed to open database in networkTable_readDevices()");
		return false;
	}

	// Delete row from network table by ID
	const char *sql_msg = NULL;
	int deleted = 0;
	if(!networkTable_deleteDevice(db, device_id, &deleted, &sql_msg))
	{
		// Add SQL message (may be NULL = not available)
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not delete network details from database table",
		                       sql_msg);
	}

	// Close database
	dbclose(&db);

	// Send empty reply with codes:
	// - 204 No Content (if any items were deleted)
	// - 404 Not Found (if no items were deleted)
	cJSON *json = JSON_NEW_OBJECT();
	JSON_SEND_OBJECT_CODE(json, deleted > 0 ? 204 : 404);
}

int api_network_devices(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
	{
		return api_network_devices_GET(api);
	}
	else if(api->method == HTTP_DELETE)
	{
		return api_network_devices_DELETE(api);
	}
	else
	{
		return send_json_error(api, 405,
		                       "method_not_allowed",
		                       "Method not allowed",
		                       NULL);
	}
}

int api_client_suggestions(struct ftl_conn *api)
{
	// Get client suggestions
	if(api->method != HTTP_GET)
	{
		// This results in error 404
		return 0;
	}

	// Does the user request a custom number of addresses per device to be included?
	unsigned int count = 50;
	get_uint_var(api->request->query_string, "count", &count);

	bool ipv4_only = true;
	get_bool_var(api->request->query_string, "ipv4_only", &ipv4_only);

	// Open pihole-FTL.db database file connection
	sqlite3 *db = dbopen(true, false);

	// Attach gravity database
	const char *message = "";
	if(!attach_database(db, &message, config.files.gravity.v.s, "g"))
	{
		log_err("Failed to attach gravity database: %s", message);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not attach gravity database",
		                       message);
	}

	// Prepare SQL statement
	sqlite3_stmt *stmt = NULL;
	const char *sql = "SELECT n.hwaddr,n.macVendor,n.lastQuery,"
	                  "(SELECT GROUP_CONCAT(DISTINCT na.ip) "
	                    "FROM network_addresses na "
	                      "WHERE na.network_id = n.id),"
	                  "(SELECT GROUP_CONCAT(DISTINCT na.name) "
	                    "FROM network_addresses na "
	                      "WHERE na.network_id = n.id) "
	                  "FROM network n "
	                  "ORDER BY lastQuery DESC LIMIT ?";

	if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		log_err("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not prepare SQL statement",
		                       sqlite3_errmsg(db));
	}

	// Bind parameters
	if(sqlite3_bind_int(stmt, 1, count) != SQLITE_OK)
	{
		log_err("Failed to bind parameter: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not bind parameter",
		                       sqlite3_errmsg(db));
	}

	// Execute SQL statement
	cJSON *clients = JSON_NEW_ARRAY();
	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		cJSON *client = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(client, "hwaddr", sqlite3_column_text(stmt, 0));
		JSON_COPY_STR_TO_OBJECT(client, "macVendor", sqlite3_column_text(stmt, 1));
		JSON_ADD_NUMBER_TO_OBJECT(client, "lastQuery", sqlite3_column_int(stmt, 2));
		JSON_COPY_STR_TO_OBJECT(client, "addresses", sqlite3_column_text(stmt, 3));
		JSON_COPY_STR_TO_OBJECT(client, "names", sqlite3_column_text(stmt, 4));
		JSON_ADD_ITEM_TO_ARRAY(clients, client);
	}

	// Finalize query
	sqlite3_finalize(stmt);

	// Detach gravity database
	if(!detach_database(db, &message, "g"))
	{
		log_err("Failed to detach gravity database: %s", message);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not detach gravity database",
		                       message);
	}

	// Close database connection
	dbclose(&db);

	// Return data to user
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_SEND_OBJECT(json);
}

