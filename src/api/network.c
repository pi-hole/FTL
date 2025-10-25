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
// PRIx64
#include <inttypes.h>
#include <linux/rtnetlink.h>
// IFA_LINK and friends
#include <linux/if_addr.h>
// nlroutes(), nladdrs(), nllinks()
#include "tools/netlink.h"

int get_gateway(struct ftl_conn *api, cJSON * json, const bool detailed)
{
	// Get routing information
	cJSON *routes = JSON_NEW_ARRAY();
	nlroutes(routes, detailed);

	// Get interface information ...
	cJSON *interfaces = JSON_NEW_ARRAY();
	nllinks(interfaces, detailed);
	// ... and enrich them with addresses
	nladdrs(interfaces, detailed);

	cJSON *gateway = JSON_NEW_ARRAY();
	// Search through routes for the default gateway
	// They are the ones with "dst" == "default"
	cJSON *route = NULL;
	cJSON_ArrayForEach(route, routes)
	{
		cJSON *dst = cJSON_GetObjectItem(route, "dst");
		if(dst != NULL &&
		   cJSON_IsString(dst) &&
		   strcmp(cJSON_GetStringValue(dst), "default") == 0)
		{
			cJSON *gwobj = JSON_NEW_OBJECT();

			// Extract and add family
			const char *family = cJSON_GetStringValue(cJSON_GetObjectItem(route, "family"));
			JSON_REF_STR_IN_OBJECT(gwobj, "family", family);

			// Extract and add interface name
			const char *iface_name = cJSON_GetStringValue(cJSON_GetObjectItem(route, "oif"));
			JSON_COPY_STR_TO_OBJECT(gwobj, "interface", iface_name);

			// Extract and add gateway address
			const char *gw_addr = cJSON_GetStringValue(cJSON_GetObjectItem(route, "gateway"));
			JSON_COPY_STR_TO_OBJECT(gwobj, "address", gw_addr);

			// Extract and add local interface address
			cJSON *local = JSON_NEW_ARRAY();
			cJSON *iface = NULL;
			cJSON_ArrayForEach(iface, interfaces)
			{
				const char *ifname = cJSON_GetStringValue(cJSON_GetObjectItem(iface, "name"));
				if(ifname != NULL && iface_name != NULL && strcmp(ifname, iface_name) == 0)
				{
					cJSON *addr = NULL;
					cJSON *addrs = cJSON_GetObjectItem(iface, "addresses");
					cJSON_ArrayForEach(addr, addrs)
					{
						// Skip addresses belonging to another address family
						const char *ifamily = cJSON_GetStringValue(cJSON_GetObjectItem(addr, "family"));
						if(ifamily == NULL || strcmp(ifamily, family) != 0)
							continue;

						const char *addr_str = cJSON_GetStringValue(cJSON_GetObjectItem(addr, "address"));
						if(addr_str != NULL)
							JSON_COPY_STR_TO_ARRAY(local, addr_str);
					}
					break;
				}
			}

			// Add local addresses array to gateway object
			JSON_ADD_ITEM_TO_OBJECT(gwobj, "local", local);

			cJSON_AddItemToArray(gateway, gwobj);
		}
	}

	// Send gateway information
	JSON_ADD_ITEM_TO_OBJECT(json, "gateway", gateway);

	if(detailed)
	{
		JSON_ADD_ITEM_TO_OBJECT(json, "routes", routes);
		JSON_ADD_ITEM_TO_OBJECT(json, "interfaces", interfaces);
	}
	else
	{
		// Free arrays
		cJSON_Delete(routes);
		cJSON_Delete(interfaces);
	}

	return 0;
}

int api_network_gateway(struct ftl_conn *api)
{
	// Get ?detailed parameter
	bool detailed = false;
	get_bool_var(api->request->query_string, "detailed", &detailed);

	cJSON *json = JSON_NEW_OBJECT();
	get_gateway(api, json, detailed);

	JSON_SEND_OBJECT(json);
}

int api_network_routes(struct ftl_conn *api)
{
	// Get ?detailed parameter
	bool detailed = false;
	get_bool_var(api->request->query_string, "detailed", &detailed);

	// Add routing information
	cJSON *routes = JSON_NEW_ARRAY();
	nlroutes(routes, detailed);
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "routes", routes);
	JSON_SEND_OBJECT(json);
}

int api_network_interfaces(struct ftl_conn *api)
{
	// Get ?detailed parameter
	bool detailed = false;
	get_bool_var(api->request->query_string, "detailed", &detailed);

	cJSON *interfaces = JSON_NEW_ARRAY();
	// Get links ...
	nllinks(interfaces, detailed);
	// ... and enrich them with addresses
	nladdrs(interfaces, detailed);

	cJSON *json = JSON_NEW_OBJECT();
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
		networkTable_readDevicesFinalize(device_stmt);
		dbclose(&db);

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

				networkTable_readIPsFinalize(ip_stmt);
				networkTable_readDevicesFinalize(device_stmt);
				dbclose(&db);

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
		networkTable_readDevicesFinalize(device_stmt);
		dbclose(&db);

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
	                  "WHERE n.hwaddr NOT IN (SELECT lower(ip) FROM g.client)" // real hardware addresses
	                    "AND n.hwaddr NOT IN (SELECT CONCAT('ip-',lower(ip)) FROM g.client)" // mock hardware addresses built from IP addresses
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
