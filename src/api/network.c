/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/network
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "api.h"
// networkrecord
#include "../database/network-table.h"
// dbopen()
#include "../database/common.h"

int api_network(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}


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
	cJSON *json = JSON_NEW_ARRAY();
	network_record network;
	while(networkTable_readDevicesGetRecord(device_stmt, &network, &sql_msg))
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(item, "id", network.id);
		JSON_COPY_STR_TO_OBJECT(item, "hwaddr", network.hwaddr);
		JSON_COPY_STR_TO_OBJECT(item, "interface", network.iface);
		JSON_COPY_STR_TO_OBJECT(item, "name", network.name);
		JSON_ADD_NUMBER_TO_OBJECT(item, "firstSeen", network.firstSeen);
		JSON_ADD_NUMBER_TO_OBJECT(item, "lastQuery", network.lastQuery);
		JSON_ADD_NUMBER_TO_OBJECT(item, "numQueries", network.numQueries);
		JSON_COPY_STR_TO_OBJECT(item, "macVendor", network.macVendor);

		// Build array of all IP addresses known associated to this client
		cJSON *ip = JSON_NEW_ARRAY();
		if(networkTable_readIPs(db, &ip_stmt, network.id, &sql_msg))
		{
			// Walk known IP addresses
			network_addresses_record network_address;
			while(networkTable_readIPsGetRecord(ip_stmt, &network_address, &sql_msg))
				JSON_COPY_STR_TO_ARRAY(ip, network_address.ip);

			// Possible error handling
			if(sql_msg != NULL)
			{
				cJSON_Delete(json);
				return send_json_error(api, 500,
				                       "database_error",
				                       "Could not read network details from database table (getting IP records)",
				                       sql_msg);
			}

			// Finalize sub-query
			networkTable_readIPsFinalize(ip_stmt);
		}

		// Add array of IP addresses to device
		JSON_ADD_ITEM_TO_OBJECT(item, "ip", ip);

		// Add device to array of all devices
		JSON_ADD_ITEM_TO_ARRAY(json, item);
	}

	if(sql_msg != NULL)
	{
		cJSON_Delete(json);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not read network details from database table (step)",
		                       sql_msg);
	}

	// Finalize query
	networkTable_readDevicesFinalize(device_stmt);

	dbclose(&db);

	// Return data to user
	JSON_SEND_OBJECT(json);
}
