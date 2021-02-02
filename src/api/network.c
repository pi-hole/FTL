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

int api_network(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// apiect to database
	const char *sql_msg = NULL;
	if(!networkTable_readDevices(&sql_msg))
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
	while(networkTable_readDevicesGetRecord(&network, &sql_msg))
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "id", network.id);
		JSON_OBJ_COPY_STR(item, "hwaddr", network.hwaddr);
		JSON_OBJ_COPY_STR(item, "interface", network.iface);
		JSON_OBJ_COPY_STR(item, "name", network.name);
		JSON_OBJ_ADD_NUMBER(item, "firstSeen", network.firstSeen);
		JSON_OBJ_ADD_NUMBER(item, "lastQuery", network.lastQuery);
		JSON_OBJ_ADD_NUMBER(item, "numQueries", network.numQueries);
		JSON_OBJ_COPY_STR(item, "macVendor", network.macVendor);

		// Build array of all IP addresses known associated to this client
		cJSON *ip = JSON_NEW_ARRAY();
		if(networkTable_readIPs(network.id, &sql_msg))
		{
			// Walk known IP addresses
			network_addresses_record network_address;
			while(networkTable_readIPsGetRecord(&network_address, &sql_msg))
				JSON_ARRAY_COPY_STR(ip, network_address.ip);

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
			networkTable_readIPsFinalize();
		}

		// Add array of IP addresses to device
		JSON_OBJ_ADD_ITEM(item, "ip", ip);

		// Add device to array of all devices
		JSON_ARRAY_ADD_ITEM(json, item);
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
	networkTable_readDevicesFinalize();

	// Return data to user
	JSON_SEND_OBJECT(json);
}
