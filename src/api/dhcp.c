/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/dhcp
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
#include "config/dnsmasq_config.h"
// rotate_files()
#include "files.h"

int api_dhcp_leases_GET(struct ftl_conn *api)
{
	// Get DHCP leases
	cJSON *leases = JSON_NEW_ARRAY();
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "leases", leases);

	FILE *fp = fopen(DHCPLEASESFILE, "r");
	if(fp == NULL)
	{
		// File does not exist or not readable, send empty array
		JSON_SEND_OBJECT(json);
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	while((read = getline(&line, &len, fp)) != -1)
	{
		// Skip empty lines
		if(read == 0)
			continue;

		// Skip duid line
		if(strncmp(line, "duid", 4) == 0)
			continue;

		// Parse line
		unsigned long expires = 0;
		char hwaddr[18] = { 0 };
		char ip[INET_ADDRSTRLEN] = { 0 };
		char name[65] = { 0 };
		char clientid[765] = { 0 };
		const int ret = sscanf(line, "%lu %17s %15s %64s %764s", &expires, hwaddr, ip, name, clientid);

		// Skip invalid lines
		if(ret != 5)
			continue;

		// Create JSON object for this lease
		cJSON *lease = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(lease, "expires", expires);
		JSON_COPY_STR_TO_OBJECT(lease, "hwaddr", hwaddr);
		JSON_COPY_STR_TO_OBJECT(lease, "ip", ip);
		JSON_COPY_STR_TO_OBJECT(lease, "name", name);
		JSON_COPY_STR_TO_OBJECT(lease, "clientid", clientid);

		// Add lease to array
		JSON_ADD_ITEM_TO_ARRAY(leases, lease);
	}
	free(line);
	fclose(fp);

	JSON_SEND_OBJECT(json);
}

// defined in dnsmasq_interface.c
extern bool FTL_unlink_DHCP_lease(const char *ipaddr, const char **hint);

// Delete DHCP leases
int api_dhcp_leases_DELETE(struct ftl_conn *api)
{
	// Validate input (must be a valid IPv4 address)
	struct sockaddr_in sa;
	if(api->item == NULL || strlen(api->item) == 0 || inet_pton(AF_INET, api->item, &(sa.sin_addr)) == 0)
	{
		// Send empty reply with code 204 No Content
		return send_json_error(api,
		                       400,
		                       "bad_request",
		                       "The provided IPv4 address is invalid",
		                       api->item);
	}

	// Delete lease
	log_debug(DEBUG_API, "Deleting DHCP lease for address %s", api->item);

	const char *hint = NULL;
	const bool found = FTL_unlink_DHCP_lease(api->item, &hint);
	if(!found && hint != NULL)
	{
		// Send error when something went wrong (hint is not NULL)
		return send_json_error(api,
		                       400,
		                       "bad_request",
		                       "Failed to delete DHCP lease",
		                       hint);
	}

	// Send empty reply with codes:
	// - 204 No Content (if a lease was deleted)
	// - 404 Not Found (if no lease was found)
	cJSON *json = JSON_NEW_OBJECT();
	JSON_SEND_OBJECT_CODE(json, found ? 204 : 404);
}