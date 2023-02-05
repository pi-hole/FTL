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

int api_dhcp_leases(struct ftl_conn *api)
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