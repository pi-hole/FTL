/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "api.h"
#include "../shmem.h"
#include "../datastructure.h"
// overTime data
#include "../overTime.h"
// config struct
#include "../config/config.h"
// read_setupVarsconf()
#include "../config/setupVars.h"
// get_aliasclient_list()
#include "../database/aliasclients.h"

int api_history(struct ftl_conn *api)
{
	lock_shm();

	// Loop over all overTime slots and add them to the array
	cJSON *history = JSON_NEW_ARRAY();
	for(unsigned int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(item, "timestamp", overTime[slot].timestamp);
		JSON_ADD_NUMBER_TO_OBJECT(item, "total", overTime[slot].total);
		JSON_ADD_NUMBER_TO_OBJECT(item, "cached", overTime[slot].cached);
		JSON_ADD_NUMBER_TO_OBJECT(item, "blocked", overTime[slot].blocked);
		JSON_ADD_NUMBER_TO_OBJECT(item, "forwarded", overTime[slot].forwarded);
		JSON_ADD_ITEM_TO_ARRAY(history, item);
	}

	// Unlock already here to avoid keeping the lock during JSON generation
	// This is safe because we don't access any shared memory after this
	// point. All numbers in the JSON are copied
	unlock_shm();

	// Minimum structure is
	// {"history":[]}
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "history", history);
	JSON_SEND_OBJECT(json);
}

int api_history_clients(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		// Minimum structure is
		// {"history":[], "clients":[]}
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *history = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "history", history);
		cJSON *clients = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
		JSON_SEND_OBJECT_UNLOCK(json);
	}

	// Get number of clients to return
	unsigned int Nc = min(counters->clients, config.webserver.api.maxClients.v.u16);
	if(api->request->query_string != NULL)
	{
		// Does the user request a non-default number of clients
		get_uint_var(api->request->query_string, "N", &Nc);

		// Limit the number of clients to return to the number of
		// clients to avoid possible overflows for very large N
		// Also allow N=0 to return all clients
		if((int)Nc > counters->clients || Nc == 0)
			Nc = counters->clients;
	}

	// Lock shared memory
	lock_shm();

	// Allocate memory for the temporary buffer for ranking our clients
	int *temparray = calloc(2*counters->clients, sizeof(int));
	if(temparray == NULL)
	{
		unlock_shm();
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to allocate memory for temporary array",
		                       NULL);
	}

	// Get MAX_CLIENTS clients with the highest number of queries
	// Skip clients included in others (in alias-clients)
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);

		// Skip invalid (recycled) clients
		if(client == NULL)
			continue;

		// Store clientID and number of queries in temporary array
		temparray[2*clientID + 0] = clientID;

		// If this client is managed by an alias-client, we substitute
		// -1 for the total count
		if(!client->flags.aliasclient && client->aliasclient_id > -1)
		{
			log_debug(DEBUG_API, "Skipping client (ID %d) contained in alias-client with ID %d",
			          clientID, client->aliasclient_id);
			temparray[2*clientID + 1] = -1;
		}
		else
			temparray[2*clientID + 1] = client->count;
	}

	// Sort temporary array
	qsort(temparray, counters->clients, sizeof(int[2]), cmpdesc);

	// Main return loop
	cJSON *history = JSON_NEW_ARRAY();
	int others_total = 0;
	for(unsigned int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(item, "timestamp", overTime[slot].timestamp);

		// Loop over clients to generate output to be sent to the client
		cJSON *data = JSON_NEW_ARRAY();
		int others = 0;
		for(int id = 0; id < counters->clients; id++)
		{
			// Get client pointer
			const int clientID = temparray[2*id + 0];
			const int count = temparray[2*id + 1];
			const clientsData* client = getClient(clientID, true);

			// Skip invalid (recycled) clients
			if(client == NULL)
				continue;

			// Skip clients which are managed by alias-clients
			// altogether. The user doesn't want them to appear as
			// individual devices
			if(count < 0)
				continue;

			// Skip clients when we reached the maximum number of
			// clients to return They are summed together under the
			// special "other" client
			if(id >= (int)Nc)
			{
				others += client->overTime[slot];
				continue;
			}

			JSON_ADD_NUMBER_TO_ARRAY(data, client->overTime[slot]);
		}
		// Add others as last element in the array
		others_total += others;
		JSON_ADD_NUMBER_TO_ARRAY(data, others);

		JSON_ADD_ITEM_TO_OBJECT(item, "data", data);
		JSON_ADD_ITEM_TO_ARRAY(history, item);
	}
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "history", history);

	// Loop over clients to generate output to be sent to the client
	cJSON *clients = JSON_NEW_ARRAY();
	for(int id = 0; id < counters->clients; id++)
	{
		// Get client pointer
		const int clientID = temparray[2*id + 0];
		const int count = temparray[2*id + 1];
		const clientsData* client = getClient(clientID, true);

		// Skip invalid (recycled) clients
		if(client == NULL)
			continue;

		// Skip clients which should be hidden (managed by
		// alias-clients). Also skip clients when we reached the maximum
		// number of clients to return
		if(count < 0 || id >= (int)Nc)
			continue;

		// Get client name and IP address
		const char *client_ip = getstr(client->ippos);
		const char *client_name = client->namepos != 0 ? getstr(client->namepos) : NULL;

		// Create JSON object for this client
		cJSON *item = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(item, "name", client_name);
		JSON_REF_STR_IN_OBJECT(item, "ip", client_ip);
		JSON_ADD_NUMBER_TO_OBJECT(item, "total", client->count);
		JSON_ADD_ITEM_TO_ARRAY(clients, item);
	}

	// Add "others" client
	cJSON *item = JSON_NEW_OBJECT();
	JSON_REF_STR_IN_OBJECT(item, "name", "other clients");
	JSON_REF_STR_IN_OBJECT(item, "ip", "0.0.0.0");
	JSON_ADD_NUMBER_TO_OBJECT(item, "total", others_total);
	JSON_ADD_ITEM_TO_ARRAY(clients, item);

	// Unlock already here to avoid keeping the lock during JSON generation
	// This is safe because we don't access any shared memory after this
	// point and all strings in the JSON are references to idempotent shared
	// memory and can, thus, be accessed at any time without locking
	unlock_shm();

	// Free memory
	free(temparray);

	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_SEND_OBJECT(json);
}
