/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
#include "shmem.h"
#include "datastructure.h"
// overTime data
#include "overTime.h"
// config struct
#include "config/config.h"
// read_setupVarsconf()
#include "config/setupVars.h"
// get_aliasclient_list()
#include "database/aliasclients.h"

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

static unsigned int build_client_temparray(int *temparray, const int slot)
{
	// Clear temporary array
	memset(temparray, 0, 2 * counters->clients * sizeof(int));

	unsigned int num_clients = 0;
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);

		// Skip invalid (recycled) clients
		if(client == NULL)
			continue;

		// If this client is managed by an alias-client, we substitute
		// -1 for the total count
		if(!client->flags.aliasclient && client->aliasclient_id > -1)
		{
			log_debug(DEBUG_API, "Skipping client (ID %d) contained in alias-client with ID %d",
			          clientID, client->aliasclient_id);
			continue;
		}
		else

		// Store clientID and number of queries in temporary array
		// If the slot is -1, we return the total number of queries.
		// Otherwise, we return the number of queries in the given time
		// slot
		temparray[2*num_clients + 0] = clientID;
		temparray[2*num_clients + 1] = slot < 0 ? client->count : client->overTime[slot];

		// Increase number of clients by one
		num_clients++;
	}

	return num_clients;
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
	}

	// Limit the number of clients to the maximum number of clients
	if(Nc == 0 || Nc > (unsigned int)counters->clients)
	{
		// Return all clients
		Nc = counters->clients;
	}

	// Lock shared memory
	lock_shm();

	// Allocate memory for the temporary buffer for ranking our clients
	int *temparray = calloc(counters->clients, 2 * sizeof(int));
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
	unsigned int num_clients = build_client_temparray(temparray, -1);

	if(config.webserver.api.client_history_global_max.v.b)
	{
		// Sort temporary array. Even when the array itself has <counters.clients>
		// elements, we only sort the first <clients> elements to avoid sorting
		// the whole array (the final elements are not used when clients have been
		// skipped above, e.g. alias-clients or recycled clients)
		qsort(temparray, num_clients, sizeof(int[2]), cmpdesc);
	}

	// Main return loop
	int others_total = 0;

	cJSON *history = JSON_NEW_ARRAY();
	for(unsigned int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(item, "timestamp", overTime[slot].timestamp);

		// If we are not in global-max mode, we need to build the temporary
		// client array for each slot individually
		if(!config.webserver.api.client_history_global_max.v.b)
		{
			// Collect global client data
			num_clients = build_client_temparray(temparray, slot);

			// Sort temporary array. Even when the array itself has <counters.clients>
			// elements, we only sort the first <clients> elements to avoid sorting
			// the whole array (the final elements are not used when clients have been
			// skipped above, e.g. alias-clients or recycled clients)
			qsort(temparray, num_clients, sizeof(int[2]), cmpdesc);
		}

		// Loop over clients to generate output to be sent to the client
		int others = 0;
		cJSON *data = JSON_NEW_OBJECT();
		for(unsigned int arrayID = 0; arrayID < num_clients; arrayID++)
		{

			// Get client pointer
			const int clientID = temparray[2*arrayID + 0];

			// All clientIDs will be valid because we only added
			// valid clients to the temparray
			const clientsData* client = getClient(clientID, true);

			// Skip further clients when we reached the maximum
			// number of clients to return They are summed together
			// under the special "other" client
			// -1 because of the special "other" client we add below
			// This is disabled when Nc is 0, which means we want to return
			// all clients
			if(arrayID >= Nc - 1)
			{
				others += client->overTime[slot];
				continue;
			}

			// Add client to the array
			cJSON_AddNumberToObject(data, getstr(client->ippos), client->overTime[slot]);
		}
		// Add others as last element in the array
		others_total += others;
		JSON_ADD_NUMBER_TO_OBJECT(data, "others", others);

		JSON_ADD_ITEM_TO_OBJECT(item, "data", data);
		JSON_ADD_ITEM_TO_ARRAY(history, item);
	}

	// Loop over clients to generate output to be sent to the client
	cJSON *clients = JSON_NEW_OBJECT();
	for(unsigned int arrayID = 0; arrayID < num_clients; arrayID++)
	{
		// Get client pointer
		const int clientID = temparray[2*arrayID + 0];

		// All clientIDs will be valid because we only added
		// valid clients to the temparray
		const clientsData* client = getClient(clientID, true);

		// Break once we reached the maximum number of clients to return
		// -1 because of the special "other" client we add below
		// This is disabled when
		// - N is 0, which means we want to return all clients, or
		// - when we are NOT in global-max mode as we need to return all
		//   clients in that case
		if(config.webserver.api.client_history_global_max.v.b && arrayID >= Nc - 1)
			break;

		// Get client name and IP address
		const char *client_ip = getstr(client->ippos);
		const char *client_name = client->namepos != 0 ? getstr(client->namepos) : NULL;

		// Create JSON object for this client
		cJSON *item = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(item, "name", client_name);
		JSON_ADD_NUMBER_TO_OBJECT(item, "total", client->count);
		JSON_ADD_ITEM_TO_OBJECT(clients, client_ip, item);
	}

	// Unlock already here to avoid keeping the lock during JSON generation
	// This is safe because we don't access any shared memory after this
	// point and all strings in the JSON are references to idempotent shared
	// memory and can, thus, be accessed at any time without locking
	unlock_shm();

	// Add "others" client only if there are more clients than we return
	// and if we are not returning all clients
	if(num_clients > Nc)
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(item, "name", "other clients");
		JSON_ADD_NUMBER_TO_OBJECT(item, "total", others_total);
		JSON_ADD_ITEM_TO_OBJECT(clients, "others", item);
	}

	// Free memory
	free(temparray);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "history", history);
	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_SEND_OBJECT(json);
}
