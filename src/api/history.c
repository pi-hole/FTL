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

#define DEFAULT_MAX_CLIENTS 20
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

	// Get number of clients to return´
	unsigned int Nc = min(counters->clients, DEFAULT_MAX_CLIENTS);
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

	// Get clients which the user doesn't want to see
	// if skipclient[i] == true then this client should be hidden from
	// returned data. We initialize it with false
	bool *skipclient = calloc(counters->clients, sizeof(bool));
	int *temparray = calloc(2*counters->clients, sizeof(int));
	if(skipclient == NULL || temparray == NULL)
	{
		unlock_shm();
		return send_json_error(api, 500, "internal_error",
		                       "Failed to allocate memory for client history", NULL);
	}

	// Check if the user wants to exclude any clients, this code path is
	// only taken if the user has configured the web interface to exclude
	// clients (it will most often be skipped)
	unsigned int excludeClients = cJSON_GetArraySize(config.webserver.api.excludeClients.v.json);
	if(excludeClients > 0)
	{
		for(int clientID = 0; clientID < counters->clients; clientID++)
		{
			// Get client pointer
			const clientsData* client = getClient(clientID, true);
			if(client == NULL)
				continue;
			// Check if this client should be skipped
			for(unsigned int i = 0; i < excludeClients; i++)
			{
				cJSON *item = cJSON_GetArrayItem(config.webserver.api.excludeClients.v.json, i);
				if(strcmp(getstr(client->ippos), item->valuestring) == 0 ||
				   strcmp(getstr(client->namepos), item->valuestring) == 0)
					skipclient[clientID] = true;
			}
		}
	}

	// Skip clients included in others (in alias-clients)
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		// Check if this client should be skipped
		if(!client->flags.aliasclient && client->aliasclient_id > -1)
			skipclient[clientID] = true;
	}

	// Get MAX_CLIENTS clients with the highest number of queries
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);

		// Skip invalid clients
		if(client == NULL)
			continue;

		// Store clientID and number of queries in temporary array
		temparray[2*clientID + 0] = clientID;
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
			const clientsData* client = getClient(clientID, true);

			// Skip invalid (recycled) clients
			if(client == NULL)
				continue;

			// Skip clients which should be hidden and add them to the "others" counter.
			// Also skip clients when we reached the maximum number of clients to return
			if(skipclient[clientID] || id >= (int)Nc)
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
		const clientsData* client = getClient(clientID, true);

		// Skip invalid (recycled) clients
		if(client == NULL)
			continue;

		// Skip clients which should be hidden. Also skip clients when
		// we reached the maximum number of clients to return
		if(skipclient[clientID] || id >= (int)Nc)
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
	free(skipclient);
	free(temparray);

	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_SEND_OBJECT(json);
}
