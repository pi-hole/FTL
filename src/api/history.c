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
#include "../config.h"
// read_setupVarsconf()
#include "../setupVars.h"
// get_aliasclient_list()
#include "../database/aliasclients.h"

int api_history(struct ftl_conn *api)
{
	int from = 0, until = OVERTIME_SLOTS;
	bool found = false;
	time_t mintime = overTime[0].timestamp;

	// Start with the first non-empty overTime slot
	for(int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		if((overTime[slot].total > 0 || overTime[slot].blocked > 0) &&
		   overTime[slot].timestamp >= mintime)
		{
			from = slot;
			found = true;
			break;
		}
	}

	// End with last non-empty overTime slot
	for(int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		if(overTime[slot].timestamp >= time(NULL))
		{
			until = slot;
			break;
		}
	}

	// If there is no data to be sent, we send back an empty array
	// and thereby return early
	if(!found)
	{
		cJSON *json = JSON_NEW_ARRAY();
		cJSON *item = JSON_NEW_OBJ();
		JSON_ARRAY_ADD_ITEM(json, item);
		JSON_SEND_OBJECT(json);
	}

	// Minimum structure is
	// {"history":[]}
	cJSON *json = JSON_NEW_OBJ();
	cJSON *history = JSON_NEW_ARRAY();
	for(int slot = from; slot < until; slot++)
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "timestamp", overTime[slot].timestamp);
		JSON_OBJ_ADD_NUMBER(item, "total", overTime[slot].total);
		JSON_OBJ_ADD_NUMBER(item, "cached", overTime[slot].cached);
		JSON_OBJ_ADD_NUMBER(item, "blocked", overTime[slot].blocked);
		JSON_ARRAY_ADD_ITEM(history, item);
	}
	JSON_OBJ_ADD_ITEM(json, "history", history);
	JSON_SEND_OBJECT(json);
}

int api_history_clients(struct ftl_conn *api)
{
	int sendit = -1, until = OVERTIME_SLOTS;

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Find minimum ID to send
	for(int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		if((overTime[slot].total > 0 || overTime[slot].blocked > 0) &&
		   overTime[slot].timestamp >= overTime[0].timestamp)
		{
			sendit = slot;
			break;
		}
	}

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS || sendit < 0)
	{
		// Minimum structure is
		// {"history":[], "clients":[]}
		cJSON *json = JSON_NEW_OBJ();
		cJSON *history = JSON_NEW_ARRAY();
		JSON_OBJ_ADD_ITEM(json, "history", history);
		cJSON *clients = JSON_NEW_ARRAY();
		JSON_OBJ_ADD_ITEM(json, "clients", clients);
		JSON_SEND_OBJECT(json);
	}

	// Find minimum ID to send
	for(int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		if(overTime[slot].timestamp >= time(NULL))
		{
			until = slot;
			break;
		}
	}

	// Get clients which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	// Array of clients to be skipped in the output
	// if skipclient[i] == true then this client should be hidden from
	// returned data. We initialize it with false
	bool skipclient[counters->clients];
	memset(skipclient, false, counters->clients*sizeof(bool));

	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);

		for(int clientID=0; clientID < counters->clients; clientID++)
		{
			// Get client pointer
			const clientsData* client = getClient(clientID, true);
			if(client == NULL)
				continue;
			// Check if this client should be skipped
			if(insetupVarsArray(getstr(client->ippos)) ||
			   insetupVarsArray(getstr(client->namepos)) ||
			   (!client->flags.aliasclient && client->aliasclient_id > -1))
				skipclient[clientID] = true;
		}
	}

	cJSON *history = JSON_NEW_ARRAY();
	// Main return loop
	for(int slot = sendit; slot < until; slot++)
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "timestamp", overTime[slot].timestamp);

		// Loop over clients to generate output to be sent to the client
		cJSON *data = JSON_NEW_ARRAY();
		for(int clientID = 0; clientID < counters->clients; clientID++)
		{
			if(skipclient[clientID])
				continue;

			// Get client pointer
			const clientsData* client = getClient(clientID, true);

			// Skip invalid clients and also those managed by alias clients
			if(client == NULL || client->aliasclient_id >= 0)
				continue;

			const int thisclient = client->overTime[slot];

			JSON_ARRAY_ADD_NUMBER(data, thisclient);
		}
		JSON_OBJ_ADD_ITEM(item, "data", data);
		JSON_ARRAY_ADD_ITEM(history, item);
	}
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "history", history);

	cJSON *clients = JSON_NEW_ARRAY();
	// Loop over clients to generate output to be sent to the client
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		if(skipclient[clientID])
			continue;

		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		const char *client_ip = getstr(client->ippos);
		const char *client_name = client->namepos != 0 ? getstr(client->namepos) : NULL;

		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(item, "name", client_name);
		JSON_OBJ_REF_STR(item, "ip", client_ip);
		JSON_ARRAY_ADD_ITEM(clients, item);
	}
	JSON_OBJ_ADD_ITEM(json, "clients", clients);

	if(excludeclients != NULL)
		clearSetupVarsArray();

	JSON_SEND_OBJECT(json);
}
