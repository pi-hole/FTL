/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/ftl
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
#include "ftl.h"
#include "datastructure.h"
// get_FTL_version()
#include "log.h"
// git constants
#include "version.h"
// config struct
#include "config.h"
// {un,}lock_shm()
#include "../shmem.h"
// networkrecord
#include "../database/network-table.h"

int api_ftl_clientIP(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const struct mg_request_info *request = mg_get_request_info(conn);
	JSON_OBJ_REF_STR(json,"remote_addr", request->remote_addr);
	JSON_SEND_OBJECT(json);
}

fifologData *fifo_log = NULL;
int api_ftl_dnsmasq_log(struct mg_connection *conn)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(conn) < 0)
	{
		return send_json_unauthorized(conn);
	}

	unsigned int start = 0u;
	const struct mg_request_info *request = mg_get_request_info(conn);
	if(request->query_string != NULL)
	{
		// Does the user request an ID to sent from?
		int num;
		if((num = get_int_var(request->query_string, "nextID")) > 0)
		{
			if(num >= fifo_log->next_id)
			{
				// Do not return any data
				start = LOG_SIZE;
			}
			else if(num < max((fifo_log->next_id) - LOG_SIZE, 0))
			{
				// Requested an ID smaller than the lowest one we have
				// We return the entire buffer
				start = 0u;
			}
			else if(fifo_log->next_id >= LOG_SIZE)
			{
				// Reply with partial buffer, measure from the end
				// (the log is full)
				start = LOG_SIZE - (fifo_log->next_id - num);
			}
			else
			{
				// Reply with partial buffer, measure from the start
				// (the log is not yet full)
				start = num;
			}
		}
	}

	// Process data
	cJSON *json = JSON_NEW_OBJ();
	cJSON *log = JSON_NEW_ARRAY();
	for(unsigned int i = start; i < LOG_SIZE; i++)
	{
		if(fifo_log->timestamp[i] == 0)
		{
			// Uninitialized buffer entry
			break;
		}

		cJSON *entry = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(entry, "timestamp", fifo_log->timestamp[i]);
		JSON_OBJ_REF_STR(entry, "message", fifo_log->message[i]);
		JSON_ARRAY_ADD_ITEM(log, entry);
	}
	JSON_OBJ_ADD_ITEM(json, "log", log);
	JSON_OBJ_ADD_NUMBER(json, "nextID", fifo_log->next_id);
	JSON_SEND_OBJECT(json);
}

void add_to_dnsmasq_log_fifo_buffer(const char *payload, const int length)
{
	// Lock SHM
	lock_shm();

	unsigned int idx = fifo_log->next_id++;
	if(idx >= LOG_SIZE)
	{
		// Log is full, move everything one slot forward to make space for a new record at the end
		// This pruges the oldest message from the list (it is overwritten by the second message)
		memmove(fifo_log->message[0], fifo_log->message[1], (LOG_SIZE - 1u) * MAX_MESSAGE);
		memmove(&fifo_log->timestamp[0], &fifo_log->timestamp[1], (LOG_SIZE - 1u) * sizeof(time_t));
		idx = LOG_SIZE - 1u;
	}

	// Copy relevant string into temporary buffer
	memcpy(fifo_log->message[idx], payload, length);

	// Zero-terminate buffer, truncate newline if found
	if(fifo_log->message[idx][length - 1u] == '\n')
	{
		fifo_log->message[idx][length - 1u] = '\0';
	}
	else
	{
		fifo_log->message[idx][length] = '\0';
	}

	// Set timestamp
	fifo_log->timestamp[idx] = time(NULL);

	// Unlock SHM
	unlock_shm();
}

int api_ftl_network(struct mg_connection *conn)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(conn) < 0)
	{
		return send_json_unauthorized(conn);
	}

	// Connect to database
	if(!networkTable_readDevices())
	{
		cJSON *json = JSON_NEW_OBJ();
		return send_json_error(conn, 500,
                                       "database_error",
                                       "Could not read network details from database table",
                                       json);
	}

	// Read record for a single device
	networkrecord network;
	cJSON *json = JSON_NEW_ARRAY();
	while(networkTable_readDevicesGetRecord(&network))
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(item, "hwaddr", network.hwaddr);
		JSON_OBJ_COPY_STR(item, "interface", network.interface);
		JSON_OBJ_COPY_STR(item, "name", network.name);
		JSON_OBJ_ADD_NUMBER(item, "firstSeen", network.firstSeen);
		JSON_OBJ_ADD_NUMBER(item, "lastQuery", network.lastQuery);
		JSON_OBJ_ADD_NUMBER(item, "numQueries", network.numQueries);
		JSON_OBJ_COPY_STR(item, "macVendor", network.macVendor);

		// Build array of all IP addresses known associated to this client
		cJSON *ip = JSON_NEW_ARRAY();
		if(networkTable_readIPs(network.id))
		{
			// Only walk known IP addresses when SELECT query succeeded
			const char *ipaddr;
			while((ipaddr = networkTable_readIPsGetRecord()) != NULL)
			{
				JSON_ARRAY_COPY_STR(ip, ipaddr);
			}
			networkTable_readIPsFinalize();
		}
		JSON_OBJ_ADD_ITEM(item, "ip", ip);

		JSON_ARRAY_ADD_ITEM(json, item);
	}
	networkTable_readDevicesFinalize();

	JSON_SEND_OBJECT(json);
}
