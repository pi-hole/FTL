/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/ftl
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
// struct fifologData
#include "../fifo.h"

int api_ftl_client(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const struct mg_request_info *request = mg_get_request_info(conn);

	// Add client's IP address
	JSON_OBJ_REF_STR(json, "remote_addr", request->remote_addr);

	// Add HTTP version
	JSON_OBJ_REF_STR(json, "http_version", request->http_version);

	// Add request method
	JSON_OBJ_REF_STR(json, "method", request->request_method);

	// Add HTTP headers
	cJSON *headers = JSON_NEW_ARRAY();
	for(int i = 0; i < request->num_headers; i++)
	{
		// Add headers
		cJSON *header = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(header, "name", request->http_headers[i].name);
		JSON_OBJ_REF_STR(header, "value", request->http_headers[i].value);
		JSON_ARRAY_ADD_ITEM(headers, header);
	}
	JSON_OBJ_ADD_ITEM(json, "headers", headers);

	JSON_SEND_OBJECT(json);
}

// fifologData is allocated in shared memory for cross-fork compatibility
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

	// Send data
	JSON_SEND_OBJECT(json);
}
