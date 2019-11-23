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
#include "http-common.h"
#include "routes.h"
#include "ftl.h"
#include "json_macros.h"
#include "datastructure.h"
// get_FTL_version()
#include "log.h"
// git constants
#include "version.h"
// config struct
#include "config.h"

int api_ftl_clientIP(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const struct mg_request_info *request = mg_get_request_info(conn);
	JSON_OBJ_REF_STR(json,"remote_addr", request->remote_addr);
	JSON_SEND_OBJECT(json);
}

static char dnsmasq_log_messages[LOG_SIZE][MAX_MESSAGE] = {{ 0 }};
static time_t dnsmasq_log_stamps[LOG_SIZE] = { 0 };
static int dnsmasq_next_id = 0;

int api_ftl_dnsmasq_log(struct mg_connection *conn)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(conn) < 0)
	{
		return send_json_unauthorized(conn, NULL);
	}

	unsigned int start = 0u;
	const struct mg_request_info *request = mg_get_request_info(conn);
	if(request->query_string != NULL)
	{
		// Does the user request an ID to sent from?
		int num;
		if((num = get_int_var(request->query_string, "nextID")) > 0)
		{
			if(num >= dnsmasq_next_id)
			{
				// Do not return any data
				start = LOG_SIZE;
			}
			else if(num < max(dnsmasq_next_id - LOG_SIZE, 0))
			{
				// Requested an ID smaller than the lowest one we have
				// We return the entire buffer
				start = 0;
			}
			else if(dnsmasq_next_id >= LOG_SIZE)
			{
				// Reply with partial buffer, measure from the end
				// (the log is full)
				start = LOG_SIZE - (dnsmasq_next_id - num);
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
	unsigned int idx = 0u;
	for(unsigned int i = start; i < LOG_SIZE; i++)
	{
		// Reconstruct log message identification number
		if(dnsmasq_next_id < LOG_SIZE)
		{
			idx = i;
		}
		else
		{
			idx = dnsmasq_next_id - LOG_SIZE + i;
		}

		if(dnsmasq_log_stamps[i] == 0)
		{
			// Uninitialized buffer entry
			break;
		}

		cJSON *entry = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(entry, "id", idx);
		JSON_OBJ_ADD_NUMBER(entry, "timestamp", dnsmasq_log_stamps[i]);
		JSON_OBJ_REF_STR(entry, "message", dnsmasq_log_messages[i]);
		JSON_ARRAY_ADD_ITEM(log, entry);
	}
	JSON_OBJ_ADD_ITEM(json, "log", log);
	JSON_OBJ_ADD_NUMBER(json, "nextID", dnsmasq_next_id);
	JSON_SEND_OBJECT(json);
}

void add_to_dnsmasq_log_fifo_buffer(const char *payload, const int length)
{
	unsigned int idx = dnsmasq_next_id++;
	if(idx >= LOG_SIZE)
	{
		// Log is full, move everything one slot forward to make space
		memmove(dnsmasq_log_messages[0], dnsmasq_log_messages[1], (LOG_SIZE - 1u) * MAX_MESSAGE);
		idx = LOG_SIZE - 1u;
	}
	// Copy relevant string into temporary buffer
	memcpy(dnsmasq_log_messages[idx], payload, length);

	// Zero-terminate buffer, truncate newline if found
	if(dnsmasq_log_messages[idx][length - 1u] == '\n')
	{
		dnsmasq_log_messages[idx][length - 1u] = '\0';
	}
	else
	{
		dnsmasq_log_messages[idx][length] = '\0';
	}

	// Set timestamp
	dnsmasq_log_stamps[idx] = time(NULL);
}