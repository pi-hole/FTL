/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/logs
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// struct fifologData
#include "log.h"
#include "config/config.h"
// main_pid()
#include "signals.h"

// fifologData is allocated in shared memory for cross-fork compatibility
int api_logs(struct ftl_conn *api)
{
	unsigned int start = 0u;
	if(api->request->query_string != NULL)
	{
		// Does the user request an ID to sent from?
		unsigned int nextID;
		if(get_uint_var(api->request->query_string, "nextID", &nextID))
		{
			if(nextID >= fifo_log->logs[api->opts.which].next_id)
			{
				// Do not return any data
				start = LOG_SIZE;
			}
			else if((fifo_log->logs[api->opts.which].next_id > LOG_SIZE) && nextID < (fifo_log->logs[api->opts.which].next_id) - LOG_SIZE)
			{
				// Requested an ID smaller than the lowest one we have
				// We return the entire buffer
				start = 0u;
			}
			else if(fifo_log->logs[api->opts.which].next_id >= LOG_SIZE)
			{
				// Reply with partial buffer, measure from the end
				// (the log is full)
				start = LOG_SIZE - (fifo_log->logs[api->opts.which].next_id - nextID);
			}
			else
			{
				// Reply with partial buffer, measure from the start
				// (the log is not yet full)
				start = nextID;
			}
		}
	}

	// Process data
	cJSON *json = JSON_NEW_OBJECT();
	cJSON *log = JSON_NEW_ARRAY();
	for(unsigned int i = start; i < LOG_SIZE; i++)
	{
		if(fifo_log->logs[api->opts.which].timestamp[i] < 1.0)
		{
			// Uninitialized buffer entry
			break;
		}

		cJSON *entry = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(entry, "timestamp", fifo_log->logs[api->opts.which].timestamp[i]);
		JSON_REF_STR_IN_OBJECT(entry, "message", fifo_log->logs[api->opts.which].message[i]);
		JSON_REF_STR_IN_OBJECT(entry, "prio", fifo_log->logs[api->opts.which].prio[i]);
		JSON_ADD_ITEM_TO_ARRAY(log, entry);
	}
	JSON_ADD_ITEM_TO_OBJECT(json, "log", log);
	JSON_ADD_NUMBER_TO_OBJECT(json, "nextID", fifo_log->logs[api->opts.which].next_id);
	JSON_ADD_NUMBER_TO_OBJECT(json, "pid", main_pid());

	// Add file name
	const char *logfile = NULL;
	switch(api->opts.which)
	{
		case FIFO_FTL:
			logfile = config.files.log.ftl.v.s;
			break;
		case FIFO_DNSMASQ:
			logfile = config.files.log.dnsmasq.v.s;
			break;
		case FIFO_WEBSERVER:
			logfile = config.files.log.webserver.v.s;
			break;
		case FIFO_MAX:
			// This should never happen
			break;
	}
	JSON_REF_STR_IN_OBJECT(json, "file", logfile);

	// Send data
	JSON_SEND_OBJECT(json);
}
