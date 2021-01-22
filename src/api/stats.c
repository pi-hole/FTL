/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
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
#include "routes.h"
#include "../shmem.h"
#include "../datastructure.h"
// read_setupVarsconf()
#include "../setupVars.h"
// logg()
#include "../log.h"
// config struct
#include "../config.h"
// in_auditlist()
#include "../database/gravity-db.h"
// overTime data
#include "../overTime.h"
// enum REGEX
#include "../regex_r.h"
// sqrt()
#include <math.h>
// get_aliasclient_list()
#include "../database/aliasclients.h"

/* qsort comparision function (count field), sort ASC
static int __attribute__((pure)) cmpasc(const void *a, const void *b)
{
	const int *elem1 = (int*)a;
	const int *elem2 = (int*)b;

	if (elem1[1] < elem2[1])
		return -1;
	else if (elem1[1] > elem2[1])
		return 1;
	else
		return 0;
} */

// qsort subroutine, sort DESC
static int __attribute__((pure)) cmpdesc(const void *a, const void *b)
{
	const int *elem1 = (int*)a;
	const int *elem2 = (int*)b;

	if (elem1[1] > elem2[1])
		return -1;
	else if (elem1[1] < elem2[1])
		return 1;
	else
		return 0;
}

int api_stats_summary(struct ftl_conn *api)
{
	const int blocked = counters->blocked;
	const int total = counters->queries;
	float percent_blocked = 0.0f;

	// Avoid 1/0 condition
	if(total > 0)
		percent_blocked = 1e2f*blocked/total;

	// unique_clients: count only clients that have been active within the most recent 24 hours
	int activeclients = 0;
	for(int clientID=0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		if(client->count > 0)
			activeclients++;
	}

	// Send response
	cJSON *json = JSON_NEW_OBJ();
	const bool blocking = get_blockingstatus();
	JSON_OBJ_ADD_BOOL(json, "blocking", blocking); // same reply type as in /api/dns/status
	JSON_OBJ_ADD_NUMBER(json, "gravity_size", counters->gravity);
	JSON_OBJ_ADD_NUMBER(json, "blocked_queries", counters->blocked);
	JSON_OBJ_ADD_NUMBER(json, "percent_blocked", percent_blocked);
	JSON_OBJ_ADD_NUMBER(json, "unique_domains", counters->domains);
	JSON_OBJ_ADD_NUMBER(json, "forwarded_queries", counters->forwarded);
	JSON_OBJ_ADD_NUMBER(json, "cached_queries", counters->cached);
	JSON_OBJ_ADD_NUMBER(json, "privacy_level", config.privacylevel);
	JSON_OBJ_ADD_NUMBER(json, "total_clients", counters->clients);
	JSON_OBJ_ADD_NUMBER(json, "active_clients", activeclients);

	cJSON *total_queries = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(total_queries, "A", counters->querytype[TYPE_A]);
	JSON_OBJ_ADD_NUMBER(total_queries, "AAAA", counters->querytype[TYPE_AAAA]);
	JSON_OBJ_ADD_NUMBER(total_queries, "ANY", counters->querytype[TYPE_ANY]);
	JSON_OBJ_ADD_NUMBER(total_queries, "SRV", counters->querytype[TYPE_SRV]);
	JSON_OBJ_ADD_NUMBER(total_queries, "SOA", counters->querytype[TYPE_SOA]);
	JSON_OBJ_ADD_NUMBER(total_queries, "PTR", counters->querytype[TYPE_PTR]);
	JSON_OBJ_ADD_NUMBER(total_queries, "TXT", counters->querytype[TYPE_TXT]);
	JSON_OBJ_ADD_NUMBER(total_queries, "NAPTR", counters->querytype[TYPE_NAPTR]);
	JSON_OBJ_ADD_ITEM(json, "total_queries", total_queries);

	JSON_OBJ_ADD_NUMBER(json, "sum_queries", counters->queries);
	
	cJSON *reply_types = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(reply_types, "NODATA", counters->reply_NODATA);
	JSON_OBJ_ADD_NUMBER(reply_types, "NXDOMAIN", counters->reply_NXDOMAIN);
	JSON_OBJ_ADD_NUMBER(reply_types, "CNAME", counters->reply_CNAME);
	JSON_OBJ_ADD_NUMBER(reply_types, "IP", counters->reply_IP);
	JSON_OBJ_ADD_NUMBER(reply_types, "domain", counters->reply_domain);
	JSON_OBJ_ADD_ITEM(json, "reply_types", reply_types);

	// Get system object
	cJSON *system = JSON_NEW_OBJ();
	int ret = get_system_obj(api, system);
	if(ret != 0)
		return ret;
	JSON_OBJ_ADD_ITEM(json, "system", system);

	// Get FTL object
	cJSON *ftl = JSON_NEW_OBJ();
	ret = get_ftl_obj(api, ftl);
	if(ret != 0)
		return ret;
	JSON_OBJ_ADD_ITEM(json, "ftl", ftl);

	JSON_SEND_OBJECT(json);
}

int api_stats_overTime_history(struct ftl_conn *api)
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
	// {"data":[]}
	cJSON *json = JSON_NEW_OBJ();
	cJSON *data = JSON_NEW_ARRAY();
	for(int slot = from; slot < until; slot++)
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "timestamp", overTime[slot].timestamp);
		JSON_OBJ_ADD_NUMBER(item, "total", overTime[slot].total);
		JSON_OBJ_ADD_NUMBER(item, "cached", overTime[slot].cached);
		JSON_OBJ_ADD_NUMBER(item, "blocked", overTime[slot].blocked);
		JSON_ARRAY_ADD_ITEM(data, item);
	}
	JSON_OBJ_ADD_ITEM(json, "data", data);
	JSON_SEND_OBJECT(json);
}

int api_stats_top_domains(bool blocked, struct ftl_conn *api)
{
	int temparray[counters->domains][2], show = 10;
	bool audit = false;

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
	{
		if(config.debug & DEBUG_API)
			logg("Not returning top domains: Privacy level is set to %i",
			     config.privacylevel);

		// Minimum structure is
		// {"top_domains":[]}
		cJSON *json = JSON_NEW_OBJ();
		cJSON *top_domains = JSON_NEW_ARRAY();
		JSON_OBJ_ADD_ITEM(json, "top_domains", top_domains);
		JSON_SEND_OBJECT(json);
	}

	// /api/stats/top_domains?blocked=true is allowed as well
	if(api->request->query_string != NULL)
	{
		// Should blocked clients be shown?
		get_bool_var(api->request->query_string, "blocked", &blocked);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(api->request->query_string, "show", &show);

		// Apply Audit Log filtering?
		get_bool_var(api->request->query_string, "audit", &audit);
	}

	for(int domainID=0; domainID < counters->domains; domainID++)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(domainID, true);
		if(domain == NULL)
			continue;

		temparray[domainID][0] = domainID;
		if(blocked)
			temparray[domainID][1] = domain->blockedcount;
		else
			// Count only permitted queries
			temparray[domainID][1] = (domain->count - domain->blockedcount);
	}

	// Sort temporary array
	qsort(temparray, counters->domains, sizeof(int[2]), cmpdesc);

	// Get filter
	const char* filter = read_setupVarsconf("API_QUERY_LOG_SHOW");
	bool showpermitted = true, showblocked = true;
	if(filter != NULL)
	{
		if((strcmp(filter, "permittedonly")) == 0)
			showblocked = false;
		else if((strcmp(filter, "blockedonly")) == 0)
			showpermitted = false;
		else if((strcmp(filter, "nothing")) == 0)
		{
			showpermitted = false;
			showblocked = false;
		}
	}
	clearSetupVarsArray();

	// Get domains which the user doesn't want to see
	char *excludedomains = NULL;
	if(!audit)
	{
		excludedomains = read_setupVarsconf("API_EXCLUDE_DOMAINS");
		if(excludedomains != NULL)
		{
			getSetupVarsArray(excludedomains);
		}
	}

	int n = 0;
	cJSON *top_domains = JSON_NEW_ARRAY();
	for(int i=0; i < counters->domains; i++)
	{
		// Get sorted index
		const int domainID = temparray[i][0];
		// Get domain pointer
		const domainsData* domain = getDomain(domainID, true);
		if(domain == NULL)
			continue;

		// Skip this domain if there is a filter on it
		if(excludedomains != NULL && insetupVarsArray(getstr(domain->domainpos)))
			continue;

		// Skip this domain if already audited
		if(audit && in_auditlist(getstr(domain->domainpos)) > 0)
		{
			if(config.debug & DEBUG_API)
				logg("API: %s has been audited.", getstr(domain->domainpos));
			continue;
		}

		// Hidden domain, probably due to privacy level. Skip this in the top lists
		if(strcmp(getstr(domain->domainpos), HIDDEN_DOMAIN) == 0)
			continue;

		int count = -1;
		if(blocked && showblocked && domain->blockedcount > 0)
		{
			count = domain->blockedcount;
			n++;
		}
		else if(!blocked && showpermitted && (domain->count - domain->blockedcount) > 0)
		{
			count = domain->count - domain->blockedcount;
			n++;
		}
		if(count > -1)
		{
			cJSON *domain_item = JSON_NEW_OBJ();
			JSON_OBJ_REF_STR(domain_item, "domain", getstr(domain->domainpos));
			JSON_OBJ_ADD_NUMBER(domain_item, "count", count);
			JSON_ARRAY_ADD_ITEM(top_domains, domain_item);
		}

		// Only count entries that are actually sent and return when we have send enough data
		if(n == show)
			break;
	}

	if(excludedomains != NULL)
		clearSetupVarsArray();

	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "top_domains", top_domains);

	if(blocked)
	{
		JSON_OBJ_ADD_NUMBER(json, "blocked_queries", counters->blocked);
	}
	else
	{
		const int total_queries = counters->forwarded + counters->cached + counters->blocked;
		JSON_OBJ_ADD_NUMBER(json, "total_queries", total_queries);
	}

	JSON_SEND_OBJECT(json);
}

int api_stats_top_clients(bool blocked, struct ftl_conn *api)
{
	int temparray[counters->clients][2], show = 10;
	bool includezeroclients = false;

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		if(config.debug & DEBUG_API)
			logg("Not returning top clients: Privacy level is set to %i",
			     config.privacylevel);

		// Minimum structure is
		// {"top_clients":[]}
		cJSON *json = JSON_NEW_OBJ();
		cJSON *top_clients = JSON_NEW_ARRAY();
		JSON_OBJ_ADD_ITEM(json, "top_clients", top_clients);
		JSON_SEND_OBJECT(json);
	}

	// /api/stats/top_clients9?blocked=true is allowed as well
	if(api->request->query_string != NULL)
	{
		// Should blocked clients be shown?
		get_bool_var(api->request->query_string, "blocked", &blocked);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(api->request->query_string, "show", &show);

		// Show also clients which have not been active recently?
		get_bool_var(api->request->query_string, "withzero", &includezeroclients);
	}

	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);

		// Skip invalid clients and also those managed by alias clients
		if(client == NULL || (!client->flags.aliasclient && client->aliasclient_id >= 0))
			continue;

		temparray[clientID][0] = clientID;
		// Use either blocked or total count based on request string
		temparray[clientID][1] = blocked ? client->blockedcount : client->count;
	}

	// Sort temporary array
	qsort(temparray, counters->clients, sizeof(int[2]), cmpdesc);

	// Get clients which the user doesn't want to see
	const char* excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);
	}

	int n = 0;
	cJSON *top_clients = JSON_NEW_ARRAY();
	for(int i=0; i < counters->clients; i++)
	{
		// Get sorted indices and counter values (may be either total or blocked count)
		const int clientID = temparray[i][0];
		const int count = temparray[i][1];
		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		// Skip this client if there is a filter on it
		if(excludeclients != NULL &&
			(insetupVarsArray(getstr(client->ippos)) || insetupVarsArray(getstr(client->namepos))))
			continue;

		// Hidden client, probably due to privacy level. Skip this in the top lists
		if(strcmp(getstr(client->ippos), HIDDEN_CLIENT) == 0)
			continue;

		// Get client IP and name
		const char *client_ip = getstr(client->ippos);
		const char *client_name = getstr(client->namepos);

		// Return this client if either
		// - "withzero" option is set, and/or
		// - the client made at least one query within the most recent 24 hours
		if(includezeroclients || count > 0)
		{
			cJSON *client_item = JSON_NEW_OBJ();
			JSON_OBJ_REF_STR(client_item, "name", client_name);
			JSON_OBJ_REF_STR(client_item, "ip", client_ip);
			JSON_OBJ_ADD_NUMBER(client_item, "count", count);
			JSON_ARRAY_ADD_ITEM(top_clients, client_item);
			n++;
		}

		if(n == show)
			break;
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();

	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "top_clients", top_clients);

	if(blocked)
	{
		JSON_OBJ_ADD_NUMBER(json, "blocked_queries", counters->blocked);
	}
	else
	{
		const int total_queries = counters->forwarded + counters->cached + counters->blocked;
		JSON_OBJ_ADD_NUMBER(json, "total_queries", total_queries);
	}

	JSON_SEND_OBJECT(json);
}


int api_stats_upstreams(struct ftl_conn *api)
{
	int temparray[counters->forwarded][2];

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}
	for(int upstreamID = 0; upstreamID < counters->upstreams; upstreamID++)
	{
		// Get forward pointer
		const upstreamsData* forward = getUpstream(upstreamID, true);
		if(forward == NULL)
			continue;

		temparray[upstreamID][0] = upstreamID;
		temparray[upstreamID][1] = forward->count;
	}

	// Sort temporary array in descending order
	qsort(temparray, counters->forwarded, sizeof(int[2]), cmpdesc);

	// Loop over available forward destinations
	cJSON *upstreams = JSON_NEW_ARRAY();
	for(int i = -2; i < min(counters->upstreams, 8); i++)
	{
		int count = 0;
		const char* ip, *name;
		unsigned short port = 53;
		double responsetime = 0.0, uncertainty = 0.0;

		if(i == -2)
		{
			// Blocked queries (local lists)
			ip = "blocklist";
			name = ip;
			count = counters->blocked;
		}
		else if(i == -1)
		{
			// Local cache
			ip = "cache";
			name = ip;
			count = counters->cached;
		}
		else
		{
			// Regular upstream destionation
			// Get sorted indices
			const int upstreamID = temparray[i][0];

			// Get upstream pointer
			const upstreamsData* upstream = getUpstream(upstreamID, true);
			if(upstream == NULL)
				continue;

			// Get IP and host name of upstream destination if available
			ip = getstr(upstream->ippos);
			name = getstr(upstream->namepos);
			port = upstream->port;

			// Get percentage
			count = upstream->count;

			// Compute average response time and uncertainty (unit: seconds)
			if(upstream->responses > 0)
			{
				// Wehave to multiply runcertainty by 1e-4 to get seconds
				responsetime = 1e-4 * upstream->rtime / upstream->responses;
			}
			if(upstream->responses > 1)
			{
				// The actual value will be somewhere in a neighborhood around the mean value.
				// This neighborhood of values is the uncertainty in the mean.
				// Wehave to multiply runcertainty by (1e-4)^2 to get seconds
				uncertainty = sqrt(1e-8 * upstream->rtuncertainty / upstream->responses / (upstream->responses-1));
			}
		}

		// Send data:
		// - always if i < 0 (special upstreams: blocklist and cache)
		// - only if there are any queries for all others (i > 0)
		if(count > 0 || i < 0)
		{
			cJSON *upstream = JSON_NEW_OBJ();
			JSON_OBJ_REF_STR(upstream, "name", name);
			JSON_OBJ_REF_STR(upstream, "ip", ip);
			JSON_OBJ_ADD_NUMBER(upstream, "port", port);
			JSON_OBJ_ADD_NUMBER(upstream, "count", count);
			JSON_OBJ_ADD_NUMBER(upstream, "responsetime", responsetime);
			JSON_OBJ_ADD_NUMBER(upstream, "uncertainty", uncertainty);
			JSON_ARRAY_ADD_ITEM(upstreams, upstream);
		}
	}
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "upstreams", upstreams);
	JSON_OBJ_ADD_NUMBER(json, "forwarded_queries", counters->forwarded);
	const int total_queries = counters->forwarded + counters->cached + counters->blocked;
	JSON_OBJ_ADD_NUMBER(json, "total_queries", total_queries);
	JSON_SEND_OBJECT(json);
}

int api_stats_query_types(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Send response
	cJSON *json = JSON_NEW_ARRAY();
	for(int i = TYPE_A; i < TYPE_MAX; i++)
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(item, "name", querytypes[i]);
		JSON_OBJ_ADD_NUMBER(item, "count", counters->querytype[i]);
		JSON_ARRAY_ADD_ITEM(json, item);
	}
	JSON_SEND_OBJECT(json);
}

int api_stats_history(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_MAXIMUM)
	{
		// Minimum structure is
		// {"history":[{}]}
		cJSON *json = JSON_NEW_OBJ();
		cJSON *history = JSON_NEW_ARRAY();
		cJSON *item = JSON_NEW_OBJ();
		JSON_ARRAY_ADD_ITEM(history, item);
		JSON_OBJ_ADD_ITEM(json, "history", history);
		// There are no more queries available, send NULL cursor
		JSON_OBJ_ADD_NULL(json, "cursor");
		JSON_SEND_OBJECT(json);
	}

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Do we want a more specific version of this command (domain/client/time interval filtered)?
	unsigned int from = 0, until = 0;

	char *domainname = NULL;
	bool filterdomainname = false;
	int domainid = -1;

	char *clientname = NULL;
	bool filterclientname = false;
	int clientid = -1;
	int *clientid_list = NULL;

	int querytype = 0;

	char *forwarddest = NULL;
	bool filterforwarddest = false;
	int forwarddestid = 0;

	// We start with the most recent query at the beginning (until the cursor is changed)
	unsigned int cursor = counters->queries;
	// We send 200 queries (until the API is asked for a different limit)
	unsigned int show = 200u;

	if(api->request->query_string != NULL)
	{
		// Time filtering?
		get_uint_var(api->request->query_string, "from", &from);
		get_uint_var(api->request->query_string, "until", &until);

		// Query type filtering?
		int num;
		if(get_int_var(api->request->query_string, "querytype", &num) && num < TYPE_MAX)
			querytype = num;

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_uint_var(api->request->query_string, "show", &show);

		// Forward destination filtering?
		char buffer[256] = { 0 };
		if(GET_VAR("forward", buffer, api->request->query_string) > 0)
		{
			forwarddest = calloc(256, sizeof(char));
			if(forwarddest == NULL)
			{
				return false;
			}
			sscanf(buffer, "%255s", forwarddest);
			filterforwarddest = true;

			if(strcmp(forwarddest, "cache") == 0)
			{
				forwarddestid = -1;
			}
			else if(strcmp(forwarddest, "blocklist") == 0)
			{
				forwarddestid = -2;
			}
			else
			{
				// Extract address/name and port
				char serv_addr[256] = { 0 };
				unsigned int serv_port = 53;
				// We limit the number of bytes written into the serv_addr buffer
				// to prevent buffer overflows. If there is no port available in
				// the database, we skip extracting them and use the default port
				sscanf(forwarddest, "%255[^#]#%u", serv_addr, &serv_port);
				serv_addr[INET6_ADDRSTRLEN-1] = '\0';

				// Iterate through all known forward destinations
				forwarddestid = -3;
				for(int i = 0; i < counters->forwarded; i++)
				{
					// Get forward pointer
					const upstreamsData* upstream = getUpstream(i, true);
					if(upstream == NULL)
					{
						continue;
					}

					// Try to match the requested string against their IP addresses and
					// (if available) their host names + port
					if((strcmp(getstr(upstream->ippos), serv_addr) == 0 ||
					   (upstream->namepos != 0 &&
					    strcmp(getstr(upstream->namepos), serv_addr) == 0)) &&
					   serv_port == upstream->port)
					{
						forwarddestid = i;
						break;
					}
				}
				if(forwarddestid < 0)
				{
					// Requested upstream has not been found, we directly
					// tell the user here as there is no data to be returned
					cJSON *json = JSON_NEW_OBJ();
					JSON_OBJ_COPY_STR(json, "upstream", forwarddest);
					free(forwarddest);

					return send_json_error(api, 400,
					                       "bad_request",
					                       "Requested upstream not found",
					                       json);
				}
			}
		}

		// Domain filtering?
		if(GET_VAR("domain", buffer, api->request->query_string) > 0)
		{
			domainname = calloc(512, sizeof(char));
			if(domainname == NULL)
			{
				return false;
			}
			sscanf(buffer, "%511s", domainname);
			filterdomainname = true;
			// Iterate through all known domains
			for(int domainID = 0; domainID < counters->domains; domainID++)
			{
				// Get domain pointer
				const domainsData* domain = getDomain(domainID, true);
				if(domain == NULL)
				{
					continue;
				}

				// Try to match the requested string
				if(strcmp(getstr(domain->domainpos), domainname) == 0)
				{
					domainid = domainID;
					break;
				}
			}
			if(domainid < 0)
			{
				// Requested domain has not been found, we directly
				// tell the user here as there is no data to be returned
				cJSON *json = JSON_NEW_OBJ();
				JSON_OBJ_COPY_STR(json, "domain", domainname);
				free(domainname);

				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested domain not found",
				                       json);
			}
		}

		// Client filtering?
		if(GET_VAR("client", buffer, api->request->query_string) > 0)
		{
			clientname = calloc(512, sizeof(char));
			if(clientname == NULL)
			{
				return false;
			}
			sscanf(buffer, "%511s", clientname);
			filterclientname = true;

			// Iterate through all known clients
			for(int i = 0; i < counters->clients; i++)
			{
				// Get client pointer
				const clientsData* client = getClient(i, true);

				// Skip invalid clients and also those managed by alias clients
				if(client == NULL || client->aliasclient_id >= 0)
					continue;

				// Try to match the requested string
				if(strcmp(getstr(client->ippos), clientname) == 0 ||
				   (client->namepos != 0 &&
				    strcmp(getstr(client->namepos), clientname) == 0))
				{
					clientid = i;

					// Is this an alias-client?
					if(client->flags.aliasclient)
						clientid_list = get_aliasclient_list(i);

					break;
				}
			}
			if(clientid < 0)
			{
				// Requested client has not been found, we directly
				// tell the user here as there is no data to be returned
				cJSON *json = JSON_NEW_OBJ();
				JSON_OBJ_COPY_STR(json, "client", clientname);
				free(clientname);

				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested client not found",
				                       json);
			}
		}

		unsigned int unum = 0u;
		if(GET_VAR("cursor", buffer, api->request->query_string) > 0 &&
		   sscanf(buffer, "%u", &unum) > 0)
		{
			// Do not start at the most recent, but at an older query
			if(unum < (unsigned int)counters->queries)
			{
				cursor = unum;
			}
			else
			{
				// Cursors larger than the current known number
				// of queries are invalid
				cJSON *json = JSON_NEW_OBJ();
				JSON_OBJ_ADD_NUMBER(json, "cursor", unum);
				JSON_OBJ_ADD_NUMBER(json, "maxval", counters->queries);
				free(clientname);

				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested cursor larger than number of queries",
				                       json);
			}
			
		}
	}

	// Compute limits for the main for-loop
	// Default: Show the most recent 200 queries
	unsigned int ibeg = cursor;

	// Get potentially existing filtering flags
	char * filter = read_setupVarsconf("API_QUERY_LOG_SHOW");
	bool showpermitted = true, showblocked = true;
	if(filter != NULL)
	{
		if((strcmp(filter, "permittedonly")) == 0)
			showblocked = false;
		else if((strcmp(filter, "blockedonly")) == 0)
			showpermitted = false;
		else if((strcmp(filter, "nothing")) == 0)
		{
			showpermitted = false;
			showblocked = false;
		}
	}
	clearSetupVarsArray();

	cJSON *history = JSON_NEW_ARRAY();
	unsigned int added = 0u;
	unsigned int lastID = 0u;
	for(unsigned int i = ibeg; i > 0u; i--)
	{
		const unsigned int queryID = i-1u;
		const queriesData* query = getQuery(queryID, true);
		// Check if this query has been create while in maximum privacy mode
		if(query == NULL || query->privacylevel >= PRIVACY_MAXIMUM)
			continue;

		// Verify query type
		if(query->type >= TYPE_MAX)
			continue;

		// Skip blocked queries when asked to
		if(query->flags.blocked && !showblocked)
			continue;

		// Skip permitted queries when asked to
		if(!query->flags.blocked && !showpermitted)
			continue;

		// Skip those entries which so not meet the requested timeframe
		if((from > (unsigned int)query->timestamp && from != 0) || ((unsigned int)query->timestamp > until && until != 0))
			continue;

		// Skip if domain is not identical with what the user wants to see
		if(filterdomainname && query->domainID != domainid)
			continue;
		if(filterdomainname)
		{
			// Check direct match
			if(query->domainID == domainid)
			{
				// Get this query
			}
			// If the domain of this query did not match, the CNAME
			// domain may still match - we have to check it in
			// addition if this query is of CNAME blocked type
			else if(query->CNAME_domainID > -1)
			{
				// Get this query
			}
			else
			{
				// Skip this query
				continue;
			}
		}

		// Skip if client name and IP are not identical with what the user wants to see
		if(filterclientname)
		{
			// Normal clients
			if(clientid_list == NULL && query->clientID != clientid)
				continue;
			// Alias-clients (we have to check for all clients managed by this alias-client)
			else if(clientid_list != NULL)
			{
				bool found = false;
				for(int j = 0; j < clientid_list[0]; j++)
					if(query->clientID == clientid_list[j + 1])
						found = true;
				if(!found)
					continue;
			}
		}

		// Skip if query type is not identical with what the user wants to see
		if(querytype != 0 && querytype != query->type)
			continue;

		if(filterforwarddest)
		{
			// Does the user want to see queries answered from blocking lists?
			if(forwarddestid == -2 && !query->flags.blocked)
				continue;
			// Does the user want to see queries answered from local cache?
			else if(forwarddestid == -1 && query->status != QUERY_CACHE)
				continue;
			// Does the user want to see queries answered by an upstream server?
			else if(forwarddestid >= 0 && forwarddestid != query->upstreamID)
				continue;
		}

		// Ask subroutine for domain. It may return "hidden" depending on
		// the privacy settings at the time the query was made
		const char *domain = getDomainString(query);

		// Similarly for the client
		const char *clientIPName = NULL;
		// Get client pointer
		const clientsData* client = getClient(query->clientID, true);
		if(domain == NULL || client == NULL)
			continue;

		if(strlen(getstr(client->namepos)) > 0)
			clientIPName = getClientNameString(query);
		else
			clientIPName = getClientIPString(query);

		unsigned long delay = query->response;
		// Check if received (delay should be smaller than 30min)
		if(delay > 1.8e7)
			delay = 0;

		// Get domain blocked during deep CNAME inspection, if applicable
		const char *CNAME_domain = "N/A";
		if(query->CNAME_domainID > -1)
		{
			CNAME_domain = getCNAMEDomainString(query);
		}

		// Get ID of blocking regex, if applicable
		int regex_idx = -1;
		if (query->status == QUERY_REGEX || query->status == QUERY_REGEX_CNAME)
		{
			unsigned int cacheID = findCacheID(query->domainID, query->clientID, query->type);
			DNSCacheData *dns_cache = getDNSCache(cacheID, true);
			if(dns_cache != NULL)
				regex_idx = dns_cache->black_regex_idx;
		}

		// Get IP of upstream destination, if applicable
		in_port_t upstream_port = 0;
		const char *upstream_name = "N/A";
		if(query->upstreamID > -1)
		{
			const upstreamsData *upstream = getUpstream(query->upstreamID, true);
			if(upstream != NULL)
			{
				if(upstream->namepos != 0)
					// Get upstream destination name if possible
					upstream_name = getstr(upstream->namepos);
				else
					// If we have no name, get the IP address
					upstream_name = getstr(upstream->ippos);

				upstream_port = upstream->port;
			}
		}

		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "timestamp", query->timestamp);
		JSON_OBJ_ADD_NUMBER(item, "type", query->type);
		JSON_OBJ_ADD_NUMBER(item, "status", query->status);
		JSON_OBJ_COPY_STR(item, "domain", domain);
		JSON_OBJ_COPY_STR(item, "client", clientIPName);
		JSON_OBJ_ADD_NUMBER(item, "dnssec", query->dnssec);
		JSON_OBJ_ADD_NUMBER(item, "reply", query->reply);
		JSON_OBJ_ADD_NUMBER(item, "response_time", delay);
		JSON_OBJ_COPY_STR(item, "CNAME_domain", CNAME_domain);
		JSON_OBJ_ADD_NUMBER(item, "regex_idx", regex_idx);
		JSON_OBJ_COPY_STR(item, "upstream_name", upstream_name);
		JSON_OBJ_ADD_NUMBER(item, "upstream_port", upstream_port);
		if(config.debug & DEBUG_API)
			JSON_OBJ_ADD_NUMBER(item, "queryID", queryID);
		JSON_ARRAY_ADD_ITEM(history, item);

		if(++added > show)
		{
			break;
		}

		lastID = queryID;
	}

	// Free allocated memory
	if(filterclientname)
		free(clientname);

	if(filterdomainname)
		free(domainname);

	if(filterforwarddest)
		free(forwarddest);

	if(clientid_list != NULL)
		free(clientid_list);

	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "history", history);

	if(lastID > 0)
	{
		// There are more queries available, send cursor pointing
		// onto the next older query so the API can request it if
		// needed
		JSON_OBJ_ADD_NUMBER(json, "cursor", lastID);
	}
	else
	{
		// There are no more queries available, send NULL cursor
		JSON_OBJ_ADD_NULL(json, "cursor");
	}

	JSON_SEND_OBJECT(json);
}

int api_stats_recentblocked(struct ftl_conn *api)
{
	unsigned int show = 1;

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
	{
		// Minimum structure is
		// {"blocked":null}
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NULL(json, "blocked");
		JSON_SEND_OBJECT(json);
	}

	if(api->request->query_string != NULL)
	{
		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_uint_var(api->request->query_string, "show", &show);
	}

	// Find most recently blocked query
	unsigned int found = 0;
	cJSON *blocked = JSON_NEW_ARRAY();
	for(int queryID = counters->queries - 1; queryID > 0 ; queryID--)
	{
		const queriesData* query = getQuery(queryID, true);
		if(query == NULL)
		{
			continue;
		}

		if(query->flags.blocked)
		{
			// Ask subroutine for domain. It may return "hidden" depending on
			// the privacy settings at the time the query was made
			const char *domain = getDomainString(query);
			if(domain == NULL)
			{
				continue;
			}

			JSON_ARRAY_REF_STR(blocked, domain);

			// Only count when added succesfully
			found++;
		}

		if(found >= show)
			break;
	}
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "blocked", blocked);
	JSON_SEND_OBJECT(json);
}

int api_stats_overTime_clients(struct ftl_conn *api)
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
		// {"data":[], "clients":[]}
		cJSON *json = JSON_NEW_OBJ();
		cJSON *data = JSON_NEW_ARRAY();
		JSON_OBJ_ADD_ITEM(json, "data", data);
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

	cJSON *data = JSON_NEW_ARRAY();
	// Main return loop
	for(int slot = sendit; slot < until; slot++)
	{
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "timestamp", overTime[slot].timestamp);

		// Loop over clients to generate output to be sent to the client
		cJSON *data2 = JSON_NEW_ARRAY();
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

			JSON_ARRAY_ADD_NUMBER(data2, thisclient);
		}
		JSON_OBJ_ADD_ITEM(item, "data", data2);
		JSON_ARRAY_ADD_ITEM(data, item);
	}
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "data", data);

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
		const char *client_name = getstr(client->namepos);

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
