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
#include "api.h"
#include "../shmem.h"
#include "../datastructure.h"
// read_setupVarsconf()
#include "../setupVars.h"
// logging routines
#include "../log.h"
// config struct
#include "../config/config.h"
// in_auditlist()
#include "../database/gravity-db.h"
// overTime data
#include "../overTime.h"
// enum REGEX
#include "../regex_r.h"
// sqrt()
#include <math.h>

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

static int get_query_types_obj(struct ftl_conn *api, cJSON *types)
{
	for(unsigned int i = TYPE_A; i < TYPE_MAX; i++)
	{
		// We add the collective OTHER type at the end
		if(i == TYPE_OTHER)
			continue;
		JSON_ADD_NUMBER_TO_OBJECT(types, get_query_type_str(i, NULL, NULL), counters->querytype[i]);
	}
	JSON_ADD_NUMBER_TO_OBJECT(types, "OTHER", counters->querytype[TYPE_OTHER]);

	return 0;
}

int api_stats_summary(struct ftl_conn *api)
{
	const int blocked =  get_blocked_count();
	const int forwarded =  get_forwarded_count();
	const int cached =  get_cached_count();
	const int total = counters->queries;
	float percent_blocked = 0.0f;

	// Avoid 1/0 condition
	if(total > 0)
		percent_blocked = 1e2f*blocked/total;

	// Lock shared memory
	lock_shm();

	cJSON *queries = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(queries, "total", total);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "blocked", blocked);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "percent_blocked", percent_blocked);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "unique_domains", counters->domains);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "forwarded", forwarded);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "cached", cached);

	cJSON *types = JSON_NEW_OBJECT();
	int ret = get_query_types_obj(api, types);
	if(ret != 0)
		return ret;
	JSON_ADD_ITEM_TO_OBJECT(queries, "types", types);


	cJSON *replies = JSON_NEW_OBJECT();
	for(enum reply_type reply = 0; reply <QUERY_REPLY_MAX; reply++)
		JSON_ADD_NUMBER_TO_OBJECT(replies, get_query_reply_str(reply), counters->reply[reply]);
	JSON_ADD_ITEM_TO_OBJECT(queries, "replies", replies);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);

	// Get system object
	cJSON *system = JSON_NEW_OBJECT();
	ret = get_system_obj(api, system);
	if(ret != 0)
	{
		unlock_shm();
		return ret;
	}
	JSON_ADD_ITEM_TO_OBJECT(json, "system", system);

	// Get FTL object
	cJSON *ftl = JSON_NEW_OBJECT();
	ret = get_ftl_obj(api, ftl, true);
	if(ret != 0)
	{
		unlock_shm();
		return ret;
	}
	JSON_ADD_ITEM_TO_OBJECT(json, "ftl", ftl);

	JSON_SEND_OBJECT_UNLOCK(json);
}

int api_stats_top_domains(struct ftl_conn *api)
{
	int temparray[counters->domains][2], show = 10;
	bool audit = false;

	// Get options from API struct
	bool blocked = api->opts[0]; // Can be overwritten by query string

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Exit before processing any data if requested via config setting
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
	{
		log_debug(DEBUG_API, "Not returning top domains: Privacy level is set to %i",
		          config.privacylevel);

		// Minimum structure is
		// {"top_domains":[]}
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *top_domains = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "top_domains", top_domains);
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

	// Lock shared memory
	lock_shm();

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
			getSetupVarsArray(excludedomains);
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
			log_debug(DEBUG_API, "API: %s has been audited.", getstr(domain->domainpos));
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
			cJSON *domain_item = JSON_NEW_OBJECT();
			JSON_REF_STR_IN_OBJECT(domain_item, "domain", getstr(domain->domainpos));
			JSON_ADD_NUMBER_TO_OBJECT(domain_item, "count", count);
			JSON_ADD_ITEM_TO_ARRAY(top_domains, domain_item);
		}

		// Only count entries that are actually sent and return when we have send enough data
		if(n == show)
			break;
	}

	if(excludedomains != NULL)
		clearSetupVarsArray();

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "top_domains", top_domains);

	if(blocked)
	{
		const int blocked_queries = get_blocked_count();
		JSON_ADD_NUMBER_TO_OBJECT(json, "blocked_queries", blocked_queries);
	}
	else
	{
		JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", counters->queries);
	}

	JSON_SEND_OBJECT_UNLOCK(json);
}

int api_stats_top_clients(struct ftl_conn *api)
{
	int temparray[counters->clients][2], show = 10;
	bool includezeroclients = false;

	// Get options from API struct
	bool blocked = api->opts[0]; // Can be overwritten by query string

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Exit before processing any data if requested via config setting
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		log_debug(DEBUG_API, "Not returning top clients: Privacy level is set to %i",
		          config.privacylevel);

		// Minimum structure is
		// {"top_clients":[]}
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *top_clients = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "top_clients", top_clients);
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

	// Lock shared memory
	lock_shm();

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
			cJSON *client_item = JSON_NEW_OBJECT();
			JSON_REF_STR_IN_OBJECT(client_item, "name", client_name);
			JSON_REF_STR_IN_OBJECT(client_item, "ip", client_ip);
			JSON_ADD_NUMBER_TO_OBJECT(client_item, "count", count);
			JSON_ADD_ITEM_TO_ARRAY(top_clients, client_item);
			n++;
		}

		if(n == show)
			break;
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "top_clients", top_clients);

	if(blocked)
	{
		const int blocked_queries = get_blocked_count();
		JSON_ADD_NUMBER_TO_OBJECT(json, "blocked_queries", blocked_queries);
	}
	else
	{
		JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", counters->queries);
	}

	JSON_SEND_OBJECT_UNLOCK(json);
}


int api_stats_upstreams(struct ftl_conn *api)
{
	const int forwarded = get_forwarded_count();
	unsigned int totalcount = 0;
	int temparray[forwarded][2];

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Lock shared memory
	lock_shm();

	for(int upstreamID = 0; upstreamID < counters->upstreams; upstreamID++)
	{
		// Get upstream pointer
		const upstreamsData* upstream = getUpstream(upstreamID, true);
		if(upstream == NULL)
			continue;

		temparray[upstreamID][0] = upstreamID;

		unsigned int count = 0;
		for(unsigned i = 0; i < (sizeof(upstream->overTime)/sizeof(*upstream->overTime)); i++)
			count += upstream->overTime[i];
		temparray[upstreamID][1] = count;
		totalcount += count;
	}

	// Sort temporary array in descending order
	qsort(temparray, counters->upstreams, sizeof(int[2]), cmpdesc);

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
			count = get_blocked_count();
		}
		else if(i == -1)
		{
			// Local cache
			ip = "cache";
			name = ip;
			count = get_cached_count();
		}
		else
		{
			// Regular upstream destionation
			// Get sorted indices
			const int upstreamID = temparray[i][0];

			// Get upstream pointer
			const upstreamsData *upstream = getUpstream(upstreamID, true);
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
				// Simple average of the response times
				responsetime = upstream->rtime / upstream->responses;
			}
			if(upstream->responses > 1)
			{
				// The actual value will be somewhere in a neighborhood around the mean value.
				// This neighborhood of values is the uncertainty in the mean.
				uncertainty = sqrt(upstream->rtuncertainty / upstream->responses / (upstream->responses-1));
			}
		}

		// Send data:
		// - always if i < 0 (special upstreams: blocklist and cache)
		// - only if there are any queries for all others (i > 0)
		if(count > 0 || i < 0)
		{
			cJSON *upstream = JSON_NEW_OBJECT();
			JSON_REF_STR_IN_OBJECT(upstream, "name", name);
			JSON_REF_STR_IN_OBJECT(upstream, "ip", ip);
			JSON_ADD_NUMBER_TO_OBJECT(upstream, "port", port);
			JSON_ADD_NUMBER_TO_OBJECT(upstream, "count", count);
			JSON_ADD_NUMBER_TO_OBJECT(upstream, "responsetime", responsetime);
			JSON_ADD_NUMBER_TO_OBJECT(upstream, "uncertainty", uncertainty);
			JSON_ADD_ITEM_TO_ARRAY(upstreams, upstream);
		}
	}

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "upstreams", upstreams);
	const int forwarded_queries = get_forwarded_count();
	JSON_ADD_NUMBER_TO_OBJECT(json, "forwarded_queries", forwarded_queries);
	JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", counters->queries);
	JSON_SEND_OBJECT_UNLOCK(json);
}

int api_stats_query_types(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	lock_shm();

	cJSON *types = JSON_NEW_OBJECT();
	int ret = get_query_types_obj(api, types);
	if(ret != 0)
	{
		unlock_shm();
		return ret;
	}

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "types", types);

	// Send response
	JSON_SEND_OBJECT_UNLOCK(json);
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
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
	{
		// Minimum structure is
		// {"blocked":null}
		cJSON *json = JSON_NEW_OBJECT();
		JSON_ADD_NULL_TO_OBJECT(json, "blocked");
		JSON_SEND_OBJECT(json);
	}

	if(api->request->query_string != NULL)
	{
		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_uint_var(api->request->query_string, "show", &show);
	}

	// Lock shared memory
	lock_shm();

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

			JSON_REF_STR_IN_ARRAY(blocked, domain);

			// Only count when added succesfully
			found++;
		}

		if(found >= show)
			break;
	}

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "blocked", blocked);
	JSON_SEND_OBJECT_UNLOCK(json);
}
