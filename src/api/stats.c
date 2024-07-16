/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
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
#include "api/api.h"
#include "shmem.h"
#include "datastructure.h"
// logging routines
#include "log.h"
// config struct
#include "config/config.h"
// overTime data
#include "overTime.h"
// enum REGEX
#include "regex_r.h"
// sqrt()
#include <math.h>

struct top_entries {
	int count;
	unsigned int responses;
	in_port_t port;
	size_t namepos;
	size_t ippos;
	double rtime;
	double rtuncertainty;

};

/* qsort comparison function (count field), sort ASC
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
int __attribute__((pure)) cmpdesc(const void *a, const void *b)
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

// qsort subroutine, sort DESC
static int __attribute__((pure)) cmpdesc_te(const void *a, const void *b)
{
	const struct top_entries *elem1 = (struct top_entries*)a;
	const struct top_entries *elem2 = (struct top_entries*)b;

	if (elem1->count > elem2->count)
		return -1;
	else if (elem1->count < elem2->count)
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

	cJSON *statuses = JSON_NEW_OBJECT();
	for(enum query_status status = 0; status < QUERY_STATUS_MAX; status++)
		JSON_ADD_NUMBER_TO_OBJECT(statuses, get_query_status_str(status), counters->status[status]);
	JSON_ADD_ITEM_TO_OBJECT(queries, "status", statuses);

	cJSON *replies = JSON_NEW_OBJECT();
	for(enum reply_type reply = 0; reply <QUERY_REPLY_MAX; reply++)
		JSON_ADD_NUMBER_TO_OBJECT(replies, get_query_reply_str(reply), counters->reply[reply]);
	JSON_ADD_ITEM_TO_OBJECT(queries, "replies", replies);

	// Count clients that have been active within the most recent 24 hours
	unsigned int activeclients = 0;
	for(int clientID=0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		if(client->count > 0)
			activeclients++;
	}

	cJSON *clients = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(clients, "active", activeclients);
	JSON_ADD_NUMBER_TO_OBJECT(clients, "total", counters->clients);

	cJSON *gravity = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(gravity, "domains_being_blocked", counters->database.gravity);

	// Unlock shared memory
	unlock_shm();

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);
	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_ADD_ITEM_TO_OBJECT(json, "gravity", gravity);
	JSON_SEND_OBJECT(json);
}

int api_stats_top_domains(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_HIDE_DOMAINS)
	{
		log_debug(DEBUG_API, "Not returning top domains: Privacy level is set to %i",
		          config.misc.privacylevel.v.privacy_level);

		// Minimum structure is
		// {"top_domains":[]}
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *top_domains = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "top_domains", top_domains);
		JSON_SEND_OBJECT(json);
	}

	bool blocked = false; // Can be overwritten by query string
	int count = 10;
	// /api/stats/top_domains?blocked=true
	if(api->request->query_string != NULL)
	{
		// Should blocked domains be shown?
		get_bool_var(api->request->query_string, "blocked", &blocked);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(api->request->query_string, "count", &count);
	}

	// Get domains which the user doesn't want to see
	regex_t *regex_domains = NULL;
	unsigned int N_regex_domains = 0;
	compile_filter_regex(api, "webserver.api.excludeDomains",
	                     config.webserver.api.excludeDomains.v.json,
	                     &regex_domains, &N_regex_domains);

	// Lock shared memory
	lock_shm();

	const int domains = counters->domains;
	const int total_queries = counters->queries;
	const int blocked_count = get_blocked_count();
	struct top_entries *top_domains = calloc(domains, sizeof(struct top_entries));
	if(top_domains == NULL)
	{
		log_err("Memory allocation failed in %s()", __FUNCTION__);
		return 0;
	}

	unsigned int added_domains = 0u;
	for(int domainID = 0; domainID < domains; domainID++)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(domainID, true);
		if(domain == NULL)
			continue;

		const char *domain_name = getstr(domain->domainpos);

		// Hidden domain, probably due to privacy level. Skip this in the top lists
		if(strcmp(domain_name, HIDDEN_DOMAIN) == 0)
			continue;

		// Use either blocked or total count based on request string
		top_domains[added_domains].count = blocked ? domain->blockedcount : domain->count - domain->blockedcount;

		// Get domain name
		top_domains[added_domains].namepos = domain->domainpos;

		// Increment counter
		added_domains++;
	}

	// Unlock shared memory
	unlock_shm();

	// Sort temporary array
	qsort(top_domains, added_domains, sizeof(*top_domains), cmpdesc_te);

	int n = 0;
	cJSON *jtop_domains = JSON_NEW_ARRAY();

	// Lock shared memory
	lock_shm();

	for(unsigned int i = 0; i < added_domains; i++)
	{
		// Skip e.g. recycled domains
		if(top_domains[i].namepos == 0)
			continue;

		const char *domain = getstr(top_domains[i].namepos);

		// Skip this client if there is a filter on it
		bool skip_domain = false;
		if(N_regex_domains > 0)
		{
			// Iterate over all regex filters
			for(unsigned int j = 0; j < N_regex_domains; j++)
			{
				// Check if the domain matches the regex
				if(regexec(&regex_domains[j], domain, 0, NULL, 0) == 0)
				{
					// Domain matches
					skip_domain = true;
					break;
				}
			}
		}

		if(skip_domain)
			continue;

		if(top_domains[i].count > 0)
		{
			cJSON *domain_item = JSON_NEW_OBJECT();
			JSON_COPY_STR_TO_OBJECT(domain_item, "domain", domain);
			JSON_ADD_NUMBER_TO_OBJECT(domain_item, "count", top_domains[i].count);
			JSON_ADD_ITEM_TO_ARRAY(jtop_domains, domain_item);
			n++;
		}

		// Only count entries that are actually sent and return when we have send enough data
		if(n >= count)
			break;
	}

	// Unlock shared memory
	unlock_shm();

	// Free temporary array
	free(top_domains);

	// Free regexes
	if(N_regex_domains > 0)
	{
		// Free individual regexes
		for(unsigned int i = 0; i < N_regex_domains; i++)
			regfree(&regex_domains[i]);

		// Free array of regex pointers
		free(regex_domains);
	}

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "domains", jtop_domains);

	JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", total_queries);
	JSON_ADD_NUMBER_TO_OBJECT(json, "blocked_queries", blocked_count);

	JSON_SEND_OBJECT(json);
}

int api_stats_top_clients(struct ftl_conn *api)
{
	int count = 10;

	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		log_debug(DEBUG_API, "Not returning top clients: Privacy level is set to %i",
		          config.misc.privacylevel.v.privacy_level);

		// Minimum structure is
		// {"top_clients":[]}
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *top_clients = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "top_clients", top_clients);
		JSON_SEND_OBJECT(json);
	}

	bool blocked = false; // /api/stats/top_clients?blocked=true
	if(api->request->query_string != NULL)
	{
		// Should blocked clients be shown?
		get_bool_var(api->request->query_string, "blocked", &blocked);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(api->request->query_string, "count", &count);
	}

	// Lock shared memory
	lock_shm();

	int clients = counters->clients;
	const int total_queries = counters->queries;
	const int blocked_count = get_blocked_count();
	struct top_entries *top_clients = calloc(clients, sizeof(struct top_entries));
	if(top_clients == NULL)
	{
		log_err("Memory allocation failed in %s()", __FUNCTION__);
		return 0;
	}

	unsigned int added_clients = 0;
	for(int clientID = 0; clientID < clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);

		// Skip invalid clients and also those managed by alias clients
		if(client == NULL || (!client->flags.aliasclient && client->aliasclient_id >= 0))
			continue;

		const char *client_ip = getstr(client->ippos);
		// Hidden client, probably due to privacy level. Skip this in the top lists
		if(strcmp(client_ip, HIDDEN_CLIENT) == 0)
			continue;

		// Use either blocked or total count based on request string
		top_clients[added_clients].count = blocked ? client->blockedcount : client->count;

		// Get client name and IP
		top_clients[added_clients].ippos = client->ippos;
		top_clients[added_clients].namepos = client->namepos;

		added_clients++;
	}

	// Unlock shared memory
	unlock_shm();

	// Sort temporary array
	qsort(top_clients, added_clients, sizeof(*top_clients), cmpdesc_te);

	// Get clients which the user doesn't want to see
	regex_t *regex_clients = NULL;
	unsigned int N_regex_clients = 0;
	compile_filter_regex(api, "webserver.api.excludeClients",
	                     config.webserver.api.excludeClients.v.json,
	                     &regex_clients, &N_regex_clients);

	int n = 0;
	cJSON *jtop_clients = JSON_NEW_ARRAY();

	// Lock shared memory
	lock_shm();

	for(unsigned int i = 0; i < added_clients; i++)
	{
		// Skip e.g. recycled clients
		if(top_clients[i].namepos == 0)
			continue;

		const char *client_ip = getstr(top_clients[i].ippos);
		const char *client_name = getstr(top_clients[i].namepos);

		// Skip this client if there is a filter on it
		bool skip_client = false;
		if(N_regex_clients > 0)
		{
			// Iterate over all regex filters
			for(unsigned int j = 0; j < N_regex_clients; j++)
			{
				// Check if the domain matches the regex
				if(regexec(&regex_clients[j], client_ip, 0, NULL, 0) == 0)
				{
					// Client IP matches
					skip_client = true;
					break;
				}
				else if(client_name != NULL && regexec(&regex_clients[j], client_name, 0, NULL, 0) == 0)
				{
					// Client name matches
					skip_client = true;
					break;
				}
			}
		}

		if(skip_client)
			continue;

		// Return this client if the client made at least one query
		// within the most recent 24 hours
		if(top_clients[i].count > 0)
		{
			cJSON *client_item = JSON_NEW_OBJECT();
			JSON_COPY_STR_TO_OBJECT(client_item, "name", client_name);
			JSON_COPY_STR_TO_OBJECT(client_item, "ip", client_ip);
			JSON_ADD_NUMBER_TO_OBJECT(client_item, "count", top_clients[i].count);
			JSON_ADD_ITEM_TO_ARRAY(jtop_clients, client_item);
			n++;
		}

		if(n == count)
			break;
	}

	// Unlock shared memory
	unlock_shm();

	// Free temporary array
	free(top_clients);

	// Free regexes
	if(N_regex_clients > 0)
	{
		// Free individual regexes
		for(unsigned int i = 0; i < N_regex_clients; i++)
			regfree(&regex_clients[i]);

		// Free array of regex pointers
		free(regex_clients);
	}

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "clients", jtop_clients);

	JSON_ADD_NUMBER_TO_OBJECT(json, "blocked_queries", blocked_count);
	JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", total_queries);
	JSON_SEND_OBJECT(json);
}


int api_stats_upstreams(struct ftl_conn *api)
{
	const int upstreams = counters->upstreams;
	const int forwarded_count = get_forwarded_count();
	const int total_queries = counters->queries;
	struct top_entries *top_upstreams = calloc(upstreams, sizeof(struct top_entries));
	if(top_upstreams == NULL)
	{
		log_err("Memory allocation failed in api_stats_upstreams()");
		return 0;
	}

	// Lock shared memory
	lock_shm();

	unsigned int added_upstreams = 0;
	for(int upstreamID = 0; upstreamID < upstreams; upstreamID++)
	{
		// Get upstream pointer
		const upstreamsData* upstream = getUpstream(upstreamID, true);
		if(upstream == NULL)
			continue;

		top_upstreams[added_upstreams].count = upstream->count;
		top_upstreams[added_upstreams].ippos = upstream->ippos;
		top_upstreams[added_upstreams].namepos = upstream->namepos;
		top_upstreams[added_upstreams].port = upstream->port;
		top_upstreams[added_upstreams].responses = upstream->responses;
		top_upstreams[added_upstreams].rtime = upstream->rtime;
		top_upstreams[added_upstreams].rtuncertainty = upstream->rtuncertainty;

		added_upstreams++;
	}

	// Unlock shared memory
	unlock_shm();

	// Sort temporary array in descending order
	qsort(top_upstreams, added_upstreams, sizeof(*top_upstreams), cmpdesc);

	// Loop over available forward destinations
	cJSON *jtop_upstreams = JSON_NEW_ARRAY();

	// Lock shared memory
	lock_shm();

	for(int i = -2; i < (int)added_upstreams; i++)
	{
		int count = 0;
		const char* ip, *name;
		in_port_t port = -1;
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
			// Regular upstream destination
			ip = getstr(top_upstreams[i].ippos);
			name = getstr(top_upstreams[i].namepos);
			port = top_upstreams[i].port;
			count = top_upstreams[i].count;

			// Compute average response time and uncertainty (unit: seconds)
			if(top_upstreams[i].responses > 0)
			{
				// Simple average of the response times
				responsetime = top_upstreams[i].rtime / top_upstreams[i].responses;
			}
			if(top_upstreams[i].responses > 1)
			{
				// The actual value will be somewhere in a neighborhood around the mean value.
				// This neighborhood of values is the uncertainty in the mean.
				uncertainty = sqrt(top_upstreams[i].rtuncertainty / top_upstreams[i].responses / (top_upstreams[i].responses-1));
			}
		}

		// Send data:
		// - always if i < 0 (special upstreams: blocklist and cache)
		// - only if there are any queries for all others (i > 0)
		if(count > 0 || i < 0)
		{
			cJSON *upstream = JSON_NEW_OBJECT();
			JSON_COPY_STR_TO_OBJECT(upstream, "ip", ip);
			JSON_COPY_STR_TO_OBJECT(upstream, "name", name);
			JSON_ADD_NUMBER_TO_OBJECT(upstream, "port", port);
			JSON_ADD_NUMBER_TO_OBJECT(upstream, "count", count);
			cJSON *statistics = JSON_NEW_OBJECT();
			JSON_ADD_NUMBER_TO_OBJECT(statistics, "response", responsetime);
			JSON_ADD_NUMBER_TO_OBJECT(statistics, "variance", uncertainty);
			JSON_ADD_ITEM_TO_OBJECT(upstream, "statistics", statistics);
			JSON_ADD_ITEM_TO_ARRAY(jtop_upstreams, upstream);
		}
	}

	// Unlock shared memory
	unlock_shm();

	// Free temporary array
	free(top_upstreams);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "upstreams", jtop_upstreams);

	JSON_ADD_NUMBER_TO_OBJECT(json, "forwarded_queries", forwarded_count);
	JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", total_queries);

	JSON_SEND_OBJECT(json);
}

int api_stats_query_types(struct ftl_conn *api)
{
	// Lock shared memory
	lock_shm();

	cJSON *types = JSON_NEW_OBJECT();
	int ret = get_query_types_obj(api, types);
	if(ret != 0)
	{
		unlock_shm();
		return ret;
	}

	// Unlock shared memory
	unlock_shm();

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "types", types);

	// Send response
	JSON_SEND_OBJECT(json);
}

int api_stats_recentblocked(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_HIDE_DOMAINS)
	{
		// Minimum structure is
		// {"blocked":[]}
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *blocked = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "blocked", blocked);
		JSON_SEND_OBJECT(json);
	}

	unsigned int count = 1;
	if(api->request->query_string != NULL)
	{
		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_uint_var(api->request->query_string, "count", &count);
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
			continue;

		if(query->flags.blocked)
		{
			// Ask subroutine for domain. It may return "hidden" depending on
			// the privacy settings at the time the query was made
			const char *domain = getDomainString(query);
			if(domain == NULL)
				continue;

			JSON_REF_STR_IN_ARRAY(blocked, domain);

			// Only count when added successfully
			found++;
		}

		if(found >= count)
			break;
	}

	// Unlock shared memory
	unlock_shm();

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "blocked", blocked);
	JSON_SEND_OBJECT(json);
}
