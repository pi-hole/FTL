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

// Min-heap sift-down for top-K selection: maintain the smallest element at the
// root so it can be replaced when a larger one is found
static void heap_sift_down(struct top_entries *heap, const unsigned int size, unsigned int i)
{
	for(;;)
	{
		unsigned int min = i;
		const unsigned int l = 2*i + 1, r = 2*i + 2;
		if(l < size && heap[l].count < heap[min].count)
			min = l;
		if(r < size && heap[r].count < heap[min].count)
			min = r;
		if(min == i)
			break;
		const struct top_entries tmp = heap[i];
		heap[i] = heap[min];
		heap[min] = tmp;
		i = min;
	}
}

// Check whether a string matches any of the compiled exclude filters
static bool matches_filter(const regex_t *regex, const unsigned int N_regex, const char *str)
{
	if(str == NULL)
		return false;

	for(unsigned int j = 0; j < N_regex; j++)
		if(regexec(&regex[j], str, 0, NULL, 0) == 0)
			return true;

	return false;
}

// Release the regexes compiled by compile_filter_regex()
static void free_filter_regex(regex_t *regex, const unsigned int N_regex)
{
	if(N_regex == 0)
		return;

	for(unsigned int i = 0; i < N_regex; i++)
		regfree(&regex[i]);

	free(regex);
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

// shmem needs to be locked while calling this function
unsigned int get_active_clients(void)
{
	unsigned int activeclients = 0;
	for(unsigned int clientID=0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData *client = getClient(clientID, true);
		if(client == NULL)
			continue;

		if(client->count > 0)
			activeclients++;
	}

	return activeclients;
}

int api_stats_summary(struct ftl_conn *api)
{
	// Lock shared memory
	lock_shm();

	const int blocked = get_blocked_count();
	const int forwarded = get_forwarded_count();
	const int cached = get_cached_count();
	const int total = counters->queries;
	const int num_gravity = counters->database.gravity;
	const int num_clients = counters->clients;
	const int num_domains = counters->domains;

	// Count clients that have been active within the most recent 24 hours
	unsigned int activeclients = get_active_clients();

	// Unlock shared memory
	unlock_shm();

	// Calculate percentage of blocked queries
	float percent_blocked = 0.0f;
	// Avoid 1/0 condition
	if(total > 0)
		percent_blocked = 1e2f*blocked/total;

	cJSON *queries = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(queries, "total", total);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "blocked", blocked);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "percent_blocked", percent_blocked);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "unique_domains", num_domains);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "forwarded", forwarded);
	JSON_ADD_NUMBER_TO_OBJECT(queries, "cached", cached);

	JSON_ADD_NUMBER_TO_OBJECT(queries, "frequency", get_qps());

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

	cJSON *clients = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(clients, "active", activeclients);
	JSON_ADD_NUMBER_TO_OBJECT(clients, "total", num_clients);

	cJSON *gravity = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(gravity, "domains_being_blocked", num_gravity);
	JSON_ADD_NUMBER_TO_OBJECT(gravity, "last_update", gravity_last_updated());

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);
	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_ADD_ITEM_TO_OBJECT(json, "gravity", gravity);
	JSON_SEND_OBJECT(json);
}

cJSON *get_top_domains(struct ftl_conn *api, const int count,
                       const bool blocked, const bool domains_only)
{
	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_HIDE_DOMAINS)
	{
		log_web_debug(DEBUG_API, "Not returning top domains: Privacy level is set to %i",
		          config.misc.privacylevel.v.privacy_level);

		// Minimum structure is
		// {"top_domains":[]}
		if(domains_only)
			return cJSON_CreateArray();

		cJSON *json = cJSON_CreateObject();
		cJSON_AddItemToObject(json, "domains", cJSON_CreateArray());
		cJSON_AddNumberToObject(json, "total_queries", -1);
		cJSON_AddNumberToObject(json, "blocked_queries", -1);
		return json;
	}

	// Get domains which the user doesn't want to see
	regex_t *regex_domains = NULL;
	unsigned int N_regex_domains = 0;
	compile_filter_regex(api, "webserver.api.excludeDomains",
	                     config.webserver.api.excludeDomains.v.json,
	                     &regex_domains, &N_regex_domains);

	// Lock shared memory
	lock_shm();

	const unsigned int domains = counters->domains;
	const unsigned int total_queries = counters->queries;
	const unsigned int blocked_count = get_blocked_count();

	// Heap-based top-K selection: allocate only for the top entries
	// rather than for all domains, reducing memory from O(N) to O(K).
	const unsigned int k = count > 0 ? (unsigned int)count : 1u;
	const unsigned int heap_cap = (k <= domains / 4) ? k * 4 : domains;
	struct top_entries *top_domains = heap_cap > 0 ? calloc(heap_cap, sizeof(struct top_entries)) : NULL;
	if(heap_cap > 0 && top_domains == NULL)
	{
		log_err("Memory allocation failed in %s()", __FUNCTION__);
		unlock_shm();
		free_filter_regex(regex_domains, N_regex_domains);
		return NULL;
	}

	unsigned int heap_size = 0;
	bool heap_ready = false;
	for(unsigned int domainID = 0; domainID < domains; domainID++)
	{
		// Get domain pointer
		const domainsData *domain = getDomain(domainID, true);
		if(domain == NULL)
			continue;

		// Skip recycled domains
		if(domain->domainpos == 0)
		{
			log_debug(DEBUG_API, "Skipping domain %u because it is recycled", domainID);
			continue;
		}

		const char *domain_name = getstr(domain->domainpos);

		// Hidden domain, probably due to privacy level. Skip this in the top lists
		if(strcmp(domain_name, HIDDEN_DOMAIN) == 0)
			continue;

		// Skip domains the user does not want to see. We filter here,
		// before the heap, so excluded domains cannot occupy heap capacity
		// and evict genuine top entries (see issue #2946)
		if(matches_filter(regex_domains, N_regex_domains, domain_name))
			continue;

		// Use either blocked or total count based on request string
		const int entry_count = blocked ? domain->blockedcount : domain->count - domain->blockedcount;

		// Skip zero-count entries early
		if(entry_count < 1)
			continue;

		if(heap_size < heap_cap)
		{
			// Heap not full yet, append directly
			top_domains[heap_size].count = entry_count;
			top_domains[heap_size].namepos = domain->domainpos;
			heap_size++;
		}
		else
		{
			// Build min-heap once on first overflow
			if(!heap_ready)
			{
				for(int j = (int)(heap_size / 2) - 1; j >= 0; j--)
					heap_sift_down(top_domains, heap_size, (unsigned int)j);
				heap_ready = true;
			}
			// Replace root (minimum) if this entry is larger
			if(entry_count > top_domains[0].count)
			{
				top_domains[0].count = entry_count;
				top_domains[0].namepos = domain->domainpos;
				heap_sift_down(top_domains, heap_size, 0);
			}
		}
	}

	// Unlock shared memory
	unlock_shm();

	// Sort the small heap array descending
	if(heap_size > 1)
		qsort(top_domains, heap_size, sizeof(*top_domains), cmpdesc_te);

	int n = 0;
	cJSON *jtop_domains = cJSON_CreateArray();

	// Lock shared memory
	lock_shm();

	for(unsigned int i = 0; i < heap_size; i++)
	{
		const char *domain = getstr(top_domains[i].namepos);

		if(top_domains[i].count < 1)
			continue;

		if(domains_only)
		{
			cJSON_AddStringToArray(jtop_domains, domain);
		}
		else
		{
			cJSON *domain_item = cJSON_CreateObject();
			cJSON_AddStringToObject(domain_item, "domain", domain);
			cJSON_AddNumberToObject(domain_item, "count", top_domains[i].count);
			cJSON_AddItemToArray(jtop_domains, domain_item);
		}

		// Only count entries that are actually sent and return when we have send enough data
		if(++n >= count)
			break;
	}

	// Unlock shared memory
	unlock_shm();

	// Free temporary array
	if(top_domains != NULL)
		free(top_domains);

	// Free regexes
	free_filter_regex(regex_domains, N_regex_domains);

	if(domains_only)
	{
		// Return the array of domains only
		return jtop_domains;
	}

	// else: Build and return full object
	cJSON *json = cJSON_CreateObject();
	cJSON_AddItemToObject(json, "domains", jtop_domains);
	cJSON_AddNumberToObject(json, "total_queries", total_queries);
	cJSON_AddNumberToObject(json, "blocked_queries", blocked_count);
	return json;
}

int api_stats_top_domains(struct ftl_conn *api)
{
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

	cJSON *json = get_top_domains(api, count, blocked, false);
	JSON_SEND_OBJECT(json);
}

cJSON *get_top_clients(struct ftl_conn *api, const int count,
                       const bool blocked, const bool clients_only,
                       const bool names_only, const bool ip_if_no_name)
{
	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		log_web_debug(DEBUG_API, "Not returning top clients: Privacy level is set to %i",
		          config.misc.privacylevel.v.privacy_level);

		// Minimum structure is
		// {"top_clients":[]}
		if(clients_only)
			return cJSON_CreateArray();

		cJSON *json = cJSON_CreateObject();
		cJSON_AddItemToObject(json, "clients", cJSON_CreateArray());
		cJSON_AddNumberToObject(json, "total_queries", -1);
		cJSON_AddNumberToObject(json, "blocked_queries", -1);
		return json;
	}

	// Get clients which the user doesn't want to see
	regex_t *regex_clients = NULL;
	unsigned int N_regex_clients = 0;
	compile_filter_regex(api, "webserver.api.excludeClients",
	                     config.webserver.api.excludeClients.v.json,
	                     &regex_clients, &N_regex_clients);

	// Lock shared memory
	lock_shm();

	const unsigned int clients = counters->clients;
	const int total_queries = counters->queries;
	const int blocked_count = get_blocked_count();

	// Heap-based top-K selection: allocate only for the top entries
	// rather than for all clients, reducing memory from O(N) to O(K).
	const unsigned int k = count > 0 ? (unsigned int)count : 1u;
	const unsigned int heap_cap = (k <= clients / 4) ? k * 4 : clients;
	struct top_entries *top_clients = heap_cap > 0 ? calloc(heap_cap, sizeof(struct top_entries)) : NULL;
	if(heap_cap > 0 && top_clients == NULL)
	{
		log_err("Memory allocation failed in %s()", __FUNCTION__);
		unlock_shm();
		free_filter_regex(regex_clients, N_regex_clients);
		return 0;
	}

	unsigned int heap_size = 0;
	bool heap_ready = false;
	for(unsigned int clientID = 0; clientID < clients; clientID++)
	{
		// Get client pointer
		const clientsData *client = getClient(clientID, true);

		// Skip invalid clients and also those managed by alias clients
		if(client == NULL || (!client->flags.aliasclient && client->aliasclient_id >= 0))
		{
			log_web_debug(DEBUG_API, "Skipping client %u because %s", clientID,
			          client == NULL ? "it is invalid" : "it is an alias client");
			continue;
		}

		// Skip recycled clients
		if(client->ippos == 0)
		{
			log_web_debug(DEBUG_API, "Skipping client %u because it is recycled", clientID);
			continue;
		}

		const char *client_ip = getstr(client->ippos);
		// Hidden client, probably due to privacy level. Skip this in the top lists
		if(strcmp(client_ip, HIDDEN_CLIENT) == 0)
		{
			log_web_debug(DEBUG_API, "Skipping client %u because it is hidden", clientID);
			continue;
		}

		// Skip clients the user does not want to see. We filter here,
		// before the heap, so excluded clients cannot occupy heap capacity
		// and evict genuine top entries (see issue #2946)
		const char *client_name = getstr(client->namepos);
		if(matches_filter(regex_clients, N_regex_clients, client_ip) ||
		   matches_filter(regex_clients, N_regex_clients, client_name))
		{
			log_debug(DEBUG_API, "Skipping client %u because it matches a filter", clientID);
			continue;
		}

		// Use either blocked or total count based on request string
		const int entry_count = blocked ? client->blockedcount : client->count;

		// Skip zero-count entries early
		if(entry_count < 1)
			continue;

		if(heap_size < heap_cap)
		{
			// Heap not full yet, append directly
			top_clients[heap_size].count = entry_count;
			top_clients[heap_size].ippos = client->ippos;
			top_clients[heap_size].namepos = client->namepos;
			heap_size++;
		}
		else
		{
			// Build min-heap once on first overflow
			if(!heap_ready)
			{
				for(int j = (int)(heap_size / 2) - 1; j >= 0; j--)
					heap_sift_down(top_clients, heap_size, (unsigned int)j);
				heap_ready = true;
			}
			// Replace root (minimum) if this entry is larger
			if(entry_count > top_clients[0].count)
			{
				top_clients[0].count = entry_count;
				top_clients[0].ippos = client->ippos;
				top_clients[0].namepos = client->namepos;
				heap_sift_down(top_clients, heap_size, 0);
			}
		}
	}

	log_web_debug(DEBUG_API, "Found %u clients (heap selected from %u)", heap_size, clients);

	// Unlock shared memory
	unlock_shm();

	// Sort the small heap array descending
	if(heap_size > 1)
		qsort(top_clients, heap_size, sizeof(*top_clients), cmpdesc_te);

	int n = 0;
	cJSON *jtop_clients = JSON_NEW_ARRAY();

	// Lock shared memory
	lock_shm();

	for(unsigned int i = 0; i < heap_size; i++)
	{
		const char *client_ip = getstr(top_clients[i].ippos);
		const char *client_name = getstr(top_clients[i].namepos);

		if(top_clients[i].count < 1)
		{
			log_web_debug(DEBUG_API, "Skipping client %s because it has no queries", client_ip);
			continue;
		}

		if(clients_only)
		{
			if(ip_if_no_name)
			{
				if(strlen(client_name) > 0)
					cJSON_AddStringToArray(jtop_clients, client_name);
				else
					cJSON_AddStringToArray(jtop_clients, client_ip);
			}
			else if(names_only)
			{
				if(strlen(client_name) > 0)
					cJSON_AddStringToArray(jtop_clients, client_name);
			}
			else
				cJSON_AddStringToArray(jtop_clients, client_ip);
		}
		else
		{
			cJSON *client_item = cJSON_CreateObject();
			cJSON_AddStringToObject(client_item, "name", client_name);
			cJSON_AddStringToObject(client_item, "ip", client_ip);
			cJSON_AddNumberToObject(client_item, "count", top_clients[i].count);
			cJSON_AddItemToArray(jtop_clients, client_item);
		}

		if(++n == count)
			break;
	}

	// Unlock shared memory
	unlock_shm();

	// Free temporary array
	if(top_clients != NULL)
		free(top_clients);

	// Free regexes
	free_filter_regex(regex_clients, N_regex_clients);

	if(clients_only)
	{
		// Return the array of clients only
		return jtop_clients;
	}

	// else: Build and return full object
	cJSON *json = cJSON_CreateObject();
	cJSON_AddItemToObject(json, "clients", jtop_clients);
	cJSON_AddNumberToObject(json, "total_queries", total_queries);
	cJSON_AddNumberToObject(json, "blocked_queries", blocked_count);
	return json;
}

int api_stats_top_clients(struct ftl_conn *api)
{
	bool blocked = false; // Can be overwritten by query string
	int count = 10;
	// /api/stats/top_clients?blocked=true
	if(api->request->query_string != NULL)
	{
		// Should blocked clients be shown?
		get_bool_var(api->request->query_string, "blocked", &blocked);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(api->request->query_string, "count", &count);
	}

	cJSON *json = get_top_clients(api, count, blocked, false, false, false);
	JSON_SEND_OBJECT(json);
}

cJSON *get_top_upstreams(struct ftl_conn *api, const bool upstreams_only)
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
		const upstreamsData *upstream = getUpstream(upstreamID, true);
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
	qsort(top_upstreams, added_upstreams, sizeof(*top_upstreams), cmpdesc_te);

	// Loop over available forward destinations
	cJSON *jtop_upstreams = JSON_NEW_ARRAY();

	// Lock shared memory
	lock_shm();

	for(int i = -2; i < (int)added_upstreams; i++)
	{
		int count = 0;
		const char* ip, *name;
		int port = -1; // Need signed data type here as -1 means: no port applicable
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
		if(count < 1 && i >= 0)
			continue;

		if(upstreams_only)
		{
			// Build a string in the format <ip>#<port> (<name if available>)
			if(port < 0)
			{
				// No port available, just use name
				// This is the case for special upstreams like
				// blocklist and cache
				cJSON_AddStringToArray(jtop_upstreams, name);
			}
			else if(name == NULL || strlen(name) == 0)
			{
				// No name available, just use IP and port
				char ip_port[INET6_ADDRSTRLEN + 6]; // Enough space for IPv6 address and port
				snprintf(ip_port, sizeof(ip_port), "%s#%d", ip, port);
				cJSON_AddStringToArray(jtop_upstreams, ip_port);
			}
			else
			{
				// Use IP, port and name
				char ip_port_name[INET6_ADDRSTRLEN + 6 + 256]; // Enough space for IPv6 address, port and name
				snprintf(ip_port_name, sizeof(ip_port_name), "%s#%d (%s)", ip, port, name);
				cJSON_AddStringToArray(jtop_upstreams, ip_port_name);
			}
		}
		else
		{
			cJSON *upstream = JSON_NEW_OBJECT();
			cJSON_AddStringToObject(upstream, "ip", ip);
			cJSON_AddStringToObject(upstream, "name", name);
			cJSON_AddNumberToObject(upstream, "port", port);
			cJSON_AddNumberToObject(upstream, "count", count);
			cJSON *statistics = JSON_NEW_OBJECT();
			cJSON_AddNumberToObject(statistics, "response", responsetime);
			cJSON_AddNumberToObject(statistics, "variance", uncertainty);
			cJSON_AddItemToObject(upstream, "statistics", statistics);
			cJSON_AddItemToArray(jtop_upstreams, upstream);
		}
	}

	// Unlock shared memory
	unlock_shm();

	// Free temporary array
	free(top_upstreams);

	if(upstreams_only)
	{
		// Return the array of upstreams only
		return jtop_upstreams;
	}

	// else: Build and return full object
	cJSON *json = cJSON_CreateObject();
	cJSON_AddItemToObject(json, "upstreams", jtop_upstreams);
	cJSON_AddNumberToObject(json, "total_queries", total_queries);
	cJSON_AddNumberToObject(json, "forwarded_queries", forwarded_count);

	return json;
}

int api_stats_upstreams(struct ftl_conn *api)
{
	cJSON *json = get_top_upstreams(api, false);
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
	for(int queryID = counters->queries - 1; queryID >= 0 ; queryID--)
	{
		const queriesData *query = getQuery(queryID, true);
		if(query == NULL)
			continue;

		if(query->flags.blocked)
		{
			// Ask subroutine for domain. It may return "hidden" depending on
			// the privacy settings at the time the query was made
			const char *domain = getDomainString(query);
			if(domain == NULL)
				continue;

			// Must COPY, not reference: the SHM strings buffer can
			// be relocated by mremap(MREMAP_MAYMOVE) in another
			// thread after we release the lock below, which would
			// leave a dangling pointer if we used
			// JSON_REF_STR_IN_ARRAY here (see #2786)
			JSON_COPY_STR_TO_ARRAY(blocked, domain);

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
