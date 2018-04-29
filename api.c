/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
#include "version.h"

#define min(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

/* qsort comparision function (count field), sort ASC */
int cmpasc(const void *a, const void *b)
{
	int *elem1 = (int*)a;
	int *elem2 = (int*)b;

	if (elem1[1] < elem2[1])
		return -1;
	else if (elem1[1] > elem2[1])
		return 1;
	else
		return 0;
}

// qsort subroutine, sort DESC
int cmpdesc(const void *a, const void *b)
{
	int *elem1 = (int*)a;
	int *elem2 = (int*)b;

	if (elem1[1] > elem2[1])
		return -1;
	else if (elem1[1] < elem2[1])
		return 1;
	else
		return 0;
}

void getStats(int *sock)
{
	int blocked = counters.blocked + counters.wildcardblocked;
	int total = counters.queries;
	float percentage = 0.0f;

	// Avoid 1/0 condition
	if(total > 0)
		percentage = 1e2f*blocked/total;

	// Send domains being blocked
	if(istelnet[*sock]) {
		ssend(*sock, "domains_being_blocked %i\n", counters.gravity);
	}
	else
		pack_int32(*sock, counters.gravity);

	// unique_clients: count only clients that have been active within the most recent 24 hours
	int i, activeclients = 0;
	for(i=0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(clients[i].count > 0)
			activeclients++;
	}

	if(istelnet[*sock]) {
		ssend(*sock, "dns_queries_today %i\nads_blocked_today %i\nads_percentage_today %f\n",
		      total, blocked, percentage);
		ssend(*sock, "unique_domains %i\nqueries_forwarded %i\nqueries_cached %i\n",
		      counters.domains, counters.forwardedqueries, counters.cached);
		ssend(*sock, "clients_ever_seen %i\n", counters.clients);
		ssend(*sock, "unique_clients %i\n", activeclients);
	}
	else
	{
		pack_int32(*sock, total);
		pack_int32(*sock, blocked);
		pack_float(*sock, percentage);
		pack_int32(*sock, counters.domains);
		pack_int32(*sock, counters.forwardedqueries);
		pack_int32(*sock, counters.cached);
		pack_int32(*sock, counters.clients);
		pack_int32(*sock, activeclients);
	}

	// Send status
	if(istelnet[*sock]) {
		ssend(*sock, "status %s\n", counters.gravity > 0 ? "enabled" : "disabled");
	}
	else
		pack_uint8(*sock, blockingstatus);

	if(debugclients)
		logg("Sent stats data to client, ID: %i", *sock);
}

void getOverTime(int *sock)
{
	int i, j = 9999999;

	// Start with the first non-empty overTime slot
	for(i=0; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
		if((overTime[i].total > 0 || overTime[i].blocked > 0) &&
		   overTime[i].timestamp)
		{
			j = i;
			break;
		}
	}

	if(istelnet[*sock])
	{
		for(i = j; i < counters.overTime; i++)
		{
			ssend(*sock,"%i %i %i\n",overTime[i].timestamp,overTime[i].total,overTime[i].blocked);
		}
	}
	else
	{
		// We can use the map16 type because there should only be about 288 time slots (TIMEFRAME set to "yesterday")
		// and map16 can hold up to (2^16)-1 = 65535 pairs

		// Send domains over time
		pack_map16_start(*sock, (uint16_t) (counters.overTime - j));
		for(i = j; i < counters.overTime; i++) {
			pack_int32(*sock, overTime[i].timestamp);
			pack_int32(*sock, overTime[i].total);
		}

		// Send ads over time
		pack_map16_start(*sock, (uint16_t) (counters.overTime - j));
		for(i = j; i < counters.overTime; i++) {
			pack_int32(*sock, overTime[i].timestamp);
			pack_int32(*sock, overTime[i].blocked);
		}
	}

	if(debugclients)
		logg("Sent overTime data to client, ID: %i", *sock);
}

void getTopDomains(char *client_message, int *sock)
{
	int i, temparray[counters.domains][2], count=10, num;
	bool blocked, audit = false, asc = false;

	blocked = command(client_message, ">top-ads");

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
		return;

	// Match both top-domains and top-ads
	// example: >top-domains (15)
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0) {
		// User wants a different number of requests
		count = num;
	}

	// Apply Audit Log filtering?
	// example: >top-domains for audit
	if(command(client_message, " for audit"))
		audit = true;

	// Sort in ascending order?
	// example: >top-domains asc
	if(command(client_message, " asc"))
		asc = true;

	for(i=0; i < counters.domains; i++)
	{
		validate_access("domains", i, true, __LINE__, __FUNCTION__, __FILE__);
		temparray[i][0] = i;
		if(blocked)
			temparray[i][1] = domains[i].blockedcount;
		else
			// Count only permitted queries
			temparray[i][1] = (domains[i].count - domains[i].blockedcount);
	}

	// Sort temporary array
	if(asc)
		qsort(temparray, counters.domains, sizeof(int[2]), cmpasc);
	else
		qsort(temparray, counters.domains, sizeof(int[2]), cmpdesc);


	// Get filter
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

	// Get domains which the user doesn't want to see
	char * excludedomains = NULL;
	if(!audit)
	{
		excludedomains = read_setupVarsconf("API_EXCLUDE_DOMAINS");
		if(excludedomains != NULL)
		{
			getSetupVarsArray(excludedomains);

			if(debugclients)
				logg("Excluding %i domains from being displayed", setupVarsElements);
		}
	}

	if(!istelnet[*sock])
	{
		// Send the data required to get the percentage each domain has been blocked / queried
		if(blocked)
			pack_int32(*sock, counters.blocked);
		else
			pack_int32(*sock, counters.queries);
	}

	int n = 0;
	for(i=0; i < counters.domains; i++)
	{
		// Get sorted indices
		int j = temparray[i][0];
		validate_access("domains", j, true, __LINE__, __FUNCTION__, __FILE__);

		// Skip this domain if there is a filter on it
		if(excludedomains != NULL && insetupVarsArray(domains[j].domain))
			continue;

		// Skip this domain if already included in audit
		if(audit && countlineswith(domains[j].domain, files.auditlist) > 0)
			continue;

		// Hidden domain, probably due to privacy level. Skip this in the top lists
		if(strcmp(domains[j].domain, "hidden") == 0)
			continue;

		if(blocked && showblocked && domains[j].blockedcount > 0)
		{
			if(audit && domains[j].wildcard)
			{
				if(istelnet[*sock])
					ssend(*sock, "%i %i %s wildcard\n", n, domains[j].blockedcount, domains[j].domain);
				else {
					char *fancyWildcard = calloc(3 + strlen(domains[j].domain), sizeof(char));
					if(fancyWildcard == NULL) return;
					sprintf(fancyWildcard, "*.%s", domains[j].domain);

					if(!pack_str32(*sock, fancyWildcard))
						return;

					pack_int32(*sock, domains[j].blockedcount);
					free(fancyWildcard);
				}
			}
			else
			{
				if(istelnet[*sock])
					ssend(*sock, "%i %i %s\n", n, domains[j].blockedcount, domains[j].domain);
				else {
					if(!pack_str32(*sock, domains[j].domain))
						return;

					pack_int32(*sock, domains[j].blockedcount);
				}
			}
			n++;
		}
		else if(!blocked && showpermitted && (domains[j].count - domains[j].blockedcount) > 0)
		{
			if(istelnet[*sock])
				ssend(*sock,"%i %i %s\n",n,(domains[j].count - domains[j].blockedcount),domains[j].domain);
			else
			{
				if(!pack_str32(*sock, domains[j].domain))
					return;

				pack_int32(*sock, domains[j].count - domains[j].blockedcount);
			}
			n++;
		}

		// Only count entries that are actually sent and return when we have send enough data
		if(n == count)
			break;
	}

	if(excludedomains != NULL)
		clearSetupVarsArray();

	if(debugclients)
	{
		if(blocked)
			logg("Sent top ads list data to client, ID: %i", *sock);
		else
			logg("Sent top domains list data to client, ID: %i", *sock);
	}
}

void getTopClients(char *client_message, int *sock)
{
	int i, temparray[counters.clients][2], count=10, num;

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		return;

	// Match both top-domains and top-ads
	// example: >top-clients (15)
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0) {
		// User wants a different number of requests
		count = num;
	}

	// Show also clients which have not been active recently?
	// This option can be combined with existing options,
	// i.e. both >top-clients withzero" and ">top-clients withzero (123)" are valid
	bool includezeroclients = false;
	if(command(client_message, " withzero"))
		includezeroclients = true;

	for(i=0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		temparray[i][0] = i;
		temparray[i][1] = clients[i].count;
	}

	// Sort in ascending order?
	// example: >top-clients asc
	bool asc = false;
	if(command(client_message, " asc"))
		asc = true;

	// Sort temporary array
	if(asc)
		qsort(temparray, counters.clients, sizeof(int[2]), cmpasc);
	else
		qsort(temparray, counters.clients, sizeof(int[2]), cmpdesc);

	// Get clients which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);

		if(debugclients)
			logg("Excluding %i clients from being displayed", setupVarsElements);
	}

	if(!istelnet[*sock])
	{
		// Send the total queries so they can make percentages from this data
		pack_int32(*sock, counters.queries);
	}

	int n = 0;
	for(i=0; i < counters.clients; i++)
	{
		// Get sorted indices
		int j = temparray[i][0];
		validate_access("clients", j, true, __LINE__, __FUNCTION__, __FILE__);

		// Skip this client if there is a filter on it
		if(excludeclients != NULL &&
			(insetupVarsArray(clients[j].ip) || insetupVarsArray(clients[j].name)))
			continue;

		// Hidden client, probably due to privacy level. Skip this in the top lists
		if(strcmp(clients[j].ip, "0.0.0.0") == 0)
			continue;

		// Only return name if available
		char *name;
		if(clients[j].name != NULL)
			name = clients[j].name;
		else
			name = "";

		// Return this client if either
		// - "withzero" option is set, and/or
		// - the client made at least one query within the most recent 24 hours
		if(includezeroclients || clients[j].count > 0)
		{
			if(istelnet[*sock])
				ssend(*sock,"%i %i %s %s\n",n,clients[j].count,clients[j].ip,name);
			else
			{
				if(!pack_str32(*sock, "") || !pack_str32(*sock, clients[j].ip))
					return;

				pack_int32(*sock, clients[j].count);
			}
			n++;
		}

		if(n == count)
			break;
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();

	if(debugclients)
		logg("Sent top clients data to client, ID: %i", *sock);
}


void getForwardDestinations(char *client_message, int *sock)
{
	bool sort = true;
	int i, temparray[counters.forwarded][2], forwardedsum = 0, totalqueries = 0;

	if(command(client_message, "unsorted"))
		sort = false;

	for(i=0; i < counters.forwarded; i++) {
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Compute forwardedsum
		forwardedsum += forwarded[i].count;

		// If we want to print a sorted output, we fill the temporary array with
		// the values we will use for sorting afterwards
		if(sort) {
			temparray[i][0] = i;
			temparray[i][1] = forwarded[i].count;
		}
	}

	if(sort)
	{
		// Sort temporary array in descending order
		qsort(temparray, counters.forwarded, sizeof(int[2]), cmpdesc);
	}

	totalqueries = counters.forwardedqueries + counters.cached + counters.blocked;

	// Loop over available forward destinations
	for(i=-2; i < min(counters.forwarded, 8); i++)
	{
		char *ip, *name;
		float percentage = 0.0f;

		if(i == -2)
		{
			// Blocked queries (local lists)
			ip = "blocklist";
			name = ip;

			if(totalqueries > 0)
				// Whats the percentage of locked queries on the total amount of queries?
				percentage = 1e2f * counters.blocked / totalqueries;
		}
		else if(i == -1)
		{
			// Local cache
			ip = "cache";
			name = ip;

			if(totalqueries > 0)
				// Whats the percentage of cached queries on the total amount of queries?
				percentage = 1e2f * counters.cached / totalqueries;
		}
		else
		{
			// Regular forward destionation
			// Get sorted indices
			int j;
			if(sort)
				j = temparray[i][0];
			else
				j = i;
			validate_access("forwarded", j, true, __LINE__, __FUNCTION__, __FILE__);
			ip = forwarded[j].ip;

			// Only return name if available
			if(forwarded[j].name != NULL)
				name = forwarded[j].name;
			else
				name = "";

			// Math explanation:
			// A single query may result in requests being forwarded to multiple destinations
			// Hence, in order to be able to give percentages here, we have to normalize the
			// number of forwards to each specific destination by the total number of forward
			// events. This term is done by
			//   a = forwarded[j].count / forwardedsum
			//
			// The fraction a describes now how much share an individual forward destination
			// has on the total sum of sent requests.
			// We also know the share of forwarded queries on the total number of queries
			//   b = counters.forwardedqueries / c
			// where c is the number of valid queries,
			//   c = counters.forwardedqueries + counters.cached + counters.blocked
			//
			// To get the total percentage of a specific query on the total number of queries,
			// we simply have to scale b by a which is what we do in the following.
			if(forwardedsum > 0 && totalqueries > 0)
				percentage = 1e2f * forwarded[j].count / forwardedsum * counters.forwardedqueries / totalqueries;
		}

		// Send data if count > 0
		if(percentage > 0.0f)
		{
			if(istelnet[*sock])
				ssend(*sock, "%i %.2f %s %s\n", i, percentage, ip, name);
			else
			{
				if(!pack_str32(*sock, "") || !pack_str32(*sock, ip))
					return;

				pack_float(*sock, (float) percentage);
			}
		}
	}

	if(debugclients)
		logg("Sent forward destination data to client, ID: %i", *sock);
}


void getQueryTypes(int *sock)
{
	int i,total = 0;
	for(i=0; i < TYPE_MAX-1; i++)
		total += counters.querytype[i];

	float percentage[TYPE_MAX-1] = { 0.0 };

	// Prevent floating point exceptions by checking if the divisor is != 0
	if(total > 0)
		for(i=0; i < TYPE_MAX-1; i++)
			percentage[i] = 1e2f*counters.querytype[i]/total;

	if(istelnet[*sock])
		ssend(*sock,"A (IPv4): %.2f\nAAAA (IPv6): %.2f\nANY: %.2f\nSRV: %.2f\nSOA: %.2f\nPTR: %.2f\nTXT: %.2f\n",
		      percentage[0], percentage[1], percentage[2], percentage[3],
		      percentage[4], percentage[5], percentage[6]);
	else {
		pack_float(*sock, percentage[0]);
		pack_float(*sock, percentage[1]);
	}

	if(debugclients)
		logg("Sent query type data to client, ID: %i", *sock);
}


void getAllQueries(char *client_message, int *sock)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_MAXIMUM)
		return;

	// Do we want a more specific version of this command (domain/client/time interval filtered)?
	int from = 0, until = 0;

	char *domainname = NULL;
	bool filterdomainname = false;

	char *clientname = NULL;
	bool filterclientname = false;

	// Time filtering?
	if(command(client_message, ">getallqueries-time")) {
		sscanf(client_message, ">getallqueries-time %i %i",&from, &until);
	}
	// Domain filtering?
	if(command(client_message, ">getallqueries-domain")) {
		// Get domain name we want to see only (limit length to 255 chars)
		domainname = calloc(256, sizeof(char));
		if(domainname == NULL) return;
		sscanf(client_message, ">getallqueries-domain %255s", domainname);
		if(debugclients)
			logg("Showing only queries with domain %s", domainname);
		filterdomainname = true;
	}
	// Client filtering?
	if(command(client_message, ">getallqueries-client")) {
		// Get client name we want to see only (limit length to 255 chars)
		clientname = calloc(256, sizeof(char));
		if(clientname == NULL) return;
		sscanf(client_message, ">getallqueries-client %255s", clientname);
		if(debugclients)
			logg("Showing only queries with client %s", clientname);
		filterclientname = true;
	}

	int ibeg = 0, num;
	// Test for integer that specifies number of entries to be shown
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0)
	{
		// User wants a different number of requests
		// Don't allow a start index that is smaller than zero
		ibeg = counters.queries-num;
		if(ibeg < 0)
			ibeg = 0;
	}

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

	// Get privacy mode flag
	char * privacy = read_setupVarsconf("API_PRIVACY_MODE");
	bool privacymode = false;

	if(privacy != NULL)
		if(getSetupVarsBool(privacy))
			privacymode = true;

	clearSetupVarsArray();

	if(debugclients)
	{
		if(showpermitted)
			logg("Showing permitted queries");
		else
			logg("Hiding permitted queries");

		if(showblocked)
			logg("Showing blocked queries");
		else
			logg("Hiding blocked queries");

		if(privacymode)
			logg("Privacy mode enabled");
	}

	int i;
	for(i=ibeg; i < counters.queries; i++)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Check if this query has been create while in maximum privacy mode
		if(queries[i].private) continue;

		validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);

		char *qtype = (queries[i].type == TYPE_A)? "A" : "AAAA";

		// 1 = gravity.list, 4 = wildcard, 5 = black.list
		if((queries[i].status == QUERY_GRAVITY ||
		    queries[i].status == QUERY_WILDCARD ||
		    queries[i].status == QUERY_BLACKLIST) && !showblocked)
			continue;
		// 2 = forwarded, 3 = cached
		if((queries[i].status == QUERY_FORWARDED ||
		    queries[i].status == QUERY_CACHE) && !showpermitted)
			continue;

		// Skip those entries which so not meet the requested timeframe
		if((from > queries[i].timestamp && from != 0) || (queries[i].timestamp > until && until != 0))
			continue;

		if(filterdomainname)
		{
			// Skip if domain name is not identical with what the user wants to see
			if(strcmp(domains[queries[i].domainID].domain, domainname) != 0)
				continue;
		}

		if(filterclientname)
		{
			// Skip if client name and IP are not identical with what the user wants to see
			if(strcmp(clients[queries[i].clientID].ip,   clientname) != 0 &&
			   strcmp(clients[queries[i].clientID].name, clientname) != 0)
				continue;
		}

		char *domain = domains[queries[i].domainID].domain;
		char *client;
		if(clients[queries[i].clientID].name != NULL &&
		   strlen(clients[queries[i].clientID].name) > 0)
			client = clients[queries[i].clientID].name;
		else
			client = clients[queries[i].clientID].ip;

		unsigned long delay = queries[i].response;
		// Check if received (delay should be smaller than 30min)
		if(delay > 1.8e7)
			delay = 0;

		if(istelnet[*sock])
		{
			ssend(*sock,"%i %s %s %s %i %i %i %lu\n",queries[i].timestamp,qtype,domain,client,queries[i].status,queries[i].dnssec,queries[i].reply,delay);
		}
		else
		{
			pack_int32(*sock, queries[i].timestamp);

			// Use a fixstr because the length of qtype is always 4 (max is 31 for fixstr)
			if(!pack_fixstr(*sock, qtype))
				return;

			// Use str32 for domain and client because we have no idea how long they will be (max is 4294967295 for str32)
			if(!pack_str32(*sock, domain) || !pack_str32(*sock, client))
				return;

			pack_uint8(*sock, queries[i].status);
			pack_uint8(*sock, queries[i].dnssec);
		}
	}

	// Free allocated memory
	if(filterclientname)
		free(clientname);

	if(filterdomainname)
		free(domainname);

	if(debugclients)
		logg("Sent all queries data to client, ID: %i", *sock);
}

void getRecentBlocked(char *client_message, int *sock)
{
	int i, num=1;

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
		return;

	// Test for integer that specifies number of entries to be shown
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0) {
		// User wants a different number of requests
		if(num >= counters.queries)
			num = 0;
	}

	// Find most recent query with either status 1 (blocked)
	// or status 4 (wildcard blocked)
	int found = 0;
	for(i = counters.queries - 1; i > 0 ; i--)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);

		if(queries[i].status == QUERY_GRAVITY ||
		   queries[i].status == QUERY_WILDCARD ||
		   queries[i].status == QUERY_BLACKLIST)
		{
			found++;

			if(istelnet[*sock])
				ssend(*sock,"%s\n", domains[queries[i].domainID].domain);
			else if(!pack_str32(*sock, domains[queries[i].domainID].domain))
				return;
		}

		if(found >= num)
			break;
	}
}

void getMemoryUsage(int *sock)
{
	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	char *structprefix = calloc(2, sizeof(char));
	if(structprefix == NULL) return;
	double formated = 0.0;
	format_memory_size(structprefix, structbytes, &formated);

	if(istelnet[*sock])
		ssend(*sock,"memory allocated for internal data structure: %lu bytes (%.2f %sB)\n",structbytes,formated,structprefix);
	else
		pack_uint64(*sock, structbytes);
	free(structprefix);

	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.forwardedips + memory.forwarddata;
	char *dynamicprefix = calloc(2, sizeof(char));
	if(dynamicprefix == NULL) return;
	format_memory_size(dynamicprefix, dynamicbytes, &formated);

	if(istelnet[*sock])
		ssend(*sock,"dynamically allocated allocated memory used for strings: %lu bytes (%.2f %sB)\n",dynamicbytes,formated,dynamicprefix);
	else
		pack_uint64(*sock, dynamicbytes);
	free(dynamicprefix);

	unsigned long int totalbytes = structbytes + dynamicbytes;
	char *totalprefix = calloc(2, sizeof(char));
	if(totalprefix == NULL) return;
	format_memory_size(totalprefix, totalbytes, &formated);

	if(istelnet[*sock])
		ssend(*sock,"Sum: %lu bytes (%.2f %sB)\n",totalbytes,formated,totalprefix);
	else
		pack_uint64(*sock, totalbytes);
	free(totalprefix);

	if(debugclients)
		logg("Sent memory data to client, ID: %i", *sock);
}

void getClientID(int *sock)
{
	if(istelnet[*sock])
		ssend(*sock,"%i\n", *sock);
	else
		pack_int32(*sock, *sock);

	if(debugclients)
		logg("Sent client ID to client, ID: %i", *sock);
}

void getQueryTypesOverTime(int *sock)
{
	int i, sendit = -1;
	for(i = 0; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
		if((overTime[i].total > 0 || overTime[i].blocked > 0))
		{
			sendit = i;
			break;
		}
	}

	if(sendit > -1)
	{
		for(i = sendit; i < counters.overTime; i++)
		{
			validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);

			float percentageIPv4 = 0.0, percentageIPv6 = 0.0;
			int sum = overTime[i].querytypedata[0] + overTime[i].querytypedata[1];

			if(sum > 0) {
				percentageIPv4 = (float) (1e2 * overTime[i].querytypedata[0] / sum);
				percentageIPv6 = (float) (1e2 * overTime[i].querytypedata[1] / sum);
			}

			if(istelnet[*sock])
				ssend(*sock, "%i %.2f %.2f\n", overTime[i].timestamp, percentageIPv4, percentageIPv6);
			else {
				pack_int32(*sock, overTime[i].timestamp);
				pack_float(*sock, percentageIPv4);
				pack_float(*sock, percentageIPv6);
			}
		}
	}

	if(debugclients)
		logg("Sent overTime query types data to client, ID: %i", *sock);
}

void getVersion(int *sock)
{
	const char * commit = GIT_HASH;
	const char * tag = GIT_TAG;

	if(strlen(tag) > 1) {
		if(istelnet[*sock])
			ssend(*sock, "version %s\ntag %s\nbranch %s\ndate %s\n", GIT_VERSION, tag, GIT_BRANCH, GIT_DATE);
		else {
			if(!pack_str32(*sock, GIT_VERSION) ||
					!pack_str32(*sock, (char *) tag) ||
					!pack_str32(*sock, GIT_BRANCH) ||
					!pack_str32(*sock, GIT_DATE))
				return;
		}
	}
	else {
		char hash[8];
		// Extract first 7 characters of the hash
		strncpy(hash, commit, 7); hash[7] = 0;

		if(istelnet[*sock])
			ssend(*sock, "version vDev-%s\ntag %s\nbranch %s\ndate %s\n", hash, tag, GIT_BRANCH, GIT_DATE);
		else {
			char *hashVersion = calloc(6 + strlen(hash), sizeof(char));
			if(hashVersion == NULL) return;
			sprintf(hashVersion, "vDev-%s", hash);

			if(!pack_str32(*sock, hashVersion) ||
					!pack_str32(*sock, (char *) tag) ||
					!pack_str32(*sock, GIT_BRANCH) ||
					!pack_str32(*sock, GIT_DATE))
				return;

			free(hashVersion);
		}
	}

	if(debugclients)
		logg("Sent version info to client, ID: %i", *sock);
}

void getDBstats(int *sock)
{
	// Get file details
	struct stat st;
	long int filesize = 0;
	if(stat(FTLfiles.db, &st) != 0)
		// stat() failed (maybe the file does not exist?)
		filesize = -1;
	else
		filesize = st.st_size;

	char *prefix = calloc(2, sizeof(char));
	if(prefix == NULL) return;
	double formated = 0.0;
	format_memory_size(prefix, filesize, &formated);

	if(istelnet[*sock])
		ssend(*sock,"queries in database: %i\ndatabase filesize: %.2f %sB\nSQLite version: %s\n", get_number_of_queries_in_DB(), formated, prefix, sqlite3_libversion());
	else {
		pack_int32(*sock, get_number_of_queries_in_DB());
		pack_int64(*sock, filesize);

		if(!pack_str32(*sock, (char *) sqlite3_libversion()))
			return;
	}

	if(debugclients)
		logg("Sent DB info to client, ID: %i", *sock);
}

void getClientsOverTime(int *sock)
{
	int i, sendit = -1;

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		return;

	for(i = 0; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
		if((overTime[i].total > 0 || overTime[i].blocked > 0) &&
		   overTime[i].timestamp >= time(NULL) - config.maxlogage)
		{
			sendit = i;
			break;
		}
	}
	if(sendit < 0)
		return;

	// Get clients which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	// Array of clients to be skipped in the output
	// if skipclient[i] == true then this client should be hidden from
	// returned data. We initialize it with false
	bool skipclient[counters.clients];
	memset(skipclient, false, counters.clients*sizeof(bool));

	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);

		for(i=0; i < counters.clients; i++)
		{
			validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
			// Check if this client should be skipped
			if(insetupVarsArray(clients[i].ip) ||
			   insetupVarsArray(clients[i].name))
				skipclient[i] = true;
		}
	}

	// Main return loop
	for(i = sendit; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);

		if(istelnet[*sock])
			ssend(*sock, "%i", overTime[i].timestamp);
		else
			pack_int32(*sock, overTime[i].timestamp);

		// Loop over forward destinations to generate output to be sent to the client
		int j;
		for(j = 0; j < counters.clients; j++)
		{
			int thisclient = 0;

			if(skipclient[j])
				continue;

			if(j < overTime[i].clientnum)
			{
				// This client entry does already exist at this timestamp
				// -> use counter of requests sent to this destination
				thisclient = overTime[i].clientdata[j];
			}

			if(istelnet[*sock])
				ssend(*sock, " %i", thisclient);
			else
				pack_int32(*sock, thisclient);
		}

		if(istelnet[*sock])
			ssend(*sock, "\n");
		else
			pack_int32(*sock, -1);
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();
}

void getClientNames(int *sock)
{
	int i;

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		return;

	// Get clients which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	// Array of clients to be skipped in the output
	// if skipclient[i] == true then this client should be hidden from
	// returned data. We initialize it with false
	bool skipclient[counters.clients];
	memset(skipclient, false, counters.clients*sizeof(bool));

	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);

		for(i=0; i < counters.clients; i++)
		{
			validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
			// Check if this client should be skipped
			if(insetupVarsArray(clients[i].ip) ||
			   insetupVarsArray(clients[i].name))
				skipclient[i] = true;
		}
	}

	// Loop over clients to generate output to be sent to the client
	for(i = 0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(skipclient[i])
			continue;

		char *client;
		if(clients[i].name != NULL && strlen(clients[i].name) > 0)
			client = clients[i].name;
		else
			client = clients[i].ip;

		if(istelnet[*sock])
			ssend(*sock, "%i %i %s\n", i, clients[i].count, client);
		else {
			if(!pack_str32(*sock, "") || !pack_str32(*sock, clients[i].ip))
				return;

			pack_int32(*sock, clients[i].count);
		}
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();
}

void getUnknownQueries(int *sock)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
		return;

	int i;
	for(i=0; i < counters.queries; i++)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(queries[i].status != QUERY_UNKNOWN && queries[i].complete) continue;

		char type[5];
		if(queries[i].type == TYPE_A)
		{
			strcpy(type,"IPv4");
		}
		else
		{
			strcpy(type,"IPv6");
		}

		validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);


		char *client = clients[queries[i].clientID].ip;

		if(istelnet[*sock])
			ssend(*sock, "%i %i %i %s %s %s %i %s\n", queries[i].timestamp, i, queries[i].id, type, domains[queries[i].domainID].domain, client, queries[i].status, queries[i].complete ? "true" : "false");
		else {
			pack_int32(*sock, queries[i].timestamp);
			pack_int32(*sock, queries[i].id);

			// Use a fixstr because the length of qtype is always 4 (max is 31 for fixstr)
			if(!pack_fixstr(*sock, type))
				return;

			// Use str32 for domain and client because we have no idea how long they will be (max is 4294967295 for str32)
			if(!pack_str32(*sock, domains[queries[i].domainID].domain) || !pack_str32(*sock, client))
				return;

			pack_uint8(*sock, queries[i].status);
			pack_bool(*sock, queries[i].complete);
		}
	}

	if(debugclients)
		logg("Sent unknown queries data to client, ID: %i", *sock);
}

void getDomainDetails(char *client_message, int *sock)
{
	// Get domain name
	char domain[128];
	if(sscanf(client_message, "%*[^ ] %127s", domain) < 1)
	{
		ssend(*sock, "Need domain for this request\n");
		return;
	}

	int i;
	for(i = 0; i < counters.domains; i++)
	{
		validate_access("domains", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(strcmp(domains[i].domain, domain) == 0)
		{
			ssend(*sock,"Domain \"%s\", ID: %i\n", domain, i);
			ssend(*sock,"Total: %i\n", domains[i].count);
			ssend(*sock,"Blocked: %i\n", domains[i].blockedcount);
			ssend(*sock,"Wildcard blocked: %s\n", domains[i].wildcard ? "true" : "false");
			return;
		}
	}

	// for loop finished without an exact match
	ssend(*sock,"Domain \"%s\" is unknown\n", domain);
}
