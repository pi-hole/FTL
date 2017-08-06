/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API /stats/
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

void getStats(int *sock, char type)
{
	int blocked = counters.blocked + counters.wildcardblocked;
	int total = counters.queries - counters.invalidqueries;
	float percentage = 0.0;
	// Avoid 1/0 condition
	if(total > 0)
		percentage = 1e2*blocked/total;

	if(type == SOCKET) {
		ssend(*sock, "domains_being_blocked %i\ndns_queries_today %i\nads_blocked_today %i\nads_percentage_today %f\n", \
		    counters.gravity, total, blocked, percentage);
		ssend(*sock, "unique_domains %i\nqueries_forwarded %i\nqueries_cached %i\n", \
		    counters.domains, counters.forwardedqueries, counters.cached);
		ssend(*sock, "unique_clients %i\n", counters.clients);
	}
	else
	{
		sendAPIResponse(*sock, type);
		ssend(*sock,"\"domains_being_blocked\":%i,\"dns_queries_today\":%i,\"ads_blocked_today\":%i,\"ads_percentage_today\":%.4f,\"unique_domains\":%i,\"queries_forwarded\":%i,\"queries_cached\":%i,\"unique_clients\":%i",counters.gravity,total, blocked, percentage,counters.domains,counters.forwardedqueries,counters.cached,counters.clients);
	}

	if(debugclients)
		logg("Sent stats data to client, ID: %i", *sock);
}

void getOverTime(int *sock, char type)
{
	int i, j = 9999999;

	// Get first time slot with total or blocked greater than zero (the array will go down over time due to the rolling window)
	for(i=0; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(overTime[i].total > 0 || overTime[i].blocked > 0)
		{
			j = i;
			break;
		}
	}

	// Send data in socket format if requested
	if(type == SOCKET)
	{
		for(i = j; i < counters.overTime; i++)
		{
			ssend(*sock,"%i %i %i\n",overTime[i].timestamp,overTime[i].total,overTime[i].blocked);
		}
	}
	else
	{
		// First send header with unspecified content-length outside of the for-loop
		sendAPIResponse(*sock, type);
		ssend(*sock,"\"domains_over_time\":{");

		// Send "domains_over_time" data
		for(i = j; i < counters.overTime; i++)
		{
			if(i != j) ssend(*sock, ",");
			ssend(*sock,"\"%i\":%i",overTime[i].timestamp,overTime[i].total);
		}
		ssend(*sock,"},\"ads_over_time\":{");

		// Send "ads_over_time" data
		for(i = j; i < counters.overTime; i++)
		{
			if(i != j) ssend(*sock, ",");
			ssend(*sock,"\"%i\":%i",overTime[i].timestamp,overTime[i].blocked);
		}
		ssend(*sock,"}");
	}

	if(debugclients)
		logg("Sent overTime data to client, ID: %i", *sock);
}

void getTopDomains(char *client_message, int *sock, char type)
{
	int i, temparray[counters.domains][2], count=10, num;
	bool blocked, audit = false, desc = false;

	if(type == SOCKET)
		blocked = command(client_message, ">top-ads");
	else
		blocked = command(client_message, "/top_ads");

	// Exit before processing any data if requested via config setting
	if(!config.query_display)
		return;

	// Match both top-domains and top-ads
	// SOCKET: >top-domains (15)
	// API:    /stats/top_domains?limit=15
	if(type == SOCKET)
	{
		if(sscanf(client_message, "%*[^(](%i)", &num) > 0)
		{
			// User wants a different number of requests
			count = num;
		}
	}
	else
	{
		const char * limit = strstr(client_message, "limit=");
		if(limit != NULL)
		{
			if(sscanf(limit, "limit=%i", &num) > 0)
			{
				// User wants a different number of requests
				count = num;
			}
		}
	}

	// Apply Audit Log filtering?
	// SOCKET: >top-domains for audit
	// API:    /stats/top_domains?audit
	if(type == SOCKET && command(client_message, " for audit"))
		audit = true;
	else if(type != SOCKET && command(client_message, "audit"))
		audit = true;

	// Sort in descending order?
	// SOCKET: >top-domains desc
	// API:    /stats/top_domains?order=desc
	if(type == SOCKET && command(client_message, " desc"))
		desc = true;
	else if(type != SOCKET && command(client_message, "order=desc"))
		desc = true;

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
	if(desc)
		qsort(temparray, counters.domains, sizeof(int[2]), cmpdesc);
	else
		qsort(temparray, counters.domains, sizeof(int[2]), cmpasc);


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

	if(type != SOCKET)
	{
		// First send header with unspecified content-length outside of the for-loop
		sendAPIResponse(*sock, type);

		if(blocked)
			ssend(*sock, "\"top_ads\":{");
		else
			ssend(*sock, "\"top_domains\":{");
	}

	int skip = 0; bool first = true;
	for(i=0; i < min(counters.domains, count+skip); i++)
	{
		// Get sorted indices
		int j = temparray[counters.domains-i-1][0];
		validate_access("domains", j, true, __LINE__, __FUNCTION__, __FILE__);

		// Skip this domain if there is a filter on it
		if(excludedomains != NULL)
		{
			if(insetupVarsArray(domains[j].domain))
			{
				skip++;
				continue;
			}
		}

		// Skip this domain if already included in audit
		if(audit && countlineswith(domains[j].domain, files.auditlist) > 0)
		{
			skip++;
			continue;
		}

		if(blocked && showblocked && domains[j].blockedcount > 0)
		{
			if(type == SOCKET)
			{
				if(audit && domains[j].wildcard)
					ssend(*sock,"%i %i %s wildcard\n",i,domains[j].blockedcount,domains[j].domain);
				else
					ssend(*sock,"%i %i %s\n",i,domains[j].blockedcount,domains[j].domain);
			}
			else
			{
				if(!first) ssend(*sock,",");
				first = false;
				ssend(*sock,"\"%s\":%i", domains[j].domain, domains[j].blockedcount);
			}
		}
		else if(!blocked && showpermitted && (domains[j].count - domains[j].blockedcount) > 0)
		{
			if(type == SOCKET)
			{
				ssend(*sock,"%i %i %s\n",i,(domains[j].count - domains[j].blockedcount),domains[j].domain);
			}
			else
			{
				if(!first) ssend(*sock,",");
				first = false;
				ssend(*sock,"\"%s\":%i", domains[j].domain, (domains[j].count - domains[j].blockedcount));
			}
		}
	}

	if(type != SOCKET)
	{
		if(blocked)
			ssend(*sock,"},\"ads_blocked_today\":%i", counters.blocked);
		else
			ssend(*sock,"},\"dns_queries_today\":%i", (counters.queries - counters.invalidqueries));
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

void getTopClients(char *client_message, int *sock, char type)
{
	int i, temparray[counters.clients][2], count=10, num;

	// Match both top-domains and top-ads
	// SOCKET: >top-clients (15)
	// API:    /stats/top_clients?limit=15
	if(type == SOCKET)
	{
		if(sscanf(client_message, "%*[^(](%i)", &num) > 0)
		{
			// User wants a different number of requests
			count = num;
		}
	}
	else
	{
		const char * limit = strstr(client_message, "limit=");
		if(limit != NULL)
		{
			if(sscanf(limit, "limit=%i", &num) > 0)
			{
				// User wants a different number of requests
				count = num;
			}
		}
	}

	for(i=0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		temparray[i][0] = i;
		temparray[i][1] = clients[i].count;
	}

	// Sort temporary array
	qsort(temparray, counters.clients, sizeof(int[2]), cmpasc);

	// Get domains which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);

		if(debugclients)
			logg("Excluding %i clients from being displayed", setupVarsElements);
	}

	if(type != SOCKET)
	{
		// First send header with unspecified content-length outside of the for-loop
		sendAPIResponse(*sock, type);
		ssend(*sock, "\"top_clients\":{");
	}

	int skip = 0; bool first = true;
	for(i=0; i < min(counters.clients, count+skip); i++)
	{
		// Get sorted indices
		int j = temparray[counters.clients-i-1][0];
		validate_access("clients", j, true, __LINE__, __FUNCTION__, __FILE__);

		// Skip this client if there is a filter on it
		if(excludeclients != NULL)
		{
			if(insetupVarsArray(clients[j].ip) ||
			   insetupVarsArray(clients[j].name))
			{
				skip++;
				continue;
			}
		}

		if(clients[j].count > 0)
		{
			if(type == SOCKET)
			{
				ssend(*sock,"%i %i %s %s\n",i,clients[j].count,clients[j].ip,clients[j].name);
			}
			else
			{
				if(!first) ssend(*sock,",");
				first = false;
				if(strlen(clients[j].name) > 0)
					ssend(*sock,"\"%s|%s\":%i", clients[j].name, clients[j].ip, clients[j].count);
				else
					ssend(*sock,"\"%s\":%i", clients[j].ip, clients[j].count);
			}
		}
	}

	if(type != SOCKET)
		ssend(*sock,"},\"dns_queries_today\":%i", (counters.queries - counters.invalidqueries));

	if(excludeclients != NULL)
		clearSetupVarsArray();

	if(debugclients)
		logg("Sent top clients data to client, ID: %i", *sock);
}


void getForwardDestinations(char *client_message, int *sock, char type)
{
	bool allocated = false, first = true, sort = true;
	int i, temparray[counters.forwarded+1][2];

	if(type == SOCKET && command(client_message, "unsorted"))
		sort = false;
	else if(strstr(client_message, "unsorted"))
		sort = false;

	if(sort)
	{
		for(i=0; i < counters.forwarded; i++)
		{
			validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);
			temparray[i][0] = i;
			temparray[i][1] = forwarded[i].count;
		}

		// Add "local " forward destination
		temparray[counters.forwarded][0] = counters.forwarded;
		temparray[counters.forwarded][1] = counters.cached + counters.blocked;

		// Sort temporary array in descending order
		qsort(temparray, counters.forwarded+1, sizeof(int[2]), cmpdesc);
	}

	// Send HTTP headers with unknown content length
	sendAPIResponse(*sock, type);

	// Send initial JSON output
	if(type != SOCKET)
		ssend(*sock, "\"forward_destinations\":{");

	// Loop over available forward destinations
	for(i=0; i < min(counters.forwarded+1, 10); i++)
	{
		char *name, *ip;
		int count;

		// Get sorted indices
		int j;
		if(sort)
			j = temparray[i][0];
		else
			j = i;

		// Is this the "local" forward destination?
		if(j == counters.forwarded)
		{
			ip = calloc(4,1);
			strcpy(ip, "::1");
			name = calloc(6,1);
			strcpy(name, "local");
			count = counters.cached + counters.blocked;
			allocated = true;
		}
		else
		{
			validate_access("forwarded", j, true, __LINE__, __FUNCTION__, __FILE__);
			ip = forwarded[j].ip;
			name = forwarded[j].name;
			count = forwarded[j].count;
			allocated = false;
		}

		// Send data if count > 0
		if(count > 0)
		{
			if(type == SOCKET)
			{
				ssend(*sock,"%i %i %s %s\n",i,count,ip,name);
			}
			else
			{
				if(!first) ssend(*sock, ",");
				first = false;

				if(strlen(name) > 0)
					ssend(*sock, "\"%s|%s\":%i", name, ip, count);
				else
					ssend(*sock, "\"%s\":%i", ip, count);
			}
		}

		// Free previously allocated memory only if we allocated it
		if(allocated)
		{
			free(ip);
			free(name);
		}
	}

	if(type != SOCKET)
		ssend(*sock, "}");

	if(debugclients)
		logg("Sent forward destination data to client, ID: %i", *sock);
}


void getForwardNames(int *sock, char type)
{
	int i;

	if(type != SOCKET)
	{
		sendAPIResponse(*sock, type);
		ssend(*sock,"\"forward_destinations\":{");
	}

	for(i=0; i < counters.forwarded; i++)
	{
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(type == SOCKET)
		{
			ssend(*sock, "%i %i %s %s\n", i, forwarded[i].count, forwarded[i].ip, forwarded[i].name);
		}
		else
		{
			if(strlen(forwarded[i].name) > 0)
				ssend(*sock, "\"%s|%s\":%i,", forwarded[i].name, forwarded[i].ip, forwarded[i].count);
			else
				ssend(*sock, "\"%s\":%i,", forwarded[i].ip, forwarded[i].count);
		}
		//{"2001:1608:10:25::9249:d69b":2799,"2001:1608:10:25::1c04:b12f":6382,"resolver2.ipv6-sandbox.opendns.com|2620:0:ccd::2":2478,"resolver1.ipv6-sandbox.opendns.com|2620:0:ccc::2":2219,"local|::1":2755}}

	}

	// Add "local" forward destination
	if(type == SOCKET)
		ssend(*sock,"%i %i ::1 local\n",counters.forwarded,counters.cached);
	else
		ssend(*sock, "\"local|::1\":%i}", counters.cached);

	if(debugclients)
		logg("Sent forward destination names to client, ID: %i", *sock);
}


void getQueryTypes(int *sock, char type)
{
	if(type == SOCKET)
		ssend(*sock,"A (IPv4): %i\nAAAA (IPv6): %i\n",counters.IPv4,counters.IPv6);
	else
	{
		sendAPIResponse(*sock, type);
		ssend(*sock, "\"query_types\":{\"A (IPv4)\":%i,\"AAAA (IPv6)\":%i,\"PTR\":%i,\"SRV\":%i}",
		      counters.IPv4,
		      counters.IPv6,
		      counters.PTR,
		      counters.SRV);
	}

	if(debugclients)
		logg("Sent query type data to client, ID: %i", *sock);
}


void getAllQueries(char *client_message, int *sock, char type)
{

	// Exit before processing any data if requested via config setting
	if(!config.query_display)
		return;

	// Do we want a more specific version of this command (domain/client/time interval filtered)?
	int from = 0, until = 0;

	char *domainname = NULL;
	bool filterdomainname = false;

	char *clientname = NULL;
	bool filterclientname = false;

	if(type == SOCKET)
	{
		// Time filtering?
		if(command(client_message, ">getallqueries-time"))
		{
			sscanf(client_message, ">getallqueries-time %i %i",&from, &until);
		}
		// Domain filtering?
		if(command(client_message, ">getallqueries-domain"))
		{
			sscanf(client_message, ">getallqueries-domain %ms", &domainname);
			filterdomainname = true;
		}
		// Client filtering?
		if(command(client_message, ">getallqueries-client"))
		{
			sscanf(client_message, ">getallqueries-client %ms", &clientname);
			filterclientname = true;
		}
	}
	else
	{
		// Time filtering?
		const char * temp = strstr(client_message, "from=");
		if(temp != NULL)
		{
			int num;
			if(sscanf(temp, "from=%i", &num) > 0)
			{
				// User wants a different number of requests
				from = num;
			}
		}
		temp = strstr(client_message, "until=");
		if(temp != NULL)
		{
			int num;
			if(sscanf(temp, "until=%i", &num) > 0)
			{
				// User wants a different number of requests
				until = num;
			}
		}

		// Domain filtering?
		temp = strstr(client_message, "domain=");
		if(temp != NULL)
		{
			char *temp2 = strdup(temp);
			temp2[strcspn(temp2, "&")] = 0;
			sscanf(temp2, "domain=%ms", &domainname);
			free(temp2);
			filterdomainname = true;
		}
		temp = strstr(client_message, "client=");

		// Client filtering?
		if(temp != NULL)
		{
			char *temp2 = strdup(temp);
			temp2[strcspn(temp2, "&")] = 0;
			sscanf(temp2, "client=%ms", &clientname);
			free(temp2);
			filterclientname = true;
		}
	}

	int ibeg = 0, num;
	// Test for integer that specifies number of entries to be shown
	if(type == SOCKET)
	{
		if(sscanf(client_message, "%*[^(](%i)", &num) > 0)
		{
			// User wants a different number of requests
			// Don't allow a start index that is smaller than zero
			ibeg = counters.queries-num;
			if(ibeg < 0)
				ibeg = 0;
		}
	}
	else
	{
		const char * limit = strstr(client_message, "limit=");
		if(limit != NULL)
		{
			if(sscanf(limit, "limit=%i", &num) > 0)
			{
				// User wants a different number of requests
				// Don't allow a start index that is smaller than zero
				ibeg = counters.queries-num;
				if(ibeg < 0)
					ibeg = 0;
			}
		}
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

	if(type != SOCKET)
	{
		sendAPIResponse(*sock, type);
		ssend(*sock, "\"history\":[");
	}

	int i; bool first = true;
	for(i=ibeg; i < counters.queries; i++)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Check if this query has been removed due to garbage collection
		if(!queries[i].valid) continue;

		validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);

		char qtype[5];
		if(queries[i].type == 1)
			strcpy(qtype,"IPv4");
		else
			strcpy(qtype,"IPv6");

		if((queries[i].status == 1 || queries[i].status == 4) && !showblocked)
			continue;
		if((queries[i].status == 2 || queries[i].status == 3) && !showpermitted)
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
			if((strcmp(clients[queries[i].clientID].ip, clientname) != 0) &&
			   (strcmp(clients[queries[i].clientID].name, clientname) != 0))
				continue;
		}

		if(type == SOCKET)
		{
			if(!privacymode)
			{
				if(strlen(clients[queries[i].clientID].name) > 0)
					ssend(*sock,"%i %s %s %s %i\n",queries[i].timestamp,qtype,domains[queries[i].domainID].domain,clients[queries[i].clientID].name,queries[i].status);
				else
					ssend(*sock,"%i %s %s %s %i\n",queries[i].timestamp,qtype,domains[queries[i].domainID].domain,clients[queries[i].clientID].ip,queries[i].status);
			}
			else
				ssend(*sock,"%i %s %s hidden %i\n",queries[i].timestamp,qtype,domains[queries[i].domainID].domain,queries[i].status);
		}
		else
		{
			// {"data":[["1497351662","IPv4","clients4.google.com","10.8.0.2","2"],
			if(!first) ssend(*sock, ",");
			first = false;

			if(!privacymode)
			{
				if(strlen(clients[queries[i].clientID].name) > 0)
					ssend(*sock,"[%i,\"%s\",\"%s\",\"%s\",%i]",queries[i].timestamp,qtype,domains[queries[i].domainID].domain,clients[queries[i].clientID].name,queries[i].status);
				else
					ssend(*sock,"[%i,\"%s\",\"%s\",\"%s\",%i]",queries[i].timestamp,qtype,domains[queries[i].domainID].domain,clients[queries[i].clientID].ip,queries[i].status);
			}
			else
				ssend(*sock,"[%i,\"%s\",\"%s\",\"hidden\",%i]",queries[i].timestamp,qtype,domains[queries[i].domainID].domain,queries[i].status);
		}
	}

	if(type != SOCKET)
		ssend(*sock, "]");

	// Free allocated memory
	if(filterclientname)
		free(clientname);

	if(filterdomainname)
		free(domainname);

	if(debugclients)
		logg("Sent all queries data to client, ID: %i", *sock);
}

void getRecentBlocked(char *client_message, int *sock, char type)
{
	int i, num=1;

	// Exit before processing any data if requested via config setting
	if(!config.query_display)
		return;

	// Test for integer that specifies number of entries to be shown
	if(type == SOCKET)
	{
		if(sscanf(client_message, "%*[^(](%i)", &num) > 0)
		{
			// User wants a different number of requests
			if(num >= counters.queries)
				num = 0;
		}
	}
	else
	{
		const char * limit = strstr(client_message, "limit=");
		if(limit != NULL)
		{
			if(sscanf(limit, "limit=%i", &num) > 0)
			{
				// User wants a different number of requests
				if(num >= counters.queries)
					num = 0;
			}
		}
	}

	if(type != SOCKET)
	{
		sendAPIResponse(*sock, type);
		ssend(*sock, "\"recent_blocked\":[");
	}

	// Find most recent query with either status 1 (blocked)
	// or status 4 (wildcard blocked)
	int found = 0; bool first = true;
	for(i = counters.queries - 1; i > 0 ; i--)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Check if this query has been removed due to garbage collection
		if(!queries[i].valid) continue;

		if(queries[i].status == 1 || queries[i].status == 4)
		{
			found++;
			if(type == SOCKET)
			{
				ssend(*sock,"%s\n", domains[queries[i].domainID].domain);
			}
			else
			{
				if(!first) ssend(*sock, ",");
				first = false;
				ssend(*sock, "\"%s\"", domains[queries[i].domainID].domain);
			}
		}

		if(found >= num)
			break;
	}

	if(type != SOCKET)
		ssend(*sock, "]");
}

// only available via SOCKET
void getMemoryUsage(int *sock, char type)
{
	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	char *structprefix = calloc(2, sizeof(char));
	double formated = 0.0;
	format_memory_size(structprefix, structbytes, &formated);
	ssend(*sock,"memory allocated for internal data structure: %lu bytes (%.2f %sB)\n",structbytes,formated,structprefix);
	free(structprefix);

	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata;
	char *dynamicprefix = calloc(2, sizeof(char));
	format_memory_size(dynamicprefix, dynamicbytes, &formated);
	ssend(*sock,"dynamically allocated allocated memory used for strings: %lu bytes (%.2f %sB)\n",dynamicbytes,formated,dynamicprefix);
	free(dynamicprefix);

	unsigned long int totalbytes = structbytes + dynamicbytes;
	char *totalprefix = calloc(2, sizeof(char));
	format_memory_size(totalprefix, totalbytes, &formated);
	ssend(*sock,"Sum: %lu bytes (%.2f %sB)\n",totalbytes,formated,totalprefix);
	free(totalprefix);

	if(debugclients)
		logg("Sent memory data to client, ID: %i", *sock);
}

void getForwardDestinationsOverTime(int *sock, char type)
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

	if(type != SOCKET)
	{
		sendAPIResponse(*sock, type);
		ssend(*sock,"\"over_time\":{");
	}

	if(sendit > -1)
	{
		bool first = true;
		for(i = sendit; i < counters.overTime; i++)
		{
			validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
			if(type == SOCKET)
			{
				ssend(*sock, "%i", overTime[i].timestamp);
			}
			else
			{
				if(!first) ssend(*sock, ",");
				first = false;
				ssend(*sock, "\"%i\":[", overTime[i].timestamp);
			}

			int j;

			for(j = 0; j < counters.forwarded; j++)
			{
				int k;
				if(j < overTime[i].forwardnum)
					k = overTime[i].forwarddata[j];
				else
					k = 0;
				if(type == SOCKET)
					ssend(*sock, " %i", k);
				else
					ssend(*sock, "%i,", k);
			}

			if(type == SOCKET)
				ssend(*sock, " %i\n", overTime[i].cached + overTime[i].blocked);
			else
				ssend(*sock, "%i]", overTime[i].cached + overTime[i].blocked);
		}
	}

	if(type != SOCKET)
	{
		ssend(*sock,"},");
		// Manually set API -> Don't send header a second time
		getForwardNames(sock, API);
	}

	if(debugclients)
		logg("Sent overTime forwarded data to client, ID: %i", *sock);
}

void getClientID(int *sock, char type)
{

	ssend(*sock,"%i\n", *sock);

	if(debugclients)
		logg("Sent client ID to client, ID: %i", *sock);
}

void getQueryTypesOverTime(int *sock, char type)
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

	if(type != SOCKET)
	{
		sendAPIResponse(*sock, type);
		ssend(*sock,"\"query_types\":{");
	}

	if(sendit > -1)
	{
		bool first = true;
		for(i = sendit; i < counters.overTime; i++)
		{
			validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
			if(type == SOCKET)
			{
				ssend(*sock, "%i %i %i\n", overTime[i].timestamp,overTime[i].querytypedata[0],overTime[i].querytypedata[1]);
			}
			else
			{
				if(!first) ssend(*sock, ",");
				first = false;
				ssend(*sock, "\"%i\":[%i,%i]", overTime[i].timestamp,overTime[i].querytypedata[0],overTime[i].querytypedata[1]);
			}
		}
	}

	if(type != SOCKET)
		ssend(*sock,"}");

	if(debugclients)
		logg("Sent overTime query types data to client, ID: %i", *sock);
}

void getVersion(int *sock, char type)
{
	ssend(*sock,"version %s\ntag %s\nbranch %s\ndate %s\n", GIT_VERSION, GIT_TAG, GIT_BRANCH, GIT_DATE);

	if(debugclients)
		logg("Sent version info to client, ID: %i", *sock);
}

void getDBstats(int *sock, char type)
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
	double formated = 0.0;
	format_memory_size(prefix, filesize, &formated);

	ssend(*sock,"queries in database: %i\ndatabase filesize: %.2f %sB\nSQLite version: %s\n", get_number_of_queries_in_DB(), formated, prefix, sqlite3_libversion());

	if(debugclients)
		logg("Sent DB info to client, ID: %i", *sock);
}
