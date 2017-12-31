/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Socket request handling routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "version.h"

// Private
#define min(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })
#define max(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })

// Local prototypes
void getStats(int *sock);
void getOverTime(int *sock);
void getTopDomains (char *client_message, int *sock);
void getTopClients(char *client_message, int *sock);
void getForwardDestinations(char *client_message, int *sock);
void getQueryTypes(int *sock);
void getAllQueries(char *client_message, int *sock);
void getRecentBlocked(char *client_message, int *sock);
void getMemoryUsage(int *sock);
void getForwardDestinationsOverTime(int *sock);
void getClientID(int *sock);
void getQueryTypesOverTime(int *sock);
void getVersion(int *sock);
void getDBstats(int *sock);
void getClientsOverTime(int *sock);
void getClientNames(int *sock);
void getUnknownQueries(int *sock);

void process_request(char *client_message, int *sock)
{
	char EOT[2];
	EOT[0] = 0x04;
	EOT[1] = 0x00;
	char server_message[SOCKETBUFFERLEN];
	bool processed = false;
	if(command(client_message, ">stats"))
	{
		processed = true;
		getStats(sock);
	}
	else if(command(client_message, ">overTime"))
	{
		processed = true;
		getOverTime(sock);
	}
	else if(command(client_message, ">top-domains") || command(client_message, ">top-ads"))
	{
		processed = true;
		getTopDomains(client_message, sock);
	}
	else if(command(client_message, ">top-clients"))
	{
		processed = true;
		getTopClients(client_message, sock);
	}
	else if(command(client_message, ">forward-dest"))
	{
		processed = true;
		getForwardDestinations(client_message, sock);
	}
	else if(command(client_message, ">forward-names"))
	{
		processed = true;
		getForwardDestinations(">forward-dest unsorted", sock);
	}
	else if(command(client_message, ">querytypes"))
	{
		processed = true;
		getQueryTypes(sock);
	}
	else if(command(client_message, ">getallqueries"))
	{
		processed = true;
		getAllQueries(client_message, sock);
	}
	else if(command(client_message, ">recentBlocked"))
	{
		processed = true;
		getRecentBlocked(client_message, sock);
	}
	else if(command(client_message, ">memory"))
	{
		processed = true;
		getMemoryUsage(sock);
	}
	else if(command(client_message, ">clientID"))
	{
		processed = true;
		getClientID(sock);
	}
	else if(command(client_message, ">ForwardedoverTime"))
	{
		processed = true;
		getForwardDestinationsOverTime(sock);
	}
	else if(command(client_message, ">QueryTypesoverTime"))
	{
		processed = true;
		getQueryTypesOverTime(sock);
	}
	else if(command(client_message, ">version"))
	{
		processed = true;
		getVersion(sock);
	}
	else if(command(client_message, ">dbstats"))
	{
		processed = true;
		getDBstats(sock);
	}
	else if(command(client_message, ">ClientsoverTime"))
	{
		processed = true;
		getClientsOverTime(sock);
	}
	else if(command(client_message, ">client-names"))
	{
		processed = true;
		getClientNames(sock);
	}
	else if(command(client_message, ">unknown"))
	{
		processed = true;
		getUnknownQueries(sock);
	}

	// Test only at the end if we want to quit or kill
	// so things can be processed before
	if(command(client_message, ">quit") || command(client_message, EOT))
	{
		processed = true;
		if(debugclients)
			logg("Client wants to disconnect, ID: %i",*sock);

		close(*sock);
		*sock = 0;
	}
	else if(command(client_message, ">kill"))
	{
		processed = true;
		sprintf(server_message,"killed\n");
		swrite(server_message, *sock);
		logg("FTL killed by client ID: %i",*sock);
		killed = 1;
	}

	if(!processed)
	{
		sprintf(server_message,"unknown command: %s",client_message);
		swrite(server_message, *sock);
	}

	// End of queryable commands
	if(*sock != 0)
	{
		// Send EOM
		seom(server_message, *sock);
	}
}

bool command(char *client_message, const char* cmd)
{
	if(strstr(client_message,cmd) != NULL)
		return true;
	else
		return false;
}

// void formatNumber(bool raw, int n, char* buffer)
// {
// 	if(raw)
// 	{
// 		// Don't change number, echo string
// 		sprintf(buffer, "%d", n);
// 	}
// 	else
// 	{
// 		// Insert thousand separator
// 		if(n < 0) {
// 			sprintf(buffer, "-");
// 			n = -n;
// 		}
// 		else
// 		{
// 			// Empty buffer
// 			buffer[0] = '\0';
// 		}

// 		int a[20] = { 0 };
// 		int *pa = a;
// 		while(n > 0) {
// 			*++pa = n % 1000;
// 			n /= 1000;
// 		}
// 		sprintf(buffer, "%s%d", buffer, *pa);
// 		while(pa > a + 1) {
// 			sprintf(buffer, "%s,%03d", buffer, *--pa);
// 		}
// 	}
// }

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
	char server_message[SOCKETBUFFERLEN];

	int blocked = counters.blocked + counters.wildcardblocked;
	int total = counters.queries - counters.invalidqueries;
	float percentage = 0.0;
	// Avoid 1/0 condition
	if(total > 0)
	{
		percentage = 1e2*blocked/total;
	}

	switch(blockingstatus)
	{
		case 0: // Blocking disabled
			sprintf(server_message,"domains_being_blocked N/A\n");
			swrite(server_message, *sock);
			break;
		default: // Either unknown or enabled
			sprintf(server_message,"domains_being_blocked %i\n",counters.gravity);
			swrite(server_message, *sock);
			break;
	}
	sprintf(server_message,"dns_queries_today %i\nads_blocked_today %i\nads_percentage_today %f\n", \
	        total,blocked,percentage);
	swrite(server_message, *sock);
	sprintf(server_message,"unique_domains %i\nqueries_forwarded %i\nqueries_cached %i\n", \
	        counters.domains,counters.forwardedqueries,counters.cached);
	swrite(server_message, *sock);

	// clients_ever_seen: all clients ever seen by FTL
	sprintf(server_message,"clients_ever_seen %i\n", \
	        counters.clients);
	swrite(server_message, *sock);

	// unique_clients: count only clients that have been active within the most recent 24 hours
	int i, activeclients = 0;
	for(i=0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(clients[i].count > 0)
			activeclients++;
	}
	sprintf(server_message,"unique_clients %i\n", \
	        activeclients);
	swrite(server_message, *sock);

	switch(blockingstatus)
	{
		case 0: // Blocking disabled
			sprintf(server_message,"status disabled\n");
			swrite(server_message, *sock);
			break;
		case 1: // Blocking Enabled
			sprintf(server_message,"status enabled\n");
			swrite(server_message, *sock);
			break;
		default: // Unknown status
			sprintf(server_message,"status unknown\n");
			swrite(server_message, *sock);
			break;
	}

	if(debugclients)
		logg("Sent stats data to client, ID: %i", *sock);
}

void getOverTime(int *sock)
{
	char server_message[SOCKETBUFFERLEN];
	int i;
	bool sendit = false;
	for(i=0; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
		if((overTime[i].total > 0 || overTime[i].blocked > 0) && !sendit)
		{
			sendit = true;
		}
		if(sendit)
		{
			sprintf(server_message,"%i %i %i\n",overTime[i].timestamp,overTime[i].total,overTime[i].blocked);
			swrite(server_message, *sock);
		}
	}
	if(debugclients)
		logg("Sent overTime data to client, ID: %i", *sock);
}

void getTopDomains(char *client_message, int *sock)
{
	char server_message[SOCKETBUFFERLEN];
	int i, temparray[counters.domains][2], count=10, num;
	bool blocked = command(client_message, ">top-ads"), audit = false, desc = false;

	// Exit before processing any data if requested via config setting
	if(!config.query_display)
		return;

	// Match both top-domains and top-ads
	if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
	{
		// User wants a different number of requests
		count = num;
	}

	// Apply Audit Log filtering?
	if(command(client_message, " for audit"))
	{
		audit = true;
	}

	// Sort in descending order?
	if(command(client_message, " desc"))
	{
		desc = true;
	}

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
		{
			showblocked = false;
		}
		else if((strcmp(filter, "blockedonly")) == 0)
		{
			showpermitted = false;
		}
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

	int skip = 0;
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
			if(audit && domains[j].wildcard)
				sprintf(server_message,"%i %i %s wildcard\n",i,domains[j].blockedcount,domains[j].domain);
			else
				sprintf(server_message,"%i %i %s\n",i,domains[j].blockedcount,domains[j].domain);
			swrite(server_message, *sock);
		}
		else if(!blocked && showpermitted && (domains[j].count - domains[j].blockedcount) > 0)
		{
			sprintf(server_message,"%i %i %s\n",i,(domains[j].count - domains[j].blockedcount),domains[j].domain);
			swrite(server_message, *sock);
		}
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
	char server_message[SOCKETBUFFERLEN];
	int i, temparray[counters.clients][2], count=10, num;

	if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
	{
		// User wants a different number of requests
		count = num;
	}

	// Show also clients which have not been active recently?
	// This option can be combined with existing options,
	// i.e. both >top-clients withzero" and ">top-clients withzero (123)" are valid
	bool includezeroclients = false;
	if(command(client_message, " withzero"))
	{
		includezeroclients = true;
	}

	for(i=0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		temparray[i][0] = i;
		temparray[i][1] = clients[i].count;
	}

	// Sort temporary array
	qsort(temparray, counters.clients, sizeof(int[2]), cmpasc);

	// Get clients which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);
		if(debugclients)
			logg("Excluding %i clients from being displayed", setupVarsElements);
	}

	int skip = 0;
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
		// Return this client if either
		// - "withzero" option is set, and/or
		// - the client made at least one query within the most recent 24 hours
		if(includezeroclients || clients[j].count > 0)
		{
			sprintf(server_message,"%i %i %s %s\n",i,clients[j].count,clients[j].ip,clients[j].name);
			swrite(server_message, *sock);
		}
	}
	if(excludeclients != NULL)
		clearSetupVarsArray();
	if(debugclients)
		logg("Sent top clients data to client, ID: %i", *sock);
}


void getForwardDestinations(char *client_message, int *sock)
{
	char server_message[SOCKETBUFFERLEN];
	bool allocated = false, sort = true;
	int i, temparray[counters.forwarded+1][2], forwardedsum = 0, totalqueries = 0;

	if(command(client_message, "unsorted"))
		sort = false;

	for(i=0; i < counters.forwarded; i++)
	{
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Compute forwardedsum
		forwardedsum += forwarded[i].count;

		// If we want to print a sorted output, we fill the temporary array with
		// the values we will use for sorting afterwards
		if(sort)
		{
			temparray[i][0] = i;
			temparray[i][1] = forwarded[i].count;
		}
	}

	if(sort)
	{
		// Add "local " forward destination
		temparray[counters.forwarded][0] = counters.forwarded;
		temparray[counters.forwarded][1] = counters.cached + counters.blocked;

		// Sort temporary array in descending order
		qsort(temparray, counters.forwarded+1, sizeof(int[2]), cmpdesc);
	}

	totalqueries = counters.forwardedqueries + counters.cached + counters.blocked;

	// Loop over available forward destinations
	for(i=0; i < min(counters.forwarded+1, 10); i++)
	{
		char *name, *ip;
		double percentage;

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
			if(totalqueries > 0)
				// Whats the percentage of (cached + blocked) queries on the total amount of queries?
				percentage = 1e2 * (counters.cached + counters.blocked) / totalqueries;
			else
				percentage = 0.0;
			allocated = true;
		}
		else
		{
			validate_access("forwarded", j, true, __LINE__, __FUNCTION__, __FILE__);
			ip = forwarded[j].ip;
			name = forwarded[j].name;
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
				percentage = 1e2 * forwarded[j].count / forwardedsum * counters.forwardedqueries / totalqueries;
			else
				percentage = 0.0;
			allocated = false;
		}

		// Send data if count > 0
		if(percentage > 0.0)
		{
			sprintf(server_message,"%i %.2f %s %s\n",i,percentage,ip,name);
			swrite(server_message, *sock);
		}

		// Free previously allocated memory only if we allocated it
		if(allocated)
		{
			free(ip);
			free(name);
		}
	}
	if(debugclients)
		logg("Sent forward destination data to client, ID: %i", *sock);
}

void getQueryTypes(int *sock)
{
	char server_message[SOCKETBUFFERLEN];
	int total = counters.IPv4 + counters.IPv6;
	double percentageIPv4 = 0.0, percentageIPv6 = 0.0;

	// Prevent floating point exceptions by checking if the divisor is != 0
	if(total > 0)
	{
		percentageIPv4 = 1e2*counters.IPv4/total;
		percentageIPv6 = 1e2*counters.IPv6/total;
	}

	sprintf(server_message,"A (IPv4): %.2f\nAAAA (IPv6): %.2f\n", percentageIPv4, percentageIPv6);
	swrite(server_message, *sock);
	if(debugclients)
		logg("Sent query type data to client, ID: %i", *sock);
}


void getAllQueries(char *client_message, int *sock)
{
	char server_message[SOCKETBUFFERLEN];

	// Exit before processing any data if requested via config setting
	if(!config.query_display)
		return;

	// Do we want a more specific version of this command (domain/client/time interval filtered)?
	int from = 0, until = 0;
	bool filtertime = false;
	if(command(client_message, ">getallqueries-time"))
	{
		// Get from to until boundaries
		sscanf(client_message, ">getallqueries-time %i %i",&from, &until);
		if(debugclients)
		{
			logg("Showing only limited time interval starting at ",from);
			logg("Showing only limited time interval ending at ",until);
		}
		filtertime = true;
	}

	char *domainname;
	bool filterdomainname = false;
	if(command(client_message, ">getallqueries-domain"))
	{
		domainname = calloc(128, sizeof(char));
		// Get domain name we want to see only (limit length to 127 chars)
		sscanf(client_message, ">getallqueries-domain %127s", domainname);
		if(debugclients)
			logg("Showing only queries with domain %s", domainname);
		filterdomainname = true;
	}

	char *clientname;
	bool filterclientname = false;
	if(command(client_message, ">getallqueries-client"))
	{
		clientname = calloc(128, sizeof(char));
		// Get client name we want to see only (limit length to 127 chars)
		sscanf(client_message, ">getallqueries-client %127s", clientname);
		if(debugclients)
			logg("Showing only queries with client %s", clientname);
		filterclientname = true;
	}

	int ibeg = 0, num;
	// Test for integer that specifies number of entries to be shown
	if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
	{
		// User wants a different number of requests
		// Don't allow a start index that is smaller than zero
		ibeg = counters.queries-num;
		if(ibeg < 0)
			ibeg = 0;
		if(debugclients)
			logg("Showing only limited amount of queries: ",num);
	}

	// Get potentially existing filtering flags
	char * filter = read_setupVarsconf("API_QUERY_LOG_SHOW");
	bool showpermitted = true, showblocked = true;
	if(filter != NULL)
	{
		if((strcmp(filter, "permittedonly")) == 0)
		{
			showblocked = false;
		}
		else if((strcmp(filter, "blockedonly")) == 0)
		{
			showpermitted = false;
		}
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
		// Check if this query has been removed due to garbage collection
		if(!queries[i].valid) continue;

		validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);

		char type[5];
		if(queries[i].type == 1)
		{
			strcpy(type,"IPv4");
		}
		else
		{
			strcpy(type,"IPv6");
		}

		if((queries[i].status == 1 || queries[i].status == 4) && !showblocked)
			continue;
		if((queries[i].status == 2 || queries[i].status == 3) && !showpermitted)
			continue;

		if(filtertime)
		{
			// Skip those entries which so not meet the requested timeframe
			if(from > queries[i].timestamp || queries[i].timestamp > until)
				continue;
		}

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

		if(!privacymode)
		{
			if(strlen(clients[queries[i].clientID].name) > 0)
				sprintf(server_message,"%i %s %s %s %i %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].name,queries[i].status,domains[queries[i].domainID].dnssec);
			else
				sprintf(server_message,"%i %s %s %s %i %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].ip,queries[i].status,domains[queries[i].domainID].dnssec);
		}
		else
		{
			sprintf(server_message,"%i %s %s hidden %i %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,queries[i].status,domains[queries[i].domainID].dnssec);
		}
		swrite(server_message, *sock);
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
	char server_message[SOCKETBUFFERLEN];
	int i, num=1;

	// Exit before processing any data if requested via config setting
	if(!config.query_display)
		return;

	// Test for integer that specifies number of entries to be shown
	if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
	{
		// User wants a different number of requests
		if(num >= counters.queries)
			num = 0;

		if(debugclients)
			logg("Showing several blocked domains ",num);
	}
	// Find most recent query with either status 1 (blocked)
	// or status 4 (wildcard blocked)
	int found = 0;
	for(i = counters.queries - 1; i > 0 ; i--)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Check if this query has been removed due to garbage collection
		if(!queries[i].valid) continue;

		if(queries[i].status == 1 || queries[i].status == 4)
		{
			found++;
			sprintf(server_message,"%s\n",domains[queries[i].domainID].domain);
			swrite(server_message, *sock);
		}

		if(found >= num)
		{
			break;
		}
	}
}

void getMemoryUsage(int *sock)
{
	char server_message[SOCKETBUFFERLEN];
	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	char *structprefix = calloc(2, sizeof(char));
	double formated = 0.0;
	format_memory_size(structprefix, structbytes, &formated);
	sprintf(server_message,"memory allocated for internal data structure: %lu bytes (%.2f %sB)\n",structbytes,formated,structprefix);
	swrite(server_message, *sock);
	free(structprefix);

	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata;
	char *dynamicprefix = calloc(2, sizeof(char));
	format_memory_size(dynamicprefix, dynamicbytes, &formated);
	sprintf(server_message,"dynamically allocated allocated memory used for strings: %lu bytes (%.2f %sB)\n",dynamicbytes,formated,dynamicprefix);
	swrite(server_message, *sock);
	free(dynamicprefix);

	unsigned long int totalbytes = structbytes + dynamicbytes;
	char *totalprefix = calloc(2, sizeof(char));
	format_memory_size(totalprefix, totalbytes, &formated);
	sprintf(server_message,"Sum: %lu bytes (%.2f %sB)\n",totalbytes,formated,totalprefix);
	swrite(server_message, *sock);
	free(totalprefix);

	if(debugclients)
		logg("Sent memory data to client, ID: %i", *sock);
}

void getForwardDestinationsOverTime(int *sock)
{
	char server_message[SOCKETBUFFERLEN];
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
			double percentage;

			validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
			sprintf(server_message, "%i", overTime[i].timestamp);

			int j, forwardedsum = 0;

			// Compute forwardedsum used for later normalization
			for(j = 0; j < overTime[i].forwardnum; j++)
			{
				forwardedsum += overTime[i].forwarddata[j];
			}

			// Loop over forward destinations to generate output to be sent to the client
			for(j = 0; j < counters.forwarded; j++)
			{
				int thisforward = 0;

				if(j < overTime[i].forwardnum)
				{
					// This forward destination does already exist at this timestamp
					// -> use counter of requests sent to this destination
					thisforward = overTime[i].forwarddata[j];
				}
				// else
				// {
					// This forward destination does not yet exist at this timestamp
					// -> use zero as number of requests sent to this destination
				// 	thisforward = 0;
				// }

				// Avoid floating point exceptions
				if(forwardedsum > 0 && overTime[i].total > 0 && thisforward > 0)
				{
					// A single query may result in requests being forwarded to multiple destinations
					// Hence, in order to be able to give percentages here, we have to normalize the
					// number of forwards to each specific destination by the total number of forward
					// events. This is done by
					//   a = thisforward / forwardedsum
					// The fraction a describes how much share an individual forward destination
					// has on the total sum of sent requests.
					//
					// We also know the share of forwarded queries on the total number of queries
					//   b = forwardedqueries/overTime[i].total
					// where the number of forwarded queries in this time interval is given by
					//   forwardedqueries = overTime[i].total - (overTime[i].cached
					//                                           + overTime[i].blocked)
					//
					// To get the total percentage of a specific forward destination on the total
					// number of queries, we simply have to multiply a and b as done below:
					percentage = 1e2 * thisforward / forwardedsum * (overTime[i].total - (overTime[i].cached + overTime[i].blocked)) / overTime[i].total;
				}
				else
				{
					percentage = 0.0;
				}

				sprintf(server_message + strlen(server_message), " %.2f", percentage);
			}

			// Avoid floating point exceptions
			if(overTime[i].total > 0)
				// Forward count for destination "local" is cached + blocked normalized by total:
				percentage = 1e2 * (overTime[i].cached + overTime[i].blocked) / overTime[i].total;
			else
				percentage = 0.0;

			sprintf(server_message + strlen(server_message), " %.2f\n", percentage);
			swrite(server_message, *sock);
		}
	}
	if(debugclients)
		logg("Sent overTime forwarded data to client, ID: %i", *sock);
}

void getClientID(int *sock)
{
	char server_message[SOCKETBUFFERLEN];

	sprintf(server_message,"%i\n", *sock);
	swrite(server_message, *sock);

	if(debugclients)
		logg("Sent client ID to client, ID: %i", *sock);
}

void getQueryTypesOverTime(int *sock)
{
	char server_message[SOCKETBUFFERLEN];
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
			double percentageIPv4 = 0.0, percentageIPv6 = 0.0;
			int sum = overTime[i].querytypedata[0] + overTime[i].querytypedata[1];
			if(sum > 0)
			{
				percentageIPv4 = 1e2*overTime[i].querytypedata[0] / sum;
				percentageIPv6 = 1e2*overTime[i].querytypedata[1] / sum;
			}
			sprintf(server_message, "%i %.2f %.2f\n", overTime[i].timestamp, percentageIPv4, percentageIPv6);
			swrite(server_message, *sock);
		}
	}
	if(debugclients)
		logg("Sent overTime query types data to client, ID: %i", *sock);
}

void getVersion(int *sock)
{
	char server_message[SOCKETBUFFERLEN];

	const char * version = GIT_VERSION;
	const char * branch = GIT_BRANCH;
	// Travis CI pulls on a tag basis, not by branch.
	// Hence, it may happen that the master binary isn't aware of its branch.
	// We check if this is the case and if there is a "vX.YY" like tag on the
	// binary are print out branch "master" if we find that this is the case
	if(strstr(branch, "(no branch)") != NULL && strstr(version, ".") != NULL)
		branch = "master";

	if(strstr(version, ".") != NULL)
		sprintf(server_message,"version %s\ntag %s\nbranch %s\ndate %s\n", version, GIT_TAG, branch, GIT_DATE);
	else
		sprintf(server_message,"version vDev-%s\ntag %s\nbranch %s\ndate %s\n", GIT_HASH, GIT_TAG, branch, GIT_DATE);
	swrite(server_message, *sock);

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
	double formated = 0.0;
	format_memory_size(prefix, filesize, &formated);

	char server_message[SOCKETBUFFERLEN];
	sprintf(server_message,"queries in database: %i\ndatabase filesize: %.2f %sB\nSQLite version: %s\n", get_number_of_queries_in_DB(), formated, prefix, sqlite3_libversion());
	swrite(server_message, *sock);

	if(debugclients)
		logg("Sent DB info to client, ID: %i", *sock);
}

void getClientsOverTime(int *sock)
{
	char server_message[SOCKETBUFFERLEN];
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
			if(insetupVarsArray(clients[i].ip) || insetupVarsArray(clients[i].name))
			{
				skipclient[i] = true;
			}
		}
	}

	// Main return loop
	for(i = sendit; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
		sprintf(server_message, "%i", overTime[i].timestamp);

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

			sprintf(server_message + strlen(server_message), " %i", thisclient);
		}

		sprintf(server_message + strlen(server_message), "\n");
		swrite(server_message, *sock);
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();
}

void getClientNames(int *sock)
{
	char server_message[SOCKETBUFFERLEN];
	int i;

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

		}
	}

	// Loop over clients to generate output to be sent to the client
	for(i = 0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(insetupVarsArray(clients[i].ip) || insetupVarsArray(clients[i].name))
			continue;

		sprintf(server_message,"%i %i %s %s\n", i, clients[i].count, clients[i].ip, clients[i].name);
		swrite(server_message, *sock);
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();
}

void getUnknownQueries(int *sock)
{
	char server_message[SOCKETBUFFERLEN];

	int i;
	for(i=0; i < counters.queries; i++)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Check if this query has been removed due to garbage collection
		if(queries[i].status != 0 && queries[i].complete) continue;

		char type[5];
		if(queries[i].type == 1)
		{
			strcpy(type,"IPv4");
		}
		else
		{
			strcpy(type,"IPv6");
		}

		validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);

		if(strlen(clients[queries[i].clientID].name) > 0)
			sprintf(server_message,"%i %i %i %s %s %s %i %s\n",queries[i].timestamp,i,queries[i].id,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].name,queries[i].status,queries[i].complete ?"true":"false");
		else
			sprintf(server_message,"%i %i %i %s %s %s %i %s\n",queries[i].timestamp,i,queries[i].id,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].ip,queries[i].status,queries[i].complete?"true":"false");
		swrite(server_message, *sock);
	}

	if(debugclients)
		logg("Sent unknown queries data to client, ID: %i", *sock);
}
