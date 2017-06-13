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
void getStats(int *sock, char type);
void getOverTime(int *sock, char type);
void getTopDomains (char *client_message, int *sock, char type);
void getTopClients(char *client_message, int *sock, char type);
void getForwardDestinations(int *sock, char type);
void getForwardNames(int *sock, char type);
void getQueryTypes(int *sock, char type);
void getAllQueries(char *client_message, int *sock, char type);
void getRecentBlocked(char *client_message, int *sock, char type);
void getMemoryUsage(int *sock, char type);
void getForwardDestinationsOverTime(int *sock, char type);
void getClientID(int *sock, char type);
void getQueryTypesOverTime(int *sock, char type);
void getVersion(int *sock, char type);
void getDBstats(int *sock, char type);

void process_socket_request(char *client_message, int *sock)
{
	char EOT[2];
	EOT[0] = 0x04;
	EOT[1] = 0x00;
	bool processed = false;
	char type = SOCKET;

	if(command(client_message, ">stats"))
	{
		processed = true;
		getStats(sock, type);
	}
	else if(command(client_message, ">overTime"))
	{
		processed = true;
		getOverTime(sock, type);
	}
	else if(command(client_message, ">top-domains") || command(client_message, ">top-ads"))
	{
		processed = true;
		getTopDomains(client_message, sock, type);
	}
	else if(command(client_message, ">top-clients"))
	{
		processed = true;
		getTopClients(client_message, sock, type);
	}
	else if(command(client_message, ">forward-dest"))
	{
		processed = true;
		getForwardDestinations(sock, type);
	}
	else if(command(client_message, ">forward-names"))
	{
		processed = true;
		getForwardNames(sock, type);
	}
	else if(command(client_message, ">querytypes"))
	{
		processed = true;
		getQueryTypes(sock, type);
	}
	else if(command(client_message, ">getallqueries"))
	{
		processed = true;
		getAllQueries(client_message, sock, type);
	}
	else if(command(client_message, ">recentBlocked"))
	{
		processed = true;
		getRecentBlocked(client_message, sock, type);
	}
	else if(command(client_message, ">memory"))
	{
		processed = true;
		getMemoryUsage(sock, type);
	}
	else if(command(client_message, ">clientID"))
	{
		processed = true;
		getClientID(sock, type);
	}
	else if(command(client_message, ">ForwardedoverTime"))
	{
		processed = true;
		getForwardDestinationsOverTime(sock, type);
	}
	else if(command(client_message, ">QueryTypesoverTime"))
	{
		processed = true;
		getQueryTypesOverTime(sock, type);
	}
	else if(command(client_message, ">version"))
	{
		processed = true;
		getVersion(sock, type);
	}
	else if(command(client_message, ">dbstats"))
	{
		processed = true;
		getDBstats(sock, type);
	}

	// End of queryable commands
	if(processed)
	{
		// Send EOM
		seom(*sock);
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
		logg("FTL killed by client ID: %i",*sock);
		killed = 1;
	}

	if(!processed)
	{
		ssend(*sock,"unknown command: %s\n",client_message);
	}
}

void process_api_request(char *client_message, int *sock, bool header)
{
	char type;
	if(header)
		type = APIH;
	else
		type = API;

	if(command(client_message, "GET /stats/summary"))
	{
		getStats(sock, type);
	}
	else if(command(client_message, "GET /stats/overTime"))
	{
		getOverTime(sock, type);
	}
	else if(command(client_message, "GET /stats/top_domains") || command(client_message, "GET /stats/top_ads"))
	{
		getTopDomains(client_message, sock, type);
	}
	else if(header)
	{
		ssend(*sock,
		      "HTTP/1.0 404 Not Found\nServer: FTL\nCache-Control: no-cache\n"
		      "Content-Type: application/json\nContent-Length: 21\n\n{status: \"not_found\"}");
	}
}

bool command(char *client_message, const char* cmd)
{
	if(strstr(client_message,cmd) != NULL)
		return true;
	else
		return false;
}

void sendAPIResponse(int sock, char *content, char type) {
	if(type == APIH && strlen(content) > 0)
	{
		// Send header and payload
		ssend(sock,
		      "HTTP/1.0 200 OK\nServer: FTL\nCache-Control: no-cache\n"
		      "Content-Type: application/json\nContent-Length: %i\n\n%s",
		      strlen(content),
		      content);
	}
	else if(type == APIH)
	{
		// Send only header (length of content is not yet known and will be sent out in smaller packets)
		ssend(sock,
		      "HTTP/1.0 200 OK\nServer: FTL\nCache-Control: no-cache\n"
		      "Content-Type: application/json\n\n");
	}
	else
	{
		// Simple request: Don't send header, only payload
		ssend(sock,"%s",content);
	}
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

void getStats(int *sock, char type)
{
	int blocked = counters.blocked + counters.wildcardblocked;
	int total = counters.queries - counters.invalidqueries;
	float percentage = 0.0;
	// Avoid 1/0 condition
	if(total > 0)
	{
		percentage = 1e2*blocked/total;
	}

	if(type == SOCKET) {
		ssend(*sock, "domains_being_blocked %i\ndns_queries_today %i\nads_blocked_today %i\nads_percentage_today %f\n", \
		    counters.gravity, total, blocked, percentage);
		ssend(*sock, "unique_domains %i\nqueries_forwarded %i\nqueries_cached %i\n", \
		    counters.domains, counters.forwardedqueries, counters.cached);
	}
	else
	{
		char *sendbuffer;
		int ret = asprintf(&sendbuffer, "{\"domains_being_blocked\":%i,\"dns_queries_today\":%i,\"ads_blocked_today\":%i,\"ads_percentage_today\":%.4f,\"unique_domains\":%i,\"queries_forwarded\":%i,\"queries_cached\":%i}",counters.gravity,total, blocked, percentage,counters.domains,counters.forwardedqueries,counters.cached);
		if(ret > 0)
			sendAPIResponse(*sock, sendbuffer, type);
		else
			logg("Error allocating memory for API response (getStats)");
		free(sendbuffer);
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
		sendAPIResponse(*sock, "", type);
		ssend(*sock,"{\"domains_over_time\":{");

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
		ssend(*sock,"}}");
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
	// API:    /top/domains?limit=15
	if(sscanf(client_message, "%*[^0123456789H\n]%i", &num) > 0)
	{
		// User wants a different number of requests
		count = num;
	}

	// Apply Audit Log filtering?
	// SOCKET: >top-domains for audit
	// API:    /top/domains?audit
	if(type == SOCKET && command(client_message, " for audit"))
	{
		audit = true;
	}
	else if(type != SOCKET && command(client_message, "audit"))
	{
		audit = true;
	}

	// Sort in descending order?
	// SOCKET: >top-domains desc
	// API:    /top/domains?order=desc
	if(type == SOCKET && command(client_message, " desc"))
	{
		desc = true;
	}
	else if(type != SOCKET && command(client_message, "desc"))
	{
		audit = true;
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

	if(type != SOCKET)
	{// First send header with unspecified content-length outside of the for-loop
		sendAPIResponse(*sock, "", type);
		if(blocked)
			ssend(*sock, "{\"top_ads\":{");
		else
			ssend(*sock, "{\"top_queries\":{");
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
		ssend(*sock,"}}");

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

	if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
	{
		// User wants a different number of requests
		count = num;
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

		if(clients[j].count > 0)
		{
			ssend(*sock,"%i %i %s %s\n",i,clients[j].count,clients[j].ip,clients[j].name);
		}
	}
	if(excludeclients != NULL)
		clearSetupVarsArray();
	if(debugclients)
		logg("Sent top clients data to client, ID: %i", *sock);
}


void getForwardDestinations(int *sock, char type)
{
	bool allocated = false;
	int i, temparray[counters.forwarded+1][2];
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

	// Loop over available forward destinations
	for(i=0; i < min(counters.forwarded+1, 10); i++)
	{
		char *name, *ip;
		int count;

		// Get sorted indices
		int j = temparray[i][0];

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
			ssend(*sock,"%i %i %s %s\n",i,count,ip,name);
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


void getForwardNames(int *sock, char type)
{
	int i;

	for(i=0; i < counters.forwarded; i++)
	{
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Get sorted indices
		ssend(*sock,"%i %i %s %s\n",i,forwarded[i].count,forwarded[i].ip,forwarded[i].name);
	}

	// Add "local" forward destination
	ssend(*sock,"%i %i ::1 local\n",counters.forwarded,counters.cached);

	if(debugclients)
		logg("Sent forward destination names to client, ID: %i", *sock);
}


void getQueryTypes(int *sock, char type)
{

	ssend(*sock,"A (IPv4): %i\nAAAA (IPv6): %i\n",counters.IPv4,counters.IPv6);
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
				ssend(*sock,"%i %s %s %s %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].name,queries[i].status);
			else
				ssend(*sock,"%i %s %s %s %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].ip,queries[i].status);
		}
		else
		{
			ssend(*sock,"%i %s %s hidden %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,queries[i].status);
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

void getRecentBlocked(char *client_message, int *sock, char type)
{
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
			ssend(*sock,"%s\n",domains[queries[i].domainID].domain);
		}

		if(found >= num)
		{
			break;
		}
	}
}

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
	if(sendit > -1)
	{
		for(i = sendit; i < counters.overTime; i++)
		{
			validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
			ssend(*sock, "%i", overTime[i].timestamp);

			int j;

			for(j = 0; j < counters.forwarded; j++)
			{
				int k;
				if(j < overTime[i].forwardnum)
					k = overTime[i].forwarddata[j];
				else
					k = 0;

				ssend(*sock, " %i", k);
			}

			ssend(*sock, " %i\n", overTime[i].cached + overTime[i].blocked);
		}
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
	if(sendit > -1)
	{
		for(i = sendit; i < counters.overTime; i++)
		{
			validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
			ssend(*sock, "%i %i %i\n", overTime[i].timestamp,overTime[i].querytypedata[0],overTime[i].querytypedata[1]);
		}
	}
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
