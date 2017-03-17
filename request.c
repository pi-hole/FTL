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

// Private
// int cmpdomains(const void *a, const void *b);
int cmpdomains(int *elem1, int *elem2);
#define min(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })
#define max(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })

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
		float percentage = 0.0;
		// Avoid 1/0 condition
		if(counters.queries > 0)
		{
			percentage = 1e2*counters.blocked/counters.queries;
		}
		sprintf(server_message,"domains_being_blocked %i\ndns_queries_today %i\nads_blocked_today %i\nads_percentage_today %f\n", \
		        counters.gravity,(counters.queries-counters.invalidqueries),counters.blocked+counters.wildcardblocked,percentage);
		swrite(server_message, *sock);
		sprintf(server_message,"unique_domains %i\nqueries_forwarded %i\nqueries_cached %i\n", \
		        counters.domains,counters.forwardedqueries,counters.cached);
		swrite(server_message, *sock);
		if(debugclients)
			logg_int("Sent stats data to client, ID: ", *sock);
	}
	else if(command(client_message, ">overTime"))
	{
		processed = true;
		int i;
		bool sendit = false;
		for(i=0; i < counters.overTime; i++)
		{
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
			logg_int("Sent overTime data to client, ID: ", *sock);
	}
	else if(command(client_message, ">top-domains") || command(client_message, ">top-ads"))
	{
		processed = true;
		int i, temparray[counters.domains][2], count=10, num;
		bool blocked = command(client_message, ">top-ads");

		// Match both top-domains and top-ads
		if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
		{
			// User wants a different number of requests
			count = num;
		}

		for(i=0; i < counters.domains; i++)
		{
			temparray[i][0] = i;
			if(blocked)
				temparray[i][1] = domains[i].blockedcount;
			else
				// Count only permitted queries
				temparray[i][1] = (domains[i].count - domains[i].blockedcount);
		}

		// Sort temporary array
		qsort(temparray, counters.domains, sizeof(int[2]), (__compar_fn_t)cmpdomains);

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
		char * excludedomains = read_setupVarsconf("API_EXCLUDE_DOMAINS");
		if(excludedomains != NULL)
			getSetupVarsArray(excludedomains);


		int skip = 0;
		for(i=0; i < min(counters.domains, count+skip); i++)
		{
			// Get sorted indices
			int j = temparray[counters.domains-i-1][0];

			// Skip this domain if there is a filter on it
			if(excludedomains != NULL)
			{
				if(insetupVarsArray(domains[j].domain))
				{
					skip++;
					continue;
				}
			}

			if(blocked && showblocked && domains[j].blockedcount > 0)
			{
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
				logg_int("Sent top ads list data to client, ID: ", *sock);
			else
				logg_int("Sent top domains list data to client, ID: ", *sock);
		}
	}
	else if(command(client_message, ">top-clients"))
	{
		processed = true;
		int i, temparray[counters.clients][2], count=10, num;

		if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
		{
			// User wants a different number of requests
			count = num;
		}

		for(i=0; i < counters.clients; i++)
		{
			temparray[i][0] = i;
			temparray[i][1] = clients[i].count;
		}

		// Sort temporary array
		qsort(temparray, counters.clients, sizeof(int[2]), (__compar_fn_t)cmpdomains);

		// Get domains which the user doesn't want to see
		char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
		if(excludeclients != NULL)
			getSetupVarsArray(excludeclients);

		int skip = 0;
		for(i=0; i < min(counters.clients, count+skip); i++)
		{
			// Get sorted indices
			int j = temparray[counters.clients-i-1][0];

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
				sprintf(server_message,"%i %i %s %s\n",i,clients[j].count,clients[j].ip,clients[j].name);
				swrite(server_message, *sock);
			}
		}
		if(excludeclients != NULL)
			clearSetupVarsArray();
		if(debugclients)
			logg_int("Sent top clients data to client, ID: ", *sock);
	}
	else if(command(client_message, ">forward-dest"))
	{
		processed = true;
		int i, temparray[counters.forwarded][2];
		for(i=0; i < counters.forwarded; i++)
		{
			temparray[i][0] = i;
			temparray[i][1] = forwarded[i].count;
		}

		// Sort temporary array
		qsort(temparray, counters.forwarded, sizeof(int[2]), (__compar_fn_t)cmpdomains);

		for(i=0; i < min(counters.forwarded, 10); i++)
		{
			// Get sorted indices
			int j = temparray[counters.forwarded-i-1][0];
			if(forwarded[j].count > 0)
			{
				sprintf(server_message,"%i %i %s %s\n",i,forwarded[j].count,forwarded[j].ip,forwarded[j].name);
				swrite(server_message, *sock);
			}
		}
		if(debugclients)
			logg_int("Sent forward destination data to client, ID: ", *sock);
	}
	else if(command(client_message, ">forward-names"))
	{
		processed = true;
		int i;
		for(i=0; i < counters.forwarded; i++)
		{
			// Get sorted indices
			if(forwarded[i].count > 0)
			{
				sprintf(server_message,"%i %i %s %s\n",i,forwarded[i].count,forwarded[i].ip,forwarded[i].name);
				swrite(server_message, *sock);
			}
		}
		if(debugclients)
			logg_int("Sent forward destination names to client, ID: ", *sock);
	}
	else if(command(client_message, ">querytypes"))
	{
		processed = true;
		sprintf(server_message,"A (IPv4): %i\nAAAA (IPv6): %i\n",counters.IPv4,counters.IPv6);
		swrite(server_message, *sock);
		if(debugclients)
			logg_int("Sent query type data to client, ID: ", *sock);
	}
	else if(command(client_message, ">getallqueries"))
	{
		processed = true;
		// Do we want a more specific version of this command (domain/client/time interval filtered)?
		int from = 0, until = 0;
		bool filtertime = false;
		if(command(client_message, ">getallqueries-time"))
		{
			// Get from to until boundaries
			sscanf(client_message, ">getallqueries-time %i %i",&from, &until);
			if(debugclients)
			{
				logg_int("Showing only limited time interval starting at ",from);
				logg_int("Showing only limited time interval ending at ",until);
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
				logg_str("Showing only queries with domain ", domainname);
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
				logg_str("Showing only queries with client ", clientname);
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
				logg_int("Showing only limited amount of queries: ",num);
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
			// Check if this query has been removed due to garbage collection
			if(!queries[i].valid) continue;

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
					sprintf(server_message,"%i %s %s %s %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].name,queries[i].status);
				else
					sprintf(server_message,"%i %s %s %s %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,clients[queries[i].clientID].ip,queries[i].status);
			}
			else
			{
				sprintf(server_message,"%i %s %s hidden %i\n",queries[i].timestamp,type,domains[queries[i].domainID].domain,queries[i].status);
			}
			swrite(server_message, *sock);
		}

		// Free allocated memory
		if(filterclientname)
			free(clientname);
		if(filterdomainname)
			free(domainname);

		if(debugclients)
			logg_int("Sent all queries data to client, ID: ", *sock);
	}
	else if(command(client_message, ">recentBlocked"))
	{
		processed = true;
		int i, num=1;
		// Test for integer that specifies number of entries to be shown
		if(sscanf(client_message, ">%*[^(](%i)", &num) > 0)
		{
			// User wants a different number of requests
			if(num >= counters.queries)
				num = 0;

			if(debugclients)
				logg_int("Showing several blocked domains ",num);
		}
		// Find most recent query with either status 1 (blocked)
		// or status 4 (wildcard blocked)
		int found = 0;
		for(i = counters.queries - 1; i > 0 ; i--)
		{
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
	else if(command(client_message, ">memory"))
	{
		processed = true;
		unsigned long int structbytes = counters.queries_MAX*sizeof(queries) + counters.forwarded_MAX*sizeof(forwarded) + counters.clients_MAX*sizeof(clients) + counters.domains_MAX*sizeof(domains) + counters.overTime_MAX*sizeof(overTime) + (counters.wildcarddomains)*sizeof(wildcarddomains);
		char *structprefix = calloc(2, sizeof(char));
		double formated = 0.0;
		format_memory_size(structprefix, structbytes, &formated);
		sprintf(server_message,"memory allocated for internal data structure: %li bytes (%.2f %sB)\n",structbytes,formated,structprefix);
		swrite(server_message, *sock);
		free(structprefix);

		unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata;
		char *dynamicprefix = calloc(2, sizeof(char));
		format_memory_size(dynamicprefix, dynamicbytes, &formated);
		sprintf(server_message,"dynamically allocated allocated memory used for strings: %li bytes (%.2f %sB)\n",dynamicbytes,formated,dynamicprefix);
		swrite(server_message, *sock);
		free(dynamicprefix);

		int totalbytes = structbytes + dynamicbytes;
		char *totalprefix = calloc(2, sizeof(char));
		format_memory_size(totalprefix, totalbytes, &formated);
		sprintf(server_message,"Sum: %i bytes (%.2f %sB)\n",totalbytes,formated,totalprefix);
		swrite(server_message, *sock);
		free(totalprefix);

		if(debugclients)
			logg_int("Sent memory data to client, ID: ", *sock);
	}
	else if(command(client_message, ">clientID"))
	{
		processed = true;
		sprintf(server_message,"%i\n", *sock);
		swrite(server_message, *sock);

		if(debugclients)
			logg_int("Sent client ID to client, ID: ", *sock);
	}
	else if(command(client_message, ">ForwardedoverTime"))
	{
		processed = true;
		int i, sendit = -1;
		for(i = 0; i < counters.overTime; i++)
		{
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
				sprintf(server_message, "%i", overTime[i].timestamp);

				int j;
				for(j = 0; j < counters.forwarded; j++)
				{
					int k;
					if(j < overTime[i].forwardnum)
						k = overTime[i].forwarddata[j];
					else
						k = 0;

					sprintf(server_message + strlen(server_message), " %i", k);
				}

				sprintf(server_message + strlen(server_message), "\n");
				swrite(server_message, *sock);
			}
		}
		if(debugclients)
			logg_int("Sent overTime forwarded data to client, ID: ", *sock);
	}

	// End of queryable commands
	if(processed)
	{
		// Send EOM
		seom(server_message, *sock);
	}

	// Test only at the end if we want to quit or kill
	// so things can be processed before
	if(command(client_message, ">quit") || command(client_message, EOT))
	{
		processed = true;
		if(debugclients)
			logg_int("Client wants to disconnect, ID: ",*sock);

		close(*sock);
		*sock = 0;
	}
	else if(command(client_message, ">kill"))
	{
		processed = true;
		logg_int("FTL killed by client ID: ",*sock);
		killed = 1;
	}

	if(!processed)
	{
		sprintf(server_message,"unknown command: %s\n",client_message);
		swrite(server_message, *sock);
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

/* qsort comparision function (count field) */
int cmpdomains(int *elem1, int *elem2)
{
	if (elem1[1] < elem2[1])
		return -1;
	else if (elem1[1] > elem2[1])
		return 1;
	else
		return 0;
}
