/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Garbage collection routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

void *GC_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"GC",0,0,0);

	// Lock FTL's data structure, since it is likely that it will be changed here
	// Requests should not be processed/answered when data is about to change
	enable_thread_lock("GC_thread");

	// Get minimum time stamp to keep
	int differencetofullhour = time(NULL) % GCinterval;
	int mintime = (time(NULL) - GCdelay - differencetofullhour) - MAXLOGAGE;
	if(debugGC)
	{
		time_t timestamp = mintime;
		logg("GC all queries older than: %s", strtok(ctime(&timestamp),"\n"));
	}

	// Process all queries
	long int i;
	int invalidated = 0;
	for(i=0; i < counters.queries; i++)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(queries[i].timestamp < mintime && queries[i].valid)
		{
			// Adjust total counters and total over time data
			// We cannot edit counters.queries directly as it is used
			// as max ID for the queries[] struct
			counters.invalidqueries++;
			validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
			overTime[queries[i].timeidx].total--;

			// Adjust client and domain counters
			validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);
			clients[queries[i].clientID].count--;
			validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
			domains[queries[i].domainID].count--;

			// Change other counters according to status of this query
			switch(queries[i].status)
			{
				case 0:
					// Unknown (?)
					counters.unknown--;
					break;
				case 1:
					// Blocked by Pi-hole's blocking lists
					counters.blocked--;
					validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[queries[i].timeidx].blocked--;
					validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
					domains[queries[i].domainID].blockedcount--;
					break;
				case 2:
					// Forwarded to an upstream DNS server
					counters.forwardedqueries--;
					validate_access("forwarded", queries[i].forwardID, true, __LINE__, __FUNCTION__, __FILE__);
					forwarded[queries[i].forwardID].count--;
					break;
				case 3:
					// Answered from local cache _or_ local config
					counters.cached--;
					validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[queries[i].timeidx].cached--;
					break;
				case 4:
					counters.wildcardblocked--;
					validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[queries[i].timeidx].blocked--;
					validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
					domains[queries[i].domainID].blockedcount--;
					break;
				case 5:
					// Blocked by user's black list
					counters.blocked--;
					validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[queries[i].timeidx].blocked--;
					validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
					domains[queries[i].domainID].blockedcount--;
					break;
				default:
					/* That cannot happen */
					break;
			}

			switch(queries[i].type)
			{
				case 1:
					counters.IPv4--;
					validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[queries[i].timeidx].querytypedata[0]--;
					break;
				case 2:
					counters.IPv6--;
					validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[queries[i].timeidx].querytypedata[1]--;
					break;
				default:
					/* some other query, but neither A nor AAAA */
					break;
			}

			// Remove forwarded data from overTime and total forwarded count
			int j;
			for(j = 0; j < overTime[queries[i].timeidx].forwardnum; j++)
			{
				validate_access("forwarded", j, true, __LINE__, __FUNCTION__, __FILE__);
				validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				forwarded[j].count -= overTime[queries[i].timeidx].forwarddata[j];

				validate_access_oTfd(queries[i].timeidx, j, __LINE__, __FUNCTION__, __FILE__);
				overTime[queries[i].timeidx].forwarddata[j] = 0;
			}

			// Mark this query as garbage collected
			queries[i].valid = false;
			invalidated++;

			if(debugGC)
			{
				time_t timestamp = queries[i].timestamp;
				logg("GC query with time: %s", strtok(ctime(&timestamp),"\n"));
				printf("queries[i = %li] = {timestamp = %i, timeidx = %i, type = %i, status = %i, domainID = %i, clientID = %i, forwardID = %i, valid = false}\n", i, queries[i].timestamp, queries[i].timeidx, queries[i].type, queries[i].status, queries[i].domainID, queries[i].clientID, queries[i].forwardID);
				printf("domains[j = %i] = {count = %i, blockedcount = %i, domain = \"%s\", wildcard = %i}\n", queries[i].domainID, domains[queries[i].domainID].count, domains[queries[i].domainID].blockedcount, domains[queries[i].domainID].domain, domains[queries[i].domainID].wildcard);
				printf("clients[k = %i] = {count = %i, ip = \"%s\", name = \"%s\"}\n", queries[i].clientID, clients[queries[i].clientID].count, clients[queries[i].clientID].ip, clients[queries[i].clientID].name);
				if(queries[i].forwardID > -1)
					printf("forwarded[l = %i] = {count = %i, ip = \"%s\", name = \"%s\"}\n", queries[i].forwardID, forwarded[queries[i].forwardID].count, forwarded[queries[i].forwardID].ip, forwarded[queries[i].forwardID].name);
				printf("\n");
			}
		}
	}

	if(debug)
	{
		logg("Notice: GC removed %i queries", invalidated);
	}

	// Run reresolveHostnames at the end of GC to account for
	// formally unknown and/or changed host names on the network
	reresolveHostnames();

	// Release thread lock
	disable_thread_lock("GC_thread");


	return NULL;
}
