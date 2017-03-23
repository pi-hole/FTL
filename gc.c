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
	enable_read_write_lock("GC_thread");

	// Get minimum time stamp to keep
	int mintime = time(NULL) - GCdelay - MAXLOGAGE;
	if(debugGC)
	{
		time_t timestamp = mintime;
		logg_str("GC all queries older than: ", strtok(ctime(&timestamp),"\n"));
	}

	// Process all queries
	int i;
	for(i=0; i < counters.queries; i++)
	{
		if(queries[i].timestamp < mintime && queries[i].valid)
		{
			// Adjust total counters and total over time data
			// We cannot edit counters.queries directly as it is used
			// as max ID for the queries[] struct
			counters.invalidqueries++;
			overTime[queries[i].timeidx].total--;

			// Adjust client and domain counters
			clients[queries[i].clientID].count--;
			domains[queries[i].domainID].count--;

			// Change other counters according to status of this query
			switch(queries[i].status)
			{
				case 0: counters.unknown--; break;
				case 1: counters.blocked--; overTime[queries[i].timeidx].blocked--; domains[queries[i].domainID].blockedcount--; break;
				case 2: counters.forwardedqueries--; forwarded[queries[i].forwardID].count--; break;
				case 3: counters.cached--; break;
				case 4: counters.wildcardblocked--; overTime[queries[i].timeidx].blocked--; break;
				default: /* That cannot happen */ break;
			}

			switch(queries[i].type)
			{
				case 1: counters.IPv4--; break;
				case 2: counters.IPv6--; break;
				default: logg_int("ERROR in GC, found type ",queries[i].type); break;
			}

			// Remove forwarded data from overTime and total forwarded count
			int j;
			for(j = 0; j < overTime[queries[i].timeidx].forwardnum; j++)
			{
				forwarded[j].count -= overTime[queries[i].timeidx].forwarddata[j];
				overTime[queries[i].timeidx].forwarddata[j] = 0;
			}

			// Mark this query as garbage collected
			queries[i].valid = false;

			if(debugGC)
			{
				time_t timestamp = queries[i].timestamp;
				logg_str("GC query with time: ", strtok(ctime(&timestamp),"\n"));
				printf("queries[i = %i] = {timestamp = %i, timeidx = %i, type = %i, status = %i, domainID = %i, clientID = %i, forwardID = %i, valid = false}\n", i, queries[i].timestamp, queries[i].timeidx, queries[i].type, queries[i].status, queries[i].domainID, queries[i].clientID, queries[i].forwardID);
				printf("domains[j = %i] = {count = %i, blockedcount = %i, domain = \"%s\", wildcard = %i}\n", queries[i].domainID, domains[queries[i].domainID].count, domains[queries[i].domainID].blockedcount, domains[queries[i].domainID].domain, domains[queries[i].domainID].wildcard);
				printf("clients[k = %i] = {count = %i, ip = \"%s\", name = \"%s\"}\n", queries[i].clientID, clients[queries[i].clientID].count, clients[queries[i].clientID].ip, clients[queries[i].clientID].name);
				if(queries[i].forwardID > -1)
					printf("forwarded[l = %i] = {count = %i, ip = \"%s\", name = \"%s\"}\n", queries[i].forwardID, forwarded[queries[i].forwardID].count, forwarded[queries[i].forwardID].ip, forwarded[queries[i].forwardID].name);
				printf("\n");
			}
		}
	}

	if(debugGC)
	{
		logg_int("GC queries: ", counters.invalidqueries);
	}

	// Release thread lock
	disable_thread_locks("GC_thread");


	return NULL;
}
