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
#include "shmem.h"

bool doGC = false;

time_t lastGCrun = 0;
void *GC_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"housekeeper",0,0,0);

	// Save timestamp as we do not want to store immediately
	// to the database
	lastGCrun = time(NULL) - time(NULL)%GCinterval;
	while(!killed)
	{
		if(time(NULL) - GCdelay - lastGCrun >= GCinterval || doGC)
		{
			doGC = false;
			// Update lastGCrun timer
			lastGCrun = time(NULL) - GCdelay - (time(NULL) - GCdelay)%GCinterval;

			// Lock FTL's data structure, since it is likely that it will be changed here
			// Requests should not be processed/answered when data is about to change
			lock_shm();

			// Get minimum time stamp to keep
			time_t mintime = time(NULL) - MAXLOGAGE*360;

			if(debug) timer_start(GC_TIMER);

			long int i;
			int removed = 0;
			if(debug) logg("GC starting, mintime: %u %s", mintime, ctime(&mintime));

			// Process all queries
			for(i=0; i < counters->queries; i++)
			{
				validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
				// Test if this query is too new
				if(queries[i].timestamp > mintime)
					break;

				// Adjust client counter
				int clientID = queries[i].clientID;
				validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);
				clients[clientID].count--;

				// Adjust total counters and total over time data
				int timeidx = queries[i].timeidx;
				overTime[timeidx].total--;
				// Adjust corresponding overTime counters
				clients[clientID].overTime[timeidx]--;

				// Adjust domain counter (no overTime information)
				int domainID = queries[i].domainID;
				validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
				domains[domainID].count--;

				// Change other counters according to status of this query
				switch(queries[i].status)
				{
					case QUERY_UNKNOWN:
						// Unknown (?)
						counters->unknown--;
						break;
					case QUERY_FORWARDED:
						// Forwarded to an upstream DNS server
						counters->forwardedqueries--;
						validate_access("forwarded", queries[i].forwardID, true, __LINE__, __FUNCTION__, __FILE__);
						forwarded[queries[i].forwardID].count--;
						overTime[timeidx].forwarded--;
						break;
					case QUERY_CACHE:
						// Answered from local cache _or_ local config
						counters->cached--;
						overTime[timeidx].cached--;
						break;
					case QUERY_GRAVITY: // Blocked by Pi-hole's blocking lists (fall through)
					case QUERY_BLACKLIST: // Exact blocked (fall through)
					case QUERY_WILDCARD: // Regex blocked (fall through)
					case QUERY_EXTERNAL_BLOCKED: // Blocked by upstream provider (fall through)
						counters->blocked--;
						overTime[timeidx].blocked--;
						domains[domainID].blockedcount--;
						clients[clientID].blockedcount--;
						break;
					default:
						/* That cannot happen */
						break;
				}

				// Update reply counters
				switch(queries[i].reply)
				{
					case REPLY_NODATA: // NODATA(-IPv6)
					counters->reply_NODATA--;
					break;

					case REPLY_NXDOMAIN: // NXDOMAIN
					counters->reply_NXDOMAIN--;
					break;

					case REPLY_CNAME: // <CNAME>
					counters->reply_CNAME--;
					break;

					case REPLY_IP: // valid IP
					counters->reply_IP--;
					break;

					case REPLY_DOMAIN: // reverse lookup
					counters->reply_domain--;
					break;

					default: // Incomplete query or TXT, do nothing
					break;
				}

				// Update type counters
				if(queries[i].type >= TYPE_A && queries[i].type < TYPE_MAX)
				{
					counters->querytype[queries[i].type-1]--;
					overTime[timeidx].querytypedata[queries[i].type-1]--;
				}

				// Count removed queries
				removed++;

			}

			// Move memory forward to keep only what we want
			// Note: for overlapping memory blocks, memmove() is a safer approach than memcpy()
			// Example: (I = now invalid, X = still valid queries, F = free space)
			//   Before: IIIIIIXXXXFF
			//   After:  XXXXFFFFFFFF
			memmove(&queries[0], &queries[removed], (counters->queries - removed)*sizeof(*queries));

			// Update queries counter
			counters->queries -= removed;

			// Zero out remaining memory (marked as "F" in the above example)
			memset(&queries[counters->queries], 0, (counters->queries_MAX - counters->queries)*sizeof(*queries));

			// Determine if overTime memory needs to get moved
			moveOverTimeMemory();

			if(debug) logg("Notice: GC removed %i queries (took %.2f ms)", removed, timer_elapsed_msec(GC_TIMER));

			// Release thread lock
			unlock_shm();

			// After storing data in the database for the next time,
			// we should scan for old entries, which will then be deleted
			// to free up pages in the database and prevent it from growing
			// ever larger and larger
			DBdeleteoldqueries = true;
		}
		sleepms(100);
	}

	return NULL;
}
