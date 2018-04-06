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
bool doGC = false;

int lastGCrun = 0;
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
			enable_thread_lock();

			// Get minimum time stamp to keep
			time_t mintime = time(NULL) - config.maxlogage;

			if(debug) timer_start(GC_TIMER);

			long int i;
			int removed = 0;
			if(debug) logg("GC starting, mintime: %u %s", mintime, ctime(&mintime));

			// Process all queries
			for(i=0; i < counters.queries; i++)
			{
				validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
				// Test if this query is too new
				if(queries[i].timestamp > mintime)
					break;


				// Adjust total counters and total over time data
				// We cannot edit counters.queries directly as it is used
				// as max ID for the queries[] struct
				validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[queries[i].timeidx].total--;

				// Adjust client and corresponding overTime counters
				validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);
				clients[queries[i].clientID].count--;
				validate_access_oTcl(queries[i].timeidx, queries[i].clientID, __LINE__, __FUNCTION__, __FILE__);
				overTime[queries[i].timeidx].clientdata[queries[i].clientID]--;

				// Adjust domain counter (no overTime information)
				validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
				domains[queries[i].domainID].count--;

				// Change other counters according to status of this query
				switch(queries[i].status)
				{
					case QUERY_UNKNOWN:
						// Unknown (?)
						counters.unknown--;
						break;
					case QUERY_GRAVITY:
						// Blocked by Pi-hole's blocking lists
						counters.blocked--;
						validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
						overTime[queries[i].timeidx].blocked--;
						validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
						domains[queries[i].domainID].blockedcount--;
						break;
					case QUERY_FORWARDED:
						// Forwarded to an upstream DNS server
						counters.forwardedqueries--;
						validate_access("forwarded", queries[i].forwardID, true, __LINE__, __FUNCTION__, __FILE__);
						forwarded[queries[i].forwardID].count--;
						// Maybe we have to adjust total counters depending on the reply type
						break;
					case QUERY_CACHE:
						// Answered from local cache _or_ local config
						counters.cached--;
						validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
						overTime[queries[i].timeidx].cached--;
						break;
					case QUERY_WILDCARD:
						counters.wildcardblocked--;
						validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
						overTime[queries[i].timeidx].blocked--;
						validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
						domains[queries[i].domainID].blockedcount--;
						break;
					case QUERY_BLACKLIST:
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

				// Update reply counters
				switch(queries[i].reply)
				{
					case REPLY_NODATA: // NODATA(-IPv6)
					counters.reply_NODATA--;
					break;

					case REPLY_NXDOMAIN: // NXDOMAIN
					counters.reply_NXDOMAIN--;
					break;

					case REPLY_CNAME: // <CNAME>
					counters.reply_CNAME--;
					break;

					case REPLY_IP: // valid IP
					counters.reply_IP--;
					break;

					default: // Incomplete query, do nothing
					break;
				}

				// Update type counters
				if(queries[i].type >= TYPE_A && queries[i].type < TYPE_MAX)
				{
					counters.querytype[queries[i].type-1]--;
					validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[queries[i].timeidx].querytypedata[queries[i].type-1]--;
				}

				// Count removed queries
				removed++;

			}

			// Move memory forward to keep only what we want
			// Note: for overlapping memory blocks, memmove() is a safer approach than memcpy()
			// Example: (I = now invalid, X = still valid queries, F = free space)
			//   Before: IIIIIIXXXXFF
			//   After:  XXXXFFFFFFFF
			memmove(&queries[0], &queries[removed], (counters.queries - removed)*sizeof(*queries));

			// Update queries counter
			counters.queries -= removed;

			// Zero out remaining memory (marked as "F" in the above example)
			memset(&queries[counters.queries], 0, (counters.queries_MAX - counters.queries)*sizeof(*queries));

			if(debug) logg("Notice: GC removed %i queries (took %.2f ms)", removed, timer_elapsed_msec(GC_TIMER));

			// Release thread lock
			disable_thread_lock();
		}
		sleepms(100);
	}

	return NULL;
}
