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
#include "gc.h"
#include "shmem.h"
#include "timers.h"
#include "config.h"
#include "overTime.h"
#include "database/common.h"
#include "log.h"
// global variable killed
#include "signals.h"
// data getter functions
#include "datastructure.h"
// delete_query_from_db()
#include "database/query-table.h"

bool doGC = false;

static void reset_rate_limiting(void)
{
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		clientsData *client = getClient(clientID, true);
		if(client != NULL)
			client->rate_limit = 0;
	}
}

void *GC_thread(void *val)
{
	// Set thread name
	thread_names[GC] = "housekeeper";
	prctl(PR_SET_NAME, thread_names[GC], 0, 0, 0);

	// Remember when we last ran the actions
	time_t lastGCrun = time(NULL) - time(NULL)%GCinterval;
	time_t lastRateLimitCleaner = time(NULL);

	// Run as long as this thread is not canceled
	while(!killed)
	{
		const time_t now = time(NULL);
		if((unsigned int)(now - lastRateLimitCleaner) >= config.rate_limit.interval)
		{
			lastRateLimitCleaner = now;
			lock_shm();
			reset_rate_limiting();
			unlock_shm();
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		if(now - GCdelay - lastGCrun >= GCinterval || doGC)
		{
			doGC = false;
			// Update lastGCrun timer
			lastGCrun = now - GCdelay - (now - GCdelay)%GCinterval;

			// Lock FTL's data structure, since it is likely that it will be changed here
			// Requests should not be processed/answered when data is about to change
			lock_shm();

			// Get minimum timestamp to keep (this can be set with MAXLOGAGE)
			time_t mintime = (now - GCdelay) - config.maxlogage;

			// Align to the start of the next hour. This will also align with
			// the oldest overTime interval after GC is done.
			mintime -= mintime % 3600;
			mintime += 3600;

			if(config.debug & DEBUG_GC)
			{
				timer_start(GC_TIMER);
				char timestring[84] = "";
				get_timestr(timestring, mintime, false);
				log_info("GC starting, mintime: %s (%llu)", timestring, (long long)mintime);
			}

			// Process all queries
			int removed = 0;
			for(long int i=0; i < counters->queries; i++)
			{
				queriesData* query = getQuery(i, true);
				if(query == NULL)
					continue;

				// Test if this query is too new
				if(query->timestamp > mintime)
					break;

				// Adjust client counter (total and overTime)
				clientsData* client = getClient(query->clientID, true);
				const int timeidx = query->timeidx;
				overTime[timeidx].total--;
				if(client != NULL)
					change_clientcount(client, -1, 0, timeidx, -1);

				// Adjust domain counter (no overTime information)
				domainsData* domain = getDomain(query->domainID, true);
				if(domain != NULL)
					domain->count--;

				// Get upstream pointer

				// Change other counters according to status of this query
				switch(query->status)
				{
					case STATUS_UNKNOWN:
						// Unknown (?)
						break;
					case STATUS_FORWARDED: // (fall through)
					case STATUS_RETRIED: // (fall through)
					case STATUS_RETRIED_DNSSEC:
						// Forwarded to an upstream DNS server
						// Adjust counters
						if(query->upstreamID > -1)
						{
							upstreamsData* upstream = getUpstream(query->upstreamID, true);
							if(upstream != NULL)
								upstream->count--;
						}
						break;
					case STATUS_CACHE:
						// Answered from local cache _or_ local config
						break;
					case STATUS_GRAVITY: // Blocked by Pi-hole's blocking lists (fall through)
					case STATUS_DENYLIST: // Exact blocked (fall through)
					case STATUS_REGEX: // Regex blocked (fall through)
					case STATUS_EXTERNAL_BLOCKED_IP: // Blocked by upstream provider (fall through)
					case STATUS_EXTERNAL_BLOCKED_NXRA: // Blocked by upstream provider (fall through)
					case STATUS_EXTERNAL_BLOCKED_NULL: // Blocked by upstream provider (fall through)
					case STATUS_GRAVITY_CNAME: // Gravity domain in CNAME chain (fall through)
					case STATUS_DENYLIST_CNAME: // Exactly denied domain in CNAME chain (fall through)
					case STATUS_REGEX_CNAME: // Regex denied domain in CNAME chain (fall through)
						//counters->blocked--;
						overTime[timeidx].blocked--;
						if(domain != NULL)
							domain->blockedcount--;
						if(client != NULL)
							change_clientcount(client, 0, -1, -1, 0);
						break;
					case STATUS_IN_PROGRESS: // Don't have to do anything here
					case STATUS_MAX: // fall through
					default:
						/* That cannot happen */
						break;
				}

				// Update reply counters
				counters->reply[query->reply]--;

				// Update type counters
				if(query->type < TYPE_MAX)
					counters->querytype[query->type]--;

				// Subtract UNKNOWN from the counters before
				// setting the status if different. This ensure
				// we are not counting them at all.
				if(query->status != STATUS_UNKNOWN)
					counters->status[STATUS_UNKNOWN]--;

				// Set query again to UNKNOWN to reset the counters
				query_set_status(query, STATUS_UNKNOWN);

				// Count removed queries
				removed++;

				// Remove query from queries table (temp), we
				// can release the lock for this action to
				// prevent blocking the DNS service too long
				unlock_shm();
				delete_query_from_db(query->db);
				lock_shm();
			}

			// Only perform memory operations when we actually removed queries
			if(removed > 0)
			{
				// Move memory forward to keep only what we want
				// Note: for overlapping memory blocks, memmove() is a safer approach than memcpy()
				// Example: (I = now invalid, X = still valid queries, F = free space)
				//   Before: IIIIIIXXXXFF
				//   After:  XXXXFFFFFFFF
				memmove(getQuery(0, true), getQuery(removed, true), (counters->queries - removed)*sizeof(queriesData));

				// Update queries counter
				counters->queries -= removed;

				// ensure remaining memory is zeroed out (marked as "F" in the above example)
				memset(getQuery(counters->queries, true), 0, (counters->queries_MAX - counters->queries)*sizeof(queriesData));
			}

			// Determine if overTime memory needs to get moved
			moveOverTimeMemory(mintime);

			log_debug(DEBUG_GC, "GC removed %i queries (took %.2f ms)", removed, timer_elapsed_msec(GC_TIMER));

			// Release thread lock
			unlock_shm();

			// After storing data in the database for the next time,
			// we should scan for old entries, which will then be deleted
			// to free up pages in the database and prevent it from growing
			// ever larger and larger
			DBdeleteoldqueries = true;
		}
		thread_sleepms(GC, 1000);
	}

	log_info("Terminating GC thread");
	return NULL;
}
