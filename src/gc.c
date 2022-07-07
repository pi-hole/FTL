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
// logg_rate_limit_message()
#include "database/message-table.h"
// get_nprocs()
#include <sys/sysinfo.h>
// get_filepath_usage()
#include "files.h"

// Resource checking interval
// default: 300 seconds
#define RCinterval 300

bool doGC = false;

// Subtract rate-limitation count from individual client counters
// As long as client->rate_limit is still larger than the allowed
// maximum count, the rate-limitation will just continue
static void reset_rate_limiting(void)
{
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		clientsData *client = getClient(clientID, true);
		if(!client)
			continue;

		// Check if we are currently rate-limiting this client
		if(client->flags.rate_limited)
		{
			const char *clientIP = getstr(client->ippos);

			// Check if we want to continue rate limiting
			if(client->rate_limit > config.rate_limit.count)
			{
				logg("Still rate-limiting %s as it made additional %d queries", clientIP, client->rate_limit);
			}
			// or if rate-limiting ends for this client now
			else
			{
				logg("Ending rate-limitation of %s", clientIP);
				client->flags.rate_limited = false;
			}
		}

		// Reset counter
		client->rate_limit = 0;
	}
}

static time_t lastRateLimitCleaner = 0;
// Returns how many more seconds until the current rate-limiting interval is over
time_t get_rate_limit_turnaround(const unsigned int rate_limit_count)
{
	const unsigned int how_often = rate_limit_count/config.rate_limit.count;
	return (time_t)config.rate_limit.interval*how_often - (time(NULL) - lastRateLimitCleaner);
}

static void check_space(const char *file)
{
	if(config.check.disk == 0)
		return;

	int perc = 0;
	char buffer[64] = { 0 };
	// Warn if space usage at the device holding the corresponding file
	// exceeds the configured threshold
	if((perc = get_filepath_usage(file, buffer)) > config.check.disk)
		log_resource_shortage(-1.0, 0, -1, perc, file, buffer);
}

static void check_load(void)
{
	if(!config.check.load)
		return;

	// Get CPU load averages
	double load[3];
	if (getloadavg(load, 3) == -1)
		return;

	// Get number of CPU cores
	const int nprocs = get_nprocs();

	// Warn if 15 minute average of load exceeds number of available
	// processors
	if(load[2] > nprocs)
		log_resource_shortage(load[2], nprocs, -1, -1, NULL, NULL);
}

void *GC_thread(void *val)
{
	// Set thread name
	thread_names[GC] = "housekeeper";
	prctl(PR_SET_NAME, thread_names[GC], 0, 0, 0);

	// Remember when we last ran the actions
	time_t lastGCrun = time(NULL) - time(NULL)%GCinterval;
	lastRateLimitCleaner = time(NULL);
	time_t lastResourceCheck = 0;

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

		// Check available resources
		if(now - lastResourceCheck >= RCinterval)
		{
			check_load();
			check_space(FTLfiles.FTL_db);
			check_space(FTLfiles.log);
			lastResourceCheck = now;
		}

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

			// Align the start time of this GC run to the GCinterval. This will also align with the
			// oldest overTime interval after GC is done.
			mintime -= mintime % GCinterval;

			if(config.debug & DEBUG_GC)
			{
				timer_start(GC_TIMER);
				char timestring[84] = "";
				get_timestr(timestring, mintime, false);
				logg("GC starting, mintime: %s (%llu)", timestring, (long long)mintime);
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
				const int timeidx = getOverTimeID(query->timestamp);
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
					case QUERY_UNKNOWN:
						// Unknown (?)
						break;
					case QUERY_FORWARDED: // (fall through)
					case QUERY_RETRIED: // (fall through)
					case QUERY_RETRIED_DNSSEC:
						// Forwarded to an upstream DNS server
						// Adjusting counters is done below in moveOverTimeMemory()
						break;
					case QUERY_CACHE:
						// Answered from local cache _or_ local config
						break;
					case QUERY_GRAVITY: // Blocked by Pi-hole's blocking lists (fall through)
					case QUERY_BLACKLIST: // Exact blocked (fall through)
					case QUERY_REGEX: // Regex blocked (fall through)
					case QUERY_EXTERNAL_BLOCKED_IP: // Blocked by upstream provider (fall through)
					case QUERY_EXTERNAL_BLOCKED_NXRA: // Blocked by upstream provider (fall through)
					case QUERY_EXTERNAL_BLOCKED_NULL: // Blocked by upstream provider (fall through)
					case QUERY_GRAVITY_CNAME: // Gravity domain in CNAME chain (fall through)
					case QUERY_REGEX_CNAME: // Regex blacklisted domain in CNAME chain (fall through)
					case QUERY_BLACKLIST_CNAME: // Exactly blacklisted domain in CNAME chain (fall through)
					case QUERY_DBBUSY: // Blocked because gravity database was busy
					case QUERY_SPECIAL_DOMAIN: // Blocked by special domain handling
						if(domain != NULL)
							domain->blockedcount--;
						if(client != NULL)
							change_clientcount(client, 0, -1, -1, 0);
						break;
					case QUERY_IN_PROGRESS: // Don't have to do anything here
					case QUERY_STATUS_MAX: // fall through
					default:
						/* That cannot happen */
						break;
				}

				// Update reply counters
				counters->reply[query->reply]--;

				// Update type counters
				if(query->type >= TYPE_A && query->type < TYPE_MAX)
				{
					counters->querytype[query->type-1]--;
				}

				// Set query again to UNKNOWN to reset the counters
				query_set_status(query, QUERY_UNKNOWN);

				// Finally, remove the last trace of this query
				counters->status[QUERY_UNKNOWN]--;

				// Count removed queries
				removed++;
			}

			// Only perform memory operations when we actually removed queries
			if(removed > 0)
			{
				// Move memory forward to keep only what we want
				// Note: for overlapping memory blocks, memmove() is a safer approach than memcpy()
				// Example: (I = now invalid, X = still valid queries, F = free space)
				//   Before: IIIIIIXXXXFF
				//   After:  XXXXFFFFFFFF
				queriesData *dest = getQuery(0, true);
				queriesData *src = getQuery(removed, true);
				if(dest && src)
					memmove(dest, src, (counters->queries - removed)*sizeof(queriesData));

				// Update queries counter
				counters->queries -= removed;
				// Update DB index as total number of queries reduced
				lastdbindex -= removed;

				// ensure remaining memory is zeroed out (marked as "F" in the above example)
				queriesData *tail = getQuery(counters->queries, true);
				if(tail)
					memset(tail, 0, (counters->queries_MAX - counters->queries)*sizeof(queriesData));
			}

			// Determine if overTime memory needs to get moved
			moveOverTimeMemory(mintime);

			if(config.debug & DEBUG_GC)
				logg("Notice: GC removed %i queries (took %.2f ms)", removed, timer_elapsed_msec(GC_TIMER));

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

	logg("Terminating GC thread");
	return NULL;
}
