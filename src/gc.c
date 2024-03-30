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
#include "config/config.h"
#include "overTime.h"
#include "database/common.h"
#include "log.h"
// global variable killed
#include "signals.h"
// data getter functions
#include "datastructure.h"
// delete_old_queries_from_db()
#include "database/query-table.h"
// logg_rate_limit_message()
#include "database/message-table.h"
// get_nprocs()
#include <sys/sysinfo.h>
// get_path_usage()
#include "files.h"
// void calc_cpu_usage()
#include "daemon.h"
// create_inotify_watcher()
#include "config/inotify.h"

// Resource checking interval
// default: 300 seconds
#define RCinterval 300

// CPU usage calculation interval
// default: 10 seconds
#define CPU_AVERAGE_INTERVAL 10

bool doGC = false;

// Recycle old clients and domains in our internal data structure
// This has the side-effect of recycling intermediate domains
// seen during CNAME inspection, too, as they are never referenced
// by any query (only head and tail of the CNAME chain are)
static void recycle(void)
{
	bool *client_used = calloc(counters->clients, sizeof(bool));
	bool *domain_used = calloc(counters->domains, sizeof(bool));
	bool *cache_used = calloc(counters->dns_cache_size, sizeof(bool));
	if(client_used == NULL || domain_used == NULL || cache_used == NULL)
	{
		log_err("Cannot allocate memory for recycling");
		return;
	}

	// Find list of client and domain IDs no active query is referencing anymore
	// and recycle them
	for(int queryID = 0; queryID < counters->queries; queryID++)
	{
		queriesData* query = getQuery(queryID, true);
		if(query == NULL)
			continue;

		// Mark client and domain as used
		client_used[query->clientID] = true;
		domain_used[query->domainID] = true;

		// Mark CNAME domain as used (if any)
		if(query->CNAME_domainID > -1)
			domain_used[query->CNAME_domainID] = true;

		// Mark cache entry as used (if any)
		if(query->cacheID > -1)
			cache_used[query->cacheID] = true;
	}

	// Recycle clients
	unsigned int clients_recycled = 0;
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		if(client_used[clientID])
			continue;

		clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		// Never recycle aliasclients (they are not counted above but
		// are only indirectly referenced by other clients)
		if(client->flags.aliasclient)
			continue;

		log_debug(DEBUG_GC, "Recycling client %s (ID %d, lastQuery at %.3f)",
		          getstr(client->ippos), clientID, client->lastQuery);

		// Wipe client's memory
		memset(client, 0, sizeof(clientsData));

		clients_recycled++;
	}

	// Recycle domains
	unsigned int domains_recycled = 0;
	for(int domainID = 0; domainID < counters->domains; domainID++)
	{
		if(domain_used[domainID])
			continue;

		domainsData* domain = getDomain(domainID, true);
		if(domain == NULL)
			continue;

		log_debug(DEBUG_GC, "Recycling domain %s (ID %d, lastQuery at %.3f)",
		          getstr(domain->domainpos), domainID, domain->lastQuery);

		// Wipe domain's memory
		memset(domain, 0, sizeof(domainsData));

		domains_recycled++;
	}

	// Recycle cache records
	unsigned int cache_recycled = 0;
	for(int cacheID = 0; cacheID < counters->dns_cache_size; cacheID++)
	{
		if(cache_used[cacheID])
			continue;

		DNSCacheData *cache = getDNSCache(cacheID, true);
		if(cache == NULL)
			continue;

		log_debug(DEBUG_GC, "Recycling cache entry with ID %d", cacheID);

		// Wipe cache entry's memory
		memset(cache, 0, sizeof(DNSCacheData));

		cache_recycled++;
	}

	// Free memory
	free(client_used);
	free(domain_used);
	free(cache_used);

	// Scan number of recycled clients and domains if in debug mode
	if(config.debug.gc.v.b)
	{
		unsigned int free_domains = 0, free_clients = 0, free_cache = 0;
		for(int clientID = 0; clientID < counters->clients; clientID++)
		{
			// Do not check magic to avoid skipping recycled clients
			clientsData *client = getClient(clientID, false);
			if(client == NULL)
				continue;
			if(client->magic == 0x00)
				free_clients++;
		}
		for(int domainID = 0; domainID < counters->domains; domainID++)
		{
			// Do not check magic to avoid skipping recycled domains
			domainsData *domain = getDomain(domainID, false);
			if(domain == NULL)
				continue;
			if(domain->magic == 0x00)
				free_domains++;
		}
		for(int cacheID = 0; cacheID < counters->dns_cache_size; cacheID++)
		{
			// Do not check magic to avoid skipping recycled cache entries
			DNSCacheData *cache = getDNSCache(cacheID, false);
			if(cache == NULL)
				continue;
			if(cache->magic == 0x00)
				free_cache++;
		}

		log_debug(DEBUG_GC, "%d/%d clients, %d/%d domains and %d/%d cache records are free",
		          counters->clients_MAX + (int)free_clients - counters->clients, counters->clients_MAX,
		          counters->domains_MAX + (int)free_domains - counters->domains_MAX, counters->domains_MAX,
		          counters->dns_cache_MAX + (int)free_cache - counters->dns_cache_MAX, counters->dns_cache_MAX);

		log_debug(DEBUG_GC, "Recycled additional %u clients, %u domains, and %u cache records (scanned %d queries)",
		          clients_recycled, domains_recycled, cache_recycled, counters->queries);
	}
}

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
			if(client->rate_limit > config.dns.rateLimit.count.v.ui)
			{
				log_info("Still rate-limiting %s as it made additional %u queries", clientIP, client->rate_limit);
			}
			// or if rate-limiting ends for this client now
			else
			{
				log_info("Ending rate-limitation of %s", clientIP);
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
	const unsigned int how_often = rate_limit_count/config.dns.rateLimit.count.v.ui;
	return (time_t)config.dns.rateLimit.interval.v.ui*how_often - (time(NULL) - lastRateLimitCleaner);
}

static int check_space(const char *file, unsigned int LastUsage)
{
	if(config.misc.check.disk.v.ui == 0)
		return 0;

	unsigned int perc = 0;
	char buffer[64] = { 0 };
	// Warn if space usage at the device holding the corresponding file
	// exceeds the configured threshold and current usage is higher than
	// usage in the last run (to prevent log spam)
	perc = get_path_usage(file, buffer);
	log_debug(DEBUG_GC, "Checking free space at %s: %u%% %s %u%%", file, perc,
	          perc > config.misc.check.disk.v.ui ? ">" : "<=",
	          config.misc.check.disk.v.ui);
	if(perc > config.misc.check.disk.v.ui && perc > LastUsage && perc <= 100.0)
		log_resource_shortage(-1.0, 0, -1, perc, file, buffer);

	return perc;
}

static void check_load(void)
{
	if(!config.misc.check.load.v.b)
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

void runGC(const time_t now, time_t *lastGCrun, const bool flush)
{
	doGC = false;
	// Update lastGCrun timer
	if(lastGCrun != NULL)
		*lastGCrun = now - GCdelay - (now - GCdelay)%GCinterval;

	// Lock FTL's data structure, since it is likely that it will be changed here
	// Requests should not be processed/answered when data is about to change
	if(!flush)
		lock_shm();

	// Get minimum timestamp to keep
	time_t mintime = now;
	if(!flush)
	{
		// Normal GC run
		mintime -= GCdelay + config.webserver.api.maxHistory.v.ui;

		// Align the start time of this GC run to the GCinterval. This will also align with the
		// oldest overTime interval after GC is done.
		mintime -= mintime % GCinterval;
	}

	if(config.debug.gc.v.b)
	{
		timer_start(GC_TIMER);
		char timestring[TIMESTR_SIZE] = "";
		get_timestr(timestring, mintime, false, false);
		log_debug(DEBUG_GC, "GC starting, mintime: %s (%lu), counters->queries = %d",
		          timestring, (unsigned long)mintime, counters->queries);
	}

	// Process all queries
	unsigned int removed = 0;
	for(long int i = 0; i < counters->queries; i++)
	{
		queriesData* query = getQuery(i, true);
		if(query == NULL)
			continue;

		// Test if this query is too new
		if(query->timestamp > mintime)
			break;

		// Adjust client counter (total and overTime)
		const int timeidx = getOverTimeID(query->timestamp);
		clientsData* client = getClient(query->clientID, true);
		if(client != NULL)
			change_clientcount(client, -1, 0, timeidx, -1);

		// Adjust domain counter (no overTime information)
		domainsData *domain = getDomain(query->domainID, true);
		if(domain != NULL)
			domain->count--;

		// Adjust upstream counter (no overTime information)
		upstreamsData *upstream = getUpstream(query->upstreamID, true);
		if(upstream != NULL)
			// Adjust upstream counter
			upstream->count--;

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
				break;
			case QUERY_CACHE:
			case QUERY_CACHE_STALE:
				// Answered from local cache _or_ local config
				break;
			case QUERY_GRAVITY: // Blocked by Pi-hole's blocking lists (fall through)
			case QUERY_DENYLIST: // Exact blocked (fall through)
			case QUERY_REGEX: // Regex blocked (fall through)
			case QUERY_EXTERNAL_BLOCKED_IP: // Blocked by upstream provider (fall through)
			case QUERY_EXTERNAL_BLOCKED_NXRA: // Blocked by upstream provider (fall through)
			case QUERY_EXTERNAL_BLOCKED_NULL: // Blocked by upstream provider (fall through)
			case QUERY_GRAVITY_CNAME: // Gravity domain in CNAME chain (fall through)
			case QUERY_REGEX_CNAME: // Regex denied domain in CNAME chain (fall through)
			case QUERY_DENYLIST_CNAME: // Exactly denied domain in CNAME chain (fall through)
			case QUERY_DBBUSY: // Blocked because gravity database was busy
			case QUERY_SPECIAL_DOMAIN: // Blocked by special domain handling
				overTime[timeidx].blocked--;
				if(domain != NULL)
					domain->blockedcount--;
				if(client != NULL)
					change_clientcount(client, 0, -1, -1, 0);
				break;
			case QUERY_IN_PROGRESS: // fall through
			case QUERY_STATUS_MAX: // fall through
			default:
				// Don't have to do anything here
				break;
		}

		// Update reply counters
		counters->reply[query->reply]--;
		log_debug(DEBUG_STATUS, "reply type %d removed (GC), ID = %d, new count = %d", query->reply, query->id, counters->reply[query->reply]);

		// Update type counters
		counters->querytype[query->type]--;
		log_debug(DEBUG_STATUS, "query type %d removed (GC), ID = %d, new count = %d", query->type, query->id, counters->querytype[query->type]);

		// Subtract UNKNOWN from the counters before
		// setting the status if different.
		// Minus one here and plus one below = net zero
		counters->status[QUERY_UNKNOWN]--;
		log_debug(DEBUG_STATUS, "status %d removed (GC), ID = %d, new count = %d", QUERY_UNKNOWN, query->id, counters->status[QUERY_UNKNOWN]);

		// Set query again to UNKNOWN to reset the counters
		query_set_status(query, QUERY_UNKNOWN);

		// Count removed queries
		removed++;
	}

	// Remove query from queries table (temp), we can release the lock for this
	// action to prevent blocking the DNS service too long
	if(!flush)
		unlock_shm();
	delete_old_queries_from_db(true, mintime);
	if(!flush)
		lock_shm();

	// Only perform memory operations when we actually removed queries
	if(removed > 0)
	{
		// Move memory forward to keep only what we want
		// Note: for overlapping memory blocks, memmove() is a safer approach than memcpy()
		//
		//  ┌──────────────────────┐
		//  │ Example: removed = 5 │▒
		//  │                      │▒
		//  │ query with ID = 6    │▒
		//  │ is moved to ID = 0,  │▒
		//  │ 7 ─> 1, 8 ─> 2, etc. │▒
		//  │                      │▒
		//  │ ID:         111111   │▒
		//  │   0123456789012345   │▒
		//  │                      │▒
		//  │   ......QQQQ------   │▒
		//  │         vvvv         │▒
		//  │   ┌─────┘│││         │▒
		//  │   │┌─────┘││         │▒
		//  │   ││┌─────┘│         │▒
		//  │   │││┌─────┘         │▒
		//  │   vvvv               │▒
		//  │   QQQQ------------   │▒
		//  └──────────────────────┘▒
		//    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
		//
		// Legend: . = removed queries, Q = valid queries, - = free space
		//
		// We move the memory block starting at the first valid query (index 5) to the
		// beginning of the memory block, overwriting the invalid queries (index 0-4).
		// The remaining memory (index 5-15) is then zeroed out by memset() below.
		queriesData *dest = getQuery(0, true);
		queriesData *src = getQuery(removed, true);
		if(dest != NULL && src != NULL)
			memmove(dest, src, (counters->queries - removed)*sizeof(queriesData));

		// Update queries counter
		counters->queries -= removed;

		// Ensure remaining memory is zeroed out (marked as "F" in the above example)
		queriesData *tail = getQuery(counters->queries, true);
		if(tail)
			memset(tail, 0, (counters->queries_MAX - counters->queries)*sizeof(queriesData));
	}

	// Recycle old clients and domains
	recycle();

	// Determine if overTime memory needs to get moved
	moveOverTimeMemory(mintime);

	log_debug(DEBUG_GC, "GC removed %u queries (took %.2f ms)", removed, timer_elapsed_msec(GC_TIMER));

	// Release thread lock
	if(!flush)
		unlock_shm();

	// After storing data in the database for the next time,
	// we should scan for old entries, which will then be deleted
	// to free up pages in the database and prevent it from growing
	// ever larger and larger
	DBdeleteoldqueries = true;
}

static bool check_files_on_same_device(const char *path1, const char *path2)
{
	struct stat s1, s2;
	if(stat(path1, &s1) != 0 || stat(path2, &s2) != 0)
	{
		log_warn("check_files_on_same_device(): stat() failed: %s", strerror(errno));
		return false;
	}

	return s1.st_dev == s2.st_dev;
}

void *GC_thread(void *val)
{
	// Set thread name
	thread_names[GC] = "housekeeper";
	thread_running[GC] = true;
	prctl(PR_SET_NAME, thread_names[GC], 0, 0, 0);

	// Remember when we last ran the actions
	time_t lastGCrun = time(NULL) - time(NULL)%GCinterval;
	lastRateLimitCleaner = time(NULL);
	time_t lastResourceCheck = 0;
	time_t lastCPUcheck = 0;

	// Remember disk usage
	unsigned int LastLogStorageUsage = 0;
	unsigned int LastDBStorageUsage = 0;

	bool db_and_log_on_same_dev = false;
	db_and_log_on_same_dev = check_files_on_same_device(config.files.database.v.s, config.files.log.ftl.v.s);

	// Create inotify watcher for pihole.toml config file
	watch_config(true);

	// Run as long as this thread is not canceled
	while(!killed)
	{
		const time_t now = time(NULL);
		if(config.dns.rateLimit.interval.v.ui > 0 &&
		   (unsigned int)(now - lastRateLimitCleaner) >= config.dns.rateLimit.interval.v.ui)
		{
			lastRateLimitCleaner = now;
			lock_shm();
			reset_rate_limiting();
			unlock_shm();
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Calculate average CPU usage
		// This is done once every ten seconds to get averaged values
		if(now - lastCPUcheck >= CPU_AVERAGE_INTERVAL)
		{
			lastCPUcheck = now;
			calc_cpu_usage(CPU_AVERAGE_INTERVAL);
		}

		// Check available resources
		if(now - lastResourceCheck >= RCinterval)
		{
			// Check load averages
			check_load();

			// Check disk space of database file
			LastDBStorageUsage = check_space(config.files.database.v.s, LastDBStorageUsage);

			// Check disk space of log file only if they are not on
			// the same file system
			if(!db_and_log_on_same_dev)
				LastLogStorageUsage = check_space(config.files.log.ftl.v.s, LastLogStorageUsage);

			lastResourceCheck = now;
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		if(now - GCdelay - lastGCrun >= GCinterval || doGC)
			runGC(now, &lastGCrun, false);

		// Intermediate cancellation-point
		if(killed)
			break;

		// Check if pihole.toml has been modified
		if(check_inotify_event())
		{
			// Reload config
			reread_config();
		}

		thread_sleepms(GC, 1000);
	}

	// Close inotify watcher
	watch_config(false);

	log_info("Terminating GC thread");
	thread_running[GC] = false;
	return NULL;
}
