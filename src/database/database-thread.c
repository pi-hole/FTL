/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Database thread
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "database-thread.h"
#include "common.h"
// [un]lock_shm();
#include "../shmem.h"
// parse_neighbor_cache()
#include "network-table.h"
// export_queries_to_disk()
#include "query-table.h"
#include "../config.h"
#include "../log.h"
#include "../timers.h"
// global variable killed
#include "../signals.h"
// reimport_aliasclients()
#include "aliasclients.h"
// Eventqueue routines
#include "../events.h"
// get_FTL_db_filesize()
#include "../files.h"

static void delete_old_queries_in_DB(void)
{
	// Open database
	if(!FTL_DB_avail())
	{
		return;
	}

	int timestamp = time(NULL) - config.maxDBdays * 86400;

	if(dbquery("DELETE FROM queries WHERE timestamp <= %i", timestamp) != SQLITE_OK)
	{
		logg("delete_old_queries_in_DB(): Deleting queries due to age of entries failed!");
		return;
	}

	// Get how many rows have been affected (deleted)
	const int affected = sqlite3_changes(FTL_db);

	// Print final message only if there is a difference
	if((config.debug & DEBUG_DATABASE) || affected)
		logg("Notice: Database size is %.2f MB, deleted %i rows", 1e-6*get_FTL_db_filesize(), affected);
}

void *DB_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"database",0,0,0);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t before = time(NULL);
	time_t lastDBsave = before - before%config.DBinterval;

	while(!killed)
	{
		if(FTL_DB_avail())
		{
			time_t now = time(NULL);

			// Move queries from non-blocking newdb into the larger memdb
			// Do this once per second
			if(now > before)
			{
				mv_newdb_memdb();
				before = now;
			}

			// Store queries in on-disk database
			if(now - lastDBsave >= config.DBinterval)
			{
				// Update lastDBsave timer
				lastDBsave = now - now%config.DBinterval;

				// Save data to database (if enabled)
				if(config.DBexport)
				{
					export_queries_to_disk(false);

					// Check if GC should be done on the database
					if(DBdeleteoldqueries && config.maxDBdays != -1)
					{
						// No thread locks needed
						delete_old_queries_in_DB();
						DBdeleteoldqueries = false;
					}
				}

				// Parse neighbor cache (fill network table) if enabled
				if (config.parse_arp_cache)
					set_event(PARSE_NEIGHBOR_CACHE);
			}

			// Update MAC vendor strings once a month (the MAC vendor
			// database is not updated very often)
			if(now % 2592000L == 0)
				updateMACVendorRecords();

			if(get_and_clear_event(PARSE_NEIGHBOR_CACHE))
				parse_neighbor_cache();
		}

		// Process database related event queue elements
		if(get_and_clear_event(RELOAD_GRAVITY))
			FTL_reload_all_domainlists();

		// Reload privacy level from pihole-FTL.conf
		if(get_and_clear_event(RELOAD_PRIVACY_LEVEL))
			get_privacy_level(NULL);

		// Import alias-clients
		if(get_and_clear_event(REIMPORT_ALIASCLIENTS))
		{
			lock_shm();
			reimport_aliasclients();
			unlock_shm();
		}

		// Sleep 0.1 seconds
		sleepms(100);
	}

	return NULL;
}
