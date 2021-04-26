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

#define TIME_T "%li"

static bool delete_old_queries_in_DB(sqlite3 *db)
{
	const time_t timestamp = time(NULL) - config.maxDBdays * 86400;
	SQL_bool(db, "DELETE FROM queries WHERE timestamp <= "TIME_T, timestamp);

	// Get how many rows have been affected (deleted)
	const int affected = sqlite3_changes(db);

	// Print final message only if there is a difference
	if((config.debug & DEBUG_DATABASE) || affected)
		logg("Notice: Database size is %.2f MB, deleted %i rows",
		     1e-6*get_FTL_db_filesize(), affected);

	return true;
}

void *DB_thread(void *val)
{
	// Set thread name
	thread_names[DB] = "database";
	prctl(PR_SET_NAME, thread_names[DB], 0, 0, 0);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t before = time(NULL);
	time_t lastDBsave = before - before%config.DBinterval;

	// Run until shutdown of the process
	while(!killed)
	{
		const time_t now = time(NULL);

		// Move queries from non-blocking newdb into the larger memdb
		// Do this once per second
		if(now > before)
		{
			mv_newdb_memdb();
			before = now;
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Open database connection
		sqlite3 *db = dbopen(false);
		if(db == NULL)
		{
			// Try again after 5 sec
			thread_sleepms(DB, 5000);
			continue;
		}

		// Store queries in on-disk database
		if(now - lastDBsave >= config.DBinterval)
		{
			// Update lastDBsave timer
			lastDBsave = now - now%config.DBinterval;

			// Save data to database (if enabled)
			if(config.DBexport)
			{
				lock_shm();
				export_queries_to_disk(false);
				unlock_shm();

				// Intermediate cancellation-point
				if(killed)
					break;

				// Check if GC should be done on the database
				if(DBdeleteoldqueries && config.maxDBdays != -1)
				{
					// No thread locks needed
					delete_old_queries_in_DB(db);
					DBdeleteoldqueries = false;
				}
			}

			// Parse neighbor cache (fill network table) if enabled
			if (config.parse_arp_cache)
				set_event(PARSE_NEIGHBOR_CACHE);
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Update MAC vendor strings once a month (the MAC vendor
		// database is not updated very often)
		if(now % 2592000L == 0)
			updateMACVendorRecords(db);

		// Intermediate cancellation-point
		if(killed)
			break;

		if(get_and_clear_event(PARSE_NEIGHBOR_CACHE))
			parse_neighbor_cache(db);

		// Intermediate cancellation-point
		if(killed)
			break;

		// Process database related event queue elements
		if(get_and_clear_event(RELOAD_GRAVITY))
			FTL_reload_all_domainlists();

		// Intermediate cancellation-point
		if(killed)
			break;

		// Reload privacy level from pihole-FTL.conf
		if(get_and_clear_event(RELOAD_PRIVACY_LEVEL))
			get_privacy_level(NULL);

		// Intermediate cancellation-point
		if(killed)
			break;

		// Import alias-clients
		if(get_and_clear_event(REIMPORT_ALIASCLIENTS))
		{
			lock_shm();
			reimport_aliasclients(db);
			unlock_shm();
		}

		dbclose(&db);

		// Sleep 1 sec
		thread_sleepms(DB, 1000);
	}

	logg("Terminating database thread");
	return NULL;
}
