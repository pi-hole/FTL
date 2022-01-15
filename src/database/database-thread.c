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
#include "../config/config.h"
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
		log_info("Size of %s is %.2f MB, deleted %i rows",
		         config.files.database, 1e-6*get_FTL_db_filesize(), affected);

	return true;
}

#define DBOPEN_OR_AGAIN() { if(!db) db = dbopen(false); if(!db) { thread_sleepms(DB, 5000); continue; } }
#define BREAK_IF_KILLED() { if(killed) break; }
#define DBCLOSE_OR_BREAK() { dbclose(&db); BREAK_IF_KILLED(); }

void *DB_thread(void *val)
{
	// Set thread name
	thread_names[DB] = "database";
	prctl(PR_SET_NAME, thread_names[DB], 0, 0, 0);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t before = time(NULL);
	time_t lastDBsave = before - before%config.DBinterval;

	// This thread runs until shutdown of the process. We keep this thread
	// running when pihole-FTL.db is corrupted because reloading of privacy
	// level, and the gravity database (initially and after gravity)
	sqlite3 *db = NULL;
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

		// Store queries in on-disk database
		if(now - lastDBsave >= (time_t)config.DBinterval)
		{
			// Update lastDBsave timer
			lastDBsave = now - now%config.DBinterval;

			// Save data to database (if enabled)
			if(config.DBexport)
			{
				DBOPEN_OR_AGAIN();
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

				DBCLOSE_OR_BREAK();
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
		{
			DBOPEN_OR_AGAIN();
			updateMACVendorRecords(db);
			DBCLOSE_OR_BREAK();
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Parse ARP cache if requested
		if(get_and_clear_event(PARSE_NEIGHBOR_CACHE))
		{
			DBOPEN_OR_AGAIN();
			parse_neighbor_cache(db);
			DBCLOSE_OR_BREAK();
		}

		// Intermediate cancellation-point
		BREAK_IF_KILLED();

		// Import alias-clients
		if(get_and_clear_event(REIMPORT_ALIASCLIENTS))
		{
			DBOPEN_OR_AGAIN();
			lock_shm();
			reimport_aliasclients(db);
			unlock_shm();
			DBCLOSE_OR_BREAK();
		}

		// Process database related event queue elements
		if(get_and_clear_event(RELOAD_GRAVITY))
			FTL_reload_all_domainlists();

		// Intermediate cancellation-point
		BREAK_IF_KILLED();

		// Reload privacy level from pihole-FTL config
		if(get_and_clear_event(RELOAD_PRIVACY_LEVEL))
			getPrivacyLevel();

		// Intermediate cancellation-point
		BREAK_IF_KILLED();

		// Import alias-clients
		if(get_and_clear_event(REIMPORT_ALIASCLIENTS))
		{
			lock_shm();
			reimport_aliasclients(db);
			unlock_shm();
		}

		BREAK_IF_KILLED();

		// Sleep 1 sec
		thread_sleepms(DB, 1000);
	}

	// Close database handle if still open
	if(db)
		dbclose(&db);

	log_info("Terminating database thread");
	return NULL;
}
