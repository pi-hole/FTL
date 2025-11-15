/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Database thread
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "database/database-thread.h"
#include "database/common.h"
// [un]lock_shm();
#include "shmem.h"
// parse_neighbor_cache()
#include "database/network-table.h"
// export_queries_to_disk()
#include "database/query-table.h"
#include "config/config.h"
#include "log.h"
#include "timers.h"
// global variable killed
#include "signals.h"
// reimport_aliasclients()
#include "database/aliasclients.h"
// Eventqueue routines
#include "events.h"
// get_FTL_db_filesize()
#include "files.h"
// gravity_updated()
#include "database/gravity-db.h"

static bool delete_old_queries_in_DB(sqlite3 *db)
{
	// Delete old queries from the database but never more than 1% of the
	// database at once to avoid long blocking times. Check out
	// https://github.com/pi-hole/FTL/issues/1372 for details.
	// As deleting database entries happens typically once per minute,
	// this method could still delete 1440% of the database per day.
	// Even when the database storing interval is set to 1 hour, this
	// method would still delete 24% of the database per day so maxDBdays > 4
	// does still work.
	const time_t timestamp = time(NULL) - config.database.maxDBdays.v.ui * 86400;
	SQL_bool(db, "DELETE FROM query_storage WHERE id IN (SELECT id FROM query_storage WHERE timestamp <= %lu LIMIT (SELECT COUNT(*)/100 FROM query_storage));",
	         (unsigned long)timestamp);

	// Get how many rows have been affected (deleted)
	const int affected = sqlite3_changes(db);

	// Print debug message
	log_debug(DEBUG_DATABASE, "Size of %s is %.2f MB, deleted %i rows",
	          config.files.database.v.s, 1e-6*get_FTL_db_filesize(), affected);

	return true;
}

static bool analyze_database(sqlite3 *db)
{
	// Optimize the database by running ANALYZE
	// The ANALYZE command gathers statistics about tables and indices and
	// stores the collected information in internal tables of the database
	// where the query optimizer can access the information and use it to
	// help make better query planning choices.
	log_debug(DEBUG_DATABASE, "Optimizing database %s", config.files.database.v.s);

	// Measure time
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	SQL_bool(db, "ANALYZE;");
	clock_gettime(CLOCK_MONOTONIC, &end);

	// Print final message
	log_info("Optimized database in %.3f seconds",
	         (double)(end.tv_sec - start.tv_sec) + 1e-9*(end.tv_nsec - start.tv_nsec));

	return true;
}

#define DBOPEN_OR_AGAIN() { if(!db) db = dbopen(false, false); if(!db) { thread_sleepms(DB, 5000); continue; } }
#define DBCLOSE_OR_BREAK() { dbclose(&db); BREAK_IF_KILLED(); }

void *DB_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME, thread_names[DB], 0, 0, 0);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t before = time(NULL);
	time_t lastDBsave = before - before%config.database.DBinterval.v.ui;

	// Add some randomness (between one and two hours) to these timestamps
	// to avoid them running at the same time and immediately after FTL was
	// (re)started. We really only want them to run in the background when
	// FTL is running for a while.
	time_t lastAnalyze = before + 3600 + (rand() % 3600);
	time_t lastMACVendor = before + 3600 + (rand() % 3600);

	// This thread runs until shutdown of the process. We keep this thread
	// running when pihole-FTL.db is corrupted because reloading of privacy
	// level, and the gravity database (initially and after gravity)
	sqlite3 *db = NULL;
	while(!killed)
	{
		const time_t now = time(NULL);

		// If the database is busy, no moving is happening and queries are retained in
		// here until the next try. This ensures we cannot loose queries.
		// Do this once per second
		if(now > before)
		{
			lock_shm();
			queries_to_database();
			unlock_shm();
			before = now;

			// Check if we need to reload gravity
			if(gravity_updated())
			{
				// Reload gravity
				set_event(RELOAD_GRAVITY);
			}
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Store queries in on-disk database
		if(now - lastDBsave >= (time_t)config.database.DBinterval.v.ui)
		{
			// Update lastDBsave timer
			lastDBsave = now - now%config.database.DBinterval.v.ui;

			// Save data to database
			DBOPEN_OR_AGAIN();
			TIMED_DB_OP(export_queries_to_disk(false));

			// Intermediate cancellation-point
			if(killed)
				break;

			// Check if GC should be done on the database
			if(DBdeleteoldqueries)
			{
				/* No thread locks needed */
				TIMED_DB_OP(delete_old_queries_in_DB(db));
				DBdeleteoldqueries = false;
			}

			DBCLOSE_OR_BREAK();

			// Parse neighbor cache (fill network table)
			set_event(PARSE_NEIGHBOR_CACHE);
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Optimize database once per week
		if(now - lastAnalyze >= DATABASE_ANALYZE_INTERVAL)
		{
			DBOPEN_OR_AGAIN();
			TIMED_DB_OP(analyze_database(db));
			lastAnalyze = now;
			DBCLOSE_OR_BREAK();
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Update MAC vendor strings once a month (the MAC vendor
		// database is not updated very often)
		if(now  - lastMACVendor >= DATABASE_MACVENDOR_INTERVAL)
		{
			DBOPEN_OR_AGAIN();
			TIMED_DB_OP(updateMACVendorRecords(db));
			lastMACVendor = now;
			DBCLOSE_OR_BREAK();
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Parse ARP cache if requested
		if(get_and_clear_event(PARSE_NEIGHBOR_CACHE))
		{
			DBOPEN_OR_AGAIN();
			TIMED_DB_OP(parse_neighbor_cache(db));
			DBCLOSE_OR_BREAK();
		}

		// Intermediate cancellation-point
		BREAK_IF_KILLED();

		// Import alias-clients
		if(get_and_clear_event(REIMPORT_ALIASCLIENTS))
		{
			DBOPEN_OR_AGAIN();
			lock_shm();
			TIMED_DB_OP(reimport_aliasclients(db));
			unlock_shm();
			DBCLOSE_OR_BREAK();
		}

		// Process database related event queue elements
		if(get_and_clear_event(RELOAD_GRAVITY))
			FTL_reload_all_domainlists();

		// Intermediate cancellation-point
		BREAK_IF_KILLED();

		// Sleep 0.1 sec
		thread_sleepms(DB, 100);
	}

	// Close database handle if still open
	if(db)
		dbclose(&db);

	log_info("Terminating database thread");
	return NULL;
}
