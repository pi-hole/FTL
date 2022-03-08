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
// DB_save_queries()
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
// check_blocking_status()
#include "../setupVars.h"

#define DBOPEN_OR_AGAIN() { db = dbopen(false); if(db == NULL) { thread_sleepms(DB, 5000); continue; } }
#define BREAK_IF_KILLED() { if(killed) break; }
#define DBCLOSE_OR_BREAK() { dbclose(&db); BREAK_IF_KILLED(); }

void *DB_thread(void *val)
{
	// Set thread name
	thread_names[DB] = "database";
	prctl(PR_SET_NAME, thread_names[DB], 0, 0, 0);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

	// This thread runs until shutdown of the process. We keep this thread
	// running when pihole-FTL.db is corrupted because reloading of privacy
	// level, and the gravity database (initially and after gravity)
	while(!killed)
	{
		sqlite3 *db = NULL;
		time_t now = time(NULL);
		if(now - lastDBsave >= config.DBinterval)
		{
			// Update lastDBsave timer
			lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

			// Save data to database (if enabled)
			if(config.DBexport)
			{
				DBOPEN_OR_AGAIN();
				lock_shm();
				DB_save_queries(db);
				unlock_shm();

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

		// Update MAC vendor strings once a month (the MAC vendor
		// database is not updated very often)
		if(now % 2592000L == 0)
		{
			DBOPEN_OR_AGAIN();
			updateMACVendorRecords(db);
			DBCLOSE_OR_BREAK();
		}

		// Parse ARP cache if requested
		if(get_and_clear_event(PARSE_NEIGHBOR_CACHE))
		{
			DBOPEN_OR_AGAIN();
			parse_neighbor_cache(db);
			DBCLOSE_OR_BREAK();
		}

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

		BREAK_IF_KILLED();

		// Reload privacy level from pihole-FTL.conf
		if(get_and_clear_event(RELOAD_PRIVACY_LEVEL))
			get_privacy_level(NULL);

		BREAK_IF_KILLED();

		// Inspect setupVars.conf to see if Pi-hole blocking is enabled
		if(get_and_clear_event(RELOAD_BLOCKINGSTATUS))
			check_blocking_status();

		BREAK_IF_KILLED();

		// Sleep 0.1 sec
		thread_sleepms(DB, 100);
	}

	logg("Terminating database thread");
	return NULL;
}
