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

void *DB_thread(void *val)
{
	// Set thread name
	thread_names[DB] = "database";
	prctl(PR_SET_NAME, thread_names[DB], 0, 0, 0);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

	// Run until shutdown of the process
	while(!killed)
	{
		sqlite3 *db = dbopen(false);
		if(db == NULL)
		{
			// Sleep 5 seconds and try again
			thread_sleepms(DB, 5000);
			continue;
		}
		time_t now = time(NULL);
		if(now - lastDBsave >= config.DBinterval)
		{
			// Update lastDBsave timer
			lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

			// Save data to database (if enabled)
			if(config.DBexport)
			{
				lock_shm();
				DB_save_queries(db);
				unlock_shm();

				// Intermediate cancellation-point
				if(killed)
				{
					dbclose(&db);
					break;
				}

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
		{
			dbclose(&db);
			break;
		}

		// Update MAC vendor strings once a month (the MAC vendor
		// database is not updated very often)
		if(now % 2592000L == 0)
			updateMACVendorRecords(db);

		// Intermediate cancellation-point
		if(killed)
		{
			dbclose(&db);
			break;
		}

		if(get_and_clear_event(PARSE_NEIGHBOR_CACHE))
			parse_neighbor_cache(db);

		// Intermediate cancellation-point
		if(killed)
		{
			dbclose(&db);
			break;
		}

		// Process database related event queue elements
		if(get_and_clear_event(RELOAD_GRAVITY))
			FTL_reload_all_domainlists();

		// Intermediate cancellation-point
		if(killed)
		{
			dbclose(&db);
			break;
		}

		// Reload privacy level from pihole-FTL.conf
		if(get_and_clear_event(RELOAD_PRIVACY_LEVEL))
			get_privacy_level(NULL);

		// Intermediate cancellation-point
		if(killed)
		{
			dbclose(&db);
			break;
		}

		// Import alias-clients
		if(get_and_clear_event(REIMPORT_ALIASCLIENTS))
		{
			lock_shm();
			reimport_aliasclients(db);
			unlock_shm();
		}

		// Close database connection
		dbclose(&db);

		// Sleep 1 sec
		thread_sleepms(DB, 1000);
	}

	logg("Terminating database thread");
	return NULL;
}
