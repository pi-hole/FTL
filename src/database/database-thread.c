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
	prctl(PR_SET_NAME,"database",0,0,0);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

	while(!killed)
	{
		if(FTL_DB_avail())
		{
			time_t now = time(NULL);
			if(now - lastDBsave >= config.DBinterval)
			{
				// Update lastDBsave timer
				lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

				// Save data to database (if enabled)
				if(config.DBexport)
				{
					lock_shm();
					DB_save_queries();
					unlock_shm();

					// Check if GC should be done on the database
					if(DBdeleteoldqueries)
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

		// Try to resolve host names from clients in the network table
		// which have empty/undefined host names
		if(get_and_clear_event(RERESOLVE_DATABASE_NAMES))
			resolveNetworkTableNames();

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
