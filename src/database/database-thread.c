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
#include "database-thread.h"
#include "common.h"
// [un]lock_shm();
#include "shmem.h"
// parse_neighbor_cache()
#include "network-table.h"
// DB_save_queries()
#include "query-table.h"
#include "config.h"
#include "log.h"
#include "timers.h"
// global variable killed
#include "signals.h"
// reimport_superclients()
#include "database/superclients.h"

void *DB_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"database",0,0,0);

	// First check if the user doesn't want to use the database.
	// If this is the case, we terminate the database thread as
	// there is no point in having it around
	if(!use_database())
		return NULL;

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

	while(!killed && database)
	{
		time_t now = time(NULL);
		if(now - lastDBsave >= config.DBinterval)
		{
			// Update lastDBsave timer
			lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

			// Lock FTL's data structures, since it is
			// likely that they will be changed here
			lock_shm();

			// Save data to database
			DB_save_queries();

			// Release data lock
			unlock_shm();

			// Check if GC should be done on the database
			if(DBdeleteoldqueries)
			{
				// No thread locks needed
				delete_old_queries_in_DB();
				DBdeleteoldqueries = false;
			}

			// Parse neighbor cache (fill network table) if enabled
			if (config.parse_arp_cache)
				parse_neighbor_cache();
		}

		// Update MAC vendor strings once a month (the MAC vendor
		// database is not updated very often)
		if(now % 2592000L == 0)
			updateMACVendorRecords();

		// Reload all FTL-related lists on request
		if(want_to_reload_lists)
		{
			want_to_reload_lists = false;

			lock_shm();

			// Reload
			// - gravity
			// - exact whitelist
			// - regex whitelist
			// - exact blacklist
			// - exact blacklist
			// WITHOUT wiping the DNS cache itself
			FTL_reload_all_domainlists();

			// Reload the privacy level in case the user changed it
			get_privacy_level(NULL);

			unlock_shm();
		}

		// Re-import super-clients on request
		// We do this in the database thread to avoid lock-clashing
		// when a signal arrives in the middle of another (locked)
		// operation
		if(want_to_reimport_superclients)
		{
			want_to_reimport_superclients = false;

			lock_shm();
			reimport_superclients();
			unlock_shm();
		}

		sleepms(100);
	}

	return NULL;
}
