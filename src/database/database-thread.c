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
// get_FTL_db_stats()
#include "files.h"
// gravity_updated(), gravityDB_dump_perf_stats()
#include "database/gravity-db.h"
// FTL_dump_cache_stats() - forward declaration to avoid pulling in dnsmasq headers
extern void FTL_dump_cache_stats(void);
// parse_proc_meminfo()
#include "procps.h"
// sqlite3_mem_used()
#include "database/sqlite3-ext.h"
// PRId64
#include <inttypes.h>
// db_import_done
#include "gc.h"

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

/**
 * log_used_memory
 *
 * Gather and log memory-usage statistics for the process, SQLite and on-disk
 * database tables. This helper is intended for periodic debugging/monitoring
 * output and does not change program state.
 *
 * @return void
 * @see parse_proc_meminfo(), getProcessMemory(), format_memory_size(),
 *      sqlite3_mem_used(), get_FTL_db_stats(), get_row_count(), log_debug()
 */
static void log_used_memory(void)
{
	log_debug(DEBUG_TIMING, "Memory usage overview:");

	struct proc_mem pmem = { 0 };
	struct proc_meminfo mem = { 0 };
	parse_proc_meminfo(&mem);
	getProcessMemory(&pmem, mem.total);

	char total_prefix[2] = { 0 };
	double total_formatted = 0.0;
	format_memory_size(total_prefix, (uint64_t)mem.total * 1024, &total_formatted);

	char used_prefix[2] = { 0 };
	double used_formatted = 0.0;
	format_memory_size(used_prefix, (uint64_t)pmem.VmRSS * 1024, &used_formatted);

	log_debug(DEBUG_TIMING, "  System: %.2f %sB used of %.2f %sB total (%.1f%%)",
	         used_formatted, used_prefix, total_formatted, total_prefix, pmem.VmRSS_percent);
	log_debug(DEBUG_TIMING, "  Process: VmSize: %lu kB, VmRSS: %lu kB, VmPeak: %lu kB, VmHWM: %lu kB",
	         pmem.VmSize, pmem.VmRSS, pmem.VmPeak, pmem.VmHWM);

	const struct sqlite3_memory_usage *sqlite3_memory = sqlite3_mem_used();
	char sqlite3_mem_prefix[2] = { 0 };
	double sqlite3_mem_formatted = 0.0;
	format_memory_size(sqlite3_mem_prefix, sqlite3_memory->total, &sqlite3_mem_formatted);

	char sqlite3_mem_highwater_prefix[2] = { 0 };
	double sqlite3_mem_highwater_formatted = 0.0;
	format_memory_size(sqlite3_mem_highwater_prefix, sqlite3_memory->highwater, &sqlite3_mem_highwater_formatted);

	char sqlite3_mem_largest_block_prefix[2] = { 0 };
	double sqlite3_mem_largest_block_formatted = 0.0;
	format_memory_size(sqlite3_mem_largest_block_prefix, sqlite3_memory->largest_block, &sqlite3_mem_largest_block_formatted);

	size_t memsize = 0;
	get_memdb_size(&memsize, NULL);
	char memdb_size_prefix[2] = { 0 };
	double memdb_size_formatted = 0.0;
	format_memory_size(memdb_size_prefix, memsize, &memdb_size_formatted);

	log_debug(DEBUG_TIMING, "  SQLite3 (in-memory): %.2f %sB usage, high-water %.2f %sB, max. block %.2f %sB, %zu allocations, PRAGMA size: %.2f %sB",
	         sqlite3_mem_formatted, sqlite3_mem_prefix,
	         sqlite3_mem_highwater_formatted, sqlite3_mem_highwater_prefix,
	         sqlite3_mem_largest_block_formatted, sqlite3_mem_largest_block_prefix,
	         sqlite3_memory->current_allocations,
	         memdb_size_formatted, memdb_size_prefix);
	log_debug(DEBUG_TIMING, "    Table sizes: "
	         "domain_by_id=%"PRId64", client_by_id=%"PRId64", forward_by_id=%"PRId64", addinfo_by_id=%"PRId64", query_storage=%"PRId64"",
	          get_row_count("domain_by_id", true),
	          get_row_count("client_by_id", true),
	          get_row_count("forward_by_id", true),
	          get_row_count("addinfo_by_id", true),
	          get_row_count("query_storage", true));

	// Log on-disk database file size
	struct stat st;
	get_FTL_db_stats(&st);
	char db_size_prefix[2] = { 0 };
	double db_size_formatted = 0.0;
	format_memory_size(db_size_prefix, st.st_size, &db_size_formatted);
	log_debug(DEBUG_TIMING, "  SQLite3 (on-disk): %.2f %sB", db_size_formatted, db_size_prefix);
	log_debug(DEBUG_TIMING, "    Table sizes: "
	         "domain_by_id=%"PRId64", client_by_id=%"PRId64", forward_by_id=%"PRId64", addinfo_by_id=%"PRId64", query_storage=%"PRId64"",
	          get_row_count("domain_by_id", false),
	          get_row_count("client_by_id", false),
	          get_row_count("forward_by_id", false),
	          get_row_count("addinfo_by_id", false),
	          get_row_count("query_storage", false));
}

#define DBOPEN_OR_AGAIN() { if(!db) db = dbopen(false, false); if(!db) { thread_sleepms(DB, 5000); continue; } }
#define DBCLOSE_OR_BREAK() { dbclose(&db); BREAK_IF_KILLED(); }

void *DB_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME, thread_names[DB], 0, 0, 0);

	// Asynchronously import queries from the on-disk database
	if(config.database.DBimport.v.b)
		DB_read_queries();

	// Signify that the import is done, so garbage collection will run
	db_import_done = true;

	// Log some information about the imported queries (if any)
	log_counter_info();

	// Random minute for daily cleaning task between 3:10 and 3:50 am
	const int cleaning_minute = 10u + (rand() % 40);

	// Save timestamp as we do not want to store immediately
	// to the database
	time_t before = time(NULL);
	time_t lastDBsave = before - before%config.database.DBinterval.v.ui;
	time_t lastDBdelete = before;

	// Add some randomness (between one and two hours) to these timestamps
	// to avoid them running at the same time and immediately after FTL was
	// (re)started. We really only want them to run in the background when
	// FTL is running for a while.
	time_t lastAnalyze = before + 3600 + (rand() % 3600);
	time_t lastMACVendor = before + 3600 + (rand() % 3600);

	// Last memory log timestamp
	time_t lastMemLog = 0;

	// Last gravity performance statistics dump (start from now so the first
	// dump happens after 5 minutes of actual activity, not immediately)
	time_t lastGravityStats = before;

	// This thread runs until shutdown of the process. We keep this thread
	// running when pihole-FTL.db is corrupted because reloading of privacy
	// level, and the gravity database (initially and after gravity)
	sqlite3 *db = NULL;
	while(!killed)
	{
		const time_t now = time(NULL);

		// Log memory usage once per ten minutes
		if(config.debug.timing.v.b && now - lastMemLog >= 600)
		{
			log_used_memory();
			lastMemLog = now;
		}

		// Dump gravity lookup and FTL cache performance statistics every 5 minutes
		// (only when debug.performance is enabled)
		if(config.debug.performance.v.b && now - lastGravityStats >= 300)
		{
			TIMED_DB_OP(FTL_dump_cache_stats());
			TIMED_DB_OP(gravityDB_dump_perf_stats());
			lastGravityStats = now;
		}

		// If the database is busy, no moving is happening and queries are retained in
		// here until the next try. This ensures we cannot loose queries.
		// Do this once per second
		if(now > before)
		{
			TIMED_DB_OP(queries_to_database());
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
			DBCLOSE_OR_BREAK();

			// Parse neighbor cache (fill network table)
			set_event(PARSE_NEIGHBOR_CACHE);
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Delete old queries from the database once per day between 3am
		// and 4am
		struct tm tm_now = { 0 };
		localtime_r(&now, &tm_now);
		if(tm_now.tm_hour == 3 && tm_now.tm_min > cleaning_minute &&
		   now - lastDBdelete >= DATABASE_DELETE_OLD_QUERIES_INTERVAL)
		{
			// Update lastDBdelete timer to avoid multiple deletions
			lastDBdelete = now;
			// Widen before multiplying: maxDBdays is an unsigned int, so
			// the product was computed in 32-bit arithmetic and wrapped
			// for large values, turning a long retention into a cutoff
			// that deletes almost everything
			const double mintime = now - (double)config.database.maxDBdays.v.ui * 86400.0;
			DBOPEN_OR_AGAIN();
			TIMED_DB_OP(delete_old_queries_from_db(false, mintime));
			DBCLOSE_OR_BREAK();
		}

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
			TIMED_DB_OP(FTL_reload_all_domainlists());

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
