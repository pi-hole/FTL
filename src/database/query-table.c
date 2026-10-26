/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "database/query-table.h"
#include "database/sqlite3.h"
#include "log.h"
#include "config/config.h"
#include "enums.h"
#include "config/config.h"
// counters
#include "shmem.h"
#include "overTime.h"
#include "database/common.h"
#include "timers.h"
// runGC()
#include "gc.h"
// flush_message_table()
#include "database/message-table.h"
// killed
#include "signals.h"
// file_exists()
#include "files.h"
// INFINITY
#include <math.h>
// name_history_import(), client_name_at()
#include "name-history.h"

// The database thread's own connection to pihole-FTL.db, kept open
static sqlite3 *querydb = NULL;
// Unix timestamp of the newest query stored
static double new_last_timestamp = 0;
static uint64_t diskdb_queries_count = 0;
static double diskdb_earliest_timestamp = 0;

// Process-local cache for addinfo_by_id row IDs.
// The type is packed into the low bits of a combined key, with the actual key
// value (CNAME_domainID or list_id) shifted above it. db_id == 0 means the slot
// is empty.  1024 slots (8 KB at 8 bytes/slot) keeps the table under 75% load
// even for users with hundreds of regex rules plus CNAME-blocked domains.
// If it ever overflows (>8 probe collisions in store_addinfo_id), the store
// silently gives up and the next lookup returns 0, falling through to the
// original INSERT OR IGNORE + SELECT path — so it degrades gracefully with no
// correctness impact.
#define ADDINFO_CACHE_SLOTS 1024

// Derive the number of bits needed to represent all addinfo_type values at
// compile time from the ADDINFO_TYPE_MAX sentinel
#define ADDINFO_TYPE_BITS \
	(ADDINFO_TYPE_MAX <= 2 ? 1 : ADDINFO_TYPE_MAX <= 4 ? 2 : \
	 ADDINFO_TYPE_MAX <= 8 ? 3 : 4)

// Knuth multiplicative hash constant (golden ratio derived):
// floor(2^32 / phi), where phi = (1+sqrt(5))/2.
// Multiplying a key by this and masking to the table size spreads consecutive
// packed keys (which are dense small integers) across all slots.  Without this,
// masking a small integer directly would cluster entries in the first few
// buckets of the power-of-two table.
#define KNUTH_PHI32 2654435761u

// Cache for addinfo_by_id lookups to speed up repeated lookups of the same ID
// (e.g., for frequently queried CNAME domains or lists). The cache is a simple
// open-addressing hash table with linear probing.
static struct {
	int key;   // packed type and key (CNAME_domainID or list_id)
	int db_id; // corresponding addinfo_by_id row ID in the database; 0 if the slot is empty
} addinfo_id_cache[ADDINFO_CACHE_SLOTS] = {{0}};

// Pack addinfo type and key into a single integer
static inline int addinfo_pack(const int type, const int key)
{
	// Shift as unsigned: list IDs can be negative, and left-shifting a
	// negative int is undefined behaviour
	return (int)(((unsigned int)key << ADDINFO_TYPE_BITS) | (type & ((1u << ADDINFO_TYPE_BITS) - 1)));
}

static inline int lookup_addinfo_id(const int type, const int key)
{
	const int packed = addinfo_pack(type, key);
	unsigned int slot = ((unsigned int)packed * KNUTH_PHI32) & (ADDINFO_CACHE_SLOTS - 1);
	for(int i = 0; i < 8; i++)
	{
		if(addinfo_id_cache[slot].db_id == 0)
			return 0;
		if(addinfo_id_cache[slot].key == packed)
			return addinfo_id_cache[slot].db_id;
		slot = (slot + 1) & (ADDINFO_CACHE_SLOTS - 1);
	}
	return 0;
}

static inline void store_addinfo_id(const int type, const int key, const int db_id)
{
	const int packed = addinfo_pack(type, key);
	unsigned int slot = ((unsigned int)packed * KNUTH_PHI32) & (ADDINFO_CACHE_SLOTS - 1);
	for(int i = 0; i < 8; i++)
	{
		if(addinfo_id_cache[slot].db_id == 0 ||
		   addinfo_id_cache[slot].key == packed)
		{
			addinfo_id_cache[slot].key = packed;
			addinfo_id_cache[slot].db_id = db_id;
			return;
		}
		slot = (slot + 1) & (ADDINFO_CACHE_SLOTS - 1);
	}
}

// Forget all cached addinfo_by_id row IDs. CNAME entries are keyed on SHM
// domain IDs, so this has to be called when domain IDs are recycled. Call it
// with the SHM lock held, as the export uses the cache under it
void clear_addinfo_id_cache(void)
{
	memset(addinfo_id_cache, 0, sizeof(addinfo_id_cache));
}

// Linking table rows shared by all queries whose privacy level hides their
// domain, client or CNAME domain, 0 until first stored
static int hidden_domain_db_id = 0, hidden_client_db_id = 0, hidden_cname_db_id = 0;

// Step a statement that changes rows and read sqlite3_changes() and the last
// inserted rowid for it. The connection mutex is held throughout so that a
// statement of another thread sharing the connection cannot overwrite them
static int step_and_count(sqlite3 *db, sqlite3_stmt *stmt, int64_t *changes, sqlite3_int64 *rowid)
{
	sqlite3_mutex *mutex = sqlite3_db_mutex(db);
	sqlite3_mutex_enter(mutex);
	const int rc = sqlite3_step(stmt);
	*changes = sqlite3_changes64(db);
	if(rowid != NULL)
		*rowid = sqlite3_last_insert_rowid(db);
	sqlite3_mutex_leave(mutex);
	return rc;
}

// Private prototypes
static bool count_queries_on_disk(void);
static bool disk_db_maxid(sqlite3_int64 *maxid);

// Open the database thread's connection to pihole-FTL.db, which the startup
// import reads through and the export writes through. On failure, error says
// why
static bool open_query_database(char *error, const size_t size)
{
	if(querydb != NULL)
		return true;

	int rc = sqlite3_open_v2(config.files.database.v.s, &querydb, SQLITE_OPEN_READWRITE, NULL);
	if(rc != SQLITE_OK)
	{
		snprintf(error, size, "%s", sqlite3_errstr(rc));
		sqlite3_close(querydb);
		querydb = NULL;
		checkFTLDBrc(rc);
		return false;
	}

	if((rc = sqlite3_busy_handler(querydb, sqliteBusyCallback, NULL)) != SQLITE_OK)
		log_warn("Cannot set the busy handler of the query database: %s", sqlite3_errstr(rc));

	// Enable WAL mode for the on-disk database (pihole-FTL.db) if
	// configured (default is yes). User may not want to enable WAL
	// mode if the database is on a network share as all processes
	// accessing the database must be on the same host in WAL mode.
	if(config.database.useWAL.v.b)
	{
		// Change journal mode to WAL
		// - WAL is significantly faster in most scenarios.
		// - WAL provides more concurrency as readers do not block writers and a
		//   writer does not block readers. Reading and writing can proceed
		//   concurrently.
		// - Disk I/O operations tend to be more sequential using WAL.
		rc = sqlite3_exec(querydb, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
		if( rc != SQLITE_OK )
		{
			snprintf(error, size, "cannot set journal mode WAL: %s", sqlite3_errstr(rc));
			sqlite3_close(querydb);
			querydb = NULL;
			return false;
		}

		// Set synchronous=NORMAL for the on-disk WAL database.
		// SQLite's default (FULL) fsyncs the WAL file on every commit,
		// which is unnecessarily conservative in WAL mode and expensive
		// on flash/SD storage (10-100 ms per fsync on a Raspberry Pi).
		//
		// With NORMAL, SQLite skips the per-commit fsync and relies on
		// the WAL's per-frame checksums for integrity: on an abrupt
		// power loss, any WAL frame with a bad checksum is silently
		// discarded during recovery, so the database is never left
		// corrupt. At worst, queries logged since the last checkpoint
		// (up to one flush interval, default 60 s) may not be persisted
		// — an acceptable trade-off for a query log.
		//
		// SQLite documentation explicitly states:
		//   "WAL mode is safe from corruption with synchronous=NORMAL."
		rc = sqlite3_exec(querydb, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
		if( rc != SQLITE_OK )
		{
			snprintf(error, size, "cannot set synchronous mode: %s", sqlite3_errstr(rc));
			sqlite3_close(querydb);
			querydb = NULL;
			return false;
		}
	}
	else
	{
		// Unlike the other journaling modes, PRAGMA journal_mode=WAL is
		// persistent. If a process sets WAL mode, then closes and
		// reopens the database, the database will come back in WAL
		// mode. In contrast, if a process sets (for example) PRAGMA
		// journal_mode=TRUNCATE and then closes and reopens the
		// database will come back up in the default rollback mode of
		// DELETE rather than the previous TRUNCATE setting.

		// Change journal mode back to DELETE due to user configuration
		// (might have been changed to WAL before)
		rc = sqlite3_exec(querydb, "PRAGMA journal_mode=DELETE", NULL, NULL, NULL);
		if( rc != SQLITE_OK )
		{
			snprintf(error, size, "cannot set journal mode DELETE: %s", sqlite3_errstr(rc));
			sqlite3_close(querydb);
			querydb = NULL;
			return false;
		}
	}

	// Enable memory-mapped I/O for the on-disk database to eliminate
	// pread() syscall overhead during startup imports and periodic
	// exports. Without mmap, SQLite reads pages via pread() which the
	// kernel caches AND SQLite caches separately (two copies). With
	// mmap, SQLite reads directly from the kernel page cache via a
	// virtual address mapping — one copy, shared. 256 MiB is a
	// ceiling: for databases larger than this, pages beyond 256 MiB
	// fall back to regular pread() I/O transparently. Silently falls
	// back entirely on systems where mmap is unavailable.
	//
	// No posix_fadvise() pre-warming here (unlike gravity.db) because
	// pihole-FTL.db can grow to multiple GB on busy networks. Pre-
	// warming the entire file would evict useful cached pages (gravity
	// B-tree, DNS cache) on memory-constrained systems. The mmap alone
	// is sufficient: pages fault in on demand during import.
	if((rc = sqlite3_exec(querydb, "PRAGMA mmap_size = 268435456", NULL, NULL, NULL)) != SQLITE_OK)
		log_warn("open_query_database(): Error enabling mmap for disk database: %s",
		         sqlite3_errstr(rc));

	return true;
}

// Open the query database: new queries continue above the highest ID on disk,
// the history window is counted for the import, which the database thread
// does, and queries go to disk at every export
void init_query_database(void)
{
	// Clear process-local addinfo ID cache
	clear_addinfo_id_cache();

	// The database thread's connection, for the import and the export
	char error[128] = "the database is not usable";
	const bool opened = !FTLDBerror() && open_query_database(error, sizeof(error));

	// New queries continue above the highest ID on disk
	sqlite3_int64 maxid = -1;
	disk_db_maxid(&maxid);
	lock_shm();
	counters->next_query_id = maxid + 1;
	unlock_shm();

	// Flush messages stored in the long-term database
	flush_message_table();

	if(opened)
	{
		// Compensate for possible jumps in time
		runGC(time(NULL), NULL, false);

		// Try to import queries from long-term database if available
		// Skip if we are not supposed to load queries from disk
		if(config.database.DBimport.v.b)
			count_queries_on_disk();
	}
	else
		// Without the connection no query is stored until FTL is restarted
		log_query_database_error(config.files.database.v.s, error);
}

// Close the query database
void close_query_database(void)
{
	if(querydb == NULL)
		return;

	const int rc = sqlite3_close(querydb);
	if(rc != SQLITE_OK)
		log_err("Closing the query database failed: %s", sqlite3_errstr(rc));
	else
		log_debug(DEBUG_DATABASE, "Closed the query database");
	querydb = NULL;
}

// Abort a statement currently running on the query database. Used when FTL
// terminates while the initial query import is still running. Only then: an
// interrupt still pending when the connection is closed skips its checkpoint
void interrupt_import(void)
{
	if(querydb != NULL && !db_import_done)
		sqlite3_interrupt(querydb);
}

// Attach database using specified path and alias
bool attach_database(sqlite3* db, const char **message, const char *path, const char *alias)
{
	int rc;
	bool okay = false;
	sqlite3_stmt *stmt = NULL;

	// Only try to attach database if it is not known to be broken
	if(FTLDBerror())
		return false;

	log_debug(DEBUG_DATABASE, "ATTACH %s AS %s", path, alias);

	// ATTACH database file on-disk
	rc = sqlite3_prepare_v2(db, "ATTACH ? AS ?", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("attach_database(): Prepare error: %s", sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
		return false;
	}

	// Bind path to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("attach_database(): Failed to bind path: %s",
		        sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind alias to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, alias, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("attach_database(): Failed to bind alias: %s",
		        sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
	{
		log_err("attach_database(): Failed to attach database: %s",
		        sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
	}

	// Finalize statement
	sqlite3_finalize(stmt);

	return okay;
}

// Detach a previously attached database by its alias
bool detach_database(sqlite3* db, const char **message, const char *alias)
{
	int rc;
	bool okay = false;
	sqlite3_stmt *stmt = NULL;

	log_debug(DEBUG_DATABASE, "DETACH %s", alias);

	// DETACH database file on-disk
	rc = sqlite3_prepare_v2(db, "DETACH ?", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("detach_database(): Prepare error: %s", sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
		return false;
	}

	// Bind alias to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, alias, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("detach_database(): Failed to bind alias: %s",
		        sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
	{
		log_err("detach_database(): Failed to detach database: %s",
		        sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
	}

	// Finalize statement
	sqlite3_finalize(stmt);

	return okay;
}

// Get the number of queries in the on-disk database and the time of the
// earliest one
static uint64_t get_number_of_queries_in_DB(sqlite3 *db, double *earliest_timestamp)
{
	int rc = 0;
	uint64_t num = 0;
	sqlite3_stmt *stmt = NULL;

	// Two subqueries so that COUNT(*) and MIN() each get SQLite's fast path,
	// combined in one SELECT they fall back to reading every row
	rc = sqlite3_prepare_v2(db, "SELECT (SELECT COUNT(*) FROM query_storage), "
	                               "(SELECT MIN(timestamp) FROM query_storage)", -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		if(rc != SQLITE_BUSY)
			log_err("get_number_of_queries_in_DB(): Prepare error: %s", sqlite3_errstr(rc));
		return 0;
	}
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Get count from first column
		num = sqlite3_column_int64(stmt, 0);
		// Get timestamp from second column if requested
		*earliest_timestamp = sqlite3_column_double(stmt, 1);
	}
	sqlite3_finalize(stmt);

	return num;
}

static double import_from = 0.0;
static double import_until = 0.0;
static int counted_queries = 0;
static sqlite3_int64 import_min_id = 0;

// The history window of the import at startup
void get_import_window(double *from, double *until)
{
	*from = import_from;
	*until = import_until;
}

// Position of the first query the export has not stored yet, counted in
// absolute terms (index + get_queries_removed()) so the garbage collector
// removing queries from the front does not invalidate it. Guarded by the SHM
// lock
static unsigned int export_pos = 0;

// Index of that query in the queries array, the end of the array if the
// connection of the export could not be opened at startup: nothing waits for
// an export then. The caller holds the SHM lock
unsigned int __attribute__((pure)) get_export_index(void)
{
	if(querydb == NULL)
		return counters->queries;

	// Both counters wrap at UINT_MAX, their difference does not. A position
	// the garbage collector has already removed comes out above the array
	const unsigned int idx = export_pos - get_queries_removed();
	return idx <= counters->queries ? idx : 0;
}

// Count the queries of the history window on disk and reserve their slots in
// shared memory, the import fills them in the database thread. Live queries
// coming in meanwhile take the slots above
static bool count_queries_on_disk(void)
{
	// Set time range for counting queries
	import_until = double_time();
	import_from = import_until - config.webserver.api.maxHistory.v.ui;

	// The import reads the IDs from the lowest one of the window upwards
	counted_queries = DB_FAILED;
	sqlite3_stmt *stmt = NULL;
	if(sqlite3_prepare_v2(querydb, "SELECT COUNT(*), IFNULL(MIN(id), 0) FROM query_storage "
	                               "WHERE timestamp BETWEEN ?1 AND ?2", -1, &stmt, NULL) == SQLITE_OK &&
	   sqlite3_bind_double(stmt, 1, import_from) == SQLITE_OK &&
	   sqlite3_bind_double(stmt, 2, import_until) == SQLITE_OK &&
	   sqlite3_step(stmt) == SQLITE_ROW)
	{
		counted_queries = sqlite3_column_int(stmt, 0);
		import_min_id = sqlite3_column_int64(stmt, 1);
	}
	sqlite3_finalize(stmt);
	log_debug(DEBUG_DATABASE, "count_queries_on_disk(): Going to import %i queries from disk database",
	          counted_queries);

	// A failed query reports DB_FAILED, which is negative. counters->queries
	// is unsigned and init_queries_shm_sz() sizes the queries object from it,
	// so letting that through asks for an allocation of nearly the whole
	// address space and takes the startup down
	if(counted_queries < 0)
	{
		log_err("count_queries_on_disk(): Cannot count queries on disk");

		// Zero rather than leave the sentinel in this static: the import
		// compares its own progress against it further down
		counted_queries = 0;
		return false;
	}

	// Lock shared memory
	lock_shm();
	// Set query counter high enough so that the subsequent lock_shm() call
	// enlarges the queries object
	counters->queries = counted_queries;
	init_queries_shm_sz();
	// The slots reserved for the import are already in the database, the
	// export starts above them
	export_pos = counted_queries + get_queries_removed();
	// Unlock shared memory
	unlock_shm();

	return true;
}

/**
 * @brief Retrieve query count and earliest timestamp on disk or in memory.
 *
 * @param disk If true, read values of the on-disk database; if false, of the queries in shared memory.
 * @param[out] count Pointer to a uint64_t that will be set to the number of queries, or NULL.
 * @param[out] earliest_timestamp Pointer to a double that will be set to the earliest query timestamp, or NULL.
 *
 * In memory, the queries made at the maximum privacy level are not counted,
 * as the query log does not show them.
 */
void get_db_info(const bool disk, uint64_t *count, double *earliest_timestamp)
{
	if(disk)
	{
		if(count != NULL)
			*count = diskdb_queries_count;
		if(earliest_timestamp != NULL)
			*earliest_timestamp = diskdb_earliest_timestamp;
		return;
	}

	lock_shm();
	if(count != NULL)
		*count = counters->queries - counters->queries_maxprivacy - counters->hidden_queries;
	if(earliest_timestamp != NULL)
	{
		// No query is older than the first one by more than the disorder.
		// While the import runs, its slots are still empty and the query
		// log reads the window of the import from the disk
		const queriesData *oldest = db_import_done && counters->queries > 0 ? getQuery(0, true) : NULL;
		*earliest_timestamp = oldest != NULL ? oldest->timestamp - counters->query_time_disorder :
		                      db_import_done ? 0.0 : import_from;
	}
	unlock_shm();
}

// Log the size of the database and how many old queries were deleted from it
void log_deleted_old_queries(const int64_t deleted, const bool complete)
{
	struct stat st;
	get_FTL_db_stats(&st);
	log_info("Size of %s is %.2f MB, deleted %"PRId64" of %"PRIu64" rows%s",
	         config.files.database.v.s, 9.5367431640625e-07*st.st_size,
	         deleted, diskdb_queries_count, complete ? "" : " (interrupted)");
}

// Delete the oldest queries with a timestamp up to <until> from the on-disk
// database, at most DATABASE_DELETE_BATCH per call and each batch committed on
// its own. <deleted> adds up over the calls. Returns true while more are left
bool delete_old_queries_batch(sqlite3 *db, const double until, int64_t *deleted)
{
	// The database could not be opened
	if(db == NULL)
	{
		log_deleted_old_queries(*deleted, false);
		return false;
	}

	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, "DELETE FROM query_storage WHERE id IN "
	                                "(SELECT id FROM query_storage WHERE timestamp <= ? "
	                                "ORDER BY timestamp LIMIT ?)",
	                            -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("delete_old_queries_batch(): SQL error prepare: %s", sqlite3_errstr(rc));
		log_deleted_old_queries(*deleted, false);
		return false;
	}

	if((rc = sqlite3_bind_double(stmt, 1, until)) != SQLITE_OK ||
	   (rc = sqlite3_bind_int(stmt, 2, DATABASE_DELETE_BATCH)) != SQLITE_OK)
	{
		log_err("delete_old_queries_batch(): Failed to bind: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		log_deleted_old_queries(*deleted, false);
		return false;
	}

	rc = sqlite3_step(stmt);
	const int64_t changes = sqlite3_changes64(db);
	sqlite3_finalize(stmt);
	if(rc != SQLITE_DONE)
	{
		log_err("delete_old_queries_batch(): Failed to delete queries with timestamp <= %f: %s",
		        until, sqlite3_errstr(rc));
		log_deleted_old_queries(*deleted, false);
		return false;
	}

	*deleted += changes;
	diskdb_queries_count = (uint64_t)changes <= diskdb_queries_count ?
	                       diskdb_queries_count - (uint64_t)changes : 0u;
	log_debug(DEBUG_DATABASE, "Deleted %"PRId64" queries with timestamp <= %f", changes, until);

	if(changes >= DATABASE_DELETE_BATCH)
		return true;

	diskdb_earliest_timestamp = until;
	log_deleted_old_queries(*deleted, true);

	return false;
}

// Delete queries from the on-disk database that are not older than the given
// timestamp. Used when flushing the logs.
bool delete_recent_queries_from_db(const double mintime)
{
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return false;

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, "DELETE FROM query_storage WHERE timestamp >= ?", -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("delete_recent_queries_from_db(): SQL error prepare: %s", sqlite3_errstr(rc));
		dbclose(&db);
		return false;
	}

	// Bind index
	if((rc = sqlite3_bind_double(stmt, 1, mintime)) != SQLITE_OK)
	{
		log_err("delete_recent_queries_from_db(): Failed to bind timestamp: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		dbclose(&db);
		return false;
	}

	// Perform step
	bool okay = false;
	int64_t deleted = 0;
	if((rc = step_and_count(db, stmt, &deleted, NULL)) == SQLITE_DONE)
		okay = true;
	else
		log_err("delete_recent_queries_from_db(): Failed to delete queries with timestamp >= %f: %s",
		        mintime, sqlite3_errstr(rc));

	// Update number of queries in the on-disk database. Guard against
	// underflow: if the counter is somehow already below the number
	// deleted (e.g. after a failed import that set the counter to 0), clamp
	// to 0 rather than wrapping to UINT64_MAX.
	if(okay)
		diskdb_queries_count = (uint64_t)deleted <= diskdb_queries_count
		                       ? diskdb_queries_count - (uint64_t)deleted : 0u;

	// Finalize statement
	sqlite3_finalize(stmt);

	// Get size of on-disk database
	struct stat st;
	get_FTL_db_stats(&st);

	// Log size of database and number of deleted rows
	log_info("Size of %s is %.2f MB, deleted %"PRId64" of %"PRIu64" rows",
		config.files.database.v.s, 9.5367431640625e-07*st.st_size,
		deleted, diskdb_queries_count);

	// Close on-disk database
	dbclose(&db);

	return okay;
}

bool add_additional_info_column(sqlite3 *db)
{
	// Start transaction
	SQL_bool(db, "BEGIN");

	// Add column additinal_info to queries table
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN additional_info TEXT;");

	// Update the database version to 7
	if(!db_set_FTL_property(db, DB_VERSION, 7))
	{
		log_err("add_additional_info_column(): Failed to update database version!");
		return false;
	}

	// End transaction
	SQL_bool(db, "END");

	return true;
}

bool add_query_storage_columns(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN");

	// Add additional columns to the query_storage table
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN reply_type INTEGER");
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN reply_time REAL");
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN dnssec INTEGER");

	// Update VIEW queries
	SQL_bool(db, "DROP VIEW queries");
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "CASE typeof(additional_info) WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info, "
	                       "reply_type, reply_time, dnssec "
	                       "FROM query_storage q");

	// Update database version to 12
	if(!db_set_FTL_property(db, DB_VERSION, 12))
	{
		log_err("add_query_storage_columns(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

bool add_query_storage_column_regex_id(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN");

	// Add additional column to the query_storage table
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN regex_id INTEGER");

	// Update VIEW queries
	SQL_bool(db, "DROP VIEW queries");
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "CASE typeof(additional_info) WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info, "
	                       "reply_type, reply_time, dnssec, regex_id "
	                       "FROM query_storage q");

	// Update database version to 13
	if(!db_set_FTL_property(db, DB_VERSION, 13))
	{
		log_err("add_query_storage_column_regex_id(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

bool add_ftl_table_description(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN");

	// Add additional column to the ftl table
	SQL_bool(db, "ALTER TABLE ftl ADD COLUMN description TEXT");

	// Update ftl table
	SQL_bool(db, "UPDATE ftl SET description = 'Database version' WHERE id = %d", DB_VERSION);
	SQL_bool(db, "UPDATE ftl SET description = 'Unix timestamp of the latest stored query' WHERE id = %d", DB_LASTTIMESTAMP);
	SQL_bool(db, "UPDATE ftl SET description = 'Unix timestamp of the database creation' WHERE id = %d", DB_FIRSTCOUNTERTIMESTAMP);

	// Update database version to 14
	if(!db_set_FTL_property(db, DB_VERSION, 14))
	{
		log_err("add_query_storage_column_regex_id(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

bool rename_query_storage_column_regex_id(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN");

	// Rename column regex_id to list_id
	SQL_bool(db, "ALTER TABLE query_storage RENAME COLUMN regex_id TO list_id;");

	// The VIEW queries is automatically updated by SQLite3

	// Update database version to 17
	if(!db_set_FTL_property(db, DB_VERSION, 17))
	{
		log_err("rename_query_storage_column_regex_id(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

bool add_query_storage_column_ede(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN");

	// Add additional column to the query_storage table
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN ede INTEGER");

	// Update VIEW queries
	SQL_bool(db, "DROP VIEW queries");
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "CASE typeof(additional_info) WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info, "
	                       "reply_type, reply_time, dnssec, list_id, ede "
	                       "FROM query_storage q");

	// Update database version to 21
	if(!db_set_FTL_property(db, DB_VERSION, 21))
	{
		log_err("add_query_storage_column_ede(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

bool replace_queries_view_with_joins(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN");

	// Replace the queries VIEW definition: use LEFT JOINs instead of
	// correlated subqueries. The old VIEW executed 4 SELECT subqueries per
	// row; the new one uses JOINs which are evaluated once for the entire
	// result set. This is dramatically faster for users querying the
	// database via the sqlite3 CLI or third-party tools.
	SQL_bool(db, "DROP VIEW IF EXISTS queries");
	SQL_bool(db, "CREATE VIEW queries AS "
	             "SELECT q.id, q.timestamp, q.type, q.status, "
	               "COALESCE(d.domain, q.domain) AS domain, "
	               "COALESCE(c.ip, q.client) AS client, "
	               "COALESCE(f.forward, q.forward) AS forward, "
	               "COALESCE(a.content, q.additional_info) AS additional_info, "
	               "q.reply_type, q.reply_time, q.dnssec, q.list_id, q.ede "
	             "FROM query_storage q "
	             "LEFT JOIN domain_by_id d ON q.domain = d.id "
	             "LEFT JOIN client_by_id c ON q.client = c.id "
	             "LEFT JOIN forward_by_id f ON q.forward = f.id "
	             "LEFT JOIN addinfo_by_id a ON q.additional_info = a.id");

	// Update database version to 22
	if(!db_set_FTL_property(db, DB_VERSION, 22))
	{
		log_err("replace_queries_view_with_joins(): Failed to update database version!");
		dbquery(db, "ROLLBACK");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

bool optimize_queries_table(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION;");

	// Create link tables for domain, client, and forward strings
	SQL_bool(db, "CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);");
	SQL_bool(db, "CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);");
	SQL_bool(db, "CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT NOT NULL);");

	// Create UNIQUE index for the new tables
	SQL_bool(db, "CREATE UNIQUE INDEX domain_by_id_domain_idx ON domain_by_id(domain);");
	SQL_bool(db, "CREATE UNIQUE INDEX client_by_id_client_idx ON client_by_id(ip,name);");
	SQL_bool(db, "CREATE UNIQUE INDEX forward_by_id_forward_idx ON forward_by_id(forward);");

	// Rename current queries table
	SQL_bool(db, "ALTER TABLE queries RENAME TO query_storage;");

	// Change column definitions of the queries_storage table to allow
	// integer IDs. If we would leave the column definitions as TEXT, we
	// could not tell apart integer IDs easily as everything INSERTed would
	// be converted to TEXT form (this is very inefficient)
	// We have to turn off defensive mode to do this.
	SQL_bool(db, "PRAGMA writable_schema = ON;");
	SQL_bool(db, "UPDATE sqlite_master SET sql = 'CREATE TABLE \"query_storage\" (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL, forward INTEGER , additional_info TEXT)' WHERE type = 'table' AND name = 'query_storage';");
	SQL_bool(db, "PRAGMA writable_schema = OFF;");

	// Create VIEW queries so user scripts continue to work despite our
	// optimization here. The VIEW will pull the strings from the linked
	// tables when needed to always server the strings.
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "additional_info FROM query_storage q;");

	// Update database version to 10
	if(!db_set_FTL_property(db, DB_VERSION, 10))
	{
		log_err("optimize_queries_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

bool create_addinfo_table(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION;");

	// Create link table for additional_info column
	SQL_bool(db, "CREATE TABLE addinfo_by_id (id INTEGER PRIMARY KEY, type INTEGER NOT NULL, content NOT NULL);");

	// Create UNIQUE index for the new tables
	SQL_bool(db, "CREATE UNIQUE INDEX addinfo_by_id_idx ON addinfo_by_id(type,content);");

	// Change column definitions of the queries_storage table to allow
	// integer IDs. If we would leave the column definitions as TEXT, we
	// could not tell apart integer IDs easily as everything INSERTed would
	// be converted to TEXT form (this is very inefficient)
	// We have to turn off defensive mode to do this.
	SQL_bool(db, "PRAGMA writable_schema = ON;");
	SQL_bool(db, "UPDATE sqlite_master SET sql = 'CREATE TABLE \"query_storage\" (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL, forward INTEGER, additional_info INTEGER)' WHERE type = 'table' AND name = 'query_storage';");
	SQL_bool(db, "PRAGMA writable_schema = OFF;");

	// Create VIEW queries so user scripts continue to work despite our
	// optimization here. The VIEW will pull the strings from the linked
	// tables when needed to always server the strings.
	SQL_bool(db, "DROP VIEW queries");
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "CASE typeof(additional_info) WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info "
	                       "FROM query_storage q;");

	// Update database version to 11
	if(!db_set_FTL_property(db, DB_VERSION, 11))
	{
		log_err("create_addinfo_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "END");

	return true;
}

// Get most recent 24 hours data from long-term database
void DB_read_queries(void)
{
	// The columns of the queries view plus the client name, in the order of
	// the IDs for the client name history. As in the view, an ID without a
	// row in its linking table reads as NULL. The rows of the history window
	// are read from the lowest ID of the window upwards, the unary plus keeps
	// SQLite from reading them by the timestamp index and sorting them
	const char *querystr = "SELECT q.id, q.timestamp, q.type, q.status, "
	                              "CASE typeof(q.domain) WHEN 'integer' THEN d.domain ELSE q.domain END, "
	                              "CASE typeof(q.client) WHEN 'integer' THEN c.ip ELSE q.client END, "
	                              "CASE typeof(q.forward) WHEN 'integer' THEN f.forward ELSE q.forward END, "
	                              "CASE typeof(q.additional_info) WHEN 'integer' THEN a.content ELSE q.additional_info END, "
	                              "q.reply_type, q.reply_time, q.dnssec, q.list_id, q.ede, c.name "
	                       "FROM query_storage q "
	                       "LEFT JOIN domain_by_id d ON q.domain = d.id "
	                       "LEFT JOIN client_by_id c ON q.client = c.id "
	                       "LEFT JOIN forward_by_id f ON q.forward = f.id "
	                       "LEFT JOIN addinfo_by_id a ON q.additional_info = a.id "
	                       "WHERE q.id >= ?1 AND +q.timestamp BETWEEN ?2 AND ?3 "
	                       "ORDER BY q.id";

	// Only try to import from database if it is known to not be broken and
	// FTL has not been asked to terminate in the meantime
	if(FTLDBerror() || killed || querydb == NULL)
		return;

	// The rows on disk, for disk=true and /api/info/database, also when the
	// import below fails
	diskdb_queries_count = get_number_of_queries_in_DB(querydb, &diskdb_earliest_timestamp);

	// Nothing to read when no query on disk is in the history window. The
	// lowest ID of the window would be 0 then, the whole table
	if(counted_queries == 0)
	{
		log_info("Imported 0 queries from the long-term database (0 rows read, it has %"PRIu64")",
		         diskdb_queries_count);
		return;
	}

	log_info("Parsing queries in database");

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(querydb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("DB_read_queries() - SQL error prepare: %s", sqlite3_errstr(rc));
		return;
	}
	if((rc = sqlite3_bind_int64(stmt, 1, import_min_id)) != SQLITE_OK ||
	   (rc = sqlite3_bind_double(stmt, 2, import_from)) != SQLITE_OK ||
	   (rc = sqlite3_bind_double(stmt, 3, import_until)) != SQLITE_OK)
	{
		log_err("DB_read_queries() - Failed to bind the window: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return;
	}

	// Loop through returned database rows
	size_t imported_queries = 0, read_rows = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// Cancellation-point before the shared memory is locked: the
		// main thread tears down what the loop below uses once we are gone
		BREAK_IF_KILLED();
		read_rows++;

		const sqlite3_int64 dbID = sqlite3_column_int64(stmt, 0);
		const double queryTimeStamp = sqlite3_column_double(stmt, 1);
		// 1483228800 = 01/01/2017 @ 12:00am (UTC)
		if(queryTimeStamp < 1483228800)
		{
			log_warn("Database: TIMESTAMP of query should be larger than 01/01/2017 but is %f (DB ID %lli)",
			         queryTimeStamp, dbID);
			continue;
		}

		// Unmapped query types are stored as 100 + the DNS type (0 to 65535)
		const int type = sqlite3_column_int(stmt, 2);
		const bool mapped_type = type >= TYPE_NONE && type < TYPE_MAX;
		const bool offset_type = type >= 100 && type <= (100 + UINT16_MAX);
		if(!mapped_type && !offset_type)
		{
			log_warn("Database: TYPE should not be %i", type);
			continue;
		}

		const int status_int = sqlite3_column_int(stmt, 3);
		if(status_int < QUERY_UNKNOWN || status_int >= QUERY_STATUS_MAX)
		{
			log_warn("Database: STATUS should be within [%i,%i] but is %i",
			         QUERY_UNKNOWN, QUERY_STATUS_MAX-1, status_int);
			continue;
		}
		const enum query_status status = status_int;

		const char *domainname = (const char *)sqlite3_column_text(stmt, 4);
		if(domainname == NULL)
		{
			log_warn("Database: DOMAIN should never be NULL, ID = %lld, timestamp = %f",
			         dbID, queryTimeStamp);
			continue;
		}

		const char *clientIP = (const char *)sqlite3_column_text(stmt, 5);
		if(clientIP == NULL)
		{
			log_warn("Database: CLIENT should never be NULL, ID = %lld, timestamp = %f",
			         dbID, queryTimeStamp);
			continue;
		}

		// Check if user wants to skip queries coming from localhost
		if(config.dns.ignoreLocalhost.v.b &&
		   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
		{
			continue;
		}

		const int reply_int = sqlite3_column_int(stmt, 8);
		if(reply_int < REPLY_UNKNOWN || reply_int >= QUERY_REPLY_MAX)
		{
			log_warn("Database: REPLY should be within [%i,%i] but is %i, ID = %lld, timestamp = %f",
			         REPLY_UNKNOWN, QUERY_REPLY_MAX-1, reply_int, dbID, queryTimeStamp);
			continue;
		}
		const enum reply_type reply = reply_int;

		const int dnssec_int = sqlite3_column_int(stmt, 10);
		if(dnssec_int < DNSSEC_UNKNOWN || dnssec_int >= DNSSEC_MAX)
		{
			log_warn("Database: REPLY should be within [%i,%i] but is %i, ID = %lld, timestamp = %f",
			         DNSSEC_UNKNOWN, DNSSEC_MAX-1, dnssec_int, dbID, queryTimeStamp);
			continue;
		}
		const enum dnssec_status dnssec = dnssec_int;

		double reply_time = 0.0;
		bool reply_time_avail = false;
		if(sqlite3_column_type(stmt, 9) == SQLITE_FLOAT)
		{
			// The field has been added for database version 12
			reply_time = sqlite3_column_double(stmt, 9);
			reply_time_avail = true;
			if(reply_time < 0.0)
			{
				log_warn("REPLY_TIME value %f is invalid, ID = %lld, timestamp = %f",
				         reply_time, dbID, queryTimeStamp);
				continue;
			}
		}

		// All slots reserved for the import are taken: the database has
		// more rows than were counted
		if((int)imported_queries >= counted_queries)
		{
			log_warn("Database %s has changed during import: Expected to import %i queries. Parts of the history may be missing.",
			         config.files.database.v.s, counted_queries);
			break;
		}

		// Rows are only skipped above this point, so a skipped row leaves
		// nothing behind in shared memory and an imported one fills its
		// slot completely

		// Lock shared memory
		lock_shm();

		const char *buffer = NULL;
		int upstreamID = -1; // Default if not forwarded
		// Try to extract the upstream from the "forward" column if non-empty
		if(sqlite3_column_bytes(stmt, 6) > 0 &&
		   (buffer = (const char *)sqlite3_column_text(stmt, 6)) != NULL)
		{
			// Get IP address and port of upstream destination
			char serv_addr[INET6_ADDRSTRLEN + 16] = { 0 };
			unsigned int serv_port = 53;
			// We limit the number of bytes written into the serv_addr buffer
			// to prevent buffer overflows. If there is no port available in
			// the database, we skip extracting them and use the default port
			sscanf(buffer, "%"xstr(INET6_ADDRSTRLEN)"[^#]#%u", serv_addr, &serv_port);
			serv_addr[INET6_ADDRSTRLEN + 15] = '\0';
			upstreamID = findUpstreamID(serv_addr, (in_port_t)serv_port);
		}

		// Set index for this query
		const int queryIndex = imported_queries++;

		// Obtain IDs only after filtering which queries we want to keep
		const int timeidx = getOverTimeID(queryTimeStamp);
		const int domainID = findDomainID(domainname, true, false);
		const int clientID = findClientID(clientIP, true, false, queryTimeStamp, false);

		// The query keeps the client name it was stored with
		const char *clientName = (const char *)sqlite3_column_text(stmt, 13);
		name_history_import(clientID, dbID, addstr(clientName != NULL ? clientName : ""));

		// Store this query in memory, it keeps its ID from the database
		queriesData *query = getQuery(queryIndex, false);
		query->magic = MAGICBYTE;
		query->db = dbID;
		query->timestamp = queryTimeStamp;
		if(mapped_type)
			query->type = type;
		else
		{
			// Offset query type
			query->type = TYPE_OTHER;
			query->qtype = type - 100;
		}
		counters->querytype[query->type]++;
		log_debug(DEBUG_STATUS, "query type %d set (database), ID = %u, new count = %u", query->type, counters->queries, counters->querytype[query->type]);

		// Status is set below
		query->domainID = domainID;
		query->clientID = clientID;
		query->upstreamID = upstreamID;
		// An imported query holds no per-client DNS cache entry, the
		// blocking decisions of this run are made by live queries
		query->cacheID = -1;
		// No dnsmasq ID belongs to an imported query
		query->id = -1;
		query->response = 0;
		query->flags.response_calculated = reply_time_avail;
		query->dnssec = dnssec;
		query->reply = reply;
		counters->reply[query->reply]++;
		log_debug(DEBUG_STATUS, "reply type %u set (database), ID = %u, new count = %u", query->reply, counters->queries, counters->reply[query->reply]);
		query->response = reply_time;
		query->CNAME_domainID = -1;
		// Initialize flags
		query->flags.complete = true; // Mark as all information is available
		query->flags.blocked = false;
		query->flags.allowed = false;
		// List ID and extended DNS error, NULL counts as none
		query->list_id = sqlite3_column_type(stmt, 11) == SQLITE_INTEGER ? sqlite3_column_int(stmt, 11) : -1;
		query_set_ede(query, sqlite3_column_type(stmt, 12) == SQLITE_INTEGER ? sqlite3_column_int(stmt, 12) : -1);

		// Set lastQuery timer for network table
		clientsData *client = getClient(clientID, true);
		client->lastQuery = queryTimeStamp;

		// Update client's overTime data structure
		change_clientcount(client, 0, 0, timeidx, 1, false);

		// Get domain pointer
		domainsData *domain = getDomain(domainID, true);
		domain->lastQuery = queryTimeStamp;

		// Get additional information from the additional_info column if applicable
		if(status == QUERY_GRAVITY_CNAME ||
		   status == QUERY_REGEX_CNAME ||
		   status == QUERY_DENYLIST_CNAME )
		{
			// QUERY_*_CNAME: Get domain causing the blocking
			const char *CNAMEdomain = (const char *)sqlite3_column_text(stmt, 7);
			if(CNAMEdomain != NULL && strlen(CNAMEdomain) > 0)
			{
				// Add domain to FTL's memory but do not count it. Seeing a
				// domain in the middle of a CNAME trajectory does not mean
				// it was queried intentionally.
				const int CNAMEdomainID = findDomainID(CNAMEdomain, false, false);
				query->CNAME_domainID = CNAMEdomainID;

				// Get domain pointer and update lastQuery timer
				domainsData *cdomain = getDomain(CNAMEdomainID, true);
				if(cdomain != NULL)
				{
					cdomain->lastQuery = queryTimeStamp;
					cdomain->cname_refcount++;
				}
			}
		}

		// Increment status counters
		query_set_status_init(query, status);

		// Do further processing based on the query status we read from the database
		switch(status)
		{
			case QUERY_UNKNOWN: // Unknown
				break;

			case QUERY_GRAVITY: // Blocked by gravity
			case QUERY_REGEX: // Blocked by regex denylist
			case QUERY_DENYLIST: // Blocked by exact denylist
			case QUERY_EXTERNAL_BLOCKED_IP: // Blocked upstream
			case QUERY_EXTERNAL_BLOCKED_NULL: // Blocked upstream
			case QUERY_EXTERNAL_BLOCKED_NXRA: // Blocked upstream
			case QUERY_EXTERNAL_BLOCKED_EDE15: // Blocked upstream
			case QUERY_GRAVITY_CNAME: // Blocked by gravity (inside CNAME path)
			case QUERY_REGEX_CNAME: // Blocked by regex denylist (inside CNAME path)
			case QUERY_DENYLIST_CNAME: // Blocked by exact denylist (inside CNAME path)
			case QUERY_DBBUSY: // Blocked because gravity database was busy
			case QUERY_SPECIAL_DOMAIN: // Blocked by special domain handling
				query->flags.blocked = true;
				// Get domain pointer
				domain->blockedcount++;
				change_clientcount(client, 0, 1, -1, 0, false);
				break;

			case QUERY_FORWARDED: // Forwarded
			case QUERY_RETRIED: // (fall through)
			case QUERY_RETRIED_DNSSEC: // (fall through)
				// Only update upstream if there is one (there
				// won't be one for retried DNSSEC queries)
				if(upstreamID > -1)
				{
					upstreamsData *upstream = getUpstream(upstreamID, true);
					if(upstream != NULL)
					{
						upstream->lastQuery = queryTimeStamp;
						upstream->count++;
						query->flags.upstream_counted = true;
					}
				}
				break;

			case QUERY_CACHE: // Cached or local config
			case QUERY_CACHE_STALE:
				// Nothing to be done here
				break;

			case QUERY_IN_PROGRESS:
				// Nothing to be done here
				break;

			case QUERY_STATUS_MAX:
			default:
				log_warn("Found unknown status %i in long term database, ID = %lld, timestamp = %f",
				         status, dbID, queryTimeStamp);
				break;
		}

		log_debug(DEBUG_DATABASE, "Imported query %d: time=%f, type=%d, status=%d, domain='%s', client='%s'",
		          queryIndex, queryTimeStamp, type, status, domainname, clientIP);

		if(imported_queries % 10000 == 0)
			log_info("  %zu queries parsed...", imported_queries);

		// Unlock shared memory
		unlock_shm();
	}

	if(killed)
		log_info("Aborted import after %zu queries, FTL is shutting down", imported_queries);
	else if( rc == SQLITE_DONE )
		log_info("Imported %zu queries from the long-term database (%zu rows read, it has %"PRIu64")",
		         imported_queries, read_rows, diskdb_queries_count);
	else
		log_err("DB_read_queries() - SQL error step: %s", sqlite3_errstr(rc));

	if(!killed && (int)imported_queries < counted_queries)
	{
		log_warn("Database %s has changed during import: Expected to import %i queries, but found only %zu",
		         config.files.database.v.s, counted_queries, imported_queries);

		// Slots reserved for rows skipped above are still empty. Move
		// the queries that arrived during the import down so the array
		// has no gaps the GC or the export would trip over
		lock_shm();
		const unsigned int gap = counted_queries - imported_queries;
		for(unsigned int i = counted_queries; i < counters->queries; i++)
		{
			queriesData *src = getQuery(i, false);
			queriesData *dst = getQuery(i - gap, false);
			if(src == NULL || dst == NULL)
				break;
			*dst = *src;
			memset(src, 0, sizeof(*src));
		}
		counters->queries -= gap;
		// The moved queries are not exported yet
		export_pos -= gap;

		// Invalidate the query ID cache since the indices shifted
		queryIDMap_clear();
		unlock_shm();
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);
}

// The highest query ID on disk, -1 if there is none. New queries continue
// above it, and so does the export
static bool disk_db_maxid(sqlite3_int64 *maxid)
{
	*maxid = -1;
	if(FTLDBerror() || querydb == NULL)
		return false;

	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(querydb, "SELECT IFNULL(MAX(id), -1) FROM query_storage", -1, &stmt, NULL);
	const bool okay = rc == SQLITE_OK && (rc = sqlite3_step(stmt)) == SQLITE_ROW;
	if(okay)
		*maxid = sqlite3_column_int64(stmt, 0);
	else
		log_err("disk_db_maxid(): Failed to get MAX(id) from query_storage: %s",
		        sqlite3_errstr(rc));
	sqlite3_finalize(stmt);

	log_debug(DEBUG_DATABASE, "Last long-term idx is %"PRId64, (int64_t)*maxid);
	return okay;
}

// The export takes this many queries from shared memory under one hold of the
// SHM lock, as the query log does
#define EXPORT_CHUNK 64
// Room for the strings of the linking rows of one chunk. A string in shared
// memory is at most a page long, a chunk ends early when the room runs out
#define EXPORT_ROOM 65536

// A linking row whose ID on disk is not known yet, with the strings it is found
// by and the positions of the strings in shared memory. Its ID goes back to
// shared memory once the run is committed, and only if the entry still has the
// same strings
struct found_row {
	int db_id;
	size_t pos;
	size_t pos2;
};

// One query as the export takes it from shared memory
struct export_row {
	sqlite3_int64 id;
	double timestamp;
	double response;
	int type;
	int status;
	int reply;
	int dnssec;
	int list_id;
	int ede;
	bool response_calculated;
	bool blocked;
	bool hide_domain;
	bool hide_client;
	bool hide_cname;
	// The rows on disk, 0 while not known
	int domain_db_id;
	int client_db_id;
	int upstream_db_id;
	int addinfo_id;
	// The entries their IDs are kept with in shared memory, -1 if none: the
	// domain and the client are hidden or the client was renamed since
	int domainID;
	int clientID;
	int upstreamID;
	struct found_row domain_at, client_at, upstream_at;
	// ADDINFO_CNAME_DOMAIN with the CNAME domain's ID (-1 if hidden),
	// ADDINFO_LIST_ID with the list ID, or -1 for none
	int addinfo_type;
	int addinfo_key;
	// Strings of the rows not known yet, NULL otherwise
	const char *domain;
	const char *client_ip;
	const char *client_name;
	const char *upstream;
	const char *cname;
};

struct found_addinfo {
	int type;
	int key;
	int db_id;
};

// The state of one export run
struct export_run {
	sqlite3_stmt *stmts[9];
	// The rows found in this run, by shared-memory ID
	struct found_row *domains, *clients, *upstreams;
	unsigned int n_domains, n_clients, n_upstreams;
	struct found_addinfo *addinfo;
	unsigned int n_addinfo, cap_addinfo;
	// The strings of the current chunk
	char *room;
	size_t used;
	// The highest ID on disk before the run, and what the run stored. Rows
	// other processes have stored are not stored again
	sqlite3_int64 maxid;
	unsigned int inserted;
	unsigned int blocked;
	double newest;
};

enum export_stmt {
	DOMAIN_INSERT, DOMAIN_SELECT,
	CLIENT_INSERT, CLIENT_SELECT,
	FORWARD_INSERT, FORWARD_SELECT,
	ADDINFO_INSERT, ADDINFO_SELECT,
	QUERY_INSERT
};

static const char *export_sql[] = {
	"INSERT OR IGNORE INTO domain_by_id (domain) VALUES (?1)",
	"SELECT id FROM domain_by_id WHERE domain = ?1",
	"INSERT OR IGNORE INTO client_by_id (ip,name) VALUES (?1,?2)",
	"SELECT id FROM client_by_id WHERE ip = ?1 AND name = ?2",
	"INSERT OR IGNORE INTO forward_by_id (forward) VALUES (?1)",
	"SELECT id FROM forward_by_id WHERE forward = ?1",
	"INSERT OR IGNORE INTO addinfo_by_id (type,content) VALUES (?1,?2)",
	"SELECT id FROM addinfo_by_id WHERE type = ?1 AND content = ?2",
	"INSERT INTO query_storage VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"
};

// Copy a string of shared memory into the room of the chunk, NULL if it does
// not fit. The caller holds the SHM lock
static const char *room_copy(struct export_run *run, const char *str)
{
	const size_t len = strlen(str) + 1;
	if(run->used + len > EXPORT_ROOM)
		return NULL;
	char *copy = run->room + run->used;
	memcpy(copy, str, len);
	run->used += len;
	return copy;
}

// The ID of a row found earlier in this run for the entry with these strings,
// 0 if none
static int __attribute__((pure)) found_id(const struct found_row *rows, const unsigned int n,
                                          const int id, const struct found_row *at)
{
	if(rows == NULL || id < 0 || (unsigned int)id >= n)
		return 0;
	const struct found_row *row = &rows[id];
	return row->pos == at->pos && row->pos2 == at->pos2 ? row->db_id : 0;
}

// The ID of an addinfo row found earlier in this run, 0 if none
static int __attribute__((pure)) found_addinfo_id(const struct export_run *run, const int type, const int key)
{
	for(unsigned int i = 0; i < run->n_addinfo; i++)
		if(run->addinfo[i].type == type && run->addinfo[i].key == key)
			return run->addinfo[i].db_id;
	return 0;
}

// Take what the export needs from one query. False if the strings of its
// linking rows do not fit into the room of the chunk any more. The caller
// holds the SHM lock
static bool take_query(const queriesData *query, struct export_row *r, struct export_run *run)
{
	memset(r, 0, sizeof(*r));
	r->id = query->db;
	r->timestamp = query->timestamp;
	r->type = query->type != TYPE_OTHER ? query->type : query->qtype + 100;
	r->status = query->status;
	r->reply = query->reply;
	r->response = query->response;
	r->response_calculated = query->flags.response_calculated;
	r->dnssec = query->dnssec;
	r->list_id = query->list_id;
	r->ede = query_get_ede(query);
	r->blocked = query->flags.blocked;

	// DOMAIN - the row cached with a domain holds its name, a query hiding
	// the domain uses the row of the hidden domain instead
	r->hide_domain = query->privacylevel >= PRIVACY_HIDE_DOMAINS;
	r->domainID = -1;
	const domainsData *domain = getDomain(query->domainID, true);
	if(r->hide_domain)
		r->domain_db_id = hidden_domain_db_id;
	else if(domain != NULL)
	{
		r->domainID = query->domainID;
		r->domain_at.pos = domain->domainpos;
		r->domain_db_id = domain->flags.in_database ? domain->db_id :
		                  found_id(run->domains, run->n_domains, r->domainID, &r->domain_at);
	}
	if(r->domain_db_id == 0 && (r->domain = room_copy(run, getDomainString(query))) == NULL)
		return false;

	// CLIENT - the same applies to a query hiding its client. A query made
	// before its client was renamed has the old name, the row cached with
	// the client is the one of the current name
	r->hide_client = query->privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS;
	r->clientID = -1;
	const clientsData *client = getClient(query->clientID, true);
	if(r->hide_client)
		r->client_db_id = hidden_client_db_id;
	else if(client != NULL &&
	        client_name_at(query->clientID, client->namepos, query->db) == client->namepos)
	{
		r->clientID = query->clientID;
		r->client_at.pos = client->namepos;
		r->client_at.pos2 = client->ippos;
		r->client_db_id = client->flags.in_database ? client->db_id :
		                  found_id(run->clients, run->n_clients, r->clientID, &r->client_at);
	}
	if(r->client_db_id == 0 &&
	   ((r->client_ip = room_copy(run, getClientIPString(query))) == NULL ||
	    (r->client_name = room_copy(run, getClientNameString(query))) == NULL))
		return false;

	// FORWARD - the upstream a query was sent to, if any
	r->upstreamID = -1;
	const upstreamsData *upstream = query->upstreamID > -1 ? getUpstream(query->upstreamID, true) : NULL;
	if(upstream != NULL)
	{
		r->upstreamID = query->upstreamID;
		r->upstream_at.pos = upstream->ippos;
		r->upstream_at.pos2 = upstream->port;
		r->upstream_db_id = upstream->flags.in_database ? upstream->db_id :
		                    found_id(run->upstreams, run->n_upstreams, r->upstreamID, &r->upstream_at);
		if(r->upstream_db_id == 0)
		{
			char forward[64];
			const int len = snprintf(forward, sizeof(forward), "%s#%u", getstr(upstream->ippos), upstream->port);
			if(len > 0 && (size_t)len < sizeof(forward) && (r->upstream = room_copy(run, forward)) == NULL)
				return false;
		}
	}

	// ADDINFO - the domain of a CNAME that caused a block, otherwise the
	// list behind the verdict, if any
	r->addinfo_type = -1;
	if(query->status == QUERY_GRAVITY_CNAME ||
	   query->status == QUERY_REGEX_CNAME ||
	   query->status == QUERY_DENYLIST_CNAME)
	{
		r->addinfo_type = ADDINFO_CNAME_DOMAIN;
		r->hide_cname = query->privacylevel >= PRIVACY_HIDE_DOMAINS;
		r->addinfo_key = r->hide_cname ? -1 : query->CNAME_domainID;
		r->addinfo_id = r->hide_cname ? hidden_cname_db_id :
		                lookup_addinfo_id(ADDINFO_CNAME_DOMAIN, r->addinfo_key);
		if(r->addinfo_id == 0 && !r->hide_cname)
			r->addinfo_id = found_addinfo_id(run, ADDINFO_CNAME_DOMAIN, r->addinfo_key);
		if(r->addinfo_id == 0 && (r->cname = room_copy(run, getCNAMEDomainString(query))) == NULL)
			return false;
	}
	else if(query->list_id != -1)
	{
		r->addinfo_type = ADDINFO_LIST_ID;
		r->addinfo_key = query->list_id;
		r->addinfo_id = lookup_addinfo_id(ADDINFO_LIST_ID, r->addinfo_key);
		if(r->addinfo_id == 0)
			r->addinfo_id = found_addinfo_id(run, ADDINFO_LIST_ID, r->addinfo_key);
	}

	return true;
}

// Find the ID of a linking table row, inserting the row if it is new. The
// statements are bound by the caller, both are reset here
static int linking_id(sqlite3_stmt *ins, sqlite3_stmt *sel)
{
	int64_t changes = 0;
	sqlite3_int64 rowid = 0;
	int id = 0;
	if(step_and_count(querydb, ins, &changes, &rowid) == SQLITE_DONE)
	{
		if(changes > 0)
			id = (int)rowid;
		else if(sqlite3_step(sel) == SQLITE_ROW)
			id = sqlite3_column_int(sel, 0);
	}
	sqlite3_reset(ins);
	sqlite3_reset(sel);
	return id;
}

// Remember a row found in this run for the entry with the shared-memory ID id
static void remember_found(struct found_row **rows, const unsigned int n, const int id,
                           const int db_id, const struct found_row *at)
{
	if(id < 0 || (unsigned int)id >= n)
		return;
	if(*rows == NULL && (*rows = calloc(n, sizeof(**rows))) == NULL)
		return;
	(*rows)[id] = *at;
	(*rows)[id].db_id = db_id;
}

// Find or add the linking rows of one query that are not known yet. Without
// the SHM lock, the strings are copies
static bool find_linking_rows(struct export_row *r, struct export_run *run)
{
	sqlite3_stmt **s = run->stmts;
	if(r->domain_db_id == 0)
	{
		sqlite3_bind_text(s[DOMAIN_INSERT], 1, r->domain, -1, SQLITE_STATIC);
		sqlite3_bind_text(s[DOMAIN_SELECT], 1, r->domain, -1, SQLITE_STATIC);
		r->domain_db_id = linking_id(s[DOMAIN_INSERT], s[DOMAIN_SELECT]);
		if(r->hide_domain)
			hidden_domain_db_id = r->domain_db_id;
		else
			remember_found(&run->domains, run->n_domains, r->domainID, r->domain_db_id, &r->domain_at);
	}
	if(r->client_db_id == 0)
	{
		sqlite3_bind_text(s[CLIENT_INSERT], 1, r->client_ip, -1, SQLITE_STATIC);
		sqlite3_bind_text(s[CLIENT_INSERT], 2, r->client_name, -1, SQLITE_STATIC);
		sqlite3_bind_text(s[CLIENT_SELECT], 1, r->client_ip, -1, SQLITE_STATIC);
		sqlite3_bind_text(s[CLIENT_SELECT], 2, r->client_name, -1, SQLITE_STATIC);
		r->client_db_id = linking_id(s[CLIENT_INSERT], s[CLIENT_SELECT]);
		if(r->hide_client)
			hidden_client_db_id = r->client_db_id;
		else
			remember_found(&run->clients, run->n_clients, r->clientID, r->client_db_id, &r->client_at);
	}
	if(r->upstreamID > -1 && r->upstream_db_id == 0 && r->upstream != NULL)
	{
		sqlite3_bind_text(s[FORWARD_INSERT], 1, r->upstream, -1, SQLITE_STATIC);
		sqlite3_bind_text(s[FORWARD_SELECT], 1, r->upstream, -1, SQLITE_STATIC);
		r->upstream_db_id = linking_id(s[FORWARD_INSERT], s[FORWARD_SELECT]);
		remember_found(&run->upstreams, run->n_upstreams, r->upstreamID, r->upstream_db_id, &r->upstream_at);
	}
	if(r->addinfo_type > -1 && r->addinfo_id == 0)
	{
		sqlite3_bind_int(s[ADDINFO_INSERT], 1, r->addinfo_type);
		sqlite3_bind_int(s[ADDINFO_SELECT], 1, r->addinfo_type);
		if(r->addinfo_type == ADDINFO_CNAME_DOMAIN)
		{
			sqlite3_bind_text(s[ADDINFO_INSERT], 2, r->cname, -1, SQLITE_STATIC);
			sqlite3_bind_text(s[ADDINFO_SELECT], 2, r->cname, -1, SQLITE_STATIC);
		}
		else
		{
			sqlite3_bind_int(s[ADDINFO_INSERT], 2, r->addinfo_key);
			sqlite3_bind_int(s[ADDINFO_SELECT], 2, r->addinfo_key);
		}
		r->addinfo_id = linking_id(s[ADDINFO_INSERT], s[ADDINFO_SELECT]);
		if(r->hide_cname)
			hidden_cname_db_id = r->addinfo_id;
		else if(r->addinfo_id > 0)
		{
			if(run->n_addinfo == run->cap_addinfo)
			{
				const unsigned int cap = run->cap_addinfo > 0 ? 2 * run->cap_addinfo : 16;
				struct found_addinfo *grown = realloc(run->addinfo, cap * sizeof(*grown));
				if(grown != NULL)
				{
					run->addinfo = grown;
					run->cap_addinfo = cap;
				}
			}
			if(run->n_addinfo < run->cap_addinfo)
				run->addinfo[run->n_addinfo++] = (struct found_addinfo){ r->addinfo_type, r->addinfo_key, r->addinfo_id };
		}
	}

	return r->domain_db_id > 0 && r->client_db_id > 0 &&
	       (r->addinfo_type < 0 || r->addinfo_id > 0);
}

// Store one query on disk
static bool store_row(struct export_row *r, struct export_run *run)
{
	if(!find_linking_rows(r, run))
	{
		log_err("export_queries_to_disk(): Cannot store the linking rows of query %lld: %s",
		        (long long)r->id, sqlite3_errmsg(querydb));
		return false;
	}

	sqlite3_stmt *ins = run->stmts[QUERY_INSERT];
	sqlite3_bind_int64(ins, 1, r->id);
	sqlite3_bind_double(ins, 2, r->timestamp);
	sqlite3_bind_int(ins, 3, r->type);
	sqlite3_bind_int(ins, 4, r->status);
	sqlite3_bind_int(ins, 5, r->domain_db_id);
	sqlite3_bind_int(ins, 6, r->client_db_id);
	if(r->upstream_db_id > 0)
		sqlite3_bind_int(ins, 7, r->upstream_db_id);
	else
		sqlite3_bind_null(ins, 7);
	if(r->addinfo_id > 0)
		sqlite3_bind_int(ins, 8, r->addinfo_id);
	else
		sqlite3_bind_null(ins, 8);
	sqlite3_bind_int(ins, 9, r->reply);
	if(r->response_calculated)
		sqlite3_bind_double(ins, 10, r->response);
	else
		sqlite3_bind_null(ins, 10);
	sqlite3_bind_int(ins, 11, r->dnssec);
	if(r->list_id != -1)
		sqlite3_bind_int(ins, 12, r->list_id);
	else
		sqlite3_bind_null(ins, 12);
	sqlite3_bind_int(ins, 13, r->ede);

	const int rc = sqlite3_step(ins);
	sqlite3_reset(ins);
	if(rc != SQLITE_DONE)
	{
		log_err("export_queries_to_disk(): Failed to store query %lld: %s",
		        (long long)r->id, sqlite3_errstr(rc));
		return false;
	}

	run->inserted++;
	if(r->blocked)
		run->blocked++;
	if(r->timestamp > run->newest)
		run->newest = r->timestamp;

	return true;
}

// Write the IDs of the linking rows found in a committed run to shared
// memory, where the entries are still the same. The caller holds the SHM lock
static void keep_found_rows(const struct export_run *run)
{
	for(unsigned int i = 0; run->domains != NULL && i < run->n_domains; i++)
	{
		domainsData *domain = run->domains[i].db_id > 0 ? getDomain(i, true) : NULL;
		if(domain != NULL && domain->domainpos == run->domains[i].pos)
		{
			domain->db_id = run->domains[i].db_id;
			domain->flags.in_database = true;
		}
	}
	for(unsigned int i = 0; run->clients != NULL && i < run->n_clients; i++)
	{
		clientsData *client = run->clients[i].db_id > 0 ? getClient(i, true) : NULL;
		if(client != NULL && client->namepos == run->clients[i].pos &&
		   client->ippos == run->clients[i].pos2)
		{
			client->db_id = run->clients[i].db_id;
			client->flags.in_database = true;
		}
	}
	for(unsigned int i = 0; run->upstreams != NULL && i < run->n_upstreams; i++)
	{
		upstreamsData *upstream = run->upstreams[i].db_id > 0 ? getUpstream(i, true) : NULL;
		if(upstream != NULL && upstream->ippos == run->upstreams[i].pos &&
		   upstream->port == run->upstreams[i].pos2)
		{
			upstream->db_id = run->upstreams[i].db_id;
			upstream->flags.in_database = true;
		}
	}
	for(unsigned int i = 0; i < run->n_addinfo; i++)
		store_addinfo_id(run->addinfo[i].type, run->addinfo[i].key, run->addinfo[i].db_id);
}

// Release what one export run allocated
static void free_export_run(struct export_run *run)
{
	if(run->domains != NULL)
		free(run->domains);
	if(run->clients != NULL)
		free(run->clients);
	if(run->upstreams != NULL)
		free(run->upstreams);
	if(run->addinfo != NULL)
		free(run->addinfo);
	if(run->room != NULL)
		free(run->room);
}

// Store the queries that are ready on disk, in one transaction - either
// periodically (final = false) or at shutdown (final = true). A query is
// ready once it is older than REPLY_TIMEOUT, so it can still complete, at
// shutdown at once. Queries recorded at the maximum privacy level or hidden by
// dns.ignoreLocalhost are not stored. The queries are taken from shared memory
// in chunks, and the disk is written without the SHM lock
static bool store_ready_queries(const bool final)
{
	// Only try to export to database if it is known to not be broken
	if(FTLDBerror() || querydb == NULL)
		return false;

	// Nothing is stored with database.maxDBdays 0
	if(config.database.maxDBdays.v.ui == 0)
		return true;

	// Start database timer
	timer_start(DATABASE_WRITE_TIMER);

	struct export_run run = { .maxid = -1 };
	struct export_row rows[EXPORT_CHUNK];
	bool okay = disk_db_maxid(&run.maxid) && (run.room = malloc(EXPORT_ROOM)) != NULL;
	for(unsigned int i = 0; okay && i < ArraySize(export_sql); i++)
		okay = sqlite3_prepare_v2(querydb, export_sql[i], -1, &run.stmts[i], NULL) == SQLITE_OK;
	if(okay && dbquery(querydb, "BEGIN") != SQLITE_OK)
		okay = false;
	if(!okay)
	{
		log_err("export_queries_to_disk(): Cannot start the export: %s", sqlite3_errmsg(querydb));
		for(unsigned int i = 0; i < ArraySize(run.stmts); i++)
			sqlite3_finalize(run.stmts[i]);
		free_export_run(&run);
		return false;
	}

	// From the first query not stored yet to the first one that may still
	// receive a reply. A query stamped after now dates from before a
	// backwards clock step and does not hold back the others
	const double now = double_time();
	unsigned int pos = 0;
	bool done = false, started = false;
	while(okay && !done)
	{
		unsigned int n = 0;
		lock_shm_reader();
		if(!started)
		{
			pos = export_pos;
			run.n_domains = counters->domains;
			run.n_clients = counters->clients;
			run.n_upstreams = counters->upstreams;
			started = true;
		}
		// The garbage collector may have removed queries a day past the
		// cutoff, the export goes on with the oldest one left
		const unsigned int removed = get_queries_removed();
		if(pos - removed > (unsigned int)counters->queries)
			pos = removed;
		run.used = 0;
		while(n < EXPORT_CHUNK && pos - removed < (unsigned int)counters->queries)
		{
			const queriesData *query = getQuery(pos - removed, true);
			if(query != NULL && query->db > run.maxid && query->privacylevel < PRIVACY_MAXIMUM &&
			   !query->flags.hidden)
			{
				if(!final && query->timestamp >= now - REPLY_TIMEOUT && query->timestamp <= now + 1.0)
				{
					done = true;
					break;
				}
				// A query whose strings do not fit goes into the next
				// chunk, which has the whole room for it
				if(take_query(query, &rows[n], &run))
					n++;
				else if(n > 0)
					break;
				else
					log_err("export_queries_to_disk(): Strings of query %lld too long, not stored",
					        (long long)query->db);
			}
			pos++;
		}
		if(pos - removed >= (unsigned int)counters->queries)
			done = true;
		unlock_shm();

		for(unsigned int i = 0; okay && i < n; i++)
			okay = store_row(&rows[i], &run);

		// A periodic export still running at shutdown leaves the rest
		// to the final one
		if(killed && !final)
			done = true;
	}

	// The totals of the database, in the same transaction
	if(okay && run.inserted > 0)
	{
		const double newest = run.newest > new_last_timestamp ? run.newest : new_last_timestamp;
		if(dbquery(querydb, "INSERT OR REPLACE INTO ftl (id, value) VALUES ( %i, %f );",
		           DB_LASTTIMESTAMP, newest) != SQLITE_OK ||
		   !db_update_disk_counter(querydb, DB_TOTALQUERIES, (int)run.inserted) ||
		   !db_update_disk_counter(querydb, DB_BLOCKEDQUERIES, (int)run.blocked))
		{
			log_err("export_queries_to_disk(): Cannot update the counters: %s", sqlite3_errmsg(querydb));
			okay = false;
		}
		else
			new_last_timestamp = newest;
	}

	for(unsigned int i = 0; i < ArraySize(run.stmts); i++)
		sqlite3_finalize(run.stmts[i]);

	if(okay && dbquery(querydb, "END") != SQLITE_OK)
	{
		log_err("export_queries_to_disk(): Cannot end transaction: %s", sqlite3_errmsg(querydb));
		okay = false;
	}

	if(okay)
	{
		// The next export continues behind these queries, with the IDs of
		// the linking rows found now
		lock_shm();
		keep_found_rows(&run);
		export_pos = pos;
		unlock_shm();
		diskdb_queries_count += run.inserted;
	}
	else
	{
		// Nothing of this run is on disk, the hidden rows may not be either
		sqlite3_exec(querydb, "ROLLBACK", NULL, NULL, NULL);
		hidden_domain_db_id = hidden_client_db_id = hidden_cname_db_id = 0;
	}

	log_debug(DEBUG_DATABASE, "Exported %u queries to the long-term database (took %.1f ms)",
	          okay ? run.inserted : 0, timer_elapsed_msec(DATABASE_WRITE_TIMER));

	free_export_run(&run);

	return okay;
}

// Exports run in the database thread and once more at shutdown, one at a time
static pthread_mutex_t export_lock = PTHREAD_MUTEX_INITIALIZER;

bool export_queries_to_disk(const bool final)
{
	pthread_mutex_lock(&export_lock);
	const bool okay = store_ready_queries(final);
	pthread_mutex_unlock(&export_lock);
	return okay;
}
