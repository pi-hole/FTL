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
#define QUERY_TABLE_PRIVATE
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
// file_exists()
#include "files.h"

static sqlite3 *_memdb = NULL;
static double new_last_timestamp = 0;
static uint32_t new_total = 0, new_blocked = 0;
static int64_t memdb_queries_maxid = -1;
static uint64_t memdb_queries_count = 0, diskdb_queries_count = 0;
static double memdb_earliest_timestamp = 0, diskdb_earliest_timestamp = 0;
static sqlite3_stmt *query_stmt = NULL;
static sqlite3_stmt *domain_stmt = NULL;
static sqlite3_stmt *client_stmt = NULL;
static sqlite3_stmt *forward_stmt = NULL;
static sqlite3_stmt *addinfo_stmt = NULL;
static sqlite3_stmt *domain_id_stmt = NULL;
static sqlite3_stmt *client_id_stmt = NULL;
static sqlite3_stmt *forward_id_stmt = NULL;
static sqlite3_stmt *addinfo_id_stmt = NULL;
static sqlite3_stmt *queries_to_disk_stmt = NULL;
#define SUBTABLE_STMTS 5
static sqlite3_stmt *subtables_to_disk_stmts[SUBTABLE_STMTS] = { NULL };
// Array of all prepared statements
static sqlite3_stmt **stmts[] = { &query_stmt,
                                  &domain_stmt,
                                  &client_stmt,
                                  &forward_stmt,
                                  &addinfo_stmt,
                                  &domain_id_stmt,
                                  &client_id_stmt,
                                  &forward_id_stmt,
                                  &addinfo_id_stmt,
                                  &queries_to_disk_stmt,
                                  &subtables_to_disk_stmts[0],
                                  &subtables_to_disk_stmts[1],
                                  &subtables_to_disk_stmts[2],
                                  &subtables_to_disk_stmts[3],
                                  &subtables_to_disk_stmts[4] };

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
	return (key << ADDINFO_TYPE_BITS) | (type & ((1 << ADDINFO_TYPE_BITS) - 1));
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

// Private prototypes
static bool count_queries_on_disk(sqlite3 *memdb);
static void init_disk_db_idx(sqlite3 *memdb);

// Return the maximum ID of the in-memory database
sqlite3_int64 __attribute__((pure)) get_max_db_idx(void)
{
	return memdb_queries_maxid;
}

void db_counts(sqlite3_int64 *last_idx, sqlite3_int64 *mem_num, sqlite3_int64 *disk_num)
{
	if(last_idx != NULL)
		*last_idx = memdb_queries_maxid;
	if(mem_num != NULL)
		*mem_num = memdb_queries_count;
	if(disk_num != NULL)
		*disk_num = diskdb_queries_count;
}

// Initialize in-memory database, add queries table and indices
// The flow of queries is as follows:
//   1. Every second, we try to copy all queries from our internal datastructure
//      into the memory table. We iterate over the last 100 queries and check if
//      they were changed. This operation may fail if the tables is currently busy.
//      This ensures the in-memory database isn't updated midway when, e.g., an
//      API query is running. Furthermore, it ensures that new queries are not
//      blocked when the database is busy and INSERTions aren't currently possible.
//   2. At user-configured intervals, the in-memory database is dumped on-disk.
//      For this, we
//        3.1. Attach the on-disk database
//        3.2. INSERT the queries that came in since the last dumping
//        3.3. Detach the on-disk database
//   3. At the end of their lifetime (that is after 24 hours), queries are DELETEd
//      from the in-memory database to make room for new queries in the rolling
//      window. The queries are not removed from the on-disk database.
bool init_memory_database(void)
{
	int rc;
	// Try to open in-memory database
	// The :memory: database always has synchronous=OFF since the content of
	// it is ephemeral and is not expected to survive a power outage.
	// If database.forceDisk is set, we do not want an in-memory database but, instead,
	// use an additional on-disk database for query storage. This database is always
	// recreated from scratch on FTL start and deleted on FTL stop.
	const char *db_path = config.database.forceDisk.v.b ? config.files.tmp_db.v.s : ":memory:";
	rc = sqlite3_open_v2(db_path, &_memdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Error opening database: %s at %s",
		        sqlite3_errstr(rc), db_path);
		return false;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_handler(_memdb, sqliteBusyCallback, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Error setting busy timeout: %s",
		        sqlite3_errstr(rc));
		sqlite3_close(_memdb);
		return false;
	}

	// Erase any existing on-disk temporary database if used. This process
	// works even for a badly corrupted database file.
	if(config.database.forceDisk.v.b)
	{
		log_warn("Using on-disk history database. This will reduce performance.");
		sqlite3_db_config(_memdb, SQLITE_DBCONFIG_RESET_DATABASE, 1, 0);
		sqlite3_exec(_memdb, "VACUUM", NULL, NULL, NULL);
		sqlite3_db_config(_memdb, SQLITE_DBCONFIG_RESET_DATABASE, 0, 0);
	}

	// Create query_storage table in the database
	for(unsigned int i = 0; i < ArraySize(table_creation); i++)
	{
		log_debug(DEBUG_DATABASE, "init_memory_database(): Executing %s", table_creation[i]);
		rc = sqlite3_exec(_memdb, table_creation[i], NULL, NULL, NULL);
		if( rc != SQLITE_OK ){
			log_err("init_memory_database(\"%s\") failed: %s",
				table_creation[i], sqlite3_errstr(rc));
			sqlite3_close(_memdb);
			return false;
		}
	}

	// Add indices on all columns of the in-memory database
	// as well as index on auxiliary tables
	for(unsigned int i = 0; i < ArraySize(index_creation); i++)
	{
		log_debug(DEBUG_DATABASE, "init_memory_database(): Executing %s", index_creation[i]);
		rc = sqlite3_exec(_memdb, index_creation[i], NULL, NULL, NULL);
		if( rc != SQLITE_OK ){
			log_err("init_memory_database(\"%s\") failed: %s",
			        index_creation[i], sqlite3_errstr(rc));
			sqlite3_close(_memdb);
			return false;
		}
	}

	// Attach disk database. This may fail if the database is unavailable
	const bool attached = attach_database(_memdb, NULL, config.files.database.v.s, "disk");

	// Enable WAL mode for the on-disk database (pihole-FTL.db) if
	// configured (default is yes). User may not want to enable WAL
	// mode if the database is on a network share as all processes
	// accessing the database must be on the same host in WAL mode.
	if(config.database.useWAL.v.b && attached)
	{
		// Change journal mode to WAL
		// - WAL is significantly faster in most scenarios.
		// - WAL provides more concurrency as readers do not block writers and a
		//   writer does not block readers. Reading and writing can proceed
		//   concurrently.
		// - Disk I/O operations tend to be more sequential using WAL.
		rc = sqlite3_exec(_memdb, "PRAGMA disk.journal_mode=WAL", NULL, NULL, NULL);
		if( rc != SQLITE_OK )
		{
			log_err("init_memory_database(): Error setting journal mode (WAL): %s",
			        sqlite3_errstr(rc));
			sqlite3_close(_memdb);
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
		rc = sqlite3_exec(_memdb, "PRAGMA disk.synchronous=NORMAL", NULL, NULL, NULL);
		if( rc != SQLITE_OK )
		{
			log_err("init_memory_database(): Error setting synchronous mode: %s",
			        sqlite3_errstr(rc));
			sqlite3_close(_memdb);
			return false;
		}
	}
	else if(attached)
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
		rc = sqlite3_exec(_memdb, "PRAGMA disk.journal_mode=DELETE", NULL, NULL, NULL);
		if( rc != SQLITE_OK )
		{
			log_err("init_memory_database(): Error setting journal mode (DELETE): %s",
			        sqlite3_errstr(rc));
			sqlite3_close(_memdb);
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
	if(attached)
	{
		rc = sqlite3_exec(_memdb, "PRAGMA disk.mmap_size = 268435456", NULL, NULL, NULL);
		if(rc != SQLITE_OK)
			log_warn("init_memory_database(): Error enabling mmap for disk database: %s",
			         sqlite3_errstr(rc));
	}

	// Prepare persistent insertion/replace statements
	// Domain, client, forward, and addinfo IDs are cached
	rc = sqlite3_prepare_v3(_memdb, "REPLACE INTO query_storage VALUES "\
	                                "(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &query_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(query_storage) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(_memdb, "INSERT OR IGNORE INTO domain_by_id (domain) VALUES (?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &domain_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(domain_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(_memdb, "INSERT OR IGNORE INTO client_by_id (ip,name) VALUES (?,?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &client_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(client_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(_memdb, "INSERT OR IGNORE INTO forward_by_id (forward) VALUES (?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &forward_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(forward_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(_memdb, "INSERT OR IGNORE INTO addinfo_by_id (type,content) VALUES (?,?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &addinfo_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(addinfo_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	// Prepare SELECT statements for fetching linking table IDs (used once
	// per unique entry when the row already exists from a disk import)
	rc = sqlite3_prepare_v3(_memdb, "SELECT id FROM domain_by_id WHERE domain = ?",
	                        -1, SQLITE_PREPARE_PERSISTENT, &domain_id_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(domain_id) - SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(_memdb, "SELECT id FROM client_by_id WHERE ip = ? AND name = ?",
	                        -1, SQLITE_PREPARE_PERSISTENT, &client_id_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(client_id) - SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(_memdb, "SELECT id FROM forward_by_id WHERE forward = ?",
	                        -1, SQLITE_PREPARE_PERSISTENT, &forward_id_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(forward_id) - SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(_memdb, "SELECT id FROM addinfo_by_id WHERE type = ? AND content = ?",
	                        -1, SQLITE_PREPARE_PERSISTENT, &addinfo_id_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(addinfo_id) - SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Clear process-local addinfo ID cache
	memset(addinfo_id_cache, 0, sizeof(addinfo_id_cache));

	// The IFNULL() is needed to handle the case when there are no queries
	// in the on-disk database yet. In this case, we want to copy all
	// queries from the in-memory database (including the query with ID 0)
	// to the on-disk database.
	rc = sqlite3_prepare_v3(_memdb, "INSERT INTO disk.query_storage SELECT * FROM query_storage " \
	                                      "WHERE id > (SELECT IFNULL(MAX(id), -1) FROM disk.query_storage) "\
	                                        "AND timestamp < ?",
	                        -1, SQLITE_PREPARE_PERSISTENT, &queries_to_disk_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(queries_to_disk) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	// Export linking tables to disk database
	// We limit the export to new records to avoid the overhead of many
	// IGNORE executions for records that are already present on disk. It
	// follows the same logic as for the main query_storage table above.
	const char *subtable_sql[SUBTABLE_STMTS] = {
		"INSERT OR IGNORE INTO disk.domain_by_id SELECT * FROM domain_by_id WHERE id > (SELECT IFNULL(MAX(id), -1) FROM disk.domain_by_id)",
		"INSERT OR IGNORE INTO disk.client_by_id SELECT * FROM client_by_id WHERE id > (SELECT IFNULL(MAX(id), -1) FROM disk.client_by_id)",
		"INSERT OR IGNORE INTO disk.forward_by_id SELECT * FROM forward_by_id WHERE id > (SELECT IFNULL(MAX(id), -1) FROM disk.forward_by_id)",
		"INSERT OR IGNORE INTO disk.addinfo_by_id SELECT * FROM addinfo_by_id WHERE id > (SELECT IFNULL(MAX(id), -1) FROM disk.addinfo_by_id)",
		"UPDATE disk.sqlite_sequence SET seq = (SELECT seq FROM sqlite_sequence WHERE disk.sqlite_sequence.name = sqlite_sequence.name)"
	};

	// Export linking tables
	for(unsigned int i = 0; i < SUBTABLE_STMTS; i++)
	{
		rc = sqlite3_prepare_v3(_memdb, subtable_sql[i], -1,
		                        SQLITE_PREPARE_PERSISTENT, &subtables_to_disk_stmts[i], NULL);
		if( rc != SQLITE_OK )
		{
			log_err("init_memory_database(queries_to_disk) - SQL error prepare: %s", sqlite3_errstr(rc));
			return false;
		}
	}

	// Initialize in-memory database starting index
	init_disk_db_idx(_memdb);

	// Flush messages stored in the long-term database
	flush_message_table(_memdb);

	// Attach disk database
	if(attached)
	{
		// Compensate for possible jumps in time
		runGC(time(NULL), NULL, false);

		// Try to import queries from long-term database if available
		// Skip if we are not supposed to load queries from disk
		if(config.database.DBimport.v.b)
			count_queries_on_disk(_memdb);
	}
	else
		log_err("init_memory_database(): Failed to attach disk database");

	// Return that the in-memory database was initialized successfully, even
	// when attach failed
	return true;
}

// Close memory database
void close_memory_database(void)
{
	// Return early if there is no memory database to be closed
	if(_memdb == NULL)
		return;

	// Finalize all statements
	for(unsigned int i = 0; i < ArraySize(stmts); i++)
	{
		if(*stmts[i] == NULL)
			continue;
		sqlite3_finalize(*stmts[i]);
		*stmts[i] = NULL;
	}

	// Detach disk database
	if(!detach_database(_memdb, NULL, "disk"))
		log_err("close_memory_database(): Failed to detach disk database");

	// Close SQLite3 memory database
	int ret = sqlite3_close(_memdb);
	if(ret != SQLITE_OK)
		log_err("Finalizing memory database failed: %s",
		        sqlite3_errstr(ret));
	else
		log_debug(DEBUG_DATABASE, "Closed memory database");

	// Set global pointer to NULL
	_memdb = NULL;
}

// Is this the shared in-memory connection? Used to keep dbclose() away from a
// handle it does not own
bool __attribute__((pure)) is_memdb(const sqlite3 *db)
{
	return db != NULL && db == _memdb;
}

sqlite3 *__attribute__((pure)) _get_memdb(const int line, const char *func, const char *file)
{
	log_debug(DEBUG_DATABASE, "Accessing in-memory database in %s() (%s:%i)", func, file, line);
	return _memdb;
}

// Get memory usage and size of in-memory tables
bool get_memdb_size(size_t *memsize, int *queries)
{
	int rc;
	sqlite3 *db = get_memdb();
	sqlite3_stmt *stmt = NULL;
	size_t page_count = 0, page_size = 0;

	// Fetch page_count and page_size in a single round trip using the
	// pragma_* table-valued functions. This replaces two prepare/step/
	// finalize cycles with one. PRAGMAs cannot be combined inside a single
	// sqlite3_prepare_v2() (only one statement per prepare), but the
	// pragma_* TVFs can be cross-joined in a regular SELECT.
	rc = sqlite3_prepare_v2(db,
	                        "SELECT page_count, page_size "
	                        "FROM pragma_page_count(), pragma_page_size()",
	                        -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		if(rc != SQLITE_BUSY)
			log_err("get_memdb_size(): Prepare error: %s",
			        sqlite3_errstr(rc));
		return false;
	}
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		page_count = sqlite3_column_int(stmt, 0);
		page_size  = sqlite3_column_int(stmt, 1);
	}
	else
	{
		log_err("get_memdb_size(): Step error: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return false;
	}
	sqlite3_finalize(stmt);

	*memsize = page_count * page_size;

	// Get number of queries in the memory table
	if(queries != NULL)
		*queries = memdb_queries_count;

	return true;
}

// Log the memory usage of in-memory databases
static void log_in_memory_usage(void)
{
	if(!(config.debug.database.v.b))
		return;

	size_t memsize = 0;
	int queries = 0;
	if(get_memdb_size(&memsize, &queries))
	{
		char prefix[2] = { 0 };
		double num = 0.0;
		format_memory_size(prefix, memsize, &num);
		log_debug(DEBUG_DATABASE, "mem database size: %.1f%s (%d queries)",
		          num, prefix, queries);
	}
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

// Get number of queries either in the mem or in the on-disk database
// This routine is used by the API routines.
static uint64_t get_number_of_queries_in_DB(sqlite3 *db, const char *tablename, double *earliest_timestamp)
{
	int rc = 0;
	uint64_t num = 0;
	sqlite3_stmt *stmt = NULL;

	// The database pointer may be NULL, meaning we want the memdb
	if(db == NULL)
		db = get_memdb();

	// Build query string based on whether we need the earliest timestamp too
	const size_t buflen = 38 + strlen(tablename);
	char *querystr = calloc(buflen, sizeof(char));
	snprintf(querystr, buflen, "SELECT COUNT(*), MIN(timestamp) FROM %s", tablename);

	rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		if(rc != SQLITE_BUSY)
			log_err("get_number_of_queries_in_DB(%s): Prepare error: %s",
			        tablename, sqlite3_errstr(rc));
		free(querystr);
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
	free(querystr);

	return num;
}

static double import_from = 0.0;
static double import_until = 0.0;
static int counted_queries = 0;
// Start transaction and count number of queries to be imported from disk.
// We keep the transaction open so that no new queries are written to the disk
// database until we have copied the data into the in-memory database in
// import_queries_from_disk() below. Note that this function is subsequently
// called from the database thread instead of the main process thread.
static bool count_queries_on_disk(sqlite3 *memdb)
{
	// Set time range for counting queries
	import_until = double_time();
	import_from = import_until - config.webserver.api.maxHistory.v.ui;

	counted_queries = db_query_int_from_until(memdb, "SELECT COUNT(*) FROM disk.query_storage "
	                                                 "WHERE timestamp BETWEEN ? AND ?",
	                                                 import_from, import_until);
	log_debug(DEBUG_DATABASE, "count_queries_on_disk(): Going to import %i queries from disk database",
	          counted_queries);

	// Lock shared memory
	lock_shm();
	// Set query counter high enough so that the subsequent lock_shm() call
	// enlarges the queries object
	counters->queries = counted_queries;
	init_queries_shm_sz();
	// Unlock shared memory
	unlock_shm();

	return true;
}

/**
 * @brief Retrieve query count and earliest timestamp from the selected database.
 *
 * @param disk If true, read values from the on-disk database; if false, read from the in-memory database.
 * @param[out] count Pointer to a uint64_t that will be set to the number of stored queries. Must not be NULL.
 * @param[out] earliest_timestamp Pointer to a double that will be set to the earliest query timestamp. Must not be NULL.
 *
 * Populates the provided output parameters with the corresponding values from the chosen database.
 */
void get_db_info(const bool disk, uint64_t *count, double *earliest_timestamp)
{
	if(disk)
	{
		if(count != NULL)
			*count = diskdb_queries_count;
		if(earliest_timestamp != NULL)
			*earliest_timestamp = diskdb_earliest_timestamp;
	}
	else
	{
		if(count != NULL)
			*count = memdb_queries_count;
		if(earliest_timestamp != NULL)
			*earliest_timestamp = memdb_earliest_timestamp;
	}
}

// Read queries from the on-disk database into the in-memory database (after
// restart, etc.). A transaction is already running when this function is called.
bool import_queries_from_disk(void)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const char *querystr = "INSERT INTO query_storage SELECT * FROM disk.query_storage WHERE timestamp BETWEEN ? AND ?";

	// Begin transaction
	int rc;
	sqlite3 *memdb = get_memdb();
	if((rc = sqlite3_exec(memdb, "BEGIN TRANSACTION", NULL, NULL, NULL)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Cannot begin transaction: %s", sqlite3_errstr(rc));
		return false;
	}

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	if((rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): SQL error prepare: %s", sqlite3_errstr(rc));
		sqlite3_exec(memdb, "ROLLBACK", NULL, NULL, NULL);
		return false;
	}

	// Bind lower limit
	if((rc = sqlite3_bind_double(stmt, 1, import_from)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Failed to bind type mintime: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		sqlite3_exec(memdb, "ROLLBACK", NULL, NULL, NULL);
		return false;
	}

	// Bind upper limit
	if((rc = sqlite3_bind_double(stmt, 2, import_until)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Failed to bind type now: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		sqlite3_exec(memdb, "ROLLBACK", NULL, NULL, NULL);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		log_err("import_queries_from_disk(): Failed to import queries: %s",
		        sqlite3_errstr(rc));
	const int imported_queries = sqlite3_changes(memdb);
	log_debug(DEBUG_DATABASE, "Imported %i rows from disk.query_storage", imported_queries);

	if(imported_queries != counted_queries)
		log_warn("Database %s has changed during import: Expected to import %i queries, but only imported %i. You may observe memory error warnings.",
		         config.files.database.v.s, counted_queries, imported_queries);

	// Finalize statement
	sqlite3_finalize(stmt);

	// Import linking tables and current AUTOINCREMENT values from the disk database
	const char *subtable_names[] = {
		"domain_by_id",
		"client_by_id",
		"forward_by_id",
		"addinfo_by_id",
		"sqlite_sequence"
	};
	const char *subtable_sql[] = {
		"INSERT INTO domain_by_id SELECT * FROM disk.domain_by_id",
		"INSERT INTO client_by_id SELECT * FROM disk.client_by_id",
		"INSERT INTO forward_by_id SELECT * FROM disk.forward_by_id",
		"INSERT INTO addinfo_by_id SELECT * FROM disk.addinfo_by_id",
		"INSERT OR REPLACE INTO sqlite_sequence SELECT * FROM disk.sqlite_sequence"
	};
	static_assert(ArraySize(subtable_names) == ArraySize(subtable_sql), "Mismatched subtable arrays");

	// Import linking tables
	int imported[ArraySize(subtable_names)] = { 0 };
	for(unsigned int i = 0; i < ArraySize(subtable_names); i++)
	{
		if((rc = sqlite3_exec(memdb, subtable_sql[i], NULL, NULL, NULL)) != SQLITE_OK)
			log_err("import_queries_from_disk(%s): Cannot import linking table: %s",
			        subtable_sql[i], sqlite3_errstr(rc));
		imported[i] = sqlite3_changes(memdb);
		log_debug(DEBUG_DATABASE, "Imported %i rows from disk.%s", imported[i], subtable_names[i]);
	}

	// End transaction
	if((rc = sqlite3_exec(memdb, "END", NULL, NULL, NULL)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Cannot end transaction: %s", sqlite3_errstr(rc));
		sqlite3_exec(memdb, "ROLLBACK", NULL, NULL, NULL);
		return false;
	}

	// Get number of queries on disk before detaching
	memdb_queries_count = imported_queries;
	memdb_earliest_timestamp = import_from;
	diskdb_queries_count = get_number_of_queries_in_DB(memdb, "disk.query_storage", &diskdb_earliest_timestamp);

	log_info("Imported %"PRIu64" queries from the on-disk database (it has %"PRIu64" rows)", memdb_queries_count, diskdb_queries_count);

	return okay;
}

// Export in-memory queries to disk - either due to periodic dumping (final =
// false) or because of a shutdown (final = true)
// When final is false, we only export queries that are older than REPLY_TIMEOUT
// seconds. This is to give queries some time to complete before they are
// exported to disk. When final is true, we export all queries (nothing is going
// to be added to the in-memory database anymore).
bool export_queries_to_disk(const bool final)
{
	int rc = 0;
	bool okay = false;
	unsigned int insertions = 0;
	const double time = double_time() - (final ? 0.0 : REPLY_TIMEOUT);

	// Only try to export to database if it is known to not be broken
	if(FTLDBerror())
		return false;

	// Start database timer
	timer_start(DATABASE_WRITE_TIMER);

	// Start transaction
	sqlite3 *memdb = get_memdb();
	SQL_bool(memdb, "BEGIN");

	// Only store queries if database.maxDBdays > 0
	if(config.database.maxDBdays.v.ui > 0)
	{
		log_debug(DEBUG_DATABASE, "Storing queries on disk WHERE timestamp < %f (memdb_queries_maxid = %"PRId64")",
		          time, memdb_queries_maxid);

		// Bind upper time limit
		// This prevents queries from the last 30 seconds from being stored
		// immediately on-disk to give them some time to complete before finally
		// exported. We do not limit anything when storing during termination.
		if((rc = sqlite3_bind_double(queries_to_disk_stmt, 1, time)) != SQLITE_OK)
		{
			log_err("export_queries_to_disk(): Failed to bind time: %s", sqlite3_errstr(rc));
			sqlite3_reset(queries_to_disk_stmt);
			sqlite3_exec(memdb, "ROLLBACK", NULL, NULL, NULL);
			return false;
		}

		// Perform step
		if((rc = sqlite3_step(queries_to_disk_stmt)) == SQLITE_DONE)
			okay = true;
		else
		{
			log_err("export_queries_to_disk(): Failed to export queries: %s", sqlite3_errstr(rc));
			log_info("    with timestamp = %f", time);
		}

		// Get number of queries actually inserted by the INSERT INTO ... SELECT * FROM ...
		insertions = sqlite3_changes(memdb);

		// Finalize statement
		sqlite3_reset(queries_to_disk_stmt);

		/*
		 * If there are any insertions, we:
		 * 1. Insert (or replace) the last timestamp into the `disk.ftl` table.
		 * 2. Update the total queries counter in the `disk.counters` table.
		 * 3. Update the blocked queries counter in the `disk.counters` table.
		 *
		 * Note that <new_total> does not need to match the total number
		 * of insertions (stored in <insertions>) here as storing
		 * queries to the database happens time-delayed. In the end, the
		 * total number of queries will be correct (after final
		 * synchronization during FTL shutdown).
		 */
		if(insertions > 0)
		{
			// Update number of queries in the disk database (actual number of insertions)
			diskdb_queries_count += insertions;

			if((rc = dbquery(memdb, "INSERT OR REPLACE INTO disk.ftl (id, value) VALUES ( %i, %f );", DB_LASTTIMESTAMP, new_last_timestamp)) != SQLITE_OK)
				log_err("export_queries_to_disk(): Cannot update timestamp: %s", sqlite3_errstr(rc));

			// Use <new_total> and <new_blocked> counters to update
			// the respective counters in the on-disk database
			if(!db_update_disk_counter(memdb, DB_TOTALQUERIES, new_total))
				log_err("export_queries_to_disk(): Cannot update total queries counter: %s", sqlite3_errstr(rc));
			else
				// Success
				new_total = 0;

			if(!db_update_disk_counter(memdb, DB_BLOCKEDQUERIES, new_blocked))
				log_err("export_queries_to_disk(): Cannot update blocked queries counter: %s", sqlite3_errstr(rc));
			else
				// Success
				new_blocked = 0;
		}
	}

	// Export linking tables and current AUTOINCREMENT values to the disk database
	const char *subtable_names[SUBTABLE_STMTS] = {
		"domain_by_id",
		"client_by_id",
		"forward_by_id",
		"addinfo_by_id",
		"sqlite_sequence"
	};

	// Export linking tables
	for(unsigned int i = 0; i < SUBTABLE_STMTS; i++)
	{
		if((rc = sqlite3_step(subtables_to_disk_stmts[i])) != SQLITE_DONE)
			log_err("export_queries_to_disk(disk.%s): Cannot export subtable: %s",
			        subtable_names[i], sqlite3_errstr(rc));
		sqlite3_reset(subtables_to_disk_stmts[i]);
		log_debug(DEBUG_DATABASE, "Exported %i rows to disk.%s", sqlite3_changes(memdb), subtable_names[i]);
	}

	// End transaction. A bare SQL_bool() would return with the transaction
	// still open on the shared in-memory connection, which every later
	// caller inherits
	if((rc = dbquery(memdb, "END")) != SQLITE_OK)
	{
		log_err("export_queries_to_disk(): Cannot end transaction: %s",
		        sqlite3_errstr(rc));
		sqlite3_exec(memdb, "ROLLBACK", NULL, NULL, NULL);
		return false;
	}

	log_debug(DEBUG_DATABASE, "Exported %u rows for disk.query_storage (took %.1f ms)",
		  insertions, timer_elapsed_msec(DATABASE_WRITE_TIMER));

	return okay;
}

// Delete queries older than given timestamp. Used by garbage collection and
// database thread.
bool delete_old_queries_from_db(const bool use_memdb, const double mintime)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const char *querystr = "DELETE FROM query_storage WHERE timestamp <= ?";

	sqlite3 *db = NULL;
	if(use_memdb)
		db = get_memdb();
	else
		db = dbopen(false, false);

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("delete_old_queries_from_db(%s): SQL error prepare: %s",
		        use_memdb ? "memdb" : "disk", sqlite3_errstr(rc));
		if(!use_memdb) dbclose(&db);
		return false;
	}

	// Bind index
	if((rc = sqlite3_bind_double(stmt, 1, mintime)) != SQLITE_OK)
	{
		log_err("delete_old_queries_from_db(%s): Failed to bind mintime: %s",
		        use_memdb ? "memdb" : "disk", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		if(!use_memdb) dbclose(&db);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		log_err("delete_old_queries_from_db(%s): Failed to delete queries with timestamp >= %f: %s",
		        use_memdb ? "memdb" : "disk", mintime, sqlite3_errstr(rc));

	const int64_t deleted = sqlite3_changes64(db);
	if(okay)
	{
		// Update number of queries in either in-memory or on-disk
		// database (depending on what was cleaned). Guard against
		// underflow: if the counter is somehow already below the
		// number deleted (e.g. after a failed import that set the
		// counter to 0), clamp to 0 rather than wrapping to UINT64_MAX.
		if(use_memdb)
			memdb_queries_count = (uint64_t)deleted <= memdb_queries_count
			                      ? memdb_queries_count - (uint64_t)deleted : 0u;
		else
			diskdb_queries_count = (uint64_t)deleted <= diskdb_queries_count
			                       ? diskdb_queries_count - (uint64_t)deleted : 0u;
	}

	// Finalize statement
	sqlite3_finalize(stmt);

	// Update earliest timestamp in the database after deletion
	if(use_memdb)
		memdb_earliest_timestamp = mintime;
	else
		diskdb_earliest_timestamp = mintime;

	// Add additional logging and close on-disk database if used
	if(!use_memdb)
	{
		// Get size of on-disk database
		struct stat st;
		get_FTL_db_stats(&st);

		// Log size of database and number of deleted rows
		log_info("Size of %s is %.2f MB, deleted %"PRId64" of %"PRIu64" rows",
			config.files.database.v.s, 9.5367431640625e-07*st.st_size,
			deleted, diskdb_queries_count);

		// Close on-disk database
		dbclose(&db);
	}

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
	// Actually read queries from disk into memory
	import_queries_from_disk();

	// Prepare request
	// Filtering to the history window has already happened in
	// import_queries_from_disk()
	const char *querystr = "SELECT id,"\
	                              "timestamp,"\
	                              "type,"\
	                              "status,"\
	                              "domain,"\
	                              "client,"\
	                              "forward,"\
	                              "additional_info,"\
	                              "reply_type,"\
	                              "reply_time,"\
	                              "dnssec "\
	                       "FROM queries";

	// Only try to import from database if it is known to not be broken
	if(FTLDBerror())
		return;

	log_info("Parsing queries in database");

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	sqlite3 *memdb = get_memdb();
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("DB_read_queries() - SQL error prepare: %s", sqlite3_errstr(rc));
		return;
	}

	// Loop through returned database rows
	size_t imported_queries = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const sqlite3_int64 dbID = sqlite3_column_int64(stmt, 0);
		const double queryTimeStamp = sqlite3_column_double(stmt, 1);
		// 1483228800 = 01/01/2017 @ 12:00am (UTC)
		if(queryTimeStamp < 1483228800)
		{
			log_warn("Database: TIMESTAMP of query should be larger than 01/01/2017 but is %f (DB ID %lli)",
			         queryTimeStamp, dbID);
			continue;
		}

		const int type = sqlite3_column_int(stmt, 2);
		const bool mapped_type = type >= TYPE_NONE && type < TYPE_MAX;
		const bool offset_type = type > 100 && type < (100 + UINT16_MAX);
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
				unlock_shm();
				continue;
			}
		}

		// Set index for this query
		const int queryIndex = imported_queries++;

		if(queryIndex >= counted_queries)
		{
			log_warn("Database %s has changed during import: Expected to import %i queries. Parts of the history may be missing.",
			         config.files.database.v.s, counted_queries);
			unlock_shm();
			break;
		}

		// Obtain IDs only after filtering which queries we want to keep
		const int timeidx = getOverTimeID(queryTimeStamp);
		const int domainID = findDomainID(domainname, true);
		const int clientID = findClientID(clientIP, true, false, queryTimeStamp);

		// Store this query in memory
		queriesData *query = getQuery(queryIndex, false);
		query->magic = MAGICBYTE;
		query->timestamp = queryTimeStamp;
		if(type < 100)
		{
			// Mapped query type
			if(type >= TYPE_NONE && type < TYPE_MAX)
				query->type = type;
			else
			{
				// Invalid query type
				log_warn("Query type %d is invalid, ID = %lld, timestamp = %f",
				         type, dbID, queryTimeStamp);
				unlock_shm();
				continue;
			}
		}
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
		query->cacheID = -1;
		query->id = counters->queries;
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
		query->flags.database.imported = true;
		query->flags.database.changed = false;
		query->ede = -1; // EDE_UNSET == -1

		// Set lastQuery timer for network table
		clientsData *client = getClient(clientID, true);
		client->lastQuery = queryTimeStamp;

		// Update client's overTime data structure
		change_clientcount(client, 0, 0, timeidx, 1);

		// Get domain pointer
		domainsData *domain = getDomain(domainID, true);
		domain->lastQuery = queryTimeStamp;

		// Get additional information from the additional_info column if applicable
		int list_id_avail = false;
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
				const int CNAMEdomainID = findDomainID(CNAMEdomain, false);
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
		else if((list_id_avail = sqlite3_column_bytes(stmt, 7) != 0))
		{
			// Set ID of the domainlist entry that was the reason for permitting/blocking this query
			// We assume the value in this field is said ID when it is not a CNAME-related domain
			// (checked above) and the value of additional_info is not NULL (0 bytes storage size)
			query->cacheID = findCacheID(domainID, clientID, query->type, true);
			DNSCacheData *cache = getDNSCache(query->cacheID, true);
			if(cache != NULL)
			{
				cache->refcount++;
				// Only load if
				//  a) we have a cache entry
				//  b) the value of additional_info is not NULL (0 bytes storage size)
				if(list_id_avail)
					cache->list_id = sqlite3_column_int(stmt, 7);
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
				change_clientcount(client, 0, 1, -1, 0);
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

	if( rc == SQLITE_DONE )
		log_info("Imported %zu queries from the long-term database", imported_queries);
	else
		log_err("DB_read_queries() - SQL error step: %s", sqlite3_errstr(rc));

	if((int)imported_queries < counted_queries)
	{
		log_warn("Database %s has changed during import: Expected to import %i queries, but found only %zu. You may see harmless memory errors in the log.",
		         config.files.database.v.s, counted_queries, imported_queries);
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);
}

static void init_disk_db_idx(sqlite3 *memdb)
{
	const char *querystr = "SELECT MAX(id) FROM disk.query_storage";

	// If the disk database is broken, we cannot import queries from it,
	// however, as we will also never export any queries, we can safely
	// assume any index
	if(FTLDBerror())
	{
		memdb_queries_maxid = -1;
		return;
	}

	// Prepare SQLite3 statement on first call
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	
	// Perform step
	if(rc == SQLITE_OK && (rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// We need to check that the returned value is not NULL (happens
		// when there are no rows in the table). If it is NULL, we set
		// memdb_queries_maxid to -1 so that the next query will be stored
		// with index 0. If it is not NULL, we set memdb_queries_maxid to
		// the returned value.
		if(sqlite3_column_type(stmt, 0) == SQLITE_INTEGER)
			memdb_queries_maxid = sqlite3_column_int64(stmt, 0);
		else
			memdb_queries_maxid = -1;
	}
	else
		log_err("init_disk_db_idx(): Failed to get MAX(id) from disk.query_storage: %s",
		        sqlite3_errstr(rc));

	// Finalize statement
	sqlite3_finalize(stmt);

	log_debug(DEBUG_DATABASE, "Last long-term idx is %"PRId64, memdb_queries_maxid);
}

// Run one of the transaction statements of queries_to_database(). SQL_bool()
// cannot be used there, as its early return would skip the cleanup, but its
// logging is worth keeping: a busy database is transient and only warned about
static bool memdb_exec(sqlite3 *memdb, const char *sql, const char *what)
{
	const int rc = dbquery(memdb, "%s", sql);
	if(rc == SQLITE_OK)
		return true;

	if(rc == SQLITE_BUSY)
		log_warn("queries_to_database(): Database busy when trying to %s", what);
	else
		log_err("queries_to_database(): Failed to %s", what);

	return false;
}

// Snapshot struct for lock-free SQLite writes in phase 2
struct query_snap {
	unsigned int queryID;       // SHM index for writeback
	int64_t idx;                // pre-assigned db index
	double timestamp;
	int type_val;               // pre-computed type for param 3
	int status;                 // param 4
	int domain_db_id;           // param 5
	int client_db_id;           // param 6
	int upstream_db_id;         // param 7
	int addinfo_id;             // param 8
	int reply;                  // param 9
	double response;            // param 10
	int dnssec;                 // param 11
	int list_id;                // param 12
	int ede;                    // param 13
	bool has_upstream;
	bool response_calculated;
	bool is_new;
	bool blocked;
};

// Give the snapshotted queries their changed flag back so a later run picks
// them up. The caller holds the SHM lock
static void requeue_snapshots(const struct query_snap *snaps, const unsigned int from,
                              const unsigned int to)
{
	for(unsigned int i = from; i < to; i++)
	{
		queriesData *query = getQuery(snaps[i].queryID, true);
		if(query != NULL)
			query->flags.database.changed = true;
	}
}

bool queries_to_database(void)
{
	int rc;
	unsigned int added = 0, updated = 0;

	// Only try to export to database if it is known to not be broken
	if(FTLDBerror())
		return false;

	// Skip, we never store nor count queries recorded while have been in
	// maximum privacy mode in the database
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_MAXIMUM)
	{
		log_debug(DEBUG_DATABASE, "Not storing query in database due to privacy level settings");
		return true;
	}
	if(counters->queries == 0)
	{
		log_debug(DEBUG_DATABASE, "Not storing query in database as there are none");
		return true;
	}
	if(!db_import_done)
	{
		log_debug(DEBUG_DATABASE, "Not storing query in database as import not finished (or failed)");
		return true;
	}

	lock_shm();

	// The upper bound is the last query in the array, the lower bound is
	// indirectly given by the first query older than 30 seconds - we do not
	// expect replies to still arrive after 30 seconds - they are anyway
	// useless as the client will have already timed out this particular
	// query and retried or failed
	const double limit_timestamp = double_time() - REPLY_TIMEOUT;
	unsigned int last_query = counters->queries - 1;
	while(last_query > 0)
	{
		queriesData *query = getQuery(last_query, true);
		if(query == NULL)
		{
			log_err("Memory error in queries_to_database() when trying to access query %u", last_query);
			unlock_shm();
			return false;
		}
		if(query->timestamp < limit_timestamp || query->flags.database.imported)
		{
			// We found the first query older than our limit or
			// queries that have been imported (we don't want to
			// export them again)
			last_query++;
			break;
		}
		last_query--;
	}

	// Skip early if no queries are to be stored (no queries immediately after start)
	if(last_query == counters->queries)
	{
		unlock_shm();
		return true;
	}

	sqlite3 *memdb = get_memdb();

	log_debug(DEBUG_DATABASE, "Upserting queries with ID in [%u, %u] in memdb", last_query, counters->queries - 1);

	// ===================================================================
	// PHASE 1: Under SHM lock — handle linking table INSERTs (need SHM
	// string access), resolve all IDs, and snapshot scalar query data into
	// a local array.  Only linking table INSERTs and fast field copies
	// happen here.  The heavy query_stmt REPLACE work is deferred to phase
	// 2 which runs without the lock, reducing SHM lock hold time from
	// O(queries × SQLite ops) to O(queries × field copy).
	//
	// Note: The linking table INSERTs (domain_stmt, client_stmt,
	// forward_stmt, addinfo_stmt) intentionally remain in this locked phase
	// even though they are SQLite operations, because they:
	//   (a) read variable-length SHM strings (domain names, client
	//       IPs/names, upstream addresses, CNAME domains) via getstr() and
	//       friends — these pointers are only safe under the lock,
	//   (b) write back db_id and in_database to SHM structs so that
	//       subsequent queries in the same batch (and future batches) can
	//       skip the INSERT entirely for efficiency reasons.
	// Moving them to phase 2 would require copying every variable-length
	// string into the snapshot, adding complexity and memory overhead for
	// operations that are almost always skipped after the first encounter
	// (thanks to the in_database flag).
	// ===================================================================


	const unsigned int window = counters->queries - last_query;
	struct query_snap *snaps = malloc(window * sizeof(*snaps));
	if(snaps == NULL)
	{
		log_err("queries_to_database(): Failed to allocate snapshot array (%u entries)", window);
		unlock_shm();
		return false;
	}

	unsigned int snap_count = 0;
	unsigned int unchanged = 0u;
	int64_t next_maxid = memdb_queries_maxid;
	bool phase1_error = false;

	// Wrap linking table INSERTs in a transaction for efficiency (these are
	// mostly skipped due to in_database caching). SQL_bool() cannot be used
	// while we hold the SHM lock, as its early return would leave the lock
	// taken for good
	if(!memdb_exec(memdb, "BEGIN TRANSACTION", "start the linking table transaction"))
		goto unlock_fail;

	for(unsigned int queryID = last_query; queryID < counters->queries; queryID++)
	{
		// Get query pointer
		queriesData *query = getQuery(queryID, true);
		if(query == NULL)
		{
			log_err("Memory error in queries_to_database() when trying to access query %u", queryID);
			phase1_error = true;
			break;
		}

		// Skip queries which have not changed since the last iteration
		if(!query->flags.database.changed)
		{
			++unchanged;
			continue;
		}

		struct query_snap *s = &snaps[snap_count];
		s->queryID = queryID;

		// Pre-assign db index
		s->is_new = (query->db == -1);
		if(s->is_new)
			s->idx = ++next_maxid;
		else
			s->idx = query->db;

		log_debug(DEBUG_DATABASE, "Storing query ID %u in in-memory-database with idx %lld (old idx %lld)",
		          queryID, (long long)s->idx, (long long)query->db);

		// Snapshot scalar fields
		s->timestamp = query->timestamp;
		s->type_val = (query->type != TYPE_OTHER) ? query->type : (query->qtype + 100);
		s->status = query->status;
		s->reply = query->reply;
		s->response = query->response;
		s->response_calculated = query->flags.response_calculated;
		s->dnssec = query->dnssec;
		s->ede = query->ede;
		s->blocked = query->flags.blocked;

		// DOMAIN — handle linking table INSERT if first encounter
		const char *domain = getDomainString(query);
		domainsData *domaindata = getDomain(query->domainID, true);

		if(domaindata != NULL && !domaindata->flags.in_database)
		{
			sqlite3_bind_text(domain_stmt, 1, domain, -1, SQLITE_STATIC);
			rc = sqlite3_step(domain_stmt);
			if(rc != SQLITE_DONE)
			{
				log_err("Encountered error while trying to store domain");
				sqlite3_reset(domain_stmt);
				phase1_error = true;
				break;
			}
			sqlite3_reset(domain_stmt);

			if(sqlite3_changes(memdb) > 0)
				domaindata->db_id = (int)sqlite3_last_insert_rowid(memdb);
			else
			{
				sqlite3_bind_text(domain_id_stmt, 1, domain, -1, SQLITE_STATIC);
				if(sqlite3_step(domain_id_stmt) == SQLITE_ROW)
					domaindata->db_id = sqlite3_column_int(domain_id_stmt, 0);
				sqlite3_reset(domain_id_stmt);
			}
			domaindata->flags.in_database = true;
		}
		s->domain_db_id = domaindata != NULL ? domaindata->db_id : 0;

		// CLIENT — handle linking table INSERT if first encounter
		const char *clientIP = getClientIPString(query);
		const char *clientName = getClientNameString(query);
		clientsData *clientdata = getClient(query->clientID, true);

		if(clientdata != NULL && !clientdata->flags.in_database)
		{
			sqlite3_bind_text(client_stmt, 1, clientIP, -1, SQLITE_STATIC);
			sqlite3_bind_text(client_stmt, 2, clientName, -1, SQLITE_STATIC);
			rc = sqlite3_step(client_stmt);
			sqlite3_reset(client_stmt);
			if(rc != SQLITE_DONE)
			{
				log_err("Encountered error while trying to store client");
				phase1_error = true;
				break;
			}

			if(sqlite3_changes(memdb) > 0)
				clientdata->db_id = (int)sqlite3_last_insert_rowid(memdb);
			else
			{
				sqlite3_bind_text(client_id_stmt, 1, clientIP, -1, SQLITE_STATIC);
				sqlite3_bind_text(client_id_stmt, 2, clientName, -1, SQLITE_STATIC);
				if(sqlite3_step(client_id_stmt) == SQLITE_ROW)
					clientdata->db_id = sqlite3_column_int(client_id_stmt, 0);
				sqlite3_reset(client_id_stmt);
			}
			clientdata->flags.in_database = true;
		}
		s->client_db_id = clientdata != NULL ? clientdata->db_id : 0;

		// FORWARD — handle linking table INSERT if first encounter
		s->has_upstream = false;
		if(query->upstreamID > -1)
		{
			upstreamsData *upstream = getUpstream(query->upstreamID, true);
			if(upstream != NULL)
			{
				if(!upstream->flags.in_database)
				{
					const char *forwardIP = getstr(upstream->ippos);
					char buffer[64];
					const int len = snprintf(buffer, sizeof(buffer), "%s#%u", forwardIP, upstream->port);
					if(len > 0 && (size_t)len < sizeof(buffer))
					{
						sqlite3_bind_text(forward_stmt, 1, buffer, len, SQLITE_STATIC);
						rc = sqlite3_step(forward_stmt);
						sqlite3_reset(forward_stmt);
						if(rc != SQLITE_DONE)
						{
							log_err("Encountered error while trying to store forward");
							phase1_error = true;
							break;
						}

						if(sqlite3_changes(memdb) > 0)
							upstream->db_id = (int)sqlite3_last_insert_rowid(memdb);
						else
						{
							sqlite3_bind_text(forward_id_stmt, 1, buffer, len, SQLITE_STATIC);
							if(sqlite3_step(forward_id_stmt) == SQLITE_ROW)
								upstream->db_id = sqlite3_column_int(forward_id_stmt, 0);
							sqlite3_reset(forward_id_stmt);
						}
					}
					upstream->flags.in_database = true;
				}
				s->upstream_db_id = upstream->db_id;
				s->has_upstream = true;
			}
		}

		// ADDINFO — handle linking table INSERT if not cached
		s->addinfo_id = 0;
		if(query->status == QUERY_GRAVITY_CNAME ||
		   query->status == QUERY_REGEX_CNAME ||
		   query->status == QUERY_DENYLIST_CNAME)
		{
			const int cname_domainID = query->CNAME_domainID;
			int aid = lookup_addinfo_id(ADDINFO_CNAME_DOMAIN, cname_domainID);
			if(aid == 0)
			{
				const char *cname = getCNAMEDomainString(query);
				const int len = strlen(cname);
				sqlite3_bind_int(addinfo_stmt, 1, ADDINFO_CNAME_DOMAIN);
				sqlite3_bind_text(addinfo_stmt, 2, cname, len, SQLITE_STATIC);
				rc = sqlite3_step(addinfo_stmt);
				sqlite3_reset(addinfo_stmt);
				if(rc != SQLITE_DONE)
				{
					log_err("Encountered error while trying to store addinfo");
					phase1_error = true;
					break;
				}

				if(sqlite3_changes(memdb) > 0)
					aid = (int)sqlite3_last_insert_rowid(memdb);
				else
				{
					sqlite3_bind_int(addinfo_id_stmt, 1, ADDINFO_CNAME_DOMAIN);
					sqlite3_bind_text(addinfo_id_stmt, 2, cname, len, SQLITE_STATIC);
					if(sqlite3_step(addinfo_id_stmt) == SQLITE_ROW)
						aid = sqlite3_column_int(addinfo_id_stmt, 0);
					sqlite3_reset(addinfo_id_stmt);
				}
				store_addinfo_id(ADDINFO_CNAME_DOMAIN, cname_domainID, aid);
			}
			s->addinfo_id = aid;
		}
		else
		{
			// Resolve list_id from DNS cache (needs SHM access)
			const unsigned int cacheID = query->cacheID > -1
				? query->cacheID
				: findCacheID(query->domainID, query->clientID, query->type, false);
			DNSCacheData *cache = getDNSCache(cacheID, true);

			if(cache != NULL && cache->list_id != -1)
			{
				const int list_id = cache->list_id;
				int aid = lookup_addinfo_id(ADDINFO_LIST_ID, list_id);
				if(aid == 0)
				{
					sqlite3_bind_int(addinfo_stmt, 1, ADDINFO_LIST_ID);
					sqlite3_bind_int(addinfo_stmt, 2, list_id);
					rc = sqlite3_step(addinfo_stmt);
					sqlite3_reset(addinfo_stmt);
					if(rc != SQLITE_DONE)
					{
						log_err("Encountered error while trying to store addinfo");
						phase1_error = true;
						break;
					}

					if(sqlite3_changes(memdb) > 0)
						aid = (int)sqlite3_last_insert_rowid(memdb);
					else
					{
						sqlite3_bind_int(addinfo_id_stmt, 1, ADDINFO_LIST_ID);
						sqlite3_bind_int(addinfo_id_stmt, 2, list_id);
						if(sqlite3_step(addinfo_id_stmt) == SQLITE_ROW)
							aid = sqlite3_column_int(addinfo_id_stmt, 0);
						sqlite3_reset(addinfo_id_stmt);
					}
					store_addinfo_id(ADDINFO_LIST_ID, list_id, aid);
				}
				s->addinfo_id = aid;
				s->list_id = list_id;
			}
			else
			{
				s->list_id = -1;
			}
		}

		// For CNAME-blocked queries, list_id comes from the DNS cache too
		if(s->addinfo_id > 0 && (query->status == QUERY_GRAVITY_CNAME ||
		   query->status == QUERY_REGEX_CNAME ||
		   query->status == QUERY_DENYLIST_CNAME))
		{
			const unsigned int cacheID = query->cacheID > -1
				? query->cacheID
				: findCacheID(query->domainID, query->clientID, query->type, false);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			s->list_id = (cache != NULL && cache->list_id != -1) ? cache->list_id : -1;
		}

		// Clear changed flag now (under lock) so that if the DNS thread
		// updates the query during phase 2 and sets changed back to
		// true, we will later be able to update this query.
		query->flags.database.changed = false;

		snap_count++;
	}

	// Commit linking table transaction
	if(!memdb_exec(memdb, "END", "commit the linking table transaction"))
		goto rollback_unlock_fail;

	// Release SHM lock — all data needed for phase 2 is in the snapshot
	unlock_shm();

	// If phase 1 encountered an error, skip phase 2. Everything it
	// snapshotted had its changed flag cleared, so this goes out through
	// the same restore as the transaction failures below
	if(phase1_error)
		goto fail;

	// ===================================================================
	// PHASE 2: Without SHM lock — bind and step query_stmt for each
	// snapshot. This is the bulk of the SQLite work and no longer blocks
	// the DNS processing or API threads.
	// ===================================================================

	if(!memdb_exec(memdb, "BEGIN TRANSACTION", "start the query transaction"))
		goto fail;

	unsigned int succeeded = 0;
	for(unsigned int i = 0; i < snap_count; i++)
	{
		const struct query_snap *s = &snaps[i];

		sqlite3_bind_int64(query_stmt, 1, s->idx);
		sqlite3_bind_double(query_stmt, 2, s->timestamp);
		sqlite3_bind_int(query_stmt, 3, s->type_val);
		sqlite3_bind_int(query_stmt, 4, s->status);
		sqlite3_bind_int(query_stmt, 5, s->domain_db_id);
		sqlite3_bind_int(query_stmt, 6, s->client_db_id);

		if(s->has_upstream)
			sqlite3_bind_int(query_stmt, 7, s->upstream_db_id);
		else
			sqlite3_bind_null(query_stmt, 7);

		if(s->addinfo_id > 0)
			sqlite3_bind_int(query_stmt, 8, s->addinfo_id);
		else
			sqlite3_bind_null(query_stmt, 8);

		sqlite3_bind_int(query_stmt, 9, s->reply);

		if(s->response_calculated)
			sqlite3_bind_double(query_stmt, 10, s->response);
		else
			sqlite3_bind_null(query_stmt, 10);

		sqlite3_bind_int(query_stmt, 11, s->dnssec);

		if(s->list_id != -1)
			sqlite3_bind_int(query_stmt, 12, s->list_id);
		else
			sqlite3_bind_null(query_stmt, 12);

		sqlite3_bind_int(query_stmt, 13, s->ede);

		rc = sqlite3_step(query_stmt);
		sqlite3_reset(query_stmt);

		if(rc != SQLITE_DONE)
		{
			log_err("Encountered error while trying to store queries in query_storage: %s", sqlite3_errstr(rc));
			break;
		}

		succeeded++;
	}

	if(!memdb_exec(memdb, "END", "commit the query transaction"))
		goto rollback_fail;

	// ===================================================================
	// PHASE 3: Brief SHM lock — write back db indices and clear changed
	// flags only for queries that were successfully committed.
	// ===================================================================
	lock_shm();

	// A step error in phase 2 left the rest of the snapshot uncommitted, so
	// those queries get their changed flag back and are written next time
	if(succeeded < snap_count)
	{
		requeue_snapshots(snaps, succeeded, snap_count);

		log_err("Could not store %u queries, they are queued for the next run",
		        snap_count - succeeded);
	}

	// Loop through snapshots of successfully committed queries and write
	// back db indices
	for(unsigned int i = 0; i < succeeded; i++)
	{
		const struct query_snap *s = &snaps[i];
		queriesData *query = getQuery(s->queryID, true);
		if(query == NULL)
			continue;

		if(s->is_new)
		{
			query->db = s->idx;
			if(s->blocked)
				new_blocked++;
			if(s->timestamp > new_last_timestamp)
				new_last_timestamp = s->timestamp;
			added++;
		}
		else
			updated++;
	}

	// Update memdb_queries_maxid to reflect all committed new entries
	if(added > 0)
	{
		int64_t committed_maxid = memdb_queries_maxid;
		for(unsigned int i = 0; i < succeeded; i++)
			if(snaps[i].is_new && snaps[i].idx > committed_maxid)
				committed_maxid = snaps[i].idx;
		memdb_queries_maxid = committed_maxid;
	}

	// Update number of queries in in-memory database and memorize how many
	// queries will be added to the on-disk database later on
	memdb_queries_count += added;
	new_total += added;

	unlock_shm();

	// Free snapshot array
	free(snaps);

	if(config.debug.database.v.b)
	{
		log_debug(DEBUG_DATABASE, "In-memory database: Inserted %u, updated %u, skipped %u queries", added, updated, unchanged);
		log_in_memory_usage();
	}

	return true;

	// Common cleanup for the transaction failures above. `SQL_bool()` is not
	// usable there: its early return would skip the unlock and leave the SHM
	// lock taken for good
rollback_unlock_fail:
	dbquery(memdb, "ROLLBACK");
unlock_fail:
	// Nothing was committed, so give the snapshotted queries their changed
	// flag back and let the next run pick them up. The lock is still ours
	requeue_snapshots(snaps, 0, snap_count);
	unlock_shm();
	goto fail_free;
rollback_fail:
	dbquery(memdb, "ROLLBACK");
fail:
	// Same restore, but phase 2 runs without the lock
	lock_shm();
	requeue_snapshots(snaps, 0, snap_count);
	unlock_shm();
fail_free:
	free(snaps);
	return false;
}
