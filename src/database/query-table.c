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

static sqlite3 *_memdb = NULL;
static bool store_in_database = false;
static double new_last_timestamp = 0;
static unsigned int new_total = 0, new_blocked = 0;
static sqlite3_int64 last_mem_db_idx = -1;
static unsigned int mem_db_num = 0, disk_db_num = 0;
static sqlite3_stmt *query_stmt = NULL;
static sqlite3_stmt *domain_stmt = NULL;
static sqlite3_stmt *client_stmt = NULL;
static sqlite3_stmt *forward_stmt = NULL;
static sqlite3_stmt *addinfo_stmt = NULL;
static sqlite3_stmt *queries_to_disk_stmt = NULL;
#define SUBTABLE_STMTS 5
static sqlite3_stmt *subtables_to_disk_stmts[SUBTABLE_STMTS] = { NULL };
// Array of all prepared statements
static sqlite3_stmt **stmts[] = { &query_stmt,
                                  &domain_stmt,
                                  &client_stmt,
                                  &forward_stmt,
                                  &addinfo_stmt,
                                  &queries_to_disk_stmt,
                                  &subtables_to_disk_stmts[0],
                                  &subtables_to_disk_stmts[1],
                                  &subtables_to_disk_stmts[2],
                                  &subtables_to_disk_stmts[3],
                                  &subtables_to_disk_stmts[4] };

// Private prototypes
static void load_queries_from_disk(void);

// Return the maximum ID of the in-memory database
sqlite3_int64 __attribute__((pure)) get_max_db_idx(void)
{
	return last_mem_db_idx;
}

void db_counts(sqlite3_int64 *last_idx, sqlite3_int64 *mem_num, sqlite3_int64 *disk_num)
{
	*last_idx = last_mem_db_idx;
	*mem_num = mem_db_num;
	*disk_num = disk_db_num;
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
	rc = sqlite3_open_v2(":memory:", &_memdb, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Step error while trying to open database: %s",
		        sqlite3_errstr(rc));
		return false;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_handler(_memdb, sqliteBusyCallback, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Step error while trying to set busy timeout: %s",
		        sqlite3_errstr(rc));
		sqlite3_close(_memdb);
		return false;
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
			log_err("init_memory_database(): Step error while trying to set journal mode: %s",
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
			log_err("init_memory_database(): Step error while trying to set journal mode: %s",
			        sqlite3_errstr(rc));
			sqlite3_close(_memdb);
			return false;
		}
	}

	// Prepare persistent insertion/replace statements
	rc = sqlite3_prepare_v3(_memdb, "REPLACE INTO query_storage VALUES "\
	                                "(?1," \
	                                 "?2," \
	                                 "?3," \
	                                 "?4," \
	                                 "(SELECT id FROM domain_by_id WHERE domain = ?5)," \
	                                 "(SELECT id FROM client_by_id WHERE ip = ?6 AND name = ?7)," \
	                                 "(SELECT id FROM forward_by_id WHERE forward = ?8)," \
	                                 "(SELECT id FROM addinfo_by_id WHERE type = ?9 AND content = ?10),"
	                                 "?11," \
	                                 "?12," \
	                                 "?13," \
	                                 "?14,"
	                                 "?15)", -1, SQLITE_PREPARE_PERSISTENT, &query_stmt, NULL);
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


	// Attach disk database
	if(attached)
		load_queries_from_disk();
	else
		log_err("init_memory_database(): Failed to attach disk database");

	// Everything went well
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

sqlite3 *__attribute__((pure)) get_memdb(void)
{
	log_debug(DEBUG_DATABASE, "Accessing in-memory database");
	return _memdb;
}

// Get memory usage and size of in-memory tables
static bool get_memdb_size(sqlite3 *db, size_t *memsize, int *queries)
{
	int rc;
	sqlite3_stmt *stmt = NULL;
	size_t page_count, page_size;

	// PRAGMA page_count
	rc = sqlite3_prepare_v2(db, "PRAGMA page_count", -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		if(rc != SQLITE_BUSY)
			log_err("init_memory_database(PRAGMA page_count): Prepare error: %s",
			        sqlite3_errstr(rc));

		return false;
	}
	rc = sqlite3_step(stmt);
	if( rc == SQLITE_ROW )
		page_count = sqlite3_column_int(stmt, 0);
	else
	{
		log_err("init_memory_database(PRAGMA page_count): Step error: %s",
		        sqlite3_errstr(rc));
		return false;
	}
	sqlite3_finalize(stmt);

	// PRAGMA page_size
	rc = sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		if(rc != SQLITE_BUSY)
			log_err("init_memory_database(PRAGMA page_size): Prepare error: %s",
			        sqlite3_errstr(rc));

		return false;
	}
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
		page_size = sqlite3_column_int(stmt, 0);
	else
	{
		log_err("init_memory_database(PRAGMA page_size): Step error: %s",
			 sqlite3_errstr(rc));
		return false;
	}
	sqlite3_finalize(stmt);

	*memsize = page_count * page_size;

	// Get number of queries in the memory table
	if((*queries = get_number_of_queries_in_DB(db, "query_storage", NULL)) == DB_FAILED)
		return false;

	return true;
}

// Log the memory usage of in-memory databases
static void log_in_memory_usage(void)
{
	if(!(config.debug.database.v.b))
		return;

	size_t memsize = 0;
	int queries = 0;
	sqlite3 *memdb = get_memdb();
	if(get_memdb_size(memdb, &memsize, &queries))
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

// Get number of queries either in the temp or in the on-disk database
// This routine is used by the API routines.
int get_number_of_queries_in_DB(sqlite3 *db, const char *tablename, double *earliest_timestamp)
{
	int rc = 0, num = 0;
	sqlite3_stmt *stmt = NULL;

	// The database pointer may be NULL, meaning we want the memdb
	if(db == NULL)
		db = get_memdb();

	// Build query string based on whether we need the earliest timestamp too
	const size_t buflen = 38 + strlen(tablename);
	char *querystr = calloc(buflen, sizeof(char));
	if(earliest_timestamp != NULL)
	{
		// Get both count and earliest timestamp
		snprintf(querystr, buflen, "SELECT COUNT(*), MIN(timestamp) FROM %s", tablename);
	}
	else
	{
		// Get only count
		snprintf(querystr, buflen, "SELECT COUNT(*) FROM %s", tablename);
	}

	rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("get_number_of_queries_in_DB(%s): Prepare error: %s",
			        tablename, sqlite3_errstr(rc));
		free(querystr);
		return false;
	}
	rc = sqlite3_step(stmt);
	if( rc == SQLITE_ROW )
	{
		// Get count from first column
		num = sqlite3_column_int(stmt, 0);
		// Get timestamp from second column if requested
		if(earliest_timestamp != NULL && sqlite3_column_type(stmt, 1) != SQLITE_NULL)
			*earliest_timestamp = sqlite3_column_double(stmt, 1);
	}
	sqlite3_finalize(stmt);
	free(querystr);

	return num;
}

// Read queries from the on-disk database into the in-memory database (after
// restart, etc.)
bool import_queries_from_disk(void)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const double now = double_time();
	const double mintime = now - config.webserver.api.maxHistory.v.ui;
	const char *querystr = "INSERT INTO query_storage SELECT * FROM disk.query_storage WHERE timestamp >= ?";

	// Begin transaction
	int rc;
	sqlite3 *memdb = get_memdb();
	if((rc = sqlite3_exec(memdb, "BEGIN TRANSACTION", NULL, NULL, NULL)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Cannot start transaction: %s", sqlite3_errstr(rc));
		return false;
	}

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	log_debug(DEBUG_DATABASE, "Accessing in-memory database");
	if((rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL)) != SQLITE_OK){
		log_err("import_queries_from_disk(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind limit
	if((rc = sqlite3_bind_double(stmt, 1, mintime)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Failed to bind type mintime: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		log_err("import_queries_from_disk(): Failed to import queries: %s",
		        sqlite3_errstr(rc));

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

	// Import linking tables
	for(unsigned int i = 0; i < ArraySize(subtable_sql); i++)
	{
		if((rc = sqlite3_exec(memdb, subtable_sql[i], NULL, NULL, NULL)) != SQLITE_OK)
			log_err("import_queries_from_disk(%s): Cannot import linking table: %s",
			        subtable_sql[i], sqlite3_errstr(rc));
		log_debug(DEBUG_DATABASE, "Imported %i rows from disk.%s", sqlite3_changes(memdb), subtable_names[i]);
	}

	// End transaction
	if((rc = sqlite3_exec(memdb, "END TRANSACTION", NULL, NULL, NULL)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Cannot end transaction: %s", sqlite3_errstr(rc));
		return false;
	}

	// Get number of queries on disk before detaching
	disk_db_num = get_number_of_queries_in_DB(memdb, "disk.query_storage", NULL);
	mem_db_num = get_number_of_queries_in_DB(memdb, "query_storage", NULL);

	log_info("Imported %u queries from the on-disk database (it has %u rows)", mem_db_num, disk_db_num);

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
	SQL_bool(memdb, "BEGIN TRANSACTION");

	// Only store queries if database.maxDBdays > 0
	if(config.database.maxDBdays.v.ui > 0)
	{
		log_debug(DEBUG_DATABASE, "Storing queries on disk WHERE timestamp < %f (last_mem_db_idx = %lld)",
		          time, last_mem_db_idx);

		// Bind upper time limit
		// This prevents queries from the last 30 seconds from being stored
		// immediately on-disk to give them some time to complete before finally
		// exported. We do not limit anything when storing during termination.
		if((rc = sqlite3_bind_double(queries_to_disk_stmt, 1, time)) != SQLITE_OK)
		{
			log_err("export_queries_to_disk(): Failed to bind time: %s", sqlite3_errstr(rc));
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
		 * Note that new_total does not need to match the total number of
		 * insertions here as storing queries to the database happens
		 * time-delayed. In the end, the total number of queries will be
		 * correct (after final synchronization during FTL shutdown).
		 */
		if(insertions > 0)
		{
			if((rc = dbquery(memdb, "INSERT OR REPLACE INTO disk.ftl (id, value) VALUES ( %i, %f );", DB_LASTTIMESTAMP, new_last_timestamp)) != SQLITE_OK)
				log_err("export_queries_to_disk(): Cannot update timestamp: %s", sqlite3_errstr(rc));

			if((rc = dbquery(memdb, "UPDATE disk.counters SET value = value + %u WHERE id = %i;", new_total, DB_TOTALQUERIES)) != SQLITE_OK)
				log_err("export_queries_to_disk(): Cannot update total queries counter: %s", sqlite3_errstr(rc));
			else
				// Success
				new_total = 0;

			if((rc = dbquery(memdb, "UPDATE disk.counters SET value = value + %u WHERE id = %i;", new_blocked, DB_BLOCKEDQUERIES)) != SQLITE_OK)
				log_err("export_queries_to_disk(): Cannot update blocked queries counter: %s", sqlite3_errstr(rc));
			else
				// Success
				new_blocked = 0;
		}

		// Update number of queries in the disk database
		disk_db_num = get_number_of_queries_in_DB(memdb, "disk.query_storage", NULL);
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

	// End transaction
	SQL_bool(memdb, "END TRANSACTION");

	log_debug(DEBUG_DATABASE, "Exported %u rows for disk.query_storage (took %.1f ms)",
		  insertions, timer_elapsed_msec(DATABASE_WRITE_TIMER));

	return okay;
}

// Delete queries older than given timestamp. Used by garbage collection
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
		log_err("delete_old_queries_from_db(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind index
	if((rc = sqlite3_bind_double(stmt, 1, mintime)) != SQLITE_OK)
	{
		log_err("delete_old_queries_from_db(): Failed to bind mintime: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		log_err("delete_old_queries_from_db(): Failed to delete queries with timestamp >= %f: %s",
		        mintime, sqlite3_errstr(rc));

	// Update number of queries in in-memory database
	const int new_num = get_number_of_queries_in_DB(NULL, "query_storage", NULL);
	log_debug(DEBUG_GC, "delete_old_queries_from_db(): Deleted %i (%u) queries, new number of queries in memory: %i",
	          sqlite3_changes(db), (mem_db_num - new_num), new_num);
	mem_db_num = new_num;

	// Finalize statement
	sqlite3_finalize(stmt);

	if(!use_memdb)
		dbclose(&db);

	return okay;
}

bool add_additional_info_column(sqlite3 *db)
{
	// Start transaction
	SQL_bool(db, "BEGIN TRANSACTION");

	// Add column additinal_info to queries table
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN additional_info TEXT;");

	// Update the database version to 7
	if(!db_set_FTL_property(db, DB_VERSION, 7))
	{
		log_err("add_additional_info_column(): Failed to update database version!");
		return false;
	}

	// End transaction
	SQL_bool(db, "COMMIT");

	return true;
}

bool add_query_storage_columns(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION");

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
	SQL_bool(db, "COMMIT");

	return true;
}

bool add_query_storage_column_regex_id(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION");

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
	SQL_bool(db, "COMMIT");

	return true;
}

bool add_ftl_table_description(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION");

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
	SQL_bool(db, "COMMIT");

	return true;
}

bool rename_query_storage_column_regex_id(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION");

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
	SQL_bool(db, "COMMIT");

	return true;
}

bool add_query_storage_column_ede(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION");

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
	SQL_bool(db, "COMMIT");

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
	SQL_bool(db, "COMMIT");

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
	SQL_bool(db, "COMMIT");

	return true;
}

// Get most recent 24 hours data from long-term database
void DB_read_queries(void)
{
	// Prepare request
	// Get time stamp 24 hours in the past
	const double now = double_time();
	const double mintime = now - config.webserver.api.maxHistory.v.ui;
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
	                       "FROM queries WHERE timestamp >= ?";

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

	// Bind limit
	if((rc = sqlite3_bind_double(stmt, 1, mintime)) != SQLITE_OK)
	{
		log_err("DB_read_queries() - Failed to bind mintime: %s", sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return;
	}

	// Lock shared memory
	lock_shm();

	// Loop through returned database rows
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
		if(queryTimeStamp > now)
		{
			log_debug(DEBUG_DATABASE, "Skipping query logged in the future (%f > %f)", queryTimeStamp, now);
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

		// Ensure we have enough shared memory available for new data
		shm_ensure_size();

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
				continue;
			}
		}

		// Obtain IDs only after filtering which queries we want to keep
		const int timeidx = getOverTimeID(queryTimeStamp);
		const int domainID = findDomainID(domainname, true);
		const int clientID = findClientID(clientIP, true, false, queryTimeStamp);

		// Set index for this query
		const int queryIndex = counters->queries;

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
		query->flags.database.stored = true;
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

		// Increase DNS queries counter
		counters->queries++;

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
				const int CNAMEdomainID = findDomainID(CNAMEdomain, false);
				query->CNAME_domainID = CNAMEdomainID;

				// Get domain pointer and update lastQuery timer
				domainsData *cdomain = getDomain(CNAMEdomainID, true);
				if(cdomain != NULL)
					cdomain->lastQuery = queryTimeStamp;
			}
		}
		else if(sqlite3_column_bytes(stmt, 7) != 0)
		{
			// Set ID of the domainlist entry that was the reason for permitting/blocking this query
			// We assume the value in this field is said ID when it is not a CNAME-related domain
			// (checked above) and the value of additional_info is not NULL (0 bytes storage size)
			query->cacheID = findCacheID(domainID, clientID, query->type, true);
			DNSCacheData *cache = getDNSCache(query->cacheID, true);
			// Only load if
			//  a) we have a cache entry
			//  b) the value of additional_info is not NULL (0 bytes storage size)
			if(cache != NULL && sqlite3_column_bytes(stmt, 7) != 0)
				cache->list_id = sqlite3_column_int(stmt, 7);
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

		if(counters->queries % 10000 == 0)
			log_info("  %u queries parsed...", counters->queries);
	}

	// Release shared memory
	unlock_shm();

	if( rc != SQLITE_DONE )
	{
		log_err("DB_read_queries() - SQL error step: %s", sqlite3_errstr(rc));
		return;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);

	log_info("Imported %u queries from the long-term database", counters->queries);
}

void init_disk_db_idx(void)
{
	const char *querystr = "SELECT MAX(id) FROM disk.query_storage";

	// If the disk database is broken, we cannot import queries from it,
	// however, as we will also never export any queries, we can safely
	// assume any index
	if(FTLDBerror())
	{
		last_mem_db_idx = -1;
		return;
	}

	// Get memory database pointer
	sqlite3 *memdb = get_memdb();

	// Prepare SQLite3 statement on first call
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	
	// Perform step
	if(rc == SQLITE_OK && (rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// We need to check that the returned value is not NULL (happens
		// when there are no rows in the table). If it is NULL, we set
		// last_mem_db_idx to -1 so that the next query will be stored
		// with index 0. If it is not NULL, we set last_mem_db_idx to
		// the returned value.
		if(sqlite3_column_type(stmt, 0) == SQLITE_INTEGER)
			last_mem_db_idx = sqlite3_column_int64(stmt, 0);
		else
			last_mem_db_idx = -1;
	}
	else
		log_err("init_disk_db_idx(): Failed to get MAX(id) from disk.query_storage: %s",
		        sqlite3_errstr(rc));

	// Finalize statement
	sqlite3_finalize(stmt);

	log_debug(DEBUG_DATABASE, "Last long-term idx is %lld", last_mem_db_idx);
}

bool queries_to_database(void)
{
	int rc;
	unsigned int added = 0, updated = 0;
	sqlite3_int64 idx = 0;

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
	if(!store_in_database)
	{
		log_debug(DEBUG_DATABASE, "Not storing query in database as this is disabled");
		return true;
	}

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
			return false;
		}
		if(query->timestamp < limit_timestamp)
		{
			// We found the first query older than our limit
			last_query++;
			break;
		}
		last_query--;
	}

	log_debug(DEBUG_DATABASE, "Storing queries from ID %u to %u in in-memory-database", last_query, counters->queries - 1);

	// Loop over recent queries and store new or changed ones in the
	// in-memory database
	for(unsigned int queryID = last_query; queryID < counters->queries; queryID++)
	{
		// Get query pointer
		queriesData *query = getQuery(queryID, true);
		if(query == NULL)
		{
			// Encountered memory error, skip query
			log_err("Memory error in queries_to_database() when trying to access query %u", queryID);
			break;
		}

		// Skip queries which have not changed since the last iteration
		if(!query->flags.database.changed)
			continue;

		// Explicitly set ID to match what is in the on-disk database
		if(query->db > -1)
		{
			// We update an existing query
			idx = query->db;
		}
		else
		{
			// We create a new query
			idx = last_mem_db_idx + 1;
		}

		log_debug(DEBUG_DATABASE, "Storing query ID %u in in-memory-database with idx %lld (old idx %lld)",
		          queryID, idx, query->db);

		// ID
		sqlite3_bind_int64(query_stmt, 1, idx);

		// TIMESTAMP
		sqlite3_bind_double(query_stmt, 2, query->timestamp);

		// TYPE
		if(query->type != TYPE_OTHER)
		{
			// Store mapped type if query->type is not OTHER
			sqlite3_bind_int(query_stmt, 3, query->type);
		}
		else
		{
			// Store query type + offset if query-> type is OTHER
			sqlite3_bind_int(query_stmt, 3, query->qtype + 100);
		}

		// STATUS
		sqlite3_bind_int(query_stmt, 4, query->status);

		// DOMAIN
		const char *domain = getDomainString(query);
		sqlite3_bind_text(query_stmt, 5, domain, -1, SQLITE_STATIC);
		sqlite3_bind_text(domain_stmt, 1, domain, -1, SQLITE_STATIC);

		// Execute prepare domain statement and check if successful
		rc = sqlite3_step(domain_stmt);
		if(rc != SQLITE_DONE)
		{
			log_err("Encountered error while trying to store domain");
			sqlite3_clear_bindings(domain_stmt);
			sqlite3_reset(domain_stmt);
			break;
		}
		sqlite3_clear_bindings(domain_stmt);
		sqlite3_reset(domain_stmt);

		// CLIENT
		const char *clientIP = getClientIPString(query);
		sqlite3_bind_text(query_stmt, 6, clientIP, -1, SQLITE_STATIC);
		sqlite3_bind_text(client_stmt, 1, clientIP, -1, SQLITE_STATIC);
		const char *clientName = getClientNameString(query);
		sqlite3_bind_text(query_stmt, 7, clientName, -1, SQLITE_STATIC);
		sqlite3_bind_text(client_stmt, 2, clientName, -1, SQLITE_STATIC);

		// Execute prepare client statement and check if successful
		rc = sqlite3_step(client_stmt);
		sqlite3_clear_bindings(client_stmt);
		sqlite3_reset(client_stmt);
		if(rc != SQLITE_DONE)
		{
			log_err("Encountered error while trying to store client");
			break;
		}

		// FORWARD
		if(query->upstreamID > -1)
		{
			// Get forward pointer
			const upstreamsData *upstream = getUpstream(query->upstreamID, true);
			if(upstream != NULL)
			{
				char *buffer = NULL;
				const char *forwardIP = getstr(upstream->ippos);
				int len = 0; // The length of the string WITHOUT the NUL byte. This is what sqlite3_bind_text() expects.
				if((len = asprintf(&buffer, "%s#%u", forwardIP, upstream->port)) > 0)
				{
					// Use transient here as we step only after the buffer is freed below
					sqlite3_bind_text(query_stmt, 8, buffer, len, SQLITE_TRANSIENT);
					// Use static here as we insert right away
					sqlite3_bind_text(forward_stmt, 1, buffer, len, SQLITE_STATIC);

					// Execute prepared forward statement and check if successful
					rc = sqlite3_step(forward_stmt);
					sqlite3_clear_bindings(forward_stmt);
					sqlite3_reset(forward_stmt);
					if(rc != SQLITE_DONE)
					{
						log_err("Encountered error while trying to store forward");
						break;
					}
				}
				else
				{
					// Memory error: Do not store the forward destination
					sqlite3_bind_null(query_stmt, 8);
				}

				if(buffer) free(buffer);
			}
		}
		else
		{
			// No forward destination
			sqlite3_bind_null(query_stmt, 8);
		}

		// Get cache entry for this query
		const unsigned int cacheID = query->cacheID > -1 ? query->cacheID : findCacheID(query->domainID, query->clientID, query->type, false);
		DNSCacheData *cache = getDNSCache(cacheID, true);

		// ADDITIONAL_INFO
		if(query->status == QUERY_GRAVITY_CNAME ||
		   query->status == QUERY_REGEX_CNAME ||
		   query->status == QUERY_DENYLIST_CNAME)
		{
			// Save domain blocked during deep CNAME inspection
			const char *cname = getCNAMEDomainString(query);
			const int len = strlen(cname);
			sqlite3_bind_int(query_stmt, 9, ADDINFO_CNAME_DOMAIN);
			sqlite3_bind_text(query_stmt, 10, cname, len, SQLITE_STATIC);

			// Execute prepared addinfo statement and check if successful
			sqlite3_bind_int(addinfo_stmt, 1, ADDINFO_CNAME_DOMAIN);
			sqlite3_bind_text(addinfo_stmt, 2, cname, len, SQLITE_STATIC);
			rc = sqlite3_step(addinfo_stmt);
			sqlite3_clear_bindings(addinfo_stmt);
			sqlite3_reset(addinfo_stmt);
			if(rc != SQLITE_DONE)
			{
				log_err("Encountered error while trying to store addinfo");
				break;
			}
		}
		else if(cache != NULL && cache->list_id != -1)
		{
			// Restore regex ID if applicable
			sqlite3_bind_int(query_stmt, 9, ADDINFO_LIST_ID);
			sqlite3_bind_int(query_stmt, 10, cache->list_id);

			// Execute prepared addinfo statement and check if successful
			sqlite3_bind_int(addinfo_stmt, 1, ADDINFO_LIST_ID);
			sqlite3_bind_int(addinfo_stmt, 2, cache->list_id);
			rc = sqlite3_step(addinfo_stmt);
			sqlite3_clear_bindings(addinfo_stmt);
			sqlite3_reset(addinfo_stmt);
			if(rc != SQLITE_DONE)
			{
				log_err("Encountered error while trying to store addinfo");
				break;
			}
		}
		else
		{
			// Nothing to add here
			sqlite3_bind_null(query_stmt, 9);
			sqlite3_bind_null(query_stmt, 10);
		}

		// REPLY_TYPE
		sqlite3_bind_int(query_stmt, 11, query->reply);

		// REPLY_TIME
		if(query->flags.response_calculated)
			// Store difference (in seconds) when applicable
			sqlite3_bind_double(query_stmt, 12, query->response);
		else
			// Store NULL otherwise
			sqlite3_bind_null(query_stmt, 12);

		// DNSSEC
		sqlite3_bind_int(query_stmt, 13, query->dnssec);

		// LIST_ID
		if(cache != NULL && cache->list_id != -1)
			sqlite3_bind_int(query_stmt, 14, cache->list_id);
		else
			// Not applicable, setting NULL
			sqlite3_bind_null(query_stmt, 14);

		// EDE
		sqlite3_bind_int(query_stmt, 15, query->ede);

		// Step and check if successful
		rc = sqlite3_step(query_stmt);
		sqlite3_clear_bindings(query_stmt);
		sqlite3_reset(query_stmt);

		if( rc != SQLITE_DONE )
		{
			log_err("Encountered error while trying to store queries in query_storage: %s", sqlite3_errstr(rc));
			break;
		}

		// Update fields if this is a new query (skip if we are only updating an
		// existing entry)
		if(query->db == -1)
		{
			// Store database index for this query (in case we need to
			// update it later on)
			query->db = ++last_mem_db_idx;

			// Total counter information (delta computation)
			new_total++;
			if(query->flags.blocked)
				new_blocked++;

			// Update lasttimestamp variable with timestamp of the latest stored query
			if(query->timestamp > new_last_timestamp)
				new_last_timestamp = query->timestamp;

			added++;
		}
		else
			updated++;

		// Memorize query as updated in the database
		query->flags.database.changed = false;
	}

	// Update number of queries in in-memory database
	mem_db_num = get_number_of_queries_in_DB(NULL, "query_storage", NULL);

	if(config.debug.database.v.b && updated + added > 0)
	{
		log_debug(DEBUG_DATABASE, "In-memory database: Added %u new, updated %u known queries", added, updated);
		log_in_memory_usage();
	}

	return true;
}

static void load_queries_from_disk(void)
{
	// Compensate for possible jumps in time
	runGC(time(NULL), NULL, false);

	// Skip if we are not supposed to load queries from disk
	if(!config.database.DBimport.v.b)
		return;

	// Try to import queries from long-term database if available
	import_queries_from_disk();
	DB_read_queries();

	// Log some information about the imported queries (if any)
	log_counter_info();

	store_in_database = true;
}
