/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#define QUERY_TABLE_PRIVATE
#include "query-table.h"
#include "sqlite3.h"
#include "../log.h"
#include "../config/config.h"
#include "../enums.h"
#include "../config/config.h"
// counters
#include "../shmem.h"
#include "../overTime.h"
#include "common.h"
#include "../timers.h"

static sqlite3 *memdb = NULL;
static double new_last_timestamp = 0;
static unsigned int new_total = 0, new_blocked = 0;
static unsigned long last_mem_db_idx = 0, last_disk_db_idx = 0;
static unsigned int mem_db_num = 0, disk_db_num = 0;

void db_counts(unsigned long *last_idx, unsigned long *mem_num, unsigned long *disk_num)
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
	const char *uri = "file:memdb?mode=memory&cache=shared";

	// Try to open in-memory database
	rc = sqlite3_open_v2(uri, &memdb, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Step error while trying to open database: %s",
		        sqlite3_errstr(rc));
		return false;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_timeout(memdb, DATABASE_BUSY_TIMEOUT);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Step error while trying to set busy timeout (%d ms): %s",
		        DATABASE_BUSY_TIMEOUT, sqlite3_errstr(rc));
		sqlite3_close(memdb);
		return false;
	}

	// Create query_storage table in the database
	for(unsigned int i = 0; i < ArraySize(table_creation); i++)
	{
		log_debug(DEBUG_DATABASE, "init_memory_database(): Executing %s", table_creation[i]);
		rc = sqlite3_exec(memdb, table_creation[i], NULL, NULL, NULL);
		if( rc != SQLITE_OK ){
			log_err("init_memory_database(\"%s\") failed: %s",
				table_creation[i], sqlite3_errstr(rc));
			sqlite3_close(memdb);
			return false;
		}
	}

	// Add indices on all columns of the in-memory database
	// as well as index on auxilliary tables
	for(unsigned int i = 0; i < ArraySize(index_creation); i++)
	{
		log_debug(DEBUG_DATABASE, "init_memory_database(): Executing %s", index_creation[i]);
		rc = sqlite3_exec(memdb, index_creation[i], NULL, NULL, NULL);
		if( rc != SQLITE_OK ){
			log_err("init_memory_database(\"%s\") failed: %s",
			        index_creation[i], sqlite3_errstr(rc));
			sqlite3_close(memdb);
			return false;
		}
	}

	// Everything went well
	return true;
}

sqlite3 *__attribute__((pure)) get_memdb(void)
{
	return memdb;
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
	if((*queries = get_number_of_queries_in_DB(db, "query_storage", false)) == DB_FAILED)
		return false;

	return true;
}

// Log the memory usage of in-memory databases
static void log_in_memory_usage(void)
{
	if(!(config.debug & DEBUG_DATABASE))
		return;

	size_t memsize = 0;
	int queries = 0;
	if(get_memdb_size(memdb, &memsize, &queries))
	{
		char prefix[2] = { 0 };
		double num = 0.0;
		format_memory_size(prefix, memsize, &num);
		log_debug(DEBUG_DATABASE, "mem database size: %.1f%s (%d queries)",
		          num, prefix, queries);
	}
}

// Attach disk database to in-memory database
bool attach_disk_database(const char **message)
{
	int rc;
	bool okay = false;
	sqlite3_stmt *stmt = NULL;

	// ATTACH database file on-disk
	rc = sqlite3_prepare_v2(memdb, "ATTACH ? AS disk", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("attach_disk_database(): Prepare error: %s", sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
		return false;
	}
	// Bind path to prepared index
	if((rc = sqlite3_bind_text(stmt, 1, config.files.database, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("attach_disk_database(): Failed to bind path: %s",
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
		log_err("attach_disk_database(): Failed to attach database: %s",
		        sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
	}

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return okay;
}

// Detach disk database to in-memory database
bool detach_disk_database(const char **message)
{
	int rc;

	// Detach database
	rc = sqlite3_exec(memdb, "DETACH disk", NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		log_err("detach_disk_database() failed: %s",
		        sqlite3_errstr(rc));
		if(message != NULL)
			*message = sqlite3_errstr(rc);
		sqlite3_close(memdb);
		return false;
	}

	return true;
}

// Get number of queries either in the temp or in the on-diks database
// This routine is used by the API routines.
int get_number_of_queries_in_DB(sqlite3 *db, const char *tablename, const bool do_attach)
{
	int rc = 0, num = 0;
	sqlite3_stmt *stmt = NULL;
	// Attach disk database if required
	if(do_attach && !attach_disk_database(NULL))
		return DB_FAILED;

	// Count number of rows
	const size_t buflen = 42 + strlen(tablename);
	char *querystr = calloc(buflen, sizeof(char));
	snprintf(querystr, buflen, "SELECT COUNT(*) FROM %s", tablename);

	// The database pointer may be NULL, meaning we want the memdb
	if(db == NULL)
		db = memdb;

	// PRAGMA page_size
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
		num = sqlite3_column_int(stmt, 0);
	else
	{
		log_err("get_number_of_queries_in_DB(%s): Step error: %s",
		        tablename, sqlite3_errstr(rc));
		free(querystr);
		return false;
	}
	sqlite3_finalize(stmt);
	free(querystr);

	// Detach only if attached herein
	if(do_attach && !detach_disk_database(NULL))
		return DB_FAILED;

	return num;
}

// Read queries from the on-disk database into the in-memory database (after
// restart, etc.)
bool import_queries_from_disk(void)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const double now = double_time();
	const double mintime = now - config.maxHistory;
	const char *querystr = "INSERT INTO query_storage SELECT * FROM disk.query_storage WHERE timestamp >= ?";

	// Attach disk database
	if(!attach_disk_database(NULL))
		return false;

	// Begin transaction
	int rc;
	if((rc = sqlite3_exec(memdb, "BEGIN TRANSACTION", NULL, NULL, NULL)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Cannot start transaction: %s", sqlite3_errstr(rc));
		return false;
	}

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	if((rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL)) != SQLITE_OK){
		log_err("import_queries_from_disk(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind limit
	if((rc = sqlite3_bind_double(stmt, 1, mintime)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Failed to bind type mintime: %s", sqlite3_errstr(rc));
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		log_err("import_queries_from_disk(): Failed to import queries: %s",
		        sqlite3_errstr(rc));

	// Finalize statement
	sqlite3_reset(stmt);
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
	disk_db_num = get_number_of_queries_in_DB(memdb, "disk.query_storage", false);
	mem_db_num = get_number_of_queries_in_DB(memdb, "query_storage", false);

	if(!detach_disk_database(NULL))
		return false;

	log_info("Imported %d queries from the on-disk database (it has %d rows)", mem_db_num, disk_db_num);

	return okay;
}

// Export in-memory queries to disk - either due to periodic dumping (final =
// false) or because of a sutdown (final = true)
bool export_queries_to_disk(bool final)
{
	bool okay = false;
	const double time = double_time() - (final ? 0.0 : 30.0);
	const char *querystr = "INSERT INTO disk.query_storage SELECT * FROM query_storage WHERE id > ? AND timestamp < ?";

	log_debug(DEBUG_DATABASE, "Storing queries on disk WHERE id > %lu (max is %lu) and timestamp < %f",
	          last_disk_db_idx, last_mem_db_idx, time);

	// Start database timer
	timer_start(DATABASE_WRITE_TIMER);

	// Attach disk database
	if(!attach_disk_database(NULL))
		return false;

	// Start transaction
	SQL_bool(memdb, "BEGIN TRANSACTION");

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("export_queries_to_disk(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind index
	if((rc = sqlite3_bind_int64(stmt, 1, last_disk_db_idx)) != SQLITE_OK)
	{
		log_err("export_queries_to_disk(): Failed to bind id: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind upper time limit
	// This prevents queries from the last 30 seconds from being stored
	// immediately on-disk to give them some time to complete before finally
	// exported. We do not limit anything when storing during termination.
	if((rc = sqlite3_bind_int64(stmt, 2, time)) != SQLITE_OK)
	{
		log_err("export_queries_to_disk(): Failed to bind time: %s", sqlite3_errstr(rc));
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		log_err("export_queries_to_disk(): Failed to export queries: %s",
		        sqlite3_errstr(rc));

	// Get number of queries actually inserted by the INSERT INTO ... SELECT * FROM ...
	const int insertions = sqlite3_changes(memdb);

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Export linking tables and current AUTOINCREMENT values to the disk database
	const char *subtable_names[] = {
		"domain_by_id",
		"client_by_id",
		"forward_by_id",
		"addinfo_by_id",
		"sqlite_sequence"
	};
	const char *subtable_sql[] = {
		"INSERT OR IGNORE INTO disk.domain_by_id SELECT * FROM domain_by_id",
		"INSERT OR IGNORE INTO disk.client_by_id SELECT * FROM client_by_id",
		"INSERT OR IGNORE INTO disk.forward_by_id SELECT * FROM forward_by_id",
		"INSERT OR IGNORE INTO disk.addinfo_by_id SELECT * FROM addinfo_by_id",
		"UPDATE disk.sqlite_sequence SET seq = (SELECT seq FROM sqlite_sequence WHERE disk.sqlite_sequence.name = sqlite_sequence.name)"
	};

	// Export linking tables
	for(unsigned int i = 0; i < ArraySize(subtable_sql); i++)
	{
		if((rc = sqlite3_exec(memdb, subtable_sql[i], NULL, NULL, NULL)) != SQLITE_OK)
			log_err("export_queries_to_disk(disk.%s): Cannot export subtable: %s",
			        subtable_sql[i], sqlite3_errstr(rc));
		log_debug(DEBUG_DATABASE, "Exported %i rows to disk.%s", sqlite3_changes(memdb), subtable_names[i]);
	}

	// End transaction
	if((rc = sqlite3_exec(memdb, "END TRANSACTION", NULL, NULL, NULL)) != SQLITE_OK)
	{
		log_err("export_queries_to_disk(): Cannot end transaction: %s", sqlite3_errstr(rc));
		return false;
	}

	// Detach disk database
	if(!detach_disk_database(NULL))
		return false;

	// All temp queries were stored to disk, update the IDs
	last_disk_db_idx += insertions;

	if(insertions > 0)
	{
		sqlite3 *db = dbopen(false);
		if(db != NULL)
		{
			db_set_FTL_property_double(db, DB_LASTTIMESTAMP, new_last_timestamp);
			db_update_counters(db, new_total, new_blocked);
			dbclose(&db);
		}
	}

	log_debug(DEBUG_DATABASE, "Exported %u rows for disk.query_storage (took %.1f ms, last SQLite ID %li)",
	          insertions, timer_elapsed_msec(DATABASE_WRITE_TIMER), last_disk_db_idx);

	return okay;
}

// Delete query with given ID from database. Used by garbage collection
bool delete_query_from_db(const sqlite3_int64 id)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const char *querystr = "DELETE FROM query_storage WHERE id = ?";

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("delete_query_from_db(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind index
	if((rc = sqlite3_bind_int64(stmt, 1, id)) != SQLITE_OK)
	{
		log_err("delete_query_from_db(): Failed to bind type id: %s", sqlite3_errstr(rc));
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		log_err("delete_query_from_db(): Failed to delete query with ID %lli: %s",
		        id, sqlite3_errstr(rc));

	mem_db_num -= sqlite3_changes(memdb);
	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return okay;
}

bool add_additional_info_column(sqlite3 *db)
{
	// Add column additinal_info to queries table
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN additional_info TEXT;");

	// Update the database version to 7
	SQL_bool(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES (%u, 7);", DB_VERSION);

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
	const double mintime = now - config.maxHistory;
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

	log_info("Parsing queries in database");

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
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
		return;
	}

	// Lock shared memory
	lock_shm();

	// Loop through returned database rows
	sqlite3_int64 dbID = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		dbID = sqlite3_column_int64(stmt, 0);
		const double queryTimeStamp = sqlite3_column_double(stmt, 1);
		// 1483228800 = 01/01/2017 @ 12:00am (UTC)
		if(queryTimeStamp < 1483228800)
		{
			log_warn("Database: TIMESTAMP should be larger than 01/01/2017 but is %f (DB ID %lli)", queryTimeStamp, dbID);
			continue;
		}
		if(queryTimeStamp > now)
		{
			log_debug(DEBUG_DATABASE, "Skipping query logged in the future (%lli)", (long long)queryTimeStamp);
			continue;
		}

		const int type = sqlite3_column_int(stmt, 2);
		const bool mapped_type = type >= TYPE_A && type < TYPE_MAX;
		const bool offset_type = type > 100 && type < (100 + UINT16_MAX);
		if(!mapped_type && !offset_type)
		{
			log_warn("Database: TYPE should not be %i", type);
			continue;
		}
		// Don't import AAAA queries from database if the user set
		// AAAA_QUERY_ANALYSIS=no in pihole-FTL.conf
		if(type == TYPE_AAAA && !config.analyze_AAAA)
		{
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
			log_warn("Database: DOMAIN should never be NULL, %lli", (long long)queryTimeStamp);
			continue;
		}

		const char *clientIP = (const char *)sqlite3_column_text(stmt, 5);
		if(clientIP == NULL)
		{
			log_warn("Database: CLIENT should never be NULL, %lli", (long long)queryTimeStamp);
			continue;
		}

		// Check if user wants to skip queries coming from localhost
		if(config.ignore_localhost &&
		   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
		{
			continue;
		}

		const int reply_int = sqlite3_column_int(stmt, 8);
		if(reply_int < REPLY_UNKNOWN || reply_int >= QUERY_REPLY_MAX)
		{
			log_warn("Database: REPLY should be within [%i,%i] but is %i",
			         REPLY_UNKNOWN, QUERY_REPLY_MAX-1, reply_int);
			continue;
		}
		const enum reply_type reply = reply_int;

		const int dnssec_int = sqlite3_column_int(stmt, 10);
		if(dnssec_int < DNSSEC_UNKNOWN || dnssec_int >= DNSSEC_MAX)
		{
			log_warn("Database: REPLY should be within [%i,%i] but is %i",
			         DNSSEC_UNKNOWN, DNSSEC_MAX-1, dnssec_int);
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
			char serv_addr[INET6_ADDRSTRLEN] = { 0 };
			unsigned int serv_port = 53;
			// We limit the number of bytes written into the serv_addr buffer
			// to prevent buffer overflows. If there is no port available in
			// the database, we skip extracting them and use the default port
			sscanf(buffer, "%"xstr(INET6_ADDRSTRLEN)"[^#]#%u", serv_addr, &serv_port);
			serv_addr[INET6_ADDRSTRLEN-1] = '\0';
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
				log_warn("REPLY_TIME value %f is invalid, %lli", reply_time, (long long)queryTimeStamp);
				continue;
			}
		}

		// Obtain IDs only after filtering which queries we want to keep
		const int timeidx = getOverTimeID(queryTimeStamp);
		const int domainID = findDomainID(domainname, true);
		const int clientID = findClientID(clientIP, true, false);

		// Set index for this query
		const int queryIndex = counters->queries;

		// Store this query in memory
		queriesData *query = getQuery(queryIndex, false);
		query->magic = MAGICBYTE;
		query->timestamp = queryTimeStamp;
		if(type < 100)
		{
			// Mapped query type
			if(type >= TYPE_A && type < TYPE_MAX)
				query->type = type;
			else
			{
				// Invalid query type
				log_warn("Query type %d is invalid.", type);
				continue;
			}
		}
		else
		{
			// Offset query type
			query->type = TYPE_OTHER;
			query->qtype = type - 100;
		}

		// Status is set below
		query->domainID = domainID;
		query->clientID = clientID;
		query->upstreamID = upstreamID;
		query->id = 0;
		query->response = 0;
		query->flags.response_calculated = reply_time_avail;
		query->dnssec = dnssec;
		query->reply = reply;
		counters->reply[query->reply]++;
		query->response = reply_time * 1e4; // convert to tenth-millisecond unit
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

		// Handle type counters
		if(type >= TYPE_A && type < TYPE_MAX)
			counters->querytype[type]++;

		// Update overTime data
		overTime[timeidx].total++;
		// Update overTime data structure with the new client
		change_clientcount(client, 0, 0, timeidx, 1);

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
			}
		}
		else if(sqlite3_column_bytes(stmt, 7) != 0)
		{
			// Set ID of the domainlist entry that was the reason for permitting/blocking this query
			// We assume the value in this field is said ID when it is not a CNAME-related domain
			// (checked above) and the value of additional_info is not NULL (0 bytes storage size)
			const int cacheID = findCacheID(query->domainID, query->clientID, query->type, true);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			// Only load if
			//  a) we have a cache entry
			//  b) the value of additional_info is not NULL (0 bytes storage size)
			if(cache != NULL && sqlite3_column_bytes(stmt, 7) != 0)
				cache->domainlist_id = sqlite3_column_int(stmt, 7);
		}

		// Increment status counters, we first have to add one to the count of
		// unknown queries because query_set_status() will subtract from there
		// when setting a different status
		if(status != QUERY_UNKNOWN)
			counters->status[QUERY_UNKNOWN]++;
		query_set_status(query, status);

		// Do further processing based on the query status we read from the database
		switch(status)
		{
			case QUERY_UNKNOWN: // Unknown
				break;

			case QUERY_GRAVITY: // Blocked by gravity
			case QUERY_REGEX: // Blocked by regex denylist
			case QUERY_DENYLIST: // Blocked by exact denylist
			case QUERY_EXTERNAL_BLOCKED_IP: // Blocked by external provider
			case QUERY_EXTERNAL_BLOCKED_NULL: // Blocked by external provider
			case QUERY_EXTERNAL_BLOCKED_NXRA: // Blocked by external provider
			case QUERY_GRAVITY_CNAME: // Blocked by gravity (inside CNAME path)
			case QUERY_REGEX_CNAME: // Blocked by regex denylist (inside CNAME path)
			case QUERY_DENYLIST_CNAME: // Blocked by exact denylist (inside CNAME path)
			case QUERY_DBBUSY: // Blocked because gravity database was busy
			case QUERY_SPECIAL_DOMAIN: // Blocked by special domain handling
				query->flags.blocked = true;
				// Get domain pointer
				domainsData *domain = getDomain(domainID, true);
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
						upstream->overTime[timeidx]++;
						upstream->lastQuery = queryTimeStamp;
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
				log_warn("Found unknown status %i in long term database!", status);
				break;
		}

		if(counters->queries % 10000 == 0)
			log_info("  %d queries parsed...", counters->queries);
	}

	unlock_shm();

	if( rc != SQLITE_DONE )
	{
		log_err("DB_read_queries() - SQL error step: %s", sqlite3_errstr(rc));
		return;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);

	log_info("Imported %i queries from the long-term database", counters->queries);

	// If the Pi-hole was down fore more than 24 hours, we will not import
	// anything here. Query the database to get the maximum database ID is
	// important to avoid starting counting from zero
	if(dbID == 0)
	{
		querystr = "SELECT MAX(id) FROM disk.queries";

		// Attach disk database
		if(!attach_disk_database(NULL))
			return;

		// Prepare SQLite3 statement
		rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);

		// Perform step
		if((rc = sqlite3_step(stmt)) == SQLITE_ROW)
			dbID = sqlite3_column_int64(stmt, 0);
		else
			log_err("DB_read_queries(): Failed to get MAX(id) from queries: %s",
			        sqlite3_errstr(rc));

		// Finalize statement
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		if(!detach_disk_database(NULL))
			return;

		log_debug(DEBUG_DATABASE, "Last long-term idx is %lld", dbID);
	}

	// Update indices so that the next call to DB_save_queries() skips the
	// queries that we just imported from the database
	last_disk_db_idx = dbID;
	last_mem_db_idx = dbID;
}

bool queries_to_database(void)
{
	int rc;
	unsigned int added = 0, updated = 0;
	sqlite3_int64 idx = 0;
	sqlite3_stmt *query_stmt = NULL;
	sqlite3_stmt *domain_stmt = NULL;
	sqlite3_stmt *client_stmt = NULL;
	sqlite3_stmt *forward_stmt = NULL;
	sqlite3_stmt *addinfo_stmt = NULL;

	// Skip, we never store nor count queries recorded while have been in
	// maximum privacy mode in the database
	if(config.privacylevel >= PRIVACY_MAXIMUM)
	{
		log_debug(DEBUG_DATABASE, "Not storing query in database due to privacy level settings");
		return true;
	}
	if(counters->queries == 0)
	{
		log_debug(DEBUG_DATABASE, "Not storing query in database as there are none");
		return true;
	}

	// Start preparing query
	rc = sqlite3_prepare_v3(memdb, "REPLACE INTO query_storage VALUES "\
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
	                                 "?13)", -1, SQLITE_PREPARE_PERSISTENT, &query_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("queries_to_database(query_storage) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(memdb, "INSERT OR IGNORE INTO domain_by_id (domain) VALUES (?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &domain_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("queries_to_database(domain_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(memdb, "INSERT OR IGNORE INTO client_by_id (ip,name) VALUES (?,?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &client_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("queries_to_database(client_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(memdb, "INSERT OR IGNORE INTO forward_by_id (forward) VALUES (?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &forward_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("queries_to_database(forward_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	rc = sqlite3_prepare_v3(memdb, "INSERT OR IGNORE INTO addinfo_by_id (type,content) VALUES (?,?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &addinfo_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("queries_to_database(addinfo_by_id) - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	// Loop over recent queries and store new or changed ones in the in-memory database
	const unsigned int min_iter = counters->queries - 1;
	unsigned int max_iter = min_iter > DB_QUERY_MAX_ITER ? min_iter - DB_QUERY_MAX_ITER : 0;
	for(unsigned int queryID = min_iter; queryID > max_iter; queryID--)
	{
		// Get query pointer
		queriesData *query = getQuery(queryID, true);
		if(query == NULL)
		{
			// Encountered memory error, skip query
			log_err("Memory error in queries_to_database()");
			break;
		}

		// Skip queries which have not changed since the last iteration
		if(!query->flags.database.changed)
			continue;

		// Update max_iter in case we have changes queries very close to
		// the end of the interation interval
		if(min_iter - max_iter < 10)
			max_iter = max_iter > DB_QUERY_MAX_ITER ? max_iter - DB_QUERY_MAX_ITER : 0;

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
		if(sqlite3_step(domain_stmt) != SQLITE_DONE)
		{
			log_err("Encountered error while trying to store domain");
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
		if(sqlite3_step(client_stmt) != SQLITE_DONE)
		{
			log_err("Encountered error while trying to store client");
			break;
		}
		sqlite3_clear_bindings(client_stmt);
		sqlite3_reset(client_stmt);

		// FORWARD
		if(query->upstreamID > -1)
		{
			// Get forward pointer
			const upstreamsData* upstream = getUpstream(query->upstreamID, true);
			const char *forwardIP = getstr(upstream->ippos);
			if(upstream && forwardIP)
			{
				char *buffer = NULL;
				int len = 0; // The length of the string WITHOUT the NUL byte. This is what sqlite3_bind_text() expects.
				if((len = asprintf(&buffer, "%s#%u", forwardIP, upstream->port)) > 0)
				{
					// Use transient here as we step only after the buffer is freed below
					sqlite3_bind_text(query_stmt, 8, buffer, len, SQLITE_TRANSIENT);
					// Use static here as we insert right away
					sqlite3_bind_text(forward_stmt, 1, buffer, len, SQLITE_STATIC);

					// Execute prepared forward statement and check if successful
					if(sqlite3_step(forward_stmt) != SQLITE_DONE)
					{
						log_err("Encountered error while trying to store forward");
						break;
					}
					sqlite3_clear_bindings(forward_stmt);
					sqlite3_reset(forward_stmt);
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
			if(sqlite3_step(addinfo_stmt) != SQLITE_DONE)
			{
				log_err("Encountered error while trying to store addinfo");
				break;
			}
			sqlite3_clear_bindings(addinfo_stmt);
			sqlite3_reset(addinfo_stmt);
		}
		else if(query->status == QUERY_REGEX)
		{
			// Restore regex ID if applicable
			const int cacheID = findCacheID(query->domainID, query->clientID, query->type, false);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			if(cache != NULL)
			{
				sqlite3_bind_int(query_stmt, 9, ADDINFO_REGEX_ID);
				sqlite3_bind_int(query_stmt, 10, cache->domainlist_id);

				// Execute prepared addinfo statement and check if successful
				sqlite3_bind_int(addinfo_stmt, 1, ADDINFO_REGEX_ID);
				sqlite3_bind_int(addinfo_stmt, 2, cache->domainlist_id);
				if(sqlite3_step(addinfo_stmt) != SQLITE_DONE)
				{
					log_err("Encountered error while trying to store addinfo");
					break;
				}
				sqlite3_clear_bindings(addinfo_stmt);
				sqlite3_reset(addinfo_stmt);
			}
			else
				sqlite3_bind_null(query_stmt, 9);
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
			// Store difference (in milliseconds) when applicable
			sqlite3_bind_double(query_stmt, 12, 1e-4*query->response);
		else
			// Store NULL otherwise
			sqlite3_bind_null(query_stmt, 12);

		// DNSSEC
		sqlite3_bind_int(query_stmt, 13, query->dnssec);

	/*	// TTL
		sqlite3_bind_int(query_stmt, 14, query->ttl);

		// REGEX_ID
		if(query->status == QUERY_REGEX)
		{
			// Restore regex ID if applicable
			const int cacheID = findCacheID(query->domainID, query->clientID, query->type);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			if(cache != NULL)
				sqlite3_bind_int(query_stmt, 15, cache->deny_regex_id);
			else
				sqlite3_bind_null(query_stmt, 15);
		}
		else
		{
			sqlite3_bind_null(query_stmt, 15);
		}
	*/
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

	if((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		log_err("Statement finalization failed when trying to store queries to in-memory database: %s",
		        sqlite3_errstr(rc));
		return false;
	}

	if(config.debug & DEBUG_DATABASE && updated + added > 0)
	{
		log_debug(DEBUG_DATABASE, "In-memory database: Added %d new, updated %d known queries", added, updated);
		log_in_memory_usage();
	}

	return true;
}
