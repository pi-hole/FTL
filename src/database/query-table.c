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
#include "../config.h"
#include "../enums.h"
#include "../config.h"
// counters
#include "../shmem.h"
#include "../overTime.h"
#include "common.h"
#include "../timers.h"

static sqlite3 *memdb = NULL, *newdb = NULL;
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
static bool init_memory_database(sqlite3 **db, const char *name, const int busy)
{
	int rc;

	// Try to open in-memory database
	rc = sqlite3_open_v2(name, db, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Step error while trying to open %s database: %s",
		        name, sqlite3_errstr(rc));
		return false;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_timeout(*db, busy);
	if( rc != SQLITE_OK )
	{
		log_err("init_memory_database(): Step error while trying to set busy timeout (%d ms) on %s database: %s",
		        DATABASE_BUSY_TIMEOUT, name, sqlite3_errstr(rc));
		sqlite3_close(*db);
		return false;
	}

	// Create queries table in the database
	rc = sqlite3_exec(*db, CREATE_QUERIES_TABLE_V10, NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		log_err("init_memory_database(%s: \"%s\") failed: %s",
		        name, CREATE_QUERIES_TABLE_V10, sqlite3_errstr(rc));
		sqlite3_close(*db);
		return false;
	}

	// Add indices on all columns of the in-memory database
	for(unsigned int i = 0; i < ArraySize(index_creation); i++)
	{
		rc = sqlite3_exec(*db, index_creation[i], NULL, NULL, NULL);
		if( rc != SQLITE_OK ){
			log_err("init_memory_database(%s: \"%s\") failed: %s",
			        name, index_creation[i], sqlite3_errstr(rc));
			sqlite3_close(*db);
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

// Initialize in-memory databases
// The flow of queries is as follows:
//   1. A new query is always added to the special new.queries table This table
//      is only used for storing new queries and does never block because of
//      not allowing (externally triggered) SELECT statements. This ensures we
//      can always add new queries even when the in-memory queries table is
//      currently busy (e.g., a complex SELECT statement is running from the API)
//   2. Every second, we try to copy all queries from new.queries into queries.
//      When successful, we delete the queries in new.queries afterwards. This
//      operation may fail if either of the tables is currently busy. This isn't
//      an issue as the queries are simply preserved and we try again on the next
//      second. This ensures the in-memory database isn't updated midway when an
//      API query is running. Furthermore, it ensures that new queries are not
//      blocked when the database is busy and INSERTions aren't currently possible.
//   3. At user-configured intervals, the in-memory database is dumped on-disk.
//      For this, we
//        3.1. Attach the on-disk database
//        3.2. INSERT the queries that came in since the last dumping
//        3.3. Detach the on-disk database
//   4. At the end of their lifetime (that is after 24 hours), queries are DELETEd
//      from the in-memory database to make room for new queries in the rolling
//      window. The queries are not removed from the on-disk database.
bool init_memory_databases(void)
{
	// Initialize in-memory database for all queries
	if(!init_memory_database(&memdb, "file:memdb?mode=memory&cache=shared", DATABASE_BUSY_TIMEOUT))
		return false;
	// Initialize in-memory database for new queries
	if(!init_memory_database(&newdb, "file:newdb?mode=memory&cache=shared", 0))
		return false;

	// ATTACH newdb to memdb
	const char *querystr = "ATTACH 'file:newdb?mode=memory&cache=shared' AS new";
	int rc = sqlite3_exec(memdb, querystr, NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		log_err("init_memory_databases(\"%s\") failed: %s",
		        querystr, sqlite3_errstr(rc));
		return false;
	}

	return true;
}

// Get memory usage and size of in-memory tables
static bool get_memdb_size(sqlite3 *db, size_t *memsize, int *queries)
{
	int rc;
	sqlite3_stmt *stmt = NULL;
	size_t page_count, page_size;

	// PRAGMA page_count
	rc = sqlite3_prepare_v2(db, "PRAGMA page_count", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
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
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("init_memory_database(PRAGMA page_size): Prepare error: %s",
			        sqlite3_errstr(rc));

		return false;
	}
	rc = sqlite3_step(stmt);
	if( rc == SQLITE_ROW )
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
	if((*queries = get_number_of_queries_in_DB(db, false, false)) == DB_FAILED)
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
	if(get_memdb_size(newdb, &memsize, &queries))
	{
		char prefix[2] = { 0 };
		double num = 0.0;
		format_memory_size(prefix, memsize, &num);
		log_debug(DEBUG_DATABASE, "new database size: %.1f%s (%d queries)",
		          num, prefix, queries);
	}
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
	if((rc = sqlite3_bind_text(stmt, 1, FTLfiles.FTL_db, -1, SQLITE_STATIC)) != SQLITE_OK)
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
int get_number_of_queries_in_DB(sqlite3 *db, const bool disk, const bool attached)
{
	int rc = 0, num = 0;
	sqlite3_stmt *stmt = NULL;
	// Attach disk database if required
	if(disk && !attached && !attach_disk_database(NULL))
		return DB_FAILED;

	// Count number of rows
	const char *querystr = disk ?
		"SELECT COUNT(*) FROM disk.queries" :
		"SELECT COUNT(*) FROM queries";

	// The database pointer may be NULL, meaning we want the memdb
	if(db == NULL)
		db = memdb;

	// PRAGMA page_size
	rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("get_number_of_queries_in_DB(): Prepare error: %s",
			        sqlite3_errstr(rc));

		return false;
	}
	rc = sqlite3_step(stmt);
	if( rc == SQLITE_ROW )
		num = sqlite3_column_int(stmt, 0);
	else
	{
		log_err("get_number_of_queries_in_DB(): Step error: %s",
		        sqlite3_errstr(rc));
		return false;
	}
	sqlite3_finalize(stmt);

	// Detach only if attached herein
	if(disk && !attached && !detach_disk_database(NULL))
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
	const double mintime = now - config.maxlogage;
	const char *querystr = "INSERT INTO queries SELECT * FROM disk.queries WHERE timestamp >= ?";

	// Attach disk database
	if(!attach_disk_database(NULL))
		return false;

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
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

	// Get number of queries on disk before detaching
	disk_db_num = get_number_of_queries_in_DB(memdb, true, true);

	if(!detach_disk_database(NULL))
		return false;

	mem_db_num = sqlite3_changes(memdb);
	log_info("Imported %d queries from the on-disk database into memory", mem_db_num);

	return okay;
}

// Export in-memory queries to disk - either due to periodic dumping (final =
// false) or because of a sutdown (final = true)
bool export_queries_to_disk(bool final)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const char *querystr = "INSERT INTO disk.queries SELECT * FROM queries WHERE id > ? AND timestamp < ?";

	// Start database timer
	if(config.debug & DEBUG_DATABASE)
		timer_start(DATABASE_WRITE_TIMER);

	// Attach disk database
	if(!attach_disk_database(NULL))
		return false;

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("import_queries_from_disk(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind index
	if((rc = sqlite3_bind_int64(stmt, 1, last_disk_db_idx)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Failed to bind type id: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind upper time limit
	// This prevents queries from the last 30 seconds from being stored
	// immediately on-disk to give them some time to complete before finally
	// exported. We do not limit anything when storing during termination.
	const double time = double_time() - (final ? 0.0 : 30.0);
	if((rc = sqlite3_bind_int64(stmt, 2, time)) != SQLITE_OK)
	{
		log_err("import_queries_from_disk(): Failed to bind type time: %s", sqlite3_errstr(rc));
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

	if(!detach_disk_database(NULL))
		return false;

	// All temp queries were stored to disk, update the IDs
	unsigned int saved = last_mem_db_idx - last_disk_db_idx;
	last_disk_db_idx = last_mem_db_idx;

	if(saved > 0)
	{
		sqlite3 *db = dbopen(false);
		if(db != NULL)
		{
			db_set_FTL_property_double(db, DB_LASTTIMESTAMP, new_last_timestamp);
			db_update_counters(db, new_total, new_blocked);
			dbclose(&db);
		}
	}

	log_debug(DEBUG_DATABASE, "Notice: Queries stored in long-term database: %u (took %.1f ms, last SQLite ID %li)",
	          saved, timer_elapsed_msec(DATABASE_WRITE_TIMER), last_disk_db_idx);

	return okay;
}

// Delete query with given ID from database. Used by garbage collection
bool delete_query_from_db(const sqlite3_int64 id)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const char *querystr = "DELETE FROM queries WHERE id = ?";

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

// Move queries from newdb.queries into memdb.queries
// If the database is busy, no moving is happening and queries are retained in
// here until the next try. This ensures we cannot loose queries.
bool mv_newdb_memdb(void)
{
	const char *querystr[] = { "BEGIN TRANSACTION EXCLUSIVE",
                                   "REPLACE INTO queries SELECT * FROM new.queries",
                                   "DELETE FROM new.queries",
                                   "END TRANSACTION" };

	// Run queries against the database
	for(unsigned int i = 0; i < ArraySize(querystr); i++)
	{
		const int rc = sqlite3_exec(memdb, querystr[i], NULL, NULL, NULL);
		if( rc != SQLITE_OK ){
			log_err("mv_newdb_memdb(%s) failed: %s",
			        querystr[i], sqlite3_errstr(rc));

			// Try to ROLLLBACK the TRANSACTION
			const int rc2 = sqlite3_exec(memdb, "ROLLBACK", NULL, NULL, NULL);
			if( rc2 != SQLITE_OK ){
				log_err("mv_newdb_memdb(ROLLBACK) failed: %s",
				        sqlite3_errstr(rc2));
				return false;
			}
		}
	}

	int num = sqlite3_changes(memdb);
	// Debug logging
	if(num > 0)
		log_debug(DEBUG_QUERIES, "Moved %d quer%s from newdb into memdb", num, num == 1 ? "y" : "ies");
	mem_db_num += num;

	return true;
}

bool add_additional_info_column(sqlite3 *db)
{
	// Add column additinal_info to queries table
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN additional_info TEXT;");

	// Update the database version to 7
	SQL_bool(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES (%u, 7);", DB_VERSION);

	return true;
}

bool create_more_queries_columns(sqlite3 *db)
{
	// Add additional columns to the queries table
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN reply INTEGER;");
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN dnssec INTEGER;");
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN reply_time NUMBER;");
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN client_name TEXT;");
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN ttl INTEGER;");
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN regex_id INTEGER;");

	// Update the database version to 10
	SQL_bool(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES (%u, 10);", DB_VERSION);

	return true;
}

// Get most recent 24 hours data from long-term database
void DB_read_queries(void)
{
	// Prepare request
	// Get time stamp 24 hours in the past
	const char *querystr = "SELECT * FROM queries";

	log_info("Parsing queries in database");

	// Prepare SQLite3 statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("DB_read_queries() - SQL error prepare: %s", sqlite3_errstr(rc));
		return;
	}

	// Lock shared memory
	lock_shm();

	// Loop through returned database rows
	sqlite3_int64 dbid = 0;
	const double now = double_time();
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		dbid = sqlite3_column_int64(stmt, 0);
		const double queryTimeStamp = sqlite3_column_double(stmt, 1);
		// 1483228800 = 01/01/2017 @ 12:00am (UTC)
		if(queryTimeStamp < 1483228800)
		{
			log_warn("Database: TIMESTAMP should be larger than 01/01/2017 but is %f", queryTimeStamp);
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
		if(status_int < STATUS_UNKNOWN || status_int >= STATUS_MAX)
		{
			log_warn("Database: STATUS should be within [%i,%i] but is %i", STATUS_UNKNOWN, STATUS_MAX-1, status_int);
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
		if(reply_int < REPLY_UNKNOWN || reply_int >= REPLY_MAX)
		{
			log_warn("Database: REPLY should be within [%i,%i] but is %i", REPLY_UNKNOWN, REPLY_MAX-1, reply_int);
			continue;
		}
		const enum reply_type reply = reply_int;

		const int dnssec_int = sqlite3_column_int(stmt, 9);
		if(dnssec_int < DNSSEC_UNKNOWN || dnssec_int >= DNSSEC_MAX)
		{
			log_warn("Database: REPLY should be within [%i,%i] but is %i", DNSSEC_UNKNOWN, DNSSEC_MAX-1, dnssec_int);
			continue;
		}
		const enum dnssec_status dnssec = dnssec_int;

		// Lock shared memory
		lock_shm();

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
			query->type = type;
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
		query->timeidx = timeidx;
		query->db = dbid;
		query->id = 0;
		query->reply = reply;
		query->dnssec = dnssec;
		query->response = 0.0; // No need to restore this
		query->ttl = 0; // No need to restore this
		query->CNAME_domainID = -1;
		// Initialize flags
		query->flags.complete = true; // Mark as all information is available
		query->flags.blocked = false;
		query->flags.allowed = false;

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
		if(status == STATUS_GRAVITY_CNAME ||
		   status == STATUS_REGEX_CNAME ||
		   status == STATUS_DENYLIST_CNAME )
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
		else if(status == STATUS_REGEX)
		{
			// STATUS_REGEX: Set ID regex which was the reson for blocking
			const int cacheID = findCacheID(query->domainID, query->clientID, query->type);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			// Only load if
			//  a) we have a cache entry
			//  b) the value of additional_info is not NULL (0 bytes storage size)
			if(cache != NULL && sqlite3_column_bytes(stmt, 7) != 0)
				cache->deny_regex_id = sqlite3_column_int(stmt, 7);
		}

		// Increment status counters, we first have to add one to the count of
		// unknown queries because query_set_status() will subtract from there
		// when setting a different status
		if(status != STATUS_UNKNOWN)
			counters->status[STATUS_UNKNOWN]++;
		query_set_status(query, status);

		// Do further processing based on the query status we read from the database
		switch(status)
		{
			case STATUS_UNKNOWN: // Unknown
				break;

			case STATUS_GRAVITY: // Blocked by gravity
			case STATUS_REGEX: // Blocked by regex blacklist
			case STATUS_DENYLIST: // Blocked by exact blacklist
			case STATUS_EXTERNAL_BLOCKED_IP: // Blocked by external provider
			case STATUS_EXTERNAL_BLOCKED_NULL: // Blocked by external provider
			case STATUS_EXTERNAL_BLOCKED_NXRA: // Blocked by external provider
			case STATUS_GRAVITY_CNAME: // Blocked by gravity (inside CNAME path)
			case STATUS_REGEX_CNAME: // Blocked by regex blacklist (inside CNAME path)
			case STATUS_DENYLIST_CNAME: // Blocked by exact blacklist (inside CNAME path)
				query->flags.blocked = true;
				// Get domain pointer
				domainsData *domain = getDomain(domainID, true);
				domain->blockedcount++;
				change_clientcount(client, 0, 1, -1, 0);
				break;

			case STATUS_FORWARDED: // Forwarded
			case STATUS_RETRIED: // (fall through)
			case STATUS_RETRIED_DNSSEC: // (fall through)
				// Only update upstream if there is one (there
				// won't be one for retried DNSSEC queries)
				if(upstreamID > -1)
				{
					upstreamsData *upstream = getUpstream(upstreamID, true);
					if(upstream != NULL)
					{
						upstream->count++;
						upstream->lastQuery = queryTimeStamp;
					}
				}
				break;

			case STATUS_CACHE: // Cached or local config
				// Nothing to be done here
				break;

			case STATUS_IN_PROGRESS:
				// Nothing to be done here
				break;

			case STATUS_MAX:
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
	if(dbid == 0)
	{
		querystr = "SELECT MAX(id) FROM disk.queries";

		// Attach disk database
		if(!attach_disk_database(NULL))
			return;

		// Prepare SQLite3 statement
		rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);

		// Perform step
		if((rc = sqlite3_step(stmt)) == SQLITE_ROW)
			dbid = sqlite3_column_int64(stmt, 0);
		else
			log_err("DB_read_queries(): Failed to get MAX(id) from queries: %s",
			        sqlite3_errstr(rc));

		// Finalize statement
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		if(!detach_disk_database(NULL))
			return;

		log_debug(DEBUG_DATABASE, "Last long-term idx is %lld", dbid);
	}

	// Update indices so that the next call to DB_save_queries() skips the
	// queries that we just imported from the database
	last_disk_db_idx = dbid;
	last_mem_db_idx = dbid;
}

bool query_to_database(queriesData *query)
{
	int rc;
	sqlite3_int64 idx = 0;
	sqlite3_stmt *stmt = NULL;

	// Skip, we never store nor count queries recorded while have been in
	// maximum privacy mode in the database
	if(query->privacylevel >= PRIVACY_MAXIMUM)
	{
		log_debug(DEBUG_DATABASE, "Not storing query in database due to privacy level settings");
		return true;
	}

	// Start preparing query
	rc = sqlite3_prepare_v2(newdb, "REPLACE INTO queries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("query_to_database() - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

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
	sqlite3_bind_int64(stmt, 1, idx);

	// TIMESTAMP
	sqlite3_bind_double(stmt, 2, query->timestamp);

	// TYPE
	if(query->type != TYPE_OTHER)
	{
		// Store mapped type if query->type is not OTHER
		sqlite3_bind_int(stmt, 3, query->type);
	}
	else
	{
		// Store query type + offset if query-> type is OTHER
		sqlite3_bind_int(stmt, 3, query->qtype + 100);
	}

	// STATUS
	sqlite3_bind_int(stmt, 4, query->status);

	// DOMAIN
	const char *domain = getDomainString(query);
	sqlite3_bind_text(stmt, 5, domain, -1, SQLITE_STATIC);

	// CLIENT
	const char *clientip = getClientIPString(query);
	sqlite3_bind_text(stmt, 6, clientip, -1, SQLITE_STATIC);

	// FORWARD
	if(query->upstreamID > -1)
	{
		// Get forward pointer
		const upstreamsData *upstream = getUpstream(query->upstreamID, true);
		char *buffer = NULL;
		if(asprintf(&buffer, "%s#%u", getstr(upstream->ippos), upstream->port) > 0)
			sqlite3_bind_text(stmt, 7, buffer, -1, SQLITE_TRANSIENT);
		else
			sqlite3_bind_null(stmt, 7);

		if(buffer != NULL)
			free(buffer);
	}
	else
	{
		sqlite3_bind_null(stmt, 7);
	}

	// ADDITIONAL_INFO
	if(query->status == STATUS_GRAVITY_CNAME ||
	   query->status == STATUS_REGEX_CNAME ||
	   query->status == STATUS_DENYLIST_CNAME )
	{
		// Restore domain blocked during deep CNAME inspection if applicable
		const char *cname = getCNAMEDomainString(query);
		sqlite3_bind_text(stmt, 8, cname, -1, SQLITE_STATIC);
	}
	else if(query->status == STATUS_REGEX)
	{
		// Restore regex ID if applicable (only kept for legacy reasons)
		const int cacheID = findCacheID(query->domainID, query->clientID, query->type);
		DNSCacheData *cache = getDNSCache(cacheID, true);
		if(cache != NULL)
			sqlite3_bind_int(stmt, 8, cache->deny_regex_id);
		else
			sqlite3_bind_null(stmt, 8);
	}
	else
	{
		// Nothing to add here
		sqlite3_bind_null(stmt, 8);
	}

	// REPLY
	sqlite3_bind_int(stmt, 9, query->reply);

	// DNSSEC
	sqlite3_bind_int(stmt, 10, query->dnssec);

	// REPLY_TIME
	if(query->response > 0.0)
		// Store difference (in milliseconds) when applicable
		sqlite3_bind_double(stmt, 11, 1000.0*(query->response - query->timestamp));
	else
		// Store NULL otherwise
		sqlite3_bind_null(stmt, 11);

	// CLIENT_NAME
	const char *clientname = getClientNameString(query);
	const size_t clientnamelen = strlen(clientname);
	if(clientnamelen > 0)
		sqlite3_bind_text(stmt, 12, clientname, clientnamelen, SQLITE_STATIC);
	else
		sqlite3_bind_null(stmt, 12);

	// TTL
	sqlite3_bind_int(stmt, 13, query->ttl);

	// REGEX_ID
	if(query->status == STATUS_REGEX)
	{
		// Restore regex ID if applicable
		const int cacheID = findCacheID(query->domainID, query->clientID, query->type);
		DNSCacheData *cache = getDNSCache(cacheID, true);
		if(cache != NULL)
			sqlite3_bind_int(stmt, 14, cache->deny_regex_id);
		else
			sqlite3_bind_null(stmt, 14);
	}
	else
	{
		sqlite3_bind_null(stmt, 14);
	}

	// Step and check if successful
	rc = sqlite3_step(stmt);
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);

	if( rc != SQLITE_DONE )
	{
		log_err("Encountered error while trying to store queries in in-memory database: %s",
		        sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return false;
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

		log_in_memory_usage(); // only done with DEBUG_DATABASE is enabled
		log_debug(DEBUG_DATABASE, "Query added to in-memory database (ID %lli)", idx);
	}
	else
	{
		log_debug(DEBUG_DATABASE, "Query updated in in-memory database (ID %lli)", idx);
	}

	if((rc = sqlite3_finalize(stmt)) != SQLITE_OK)
	{
		log_err("Statement finalization failed when trying to store queries to in-memory database: %s",
		        sqlite3_errstr(rc));
		return false;
	}

	return true;
}
