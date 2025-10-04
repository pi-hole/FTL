/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Common database routines for pihole-FTL.db
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "database/common.h"
#include "database/network-table.h"
#include "database/message-table.h"
#include "shmem.h"
// struct config
#include "config/config.h"
#include "timers.h"
// file_exists()
#include "files.h"
#include "database/sqlite3-ext.h"
// import_aliasclients()
#include "database/aliasclients.h"
// CREATE_QUERIES_TABLE
// add_additional_info_column()
#include "database/query-table.h"
// set_event()
#include "events.h"
// generate_backtrace()
#include "signals.h"
// create_session_table()
#include "database/session-table.h"
// assert()
#include <assert.h>

bool DBdeleteoldqueries = false;
static bool DBerror = false;
static int dbopen_cnt = 0; // Number of times the database has been opened

bool __attribute__ ((pure)) FTLDBerror(void)
{
	return DBerror;
}

bool checkFTLDBrc(const int rc)
{
	// Check if the database file is malformed
	if(rc == SQLITE_CORRUPT)
	{
		log_warn("Database %s is damaged and cannot be used.", config.files.database.v.s);
		DBerror = true;
	}
	// Check if the database file is read-only
	if(rc == SQLITE_READONLY)
	{
		log_warn("Database %s is read-only and cannot be used.", config.files.database.v.s);
		DBerror = true;
	}

	return DBerror;
}

void _dbclose(sqlite3 **db, const char *func, const int line, const char *file)
{
	// Silently return if the database is known to be broken. It may not be
	// possible to close the connection properly.
	if(FTLDBerror())
		return;

	if(config.debug.database.v.b)
		log_debug(DEBUG_DATABASE, "Closing FTL database in %s() (%s:%i)", func, short_path(file), line);

	// Only try to close an existing database connection
	int rc = SQLITE_OK;
	if(db != NULL && *db != NULL && (rc = sqlite3_close(*db)) != SQLITE_OK)
	{
		log_err("Error while trying to close database: %s",
		        sqlite3_errstr(rc));
		checkFTLDBrc(rc);
	}

	// Always set database pointer to NULL, even when closing failed
	if(db) *db = NULL;

	// Decrement the number of open database connections
	dbopen_cnt--;
}

/**
 * @brief Callback function for handling SQLite database busy events.
 *
 * This function is called by SQLite when the database is locked and cannot be accessed
 * immediately. It implements an exponential backoff strategy using predefined delay and
 * total wait time arrays. The function waits for a specified delay (in milliseconds)
 * before retrying, up to DATABASE_BUSY_TIMEOUT.
 *
 * @param ptr Pointer to an unsigned int specifying the maximum allowed wait time (in ms).
 * @param count The number of times the busy handler has been invoked for the same operation.
 * @return int Returns 1 to indicate that SQLite should retry the operation after the delay,
 *             or 0 to indicate that the operation should fail because the timeout has been exceeded.
 *
 * The function logs a warning if the total wait time exceeds the allowed timeout, and
 * logs debug information for each wait period.
 */
int sqliteBusyCallback(void *ptr, int count)
{
	static const uint8_t delays[] = { 1, 2, 5, 10, 15, 20, 25, 25,  25,  50,  50, 100 };
	static const uint8_t totals[] = { 0, 1, 3,  8, 18, 33, 53, 78, 103, 128, 178, 228 };
	# define NDELAY ArraySize(delays)

	int delay, prior;

	assert(count >= 0);
	if(count < (int)NDELAY)
	{
		// Use the predefined delays and totals
		delay = delays[count];
		prior = totals[count];
	}
	else
	{
		// Use the last predefined delay and total
		delay = delays[NDELAY - 1];
		prior = totals[NDELAY - 1] + delay*(count - (NDELAY - 1));
	}

	if(prior + delay > DATABASE_BUSY_TIMEOUT)
	{
		delay = DATABASE_BUSY_TIMEOUT - prior;
		if(delay <= 0)
		{
			// If the total time waited so far plus the next delay exceeds
			// the maximum allowed time, return 0 to indicate that the
			// database is busy beyond the allowed time and that we will not
			// wait any longer.
			log_debug(DEBUG_DATABASE, "Database busy for %d ms > %d ms, not waiting any longer",
			         prior + delay, DATABASE_BUSY_TIMEOUT);
			return 0;
		}
	}
	log_debug(DEBUG_DATABASE, "Database busy - waiting %d ms (dbopen: %d)", delay, dbopen_cnt);
	usleep(delay * 1000); // Convert ms to us

	// Return 1 to indicate that we will wait for the database to become
	// available again
	return 1;
}

sqlite3* _dbopen(const bool readonly, const bool create, const char *func, const int line, const char *file)
{
	// Silently return NULL if the database is known to be broken
	if(FTLDBerror())
		return NULL;

	// Try to open database
	log_debug(DEBUG_DATABASE, "Opening FTL database in %s() (node %s%s) (%s:%i)",
	          func, readonly ? "RO" : "RW", create ? ",C" : "", short_path(file), line);

	int flags = readonly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE;
	if(create && !readonly)
		flags |= SQLITE_OPEN_CREATE;

	sqlite3 *db = NULL;
	int rc = sqlite3_open_v2(config.files.database.v.s, &db, flags, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("Error while trying to open database: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return NULL;
	}

	// If the database is opened in read-write mode, actually check if it is
	// writable. If it is not, close the database and return an error
	if(!readonly && sqlite3_db_readonly(db, NULL))
	{
		log_err("Cannot open database in read-write mode");
		dbclose(&db);
		return NULL;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_handler(db, sqliteBusyCallback, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("Error while trying to set busy timeout on database: %s",
		        sqlite3_errstr(rc));
		dbclose(&db);
		checkFTLDBrc(rc);
		return NULL;
	}

	// Increment the number of open database connections
	dbopen_cnt++;

	return db;
}

int dbquery(sqlite3* db, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	char *query = sqlite3_vmprintf(format, args);
	va_end(args);

	if(query == NULL)
	{
		log_err("Memory allocation failed in dbquery()");
		return SQLITE_ERROR;
	}

	// Log generated SQL string when dbquery() is called
	// although the database connection is not available
	if(db == NULL)
	{
		log_err("dbquery(\"%s\") called but database is not available!", query);
		sqlite3_free(query);
		return SQLITE_ERROR;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\"", query);


	int rc = sqlite3_exec(db, query, NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		log_err("ERROR: SQL query \"%s\" failed: %s (%s)",
		        query, sqlite3_errstr(rc), sqlite3ErrName(sqlite3_extended_errcode(db)));
		sqlite3_free(query);
		checkFTLDBrc(rc);
		return rc;
	}

	// Free allocated memory for query string
	sqlite3_free(query);

	log_debug(DEBUG_DATABASE,"         ---> OK");

	// Return success
	return SQLITE_OK;
}

static bool create_counter_table(sqlite3* db)
{
	// Start transaction
	SQL_bool(db, "BEGIN TRANSACTION");

	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool(db, "CREATE TABLE counters ( id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL );");

	// ID 0 = total queries
	if(!db_set_counter(db, DB_TOTALQUERIES, 0))
	{
		log_err("create_counter_table(): Failed to set total queries counter to zero!");
		return false;
	}

	// ID 1 = total blocked queries
	if(!db_set_counter(db, DB_BLOCKEDQUERIES, 0))
	{
		log_err("create_counter_table(): Failed to set blocked queries counter to zero!");
		return false;
	}

	// Time stamp of creation of the counters database
	if(!db_set_FTL_property(db, DB_FIRSTCOUNTERTIMESTAMP, (unsigned long)time(0)))
	{
		log_err("create_counter_table(): Failed to update first counter timestamp!");
		return false;
	}

	// Update database version to 2
	if(!db_set_FTL_property(db, DB_VERSION, 2))
	{
		log_err("create_counter_table(): Failed to update database version!");
		return false;
	}
	// End transaction
	SQL_bool(db, "COMMIT");

	return true;
}

static bool db_create(void)
{
	sqlite3 *db = dbopen(false, true);
	if(db == NULL)
		return false;

	// Create Queries table in the database
	SQL_bool(db, CREATE_QUERIES_TABLE_V1);

	// Add an index on the timestamps (not a unique index!)
	SQL_bool(db, CREATE_QUERIES_TIMESTAMP_INDEX);

	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool(db, CREATE_FTL_TABLE);

	// Set FTL_db version 1
	if(!db_set_FTL_property(db, DB_VERSION, 1))
		return false;

	// Most recent timestamp initialized to 00:00 1 Jan 1970
	if(!db_set_FTL_property(db, DB_LASTTIMESTAMP, 0))
		return false;

	// Close database handle
	dbclose(&db);

	return true;
}

void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg)
{
	// Note: pArg is NULL and not used
	// See https://sqlite.org/rescode.html#extrc for details
	// concerning the return codes returned here
	if(zMsg != NULL && strncmp(zMsg, "file renamed while open: ", sizeof("file renamed while open: ")-1) == 0)
	{
		// This happens when gravity.db is replaced while FTL is running
		// We can safely ignore this warning
		return;
	}

	if(iErrCode == SQLITE_WARNING)
		log_warn("SQLite3: %s (%d)", zMsg, iErrCode);
	else if(iErrCode == SQLITE_NOTICE || iErrCode == SQLITE_SCHEMA)
	{
		// SQLITE_SCHEMA is returned when the database schema has changed
		// This is not necessarily an error, as sqlite3_step() will re-prepare
		// the statement and try again. If it cannot, it will return an error
		// and this will be handled over there.
		log_debug(DEBUG_ANY, "SQLite3: %s (%d)", zMsg, iErrCode);
	}
	else
		log_err("SQLite3: %s (%d)", zMsg, iErrCode);
}

void db_init(void)
{
	// Initialize SQLite3 logging callback
	// This ensures SQLite3 errors and warnings are logged to FTL.log
	// We use this to possibly catch even more errors in places we do not
	// explicitly check for failures to have happened
	sqlite3_config(SQLITE_CONFIG_LOG, SQLite3LogCallback, NULL);

	// Register Pi-hole provided SQLite3 extensions (see sqlite3-ext.c) and
	// initialize SQLite3 engine
	pihole_sqlite3_initalize();

	// Check if database exists, if not create empty database
	if(!file_exists(config.files.database.v.s))
	{
		log_warn("No database file found, creating new (empty) database");
		if (!db_create())
		{
			log_err("Creation of database failed, database is not available");
			return;
		}
	}

	// Explicitly set permissions to 0640
	// 640 =            u+w       u+r       g+r
	const mode_t mode = S_IWUSR | S_IRUSR | S_IRGRP;
	chmod_file(config.files.database.v.s, mode);

	// Open database
	sqlite3 *db = dbopen(false, false);

	// Return if database access failed
	if(!db)
		return;

	// Test FTL_db version and see if we need to upgrade the database file
	int dbversion = db_get_int(db, DB_VERSION);
	// Warn if there is an error, however, do not warn on database file
	// corruption. This has already been logged before
	if(dbversion < 1 && !FTLDBerror())
	{
		log_warn("Database not available, please ensure the database is unlocked when starting pihole-FTL !");
		dbclose(&db);
		DBerror = true;
		return;
	}
	else
	{
		log_info("Database version is %i", dbversion);
	}


	// Update to version 2 if lower
	if(dbversion < 2)
	{
		// Update to version 2: Create counters table
		log_info("Updating long-term database to version 2");
		if (!create_counter_table(db))
		{
			log_err("Counter table not initialized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 3 if lower
	if(dbversion < 3)
	{
		// Update to version 3: Create network table
		log_info("Updating long-term database to version 3");
		if (!create_network_table(db))
		{
			log_err("Network table not initialized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 4 if lower
	if(dbversion < 4)
	{
		// Update to version 4: Unify clients in network table
		log_info("Updating long-term database to version 4");
		if(!unify_hwaddr(db))
		{
			log_err("Unable to unify clients in network table, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 5 if lower
	if(dbversion < 5)
	{
		// Update to version 5: Create network-addresses table
		log_info("Updating long-term database to version 5");
		if(!create_network_addresses_table(db))
		{
			log_err("Network-addresses table not initialized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 6 if lower
	if(dbversion < 6)
	{
		// Update to version 6: Create message table
		log_info("Updating long-term database to version 6");
		if(!create_message_table(db))
		{
			log_err("Message table not initialized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 7 if lower
	if(dbversion < 7)
	{
		// Update to version 7: Add additional_info column to queries table
		log_info("Updating long-term database to version 7");
		if(!add_additional_info_column(db))
		{
			log_err("Column additional_info not initialized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 8 if lower
	if(dbversion < 8)
	{
		// Update to version 8: Add name field to network_addresses table
		log_info("Updating long-term database to version 8");
		if(!create_network_addresses_with_names_table(db))
		{
			log_err("Network addresses table not initialized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 9 if lower
	if(dbversion < 9)
	{
		// Update to version 9: Add aliasclients table
		log_info("Updating long-term database to version 9");
		if(!create_aliasclients_table(db))
		{
			log_err("Aliasclients table not initialized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 10 if lower
	if(dbversion < 10)
	{
		// Update to version 10: Use linking tables for queries table
		log_info("Updating long-term database to version 10");
		if(!optimize_queries_table(db))
		{
			log_info("Queries table not optimized, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}

		// Reopen database after low-level schema editing to reload the schema
		dbclose(&db);
		if(!(db = dbopen(false, false)))
			return;

		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 11 if lower
	if(dbversion < 11)
	{
		// Update to version 11: Use link table also for additional_info column
		log_info("Updating long-term database to version 11");
		if(!create_addinfo_table(db))
		{
			log_info("Link table for additional_info not generated, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}

		// Reopen database after low-level schema editing to reload the schema
		dbclose(&db);
		if(!(db = dbopen(false, false)))
			return;

		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 12 if lower
	if(dbversion < 12)
	{
		// Update to version 12: Add additional columns for reply type and time, and dnssec status
		log_info("Updating long-term database to version 12");
		if(!add_query_storage_columns(db))
		{
			log_info("Additional records not generated, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 13 if lower
	if(dbversion < 13)
	{
		// Update to version 13: Add additional column for regex ID
		log_info("Updating long-term database to version 13");
		if(!add_query_storage_column_regex_id(db))
		{
			log_info("Additional records not generated, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 14 if lower
	if(dbversion < 14)
	{
		// Update to version 14: Add additional column for the ftl table
		log_info("Updating long-term database to version 14");
		if(!add_ftl_table_description(db))
		{
			log_info("FTL table description cannot be added, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 15 if lower
	if(dbversion < 15)
	{
		// Update to version 15: Add session table
		log_info("Updating long-term database to version 15");
		if(!create_session_table(db))
		{
			log_info("Session table cannot be created, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 16 if lower
	if(dbversion < 16)
	{
		// Update to version 16: Add app column to session table
		log_info("Updating long-term database to version 16");
		if(!add_session_app_column(db))
		{
			log_info("Session table cannot be updated, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 17 if lower
	if(dbversion < 17)
	{
		// Update to version 17: Rename regex_id column to regex_id_old
		log_info("Updating long-term database to version 17");
		if(!rename_query_storage_column_regex_id(db))
		{
			log_info("regex_id cannot be renamed to list_id, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 18 if lower
	if(dbversion < 18)
	{
		// Update to version 18: Add cli column to session table
		log_info("Updating long-term database to version 18");
		if(!add_session_cli_column(db))
		{
			log_info("Session table cannot be updated, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 19 if lower
	if(dbversion < 19)
	{
		// Update to version 19: Add x_forwarded_for column to session table
		log_info("Updating long-term database to version 19");
		if(!add_session_x_forwarded_for_column(db))
		{
			log_info("Session table cannot be updated, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 20 if lower
	if(dbversion < 20)
	{
		// Update to version 20: Add additional column for the network table
		log_info("Updating long-term database to version 20");
		if(!create_network_addresses_network_id_index(db))
		{
			log_info("Network addresses network_id index cannot be added, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 21 if lower
	if(dbversion < 21)
	{
		// Update to version 21: Add additional column "ede" in the query_storage table
		log_info("Updating long-term database to version 21");
		if(!add_query_storage_column_ede(db))
		{
			log_info("Additional column 'ede' in the query_storage table cannot be added, database not available");
			dbclose(&db);
			DBerror = true;
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	/* * * * * * * * * * * * * IMPORTANT * * * * * * * * * * * * *
	 * If you add a new database version, check if the in-memory
	 * schema needs to be update as well (always recreated from
	 * scratch on every FTL (re)start). Also, ensure to update the
	 * MEMDB_VERSION in src/database/query-table.h as well as the
	 * expected database schema in the CI tests.
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

	// Last check after all migrations, if this happens, it will cause the
	// CI to fail the tests
	if(dbversion != MEMDB_VERSION)
	{
		log_err("Expected query database version %d but found %d, database not available", MEMDB_VERSION, dbversion);
		dbclose(&db);
		DBerror = true;
		return;
	}

	lock_shm();
	import_aliasclients(db);
	unlock_shm();

	// Close database to prevent having it opened all time
	// We already closed the database when we returned earlier
	dbclose(&db);

	// Log if users asked us to not use the long-term database for queries
	// We will still use it to store warnings (Pi-hole diagnosis system)
	if(config.database.maxDBdays.v.ui == 0)
		log_info("Not using the database for storing queries");

	log_info("Database successfully initialized");
}

int db_get_int(sqlite3* db, const enum ftl_table_props ID)
{
	// Prepare SQL statement
	char* querystr = NULL;
	int ret = asprintf(&querystr, "SELECT VALUE FROM ftl WHERE id = %u;", ID);

	if(querystr == NULL || ret < 0)
	{
		log_err("Memory allocation failed in db_get_int db, with ID = %u (%i)", ID, ret);
		return DB_FAILED;
	}

	int value = db_query_int(db, querystr);
	free(querystr);

	return value;
}

bool db_set_FTL_property(sqlite3 *db, const enum ftl_table_props ID, const int value)
{
	// Use UPSERT (https://sqlite.org/lang_upsert.html)
	// UPSERT is a clause added to INSERT that causes the INSERT to behave
	// as an UPDATE or a no-op if the INSERT would violate a uniqueness
	// constraint. UPSERT is not standard SQL. UPSERT in SQLite follows the
	// syntax established by PostgreSQL, with generalizations. 
	SQL_bool(db, "INSERT INTO ftl (id, value) VALUES ( %u, %d ) ON CONFLICT (id) DO UPDATE SET value=%d;", ID, value, value);
	return true;
}

bool db_set_counter(sqlite3 *db, const enum counters_table_props ID, const int value)
{
	int ret = dbquery(db, "INSERT OR REPLACE INTO counters (id, value) VALUES ( %u, %d );", ID, value);
	if(ret != SQLITE_OK)
	{
		checkFTLDBrc(ret);
		return false;
	}
	return true;
}

int db_query_int(sqlite3 *db, const char* querystr)
{
	log_debug(DEBUG_DATABASE, "dbquery: \"%s\"", querystr);

	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("Encountered prepare error in db_query_int(\"%s\"): %s",
			        querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	int result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_int(stmt, 0);
		log_debug(DEBUG_DATABASE, "         ---> Result %i (int)", result);
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;
		log_debug(DEBUG_DATABASE, "         ---> No data");
	}
	else
	{
		log_err("Encountered step error in db_query_int(\"%s\"): %s",
		        querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);
	return result;
}

int db_query_int_int(sqlite3 *db, const char* querystr, const int arg)
{
	log_debug(DEBUG_DATABASE, "db_query_int_arg: \"%s\"", querystr);

	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("Encountered prepare error in db_query_int(\"%s\"): %s",
			        querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	// Bind argument to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, arg)) != SQLITE_OK)
	{
		log_err("Encountered bind error in db_query_int(\"%s\"): %s",
		        querystr, sqlite3_errstr(rc));
	}

	rc = sqlite3_step(stmt);
	int result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_int(stmt, 0);
		log_debug(DEBUG_DATABASE, "         ---> Result %i (int)", result);
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;
		log_debug(DEBUG_DATABASE, "         ---> No data");
	}
	else
	{
		log_err("Encountered step error in db_query_int(\"%s\"): %s",
		        querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);
	return result;
}

int db_query_int_str(sqlite3 *db, const char* querystr, const char *arg)
{
	log_debug(DEBUG_DATABASE, "db_query_int_str: \"%s\"", querystr);

	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			log_err("Encountered prepare error in db_query_int(\"%s\"): %s",
			        querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	// Bind argument to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, arg, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("Encountered bind error in db_query_int(\"%s\"): %s",
		        querystr, sqlite3_errstr(rc));
	}

	rc = sqlite3_step(stmt);
	int result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_int(stmt, 0);
		log_debug(DEBUG_DATABASE, "         ---> Result %i (int)", result);
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;
		log_debug(DEBUG_DATABASE, "         ---> No data");
	}
	else
	{
		log_err("Encountered step error in db_query_int(\"%s\"): %s",
		        querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);
	return result;
}

double db_query_double(sqlite3 *db, const char* querystr)
{
	log_debug(DEBUG_DATABASE, "dbquery: \"%s\"", querystr);

	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
		{
			log_err("Encountered prepare error in get_max_query_ID(): %s", sqlite3_errstr(rc));
			checkFTLDBrc(rc);
		}

		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	double result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_double(stmt, 0);
		log_debug(DEBUG_DATABASE, "         ---> Result %f (double)", result);
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;
		log_debug(DEBUG_DATABASE, "         ---> No data");
	}
	else
	{
		log_err("Encountered step error in db_query_double(\"%s\"): %s",
		        querystr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);
	return result;
}

int db_query_int_from_until(sqlite3 *db, const char* querystr, const double from, const double until)
{
	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("db_query_int_from_until(%s) - SQL error prepare (%i): %s",
		        querystr, rc, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	// Bind from and until to prepared statement
	if((rc = sqlite3_bind_double(stmt, 1, from))  != SQLITE_OK ||
	   (rc = sqlite3_bind_double(stmt, 2, until)) != SQLITE_OK)
	{
		log_err("db_query_int_from_until(%s) - SQL error bind (%i): %s",
		        querystr, rc, sqlite3_errstr(rc));
	}

	rc = sqlite3_step(stmt);
	int result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_int(stmt, 0);
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;
	}
	else
	{
		log_err("db_query_int_from_until(%s) - SQL error step (%i): %s",
		        querystr, rc, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);

	return result;
}

int db_query_int_from_until_type(sqlite3 *db, const char* querystr, const double from, const double until, const int type)
{
	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("db_query_int_from_until(%s) - SQL error prepare (%i): %s",
		        querystr, rc, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	// Bind from and until to prepared statement
	if((rc = sqlite3_bind_double(stmt, 1, from))  != SQLITE_OK ||
	   (rc = sqlite3_bind_double(stmt, 2, until)) != SQLITE_OK ||
	   (rc = sqlite3_bind_int(stmt, 3, type)) != SQLITE_OK)
	{
		log_err("db_query_int_from_until(%s) - SQL error bind (%i): %s",
		        querystr, rc, sqlite3_errstr(rc));
	}

	rc = sqlite3_step(stmt);
	int result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_int(stmt, 0);
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;
	}
	else
	{
		log_err("db_query_int_from_until(%s) - SQL error step (%i): %s",
		        querystr, rc, sqlite3_errstr(rc));
		return DB_FAILED;
	}
	rc = sqlite3_finalize(stmt);
	checkFTLDBrc(rc);
	return result;
}

// Return SQLite3 engine version string
const char *get_sqlite3_version(void)
{
	return sqlite3_libversion();
}
