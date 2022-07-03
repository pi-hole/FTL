/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Common database routines for pihole-FTL.db
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "common.h"
#include "network-table.h"
#include "message-table.h"
#include "../shmem.h"
// struct config
#include "../config.h"
// logg()
#include "../log.h"
#include "../timers.h"
// file_exists()
#include "../files.h"
#include "sqlite3-ext.h"
// import_aliasclients()
#include "aliasclients.h"
// add_additional_info_column()
#include "query-table.h"

bool DBdeleteoldqueries = false;
static bool DBerror = false;
long int lastdbindex = 0;

bool __attribute__ ((pure)) FTLDBerror(void)
{
	return DBerror;
}

bool checkFTLDBrc(const int rc)
{
	// Check if the database file is malformed
	if(rc == SQLITE_CORRUPT)
	{
		logg("WARN: Database %s is damaged and cannot be used.", FTLfiles.FTL_db);
		DBerror = true;
	}
	// Check if the database file is read-only
	if(rc == SQLITE_READONLY)
	{
		logg("WARN: Database %s is read-only and cannot be used.", FTLfiles.FTL_db);
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

	if(config.debug & DEBUG_DATABASE)
		logg("Closing FTL database in %s() (%s:%i)", func, file, line);

	// Only try to close an existing database connection
	int rc = SQLITE_OK;
	if(db != NULL && *db != NULL && (rc = sqlite3_close(*db)) != SQLITE_OK)
	{
		logg("Error while trying to close database: %s",
		     sqlite3_errstr(rc));
		checkFTLDBrc(rc);
	}

	// Always set database pointer to NULL, even when closing failed
	if(db) *db = NULL;
}

sqlite3* _dbopen(bool create, const char *func, const int line, const char *file)
{
	// Silently return NULL if the database is known to be broken
	if(FTLDBerror())
		return NULL;

	// Try to open database
	if(config.debug & DEBUG_DATABASE)
		logg("Opening FTL database in %s() (%s:%i)", func, file, line);

	int flags = SQLITE_OPEN_READWRITE;
	if(create)
		flags |= SQLITE_OPEN_CREATE;

	sqlite3 *db = NULL;
	int rc = sqlite3_open_v2(FTLfiles.FTL_db, &db, flags, NULL);
	if( rc != SQLITE_OK )
	{
		logg("Error while trying to open database: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return NULL;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_timeout(db, DATABASE_BUSY_TIMEOUT);
	if( rc != SQLITE_OK )
	{
		logg("Error while trying to set busy timeout (%d ms) on database: %s",
		     DATABASE_BUSY_TIMEOUT, sqlite3_errstr(rc));
		dbclose(&db);
		checkFTLDBrc(rc);
		return NULL;
	}

	return db;
}

int dbquery(sqlite3* db, const char *format, ...)
{
	// Return early if the database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	va_list args;
	va_start(args, format);
	char *query = sqlite3_vmprintf(format, args);
	va_end(args);

	if(query == NULL)
	{
		logg("Memory allocation failed in dbquery()");
		return SQLITE_ERROR;
	}

	// Log generated SQL string when dbquery() is called
	// although the database connection is not available
	if(db == NULL)
	{
		logg("dbquery(\"%s\") called but database is not available!", query);
		sqlite3_free(query);
		return SQLITE_ERROR;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\"", query);
	}

	int rc = sqlite3_exec(db, query, NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		logg("ERROR: SQL query \"%s\" failed: %s",
		     query, sqlite3_errstr(rc));
		sqlite3_free(query);
		checkFTLDBrc(rc);
		return rc;
	}

	// Free allocated memory for query string
	sqlite3_free(query);

	if(config.debug & DEBUG_DATABASE)
	{
		logg("         ---> OK");
	}

	// Return success
	return SQLITE_OK;
}

static bool create_counter_table(sqlite3* db)
{
	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool(db, "CREATE TABLE counters ( id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL );");

	// ID 0 = total queries
	if(!db_set_counter(db, DB_TOTALQUERIES, 0))
	{
		logg("create_counter_table(): Failed to set total queries counter to zero!");
		return false;
	}

	// ID 1 = total blocked queries
	if(!db_set_counter(db, DB_BLOCKEDQUERIES, 0))
	{
		logg("create_counter_table(): Failed to set blocked queries counter to zero!");
		return false;
	}

	// Time stamp of creation of the counters database
	if(!db_set_FTL_property(db, DB_FIRSTCOUNTERTIMESTAMP, (unsigned long)time(0)))
	{
		logg("create_counter_table(): Failed to update first counter timestamp!");
		return false;
	}

	// Update database version to 2
	if(!db_set_FTL_property(db, DB_VERSION, 2))
	{
		logg("create_counter_table(): Failed to update database version!");
		return false;
	}

	return true;
}

static bool db_create(void)
{
	sqlite3 *db = dbopen(true);
	if(db == NULL)
		return false;

	// Create Queries table in the database
	SQL_bool(db, "CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );");

	// Add an index on the timestamps (not a unique index!)
	SQL_bool(db, "CREATE INDEX idx_queries_timestamps ON queries (timestamp);");

	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool(db, "CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );");

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
	logg("SQLite3 message: %s (%d)", zMsg, iErrCode);
}

void db_init(void)
{
	// Initialize SQLite3 logging callback
	// This ensures SQLite3 errors and warnings are logged to FTL.log
	// We use this to possibly catch even more errors in places we do not
	// explicitly check for failures to have happened
	sqlite3_config(SQLITE_CONFIG_LOG, SQLite3LogCallback, NULL);

	// Register Pi-hole provided SQLite3 extensions (see sqlite3-ext.c)
	sqlite3_auto_extension((void (*)(void))sqlite3_pihole_extensions_init);

	// Check if database exists, if not create empty database
	if(!file_exists(FTLfiles.FTL_db))
	{
		logg("No database file found, creating new (empty) database");
		if (!db_create())
		{
			logg("Creation of database failed, database is not available");
			return;
		}
	}

	// Explicitly set permissions to 0664
	// 664 =            u+w       u+r       g+w       g+r       o+r
	const mode_t mode = S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH;
	chmod_file(FTLfiles.FTL_db, mode);

	// Open database
	sqlite3 *db = dbopen(false);

	// Return if database access failed
	if(!db)
		return;

	// Test FTL_db version and see if we need to upgrade the database file
	int dbversion = db_get_int(db, DB_VERSION);
	// Warn if there is an error, however, do not warn on database file
	// corruption. This has already been logged before
	if(dbversion < 1 && !FTLDBerror())
	{
		logg("Database not available, please ensure the database is unlocked when starting pihole-FTL !");
		dbclose(&db);
		return;
	}
	else
	{
		logg("Database version is %i", dbversion);
	}


	// Update to version 2 if lower
	if(dbversion < 2)
	{
		// Update to version 2: Create counters table
		logg("Updating long-term database to version 2");
		if (!create_counter_table(db))
		{
			logg("Counter table not initialized, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 3 if lower
	if(dbversion < 3)
	{
		// Update to version 3: Create network table
		logg("Updating long-term database to version 3");
		if (!create_network_table(db))
		{
			logg("Network table not initialized, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 4 if lower
	if(dbversion < 4)
	{
		// Update to version 4: Unify clients in network table
		logg("Updating long-term database to version 4");
		if(!unify_hwaddr(db))
		{
			logg("Unable to unify clients in network table, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 5 if lower
	if(dbversion < 5)
	{
		// Update to version 5: Create network-addresses table
		logg("Updating long-term database to version 5");
		if(!create_network_addresses_table(db))
		{
			logg("Network-addresses table not initialized, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 6 if lower
	if(dbversion < 6)
	{
		// Update to version 6: Create message table
		logg("Updating long-term database to version 6");
		if(!create_message_table(db))
		{
			logg("Message table not initialized, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 7 if lower
	if(dbversion < 7)
	{
		// Update to version 7: Add additional_info column to queries table
		logg("Updating long-term database to version 7");
		if(!add_additional_info_column(db))
		{
			logg("Column additional_info not initialized, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 8 if lower
	if(dbversion < 8)
	{
		// Update to version 8: Add name field to network_addresses table
		logg("Updating long-term database to version 8");
		if(!create_network_addresses_with_names_table(db))
		{
			logg("Network addresses table not initialized, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 9 if lower
	if(dbversion < 9)
	{
		// Update to version 9: Add aliasclients table
		logg("Updating long-term database to version 9");
		if(!create_aliasclients_table(db))
		{
			logg("Aliasclients table not initialized, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 10 if lower
	if(dbversion < 10)
	{
		// Update to version 10: Use linking tables for queries table
		logg("Updating long-term database to version 10");
		if(!optimize_queries_table(db))
		{
			logg("Queries table not optimized, database not available");
			dbclose(&db);
			return;
		}

		// Reopen database after low-level schema editing to reload the schema
		dbclose(&db);
		if(!(db = dbopen(false)))
			return;

		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 11 if lower
	if(dbversion < 11)
	{
		// Update to version 11: Use link table also for additional_info column
		logg("Updating long-term database to version 11");
		if(!create_addinfo_table(db))
		{
			logg("Linkt table for additional_info not generated, database not available");
			dbclose(&db);
			return;
		}

		// Reopen database after low-level schema editing to reload the schema
		dbclose(&db);
		if(!(db = dbopen(false)))
			return;

		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 12 if lower
	if(dbversion < 12)
	{
		// Update to version 12: Add additional columns for reply type and time, and dnssec status
		logg("Updating long-term database to version 12");
		if(!add_query_storage_columns(db))
		{
			logg("Additional records not generated, database not available");
			dbclose(&db);
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	lock_shm();
	import_aliasclients(db);
	unlock_shm();

	// Close database to prevent having it opened all time
	// We already closed the database when we returned earlier
	dbclose(&db);

	// Log if users asked us to not use the long-term database for queries
	// We will still use it to store warnings in it
	config.DBexport = true;
	if(config.maxDBdays == 0)
	{
		logg("Not using the database for storing queries");
		config.DBexport = false;
	}

	logg("Database successfully initialized");
}

int db_get_int(sqlite3* db, const enum ftl_table_props ID)
{
	// Prepare SQL statement
	char* querystr = NULL;
	int ret = asprintf(&querystr, "SELECT VALUE FROM ftl WHERE id = %u;", ID);

	if(querystr == NULL || ret < 0)
	{
		logg("Memory allocation failed in db_get_int db, with ID = %u (%i)", ID, ret);
		return DB_FAILED;
	}

	int value = db_query_int(db, querystr);
	free(querystr);

	return value;
}

bool db_set_FTL_property(sqlite3 *db, const enum ftl_table_props ID, const long value)
{
	return dbquery(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %ld );", ID, value) == SQLITE_OK;
}

bool db_set_counter(sqlite3 *db, const enum counters_table_props ID, const long value)
{
	const int rc = dbquery(db, "INSERT OR REPLACE INTO counters (id, value) VALUES ( %u, %ld );", ID, value);
	if(rc != SQLITE_OK)
	{
		checkFTLDBrc(rc);
		return false;
	}

	return true;
}

bool db_update_counters(sqlite3 *db, const int total, const int blocked)
{
	int rc = dbquery(db, "UPDATE counters SET value = value + %i WHERE id = %i;", total, DB_TOTALQUERIES);
	if(rc != SQLITE_OK)
	{
		checkFTLDBrc(rc);
		return false;
	}

	rc = dbquery(db, "UPDATE counters SET value = value + %i WHERE id = %i;", blocked, DB_BLOCKEDQUERIES);
	if(rc != SQLITE_OK)
	{
		checkFTLDBrc(rc);
		return false;
	}

	return true;
}

int db_query_int(sqlite3 *db, const char* querystr)
{
	// Return early if the database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\"", querystr);
	}

	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			logg("Encountered prepare error in db_query_int(\"%s\"): %s", querystr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	int result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_int(stmt, 0);
		if(config.debug & DEBUG_DATABASE)
			logg("         ---> Result %i (int)", result);
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;
		if(config.debug & DEBUG_DATABASE)
			logg("         ---> No data");
	}
	else
	{
		logg("Encountered step error in db_query_int(\"%s\"): %s", querystr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);
	return result;
}

long int get_max_query_ID(sqlite3 *db)
{
	// Return early if the database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	const char *sql = "SELECT MAX(ID) FROM queries";
	if(config.debug & DEBUG_DATABASE)
		logg("dbquery: \"%s\"", sql);

	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
		{
			logg("Encountered prepare error in get_max_query_ID(): %s", sqlite3_errstr(rc));
			checkFTLDBrc(rc);
		}

		// Return okay if the database is busy
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW )
	{
		logg("Encountered step error in get_max_query_ID(): %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return DB_FAILED;
	}

	sqlite3_int64 result = sqlite3_column_int64(stmt, 0);
	if(config.debug & DEBUG_DATABASE)
	{
		logg("         ---> Result %lli (long long int)", (long long int)result);
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
