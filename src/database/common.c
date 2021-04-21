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
long int lastdbindex = 0;

void _dbclose(sqlite3 **db, const char *func, const int line, const char *file)
{
	if(config.debug & DEBUG_DATABASE)
		logg("Closing FTL database in %s() (%s:%i)", func, file, line);

	// Only try to close an existing database connection
	int rc = SQLITE_OK;
	if(db != NULL && *db != NULL && (rc = sqlite3_close(*db)) != SQLITE_OK)
		logg("Error while trying to close database: %s",
		     sqlite3_errstr(rc));

	// Always set database pointer to NULL, even when closing failed
	*db = NULL;
}

sqlite3* _dbopen(bool create, const char *func, const int line, const char *file)
{
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
		return NULL;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_timeout(db, DATABASE_BUSY_TIMEOUT);
	if( rc != SQLITE_OK )
	{
		logg("Error while trying to set busy timeout (%d ms) on database: %s",
		     DATABASE_BUSY_TIMEOUT, sqlite3_errstr(rc));
		dbclose(&db);
		return NULL;
	}

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
		dbclose(&db);
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
	db_set_counter(db, DB_TOTALQUERIES, 0);

	// ID 1 = total blocked queries
	db_set_counter(db, DB_BLOCKEDQUERIES, 0);

	// Time stamp of creation of the counters database
	db_set_counter(db, DB_FIRSTCOUNTERTIMESTAMP, (unsigned long)time(0));

	// Update database version to 2
	db_set_FTL_property(db, DB_VERSION, 2);

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

	// Explicitly set permissions to 0644
	// 644 =            u+w       u+r       g+r       o+r
	const mode_t mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;
	chmod_file(FTLfiles.FTL_db, mode);

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
	// This ensures SQLite3 errors and warnings are logged to pihole-FTL.log
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

	// Open database
	sqlite3 *db = dbopen(false);

	// Test FTL_db version and see if we need to upgrade the database file
	int dbversion = db_get_int(db, DB_VERSION);
	if(dbversion < 1)
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

	import_aliasclients(db);

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
	if(dbquery(db, "INSERT OR REPLACE INTO counters (id, value) VALUES ( %u, %ld );", ID, value) != SQLITE_OK)
	{
		dbclose(&db);
		return false;
	}

	return true;
}

bool db_update_counters(sqlite3 *db, const int total, const int blocked)
{
	if(dbquery(db, "UPDATE counters SET value = value + %i WHERE id = %i;", total, DB_TOTALQUERIES) != SQLITE_OK)
	{
		dbclose(&db);
		return false;
	}

	if(dbquery(db, "UPDATE counters SET value = value + %i WHERE id = %i;", blocked, DB_BLOCKEDQUERIES) != SQLITE_OK)
	{
		dbclose(&db);
		return false;
	}

	return true;
}

int db_query_int(sqlite3 *db, const char* querystr)
{
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
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);
	return result;
}

long int get_max_query_ID(sqlite3 *db)
{
	const char *sql = "SELECT MAX(ID) FROM queries";
	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\"", sql);
	}

	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
		{
			logg("Encountered prepare error in get_max_query_ID(): %s", sqlite3_errstr(rc));
			dbclose(&db);
		}

		// Return okay if the database is busy
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW )
	{
		logg("Encountered step error in get_max_query_ID(): %s", sqlite3_errstr(rc));
		dbclose(&db);
		return DB_FAILED;
	}

	sqlite3_int64 result = sqlite3_column_int64(stmt, 0);
	if(config.debug & DEBUG_DATABASE)
	{
		logg("         ---> Result %lli (long long int)", (long long int)result);
	}
	sqlite3_finalize(stmt);
	return result;
}

// Return SQLite3 engine version string
const char *get_sqlite3_version(void)
{
	return sqlite3_libversion();
}