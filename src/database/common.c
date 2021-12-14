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
#include "../config/config.h"
// logging routines
#include "../log.h"
#include "../timers.h"
// file_exists()
#include "../files.h"
#include "sqlite3-ext.h"
// import_aliasclients()
#include "aliasclients.h"
// CREATE_QUERIES_TABLE
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
		log_warn("Database %s is damaged and cannot be used.", config.files.database);
		DBerror = true;
	}
	// Check if the database file is read-only
	if(rc == SQLITE_READONLY)
	{
		log_warn("Database %s is read-only and cannot be used.", config.files.database);
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
		log_debug(DEBUG_DATABASE, "Closing FTL database in %s() (%s:%i)", func, file, line);

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
}

sqlite3* _dbopen(bool create, const char *func, const int line, const char *file)
{
	// Silently return NULL if the database is known to be broken
	if(FTLDBerror())
		return NULL;

	// Try to open database
	log_debug(DEBUG_DATABASE, "Opening FTL database in %s() (%s:%i)", func, file, line);

	int flags = SQLITE_OPEN_READWRITE;
	if(create)
		flags |= SQLITE_OPEN_CREATE;

	sqlite3 *db = NULL;
	int rc = sqlite3_open_v2(config.files.database, &db, flags, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("Error while trying to open database: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return NULL;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_timeout(db, DATABASE_BUSY_TIMEOUT);
	if( rc != SQLITE_OK )
	{
		log_err("Error while trying to set busy timeout (%d ms) on database: %s",
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
		log_err("SQL query \"%s\" failed: %s",
		        query, sqlite3_errstr(rc));
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

	return true;
}

static bool db_create(void)
{
	sqlite3 *db = dbopen(true);
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
	log_err("SQLite3 message: %s (%d)", zMsg, iErrCode);
}

void db_init(void)
{
	// Initialize SQLite3 logging callback
	// This ensures SQLite3 errors and warnings are logged to pihole-FTL.log
	// We use this to possibly catch even more errors in places we do not
	// explicitly check for failures to have happened
	sqlite3_config(SQLITE_CONFIG_LOG, SQLite3LogCallback, NULL);

	// SQLITE_DBCONFIG_DEFENSIVE
	// Disbale language features that allow ordinary SQL to deliberately corrupt
	// the database file. The disabled features include but are not limited to
	// the following:
	//
	// - The PRAGMA writable_schema=ON statement.
	// - The PRAGMA journal_mode=OFF statement.
	// - Writes to the sqlite_dbpage virtual table.
	// - Direct writes to shadow tables.
	sqlite3_config(SQLITE_DBCONFIG_DEFENSIVE, true);

	// Register Pi-hole provided SQLite3 extensions (see sqlite3-ext.c)
	sqlite3_auto_extension((void (*)(void))sqlite3_pihole_extensions_init);

	// Check if database exists, if not create empty database
	if(!file_exists(config.files.database))
	{
		log_warn("No database file found, creating new (empty) database");
		if (!db_create())
		{
			log_err("Creation of database failed, database is not available");
			return;
		}
	}

	// Explicitly set permissions to 0644
	// 644 =            u+w       u+r       g+w       g+r      o+r
	const mode_t mode = S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP| S_IROTH;
	chmod_file(config.files.database, mode);

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
		log_warn("Database not available, please ensure the database is unlocked when starting pihole-FTL !");
		dbclose(&db);
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
			return;
		}
		// Get updated version
		dbversion = db_get_int(db, DB_VERSION);
	}

	// Update to version 10 if lower
	if(dbversion < 10)
	{
		// Update to version 10: Add more fields to queries table
		log_info("Updating long-term database to version 10");
		if(!create_more_queries_columns(db))
		{
			log_err("Long-term database not initialized, database not available");
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
		log_info("Not using the database for storing queries");
		config.DBexport = false;
	}

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

double db_get_FTL_property_double(sqlite3 *db, const enum ftl_table_props ID)
{
	// Prepare SQL statement
	char* querystr = NULL;
	int ret = asprintf(&querystr, "SELECT VALUE FROM ftl WHERE id = %u;", ID);

	if(querystr == NULL || ret < 0)
	{
		log_err("Memory allocation failed in db_get_FTL_property with ID = %u (%i)", ID, ret);
		checkFTLDBrc(ret);
		return DB_FAILED;
	}

	double value = db_query_double(db, querystr);
	free(querystr);

	return value;
}

bool db_set_FTL_property(sqlite3 *db, const enum ftl_table_props ID, const int value)
{
	// return dbquery(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %ld );", ID, value) == SQLITE_OK;
	SQL_bool(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %d );", ID, value);
	return true;
}

bool db_set_FTL_property_double(sqlite3 *db, const enum ftl_table_props ID, const double value)
{
	int ret = dbquery(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %f );", ID, value);
	if(ret != SQLITE_OK)
	{
		checkFTLDBrc(ret);
		return false;
	}
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

bool db_update_counters(sqlite3 *db, const int total, const int blocked)
{
	int ret = dbquery(db, "UPDATE counters SET value = value + %i WHERE id = %i;", total, DB_TOTALQUERIES);
	if(ret != SQLITE_OK)
	{
		checkFTLDBrc(ret);
		return false;
	}

	ret = dbquery(db, "UPDATE counters SET value = value + %i WHERE id = %i;", total, DB_TOTALQUERIES);
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
