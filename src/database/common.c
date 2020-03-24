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
#include "common.h"
#include "shmem.h"
#include "network-table.h"
#include "memory.h"
#include "config.h"
#include "log.h"
#include "timers.h"
#include "files.h"

sqlite3 *FTL_db = NULL;
bool database = true;
bool DBdeleteoldqueries = false;
long int lastdbindex = 0;

static pthread_mutex_t dblock;

void dbclose(void)
{
	// Only try to close an existing database connection
	int rc = SQLITE_OK;
	if( FTL_db != NULL )
	{
		rc = sqlite3_close(FTL_db);
		FTL_db = NULL;
	}

	// Report any error
	if( rc != SQLITE_OK )
	{
		logg("Encountered error while trying to close database: %s", sqlite3_errstr(rc));
		database = false;
	}

	// Unlock mutex on the database
	pthread_mutex_unlock(&dblock);
}

bool dbopen(void)
{
	// Lock mutex on the database
	pthread_mutex_lock(&dblock);

	// Try to open database
	int rc = sqlite3_open_v2(FTLfiles.FTL_db, &FTL_db, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK )
	{
		logg("Encountered error while trying to open database: %s", sqlite3_errstr(rc));
		database = false;
		pthread_mutex_unlock(&dblock);
		return false;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_timeout(FTL_db, DATABASE_BUSY_TIMEOUT);
	if( rc != SQLITE_OK )
	{
		logg("Encountered error while trying to set busy timeout (%d ms) on database: %s",
		     DATABASE_BUSY_TIMEOUT, sqlite3_errstr(rc));
		database = false;
		dbclose();
		return false;
	}

	return true;
}

int dbquery(const char *format, ...)
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
	if(database == false || ( FTL_db == NULL && !dbopen() ))
	{
		logg("dbquery(\"%s\") called but database is not available!", query);
		sqlite3_free(query);
		return SQLITE_ERROR;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\"", query);
	}

	int rc = sqlite3_exec(FTL_db, query, NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		logg("ERROR: SQL query \"%s\" failed: %s",
		     query, sqlite3_errstr(rc));
		dbclose();
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

static bool create_counter_table(void)
{
	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool("CREATE TABLE counters ( id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL );");

	// ID 0 = total queries
	if(!db_set_counter(DB_TOTALQUERIES, 0))
	{ dbclose(); return false; }

	// ID 1 = total blocked queries
	if(!db_set_counter(DB_BLOCKEDQUERIES, 0))
	{ dbclose(); return false; }

	// Time stamp of creation of the counters database
	if(!db_set_FTL_property(DB_FIRSTCOUNTERTIMESTAMP, time(NULL)))
	{ dbclose(); return false; }

	// Update database version to 2
	if(!db_set_FTL_property(DB_VERSION, 2))
	{ dbclose(); return false; }

	return true;
}

static bool db_create(void)
{
	int rc = sqlite3_open_v2(FTLfiles.FTL_db, &FTL_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if( rc != SQLITE_OK )
	{
		logg("Encountered error while trying to create database in rw-mode: %s", sqlite3_errstr(rc));
		return false;
	}
	// Create Queries table in the database
	SQL_bool("CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );");

	// Add an index on the timestamps (not a unique index!)
	SQL_bool("CREATE INDEX idx_queries_timestamps ON queries (timestamp);");

	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool("CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );");


	// Set FTL_db version 1
	if(dbquery("INSERT INTO ftl (ID,VALUE) VALUES(%i,1);", DB_VERSION) != SQLITE_OK)
		return false;

	// Most recent timestamp initialized to 00:00 1 Jan 1970
	if(dbquery("INSERT INTO ftl (ID,VALUE) VALUES(%i,0);", DB_LASTTIMESTAMP) != SQLITE_OK)
		return false;

	// Create counter table
	// Will update FTL_db version to 2
	if(!create_counter_table())
		return false;

	// Create network table
	// Will update FTL_db version to 3
	if(!create_network_table())
		return false;

	// Done initializing the database
	// Close database handle
	dbclose();

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
	// Initialize database lock mutex
	int rc;
	if((rc = pthread_mutex_init(&dblock, NULL)) != 0)
	{
		logg("FATAL: FTL_db mutex init failed (%s, %i)\n", strerror(rc), rc);
		// Return failure
		exit(EXIT_FAILURE);
	}

	if(!use_database())
	{
		logg("Not using the long-term database");
		database = false;
		return;
	}

	// Lock database thread
	pthread_mutex_lock(&dblock);

	// Initialize SQLite3 logging callback
	// This ensures SQLite3 errors and warnings are logged to pihole-FTL.log
	// We use this to possibly catch even more errors in places we do not
	// explicitly check for failures to have happened
	sqlite3_config(SQLITE_CONFIG_LOG, SQLite3LogCallback, NULL);

	// Check if database exists, if not create empty database
	if(!file_exists(FTLfiles.FTL_db))
	{
		logg("No database file found, creating new (empty) database");
		if (!db_create())
		{
			logg("Creation of database failed, database is not available");
			pthread_mutex_unlock(&dblock);
			database = false;
			return;
		}
	}

	// Try to open the database connection
	rc = sqlite3_open_v2(FTLfiles.FTL_db, &FTL_db, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK ){
		logg("Cannot initialize (open) long-term database: %s", sqlite3_errstr(rc));
		database = false;
		return;
	}

	// Test FTL_db version and see if we need to upgrade the database file
	int dbversion = db_get_FTL_property(DB_VERSION);
	logg("Database version is %i", dbversion);

	// Update to version 2 if lower
	if(dbversion < 2)
	{
		// Update to version 2: Create counters table
		logg("Updating long-term database to version 2");
		if (!create_counter_table())
		{
			logg("Counter table not initialized, database not available");
			dbclose();

			database = false;
			return;
		}
		// Get updated version
		dbversion = db_get_FTL_property(DB_VERSION);
	}

	// Update to version 3 if lower
	if(dbversion < 3)
	{
		// Update to version 3: Create network table
		logg("Updating long-term database to version 3");
		if (!create_network_table())
		{
			logg("Network table not initialized, database not available");
			dbclose();

			database = false;
			return;
		}
		// Get updated version
		dbversion = db_get_FTL_property(DB_VERSION);
	}

	// Update to version 4 if lower
	if(dbversion < 4)
	{
		// Update to version 4: Unify clients in network table
		logg("Updating long-term database to version 4");
		if(!unify_hwaddr())
		{
			logg("Unable to unify clients in network table, database not available");
			dbclose();

			database = false;
			return;
		}
		// Get updated version
		dbversion = db_get_FTL_property(DB_VERSION);
	}

	// Update to version 5 if lower
	if(dbversion < 5)
	{
		// Update to version 5: Create network-addresses table
		logg("Updating long-term database to version 5");
		if(!create_network_addresses_table())
		{
			logg("Network-addresses table not initialized, database not available");
			dbclose();

			database = false;
			return;
		}
		// Get updated version
		dbversion = db_get_FTL_property(DB_VERSION);
	}

	// Close database to prevent having it opened all time
	// We already closed the database when we returned earlier
	dbclose();

	logg("Database successfully initialized");
}

int db_get_FTL_property(const unsigned int ID)
{
	if(!database || FTL_db == NULL)
	{
		logg("db_get_FTL_property(%u) called but database is not available!", ID);
		return DB_FAILED;
	}
	// Prepare SQL statement
	char* querystr = NULL;
	int ret = asprintf(&querystr, "SELECT VALUE FROM ftl WHERE id = %u;", ID);

	if(querystr == NULL || ret < 0)
	{
		logg("Memory allocation failed in db_get_FTL_property with ID = %u (%i)", ID, ret);
		return DB_FAILED;
	}

	int value = db_query_int(querystr);
	free(querystr);

	return value;
}

bool db_set_FTL_property(const unsigned int ID, const int value)
{
	if(!database || FTL_db == NULL)
	{
		logg("db_set_FTL_property(%u, %i) called but database is not available!", ID, value);
		return false;
	}
	return dbquery("INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %i );", ID, value) == SQLITE_OK;
}

bool db_set_counter(const unsigned int ID, const int value)
{
	if(!database || FTL_db == NULL)
	{
		logg("db_set_counter(%u, %i) called but database is not available!", ID, value);
		return false;
	}
	return dbquery("INSERT OR REPLACE INTO counters (id, value) VALUES ( %u, %i );", ID, value) == SQLITE_OK;
}

bool db_update_counters(const int total, const int blocked)
{
	if(!database || FTL_db == NULL)
	{
		logg("db_update_counters(%i, %i) called but database is not available!", total, blocked);
		return false;
	}
	if(dbquery("UPDATE counters SET value = value + %i WHERE id = %i;", total, DB_TOTALQUERIES) != SQLITE_OK)
		return false;
	if(dbquery("UPDATE counters SET value = value + %i WHERE id = %i;", blocked, DB_BLOCKEDQUERIES) != SQLITE_OK)
		return false;
	return true;
}

int db_query_int(const char* querystr)
{
	if(!database || FTL_db == NULL)
	{
		logg("db_query_int(\"%s\") called but database is not available!", querystr);
		return DB_FAILED;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\"", querystr);
	}

	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("Encountered prepare error in db_query_int(\"%s\"): %s", querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	int result;

	if( rc == SQLITE_ROW )
	{
		result = sqlite3_column_int(stmt, 0);

		if(config.debug & DEBUG_DATABASE)
		{
			logg("         ---> Result %i (int)", result);
		}
	}
	else if( rc == SQLITE_DONE )
	{
		// No rows available
		result = DB_NODATA;

		if(config.debug & DEBUG_DATABASE)
		{
			logg("         ---> No data");
		}
	}
	else
	{
		logg("Encountered step error in db_query_int(\"%s\"): %s", querystr, sqlite3_errstr(rc));
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);
	return result;
}

long int get_max_query_ID(void)
{
	if(!database || FTL_db == NULL)
	{
		logg("get_max_query_ID() called but database is not available!");
		return DB_FAILED;
	}

	const char *sql = "SELECT MAX(ID) FROM queries";
	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\"", sql);
	}

	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(FTL_db, sql, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("Encountered prepare error in get_max_query_ID(): %s", sqlite3_errstr(rc));
		database = false;
		dbclose();
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW )
	{
		logg("Encountered step error in get_max_query_ID(): %s", sqlite3_errstr(rc));
		database = false;
		dbclose();
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

// Returns ID of the most recent successful INSERT.
long get_lastID(void)
{
	if(!database || FTL_db == NULL)
	{
		logg("get_lastID() called but database is not available!");
		return DB_FAILED;
	}
	return sqlite3_last_insert_rowid(FTL_db);
}

// Return SQLite3 engine version string
const char *get_sqlite3_version(void)
{
	return sqlite3_libversion();
}

// Should the long-term database be used?
__attribute__ ((pure)) bool use_database()
{
	// Check if the user doesn't want to use the database and set an
	// empty string as file name in FTL's config file or configured
	// a maximum history of zero days.
	if(FTLfiles.FTL_db == NULL ||
	   strlen(FTLfiles.FTL_db) == 0 ||
	   config.maxDBdays == 0)
	{
		return false;
	}

	return true;
}
