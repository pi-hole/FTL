/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Common database routines
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

sqlite3 *FTL_db;
bool database = false;
bool DBdeleteoldqueries = false;
long int lastdbindex = 0;

static pthread_mutex_t dblock;

bool check_database(int rc)
{
	// We will retry if the database is busy at the moment
	// However, we won't retry if any other error happened
	// and - instead - disable the database functionality
	// altogether in FTL (setting database to false)
	if(rc != SQLITE_OK &&
	   rc != SQLITE_DONE &&
	   rc != SQLITE_ROW &&
	   rc != SQLITE_BUSY)
	{
		logg("check_database(%i): Disabling database connection due to error", rc);
		dbclose();
		database = false;
	}

	return database;
}

void dbclose(void)
{
	int rc = SQLITE_OK;

	// Only try to close an existing database connection
	if(FTL_db != NULL)
		rc = sqlite3_close(FTL_db);

	// Report any error
	if( rc != SQLITE_OK )
	{
		logg("dbclose() - SQL error (%i): %s", rc, sqlite3_errmsg(FTL_db));
	}

	// Set database pointer to NULL
	FTL_db = NULL;

	// Unlock mutex on the database
	pthread_mutex_unlock(&dblock);
}

bool dbopen(void)
{
	pthread_mutex_lock(&dblock);
	int rc = sqlite3_open_v2(FTLfiles.FTL_db, &FTL_db, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK ){
		logg("dbopen() - SQL error (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();
		check_database(rc);
		return false;
	}

	return true;
}

bool dbquery(const char *format, ...)
{
	char *zErrMsg = NULL;
	va_list args;

	va_start(args, format);
	char *query = sqlite3_vmprintf(format, args);
	va_end(args);

	if(query == NULL)
	{
		logg("Memory allocation failed in dbquery()");
		return false;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\"", query);
	}

	int rc = sqlite3_exec(FTL_db, query, NULL, NULL, &zErrMsg);

	if( rc != SQLITE_OK ){
		logg("dbquery(%s) - SQL error (%i): %s", query, rc, zErrMsg);
		sqlite3_free(zErrMsg);
		check_database(rc);
		return false;
	}

	sqlite3_free(query);

	return true;

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
	if( rc != SQLITE_OK ){
		logg("db_create() - SQL error (%i): %s", rc, sqlite3_errmsg(FTL_db));
		check_database(rc);
		return false;
	}
	// Create Queries table in the database
	SQL_bool("CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );");

	// Add an index on the timestamps (not a unique index!)
	SQL_bool("CREATE INDEX idx_queries_timestamps ON queries (timestamp);");

	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool("CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );");


	// Set FTL_db version 1
	if(!dbquery("INSERT INTO ftl (ID,VALUE) VALUES(%i,1);", DB_VERSION))
		return false;

	// Most recent timestamp initialized to 00:00 1 Jan 1970
	if(!dbquery("INSERT INTO ftl (ID,VALUE) VALUES(%i,0);", DB_LASTTIMESTAMP))
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
	// First check if the user doesn't want to use the database and set an
	// empty string as file name in FTL's config file
	if(FTLfiles.FTL_db == NULL || strlen(FTLfiles.FTL_db) == 0)
	{
		database = false;
		return;
	}

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
			database = false;
			return;
		}
	}

	int rc = sqlite3_open_v2(FTLfiles.FTL_db, &FTL_db, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK ){
		logg("db_init() - Cannot open database (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();

		database = false;
		return;
	}

	// Test FTL_db version and see if we need to upgrade the database file
	int dbversion = db_get_FTL_property(DB_VERSION);
	logg("Database version is %i", dbversion);
	if(dbversion < 1)
	{
		logg("Database version incorrect, database not available");
		database = false;
		return;
	}

	// Update to version 2 if lower
	if(dbversion < 2)
	{
		// Update to version 2: Create counters table
		logg("Updating long-term database to version 2");
		if (!create_counter_table())
		{
			logg("Counter table not initialized, database not available");
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
		unify_hwaddr();
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
			database = false;
			return;
		}
		// Get updated version
		dbversion = db_get_FTL_property(DB_VERSION);
	}

	// Close database to prevent having it opened all time
	// we already closed the database when we returned earlier
	sqlite3_close(FTL_db);

	if (pthread_mutex_init(&dblock, NULL) != 0)
	{
		logg("FATAL: FTL_db mutex init failed\n");
		// Return failure
		exit(EXIT_FAILURE);
	}

	logg("Database successfully initialized");
	database = true;
}

int db_get_FTL_property(const unsigned int ID)
{
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
	return dbquery("INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %i );", ID, value);
}

bool db_set_counter(const unsigned int ID, const int value)
{
	return dbquery("INSERT OR REPLACE INTO counters (id, value) VALUES ( %u, %i );", ID, value);
}

bool db_update_counters(const int total, const int blocked)
{
	if(!dbquery("UPDATE counters SET value = value + %i WHERE id = %i;", total, DB_TOTALQUERIES))
		return false;
	if(!dbquery("UPDATE counters SET value = value + %i WHERE id = %i;", blocked, DB_BLOCKEDQUERIES))
		return false;
	return true;
}

int db_query_int(const char* querystr)
{
	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("db_query_int(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(FTL_db));
		check_database(rc);
		return DB_FAILED;
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
		logg("db_query_int(%s) - SQL error step (%i): %s", querystr, rc, sqlite3_errmsg(FTL_db));
		check_database(rc);
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);

	return result;
}

long int get_max_query_ID(void)
{
	sqlite3_stmt* stmt;

	int rc = sqlite3_prepare_v2(FTL_db, "SELECT MAX(ID) FROM queries", -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("get_max_query_ID() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();
		check_database(rc);
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW ){
		logg("get_max_query_ID() - SQL error step (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();
		check_database(rc);
		return DB_FAILED;
	}

	sqlite3_int64 result = sqlite3_column_int64(stmt, 0);

	sqlite3_finalize(stmt);

	return result;
}

// Returns ID of the most recent successful INSERT.
long get_lastID(void)
{
	long id = sqlite3_last_insert_rowid(FTL_db);
	if(config.debug & DEBUG_DATABASE)
		logg("get_lastID(): %ld", id);
	return id;
}

// Return SQLite3 engine version string
const char *get_sqlite3_version(void)
{
	return sqlite3_libversion();
}
