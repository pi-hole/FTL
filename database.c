/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

sqlite3 *db;
bool database = false;
long int lastdbindex = 0;

enum { DB_VERSION, DB_LASTTIMESTAMP };

float get_db_filesize(void)
{
	struct stat st;
	if(stat(FTLfiles.db, &st) != 0)
	{
		// stat() failed (maybe the DB file does not exist?)
		return 0;
	}
	return 1e-6*st.st_size;
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
	int i;
	for(i=0; i<argc; i++){
		logg("%s = %s", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	return 0;
}

bool dbopen(void)
{
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE, NULL);
	if( rc ){
		logg("Cannot open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}

	return true;
}

bool dbquery(const char *format, ...)
{
	char *zErrMsg = NULL;
	va_list args;
	int rc;

	va_start(args, format);

	char *query = sqlite3_vmprintf(format, args);

	if(query == NULL)
	{
		logg("Memory allocation failed in dbquery()");
		va_end(args);
		return false;
	}

	if(debugDB)
		rc = sqlite3_exec(db, query, callback, NULL, &zErrMsg);
	else
		rc = sqlite3_exec(db, query, NULL, NULL, &zErrMsg);

	sqlite3_free(query);
	va_end(args);

	if( rc != SQLITE_OK ){
		logg("SQL error (%i): %s", rc, zErrMsg);
		sqlite3_free(zErrMsg);
		return false;
	}

	return true;

}

void dbclose(void)
{
	sqlite3_close(db);
}

bool db_create(void)
{
	bool ret;
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if( rc ){
		logg("Can't create database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}
	// Create Queries table in the database
	ret = dbquery("CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );");
	if(!ret){ dbclose(); return false; }
	// Add an index on the timestamps (not a unique index!)
	ret = dbquery("CREATE INDEX idx_queries_timestamps ON queries (timestamp)");
	if(!ret){ dbclose(); return false; }
	// Create FTL table in the database (holds properties like database version, etc.)
	ret = dbquery("CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );");
	if(!ret){ dbclose(); return false; }

	// DB version 1
	ret = dbquery("INSERT INTO ftl (ID,VALUE) VALUES(0,1);");
	if(!ret){ dbclose(); return false; }

	// Most recent timestamp initialized to 00:00 1 Jan 1970
	ret = dbquery("INSERT INTO ftl (ID,VALUE) VALUES(1,0);");
	if(!ret){ dbclose(); return false; }

	// Time stamp of last DB garbage collection
	ret = dbquery("INSERT INTO ftl (ID,VALUE) VALUES(2,%i);",time(NULL));
	if(!ret){ dbclose(); return false; }

	dbclose();

	return true;
}

void db_init(void)
{
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE, NULL);
	if( rc ){
		logg("Cannot open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);

		logg("Creating new (empty) database");
		if (!db_create())
		{
			logg("Database not available ");
			database = false;
			return;
		}
	}

	logg("Database initialized");
	database = true;
}

int db_get_FTL_property(unsigned int ID)
{
	int rc, ret = 0;
	sqlite3_stmt* dbstmt;
	char *querystring = NULL;

	// Prepare SQL statement
	ret = asprintf(&querystring, "SELECT VALUE FROM ftl WHERE id = %u;",ID);

	if(querystring == NULL || ret < 0)
	{
		logg("Memory allocation failed in db_get_FTL_property, not saving query with ID = %u (%i)", ID, ret);
		return false;
	}

	rc = sqlite3_prepare(db, querystring, -1, &dbstmt, NULL);
	if( rc ){
		printf("Cannot read from database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}
	free(querystring);

	// Evaluate SQL statement
	sqlite3_step(dbstmt);
	if( rc ){
		printf("Cannot evaluate in database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	int result = sqlite3_column_int(dbstmt, 0);

	sqlite3_finalize(dbstmt);

	return result;
}

bool db_set_FTL_property(unsigned int ID, int value)
{
	return dbquery("INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %i );", ID, value);
}

int number_of_queries_in_DB(void)
{
	sqlite3_stmt* stmt;
	int result = -1;

	// Count number of rows using the index timestamp is faster than select(*)
	sqlite3_prepare_v2(db, "SELECT COUNT(timestamp) FROM queries", -1, &stmt, NULL);
	int rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		result = sqlite3_column_int(stmt, 0);
	else
		logg("get_number_of_queries_in_DB() - SQL error: %s", sqlite3_errmsg(db));

	sqlite3_finalize(stmt);

	return result;
}

int get_number_of_queries_in_DB(void)
{
	int result = -1;

	if(!dbopen())
	{
		logg("Failed to open DB in get_number_of_queries_in_DB()");
		return -2;
	}

	result = number_of_queries_in_DB();

	// Close database
	dbclose();

	return result;
}

void *DB_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"DB",0,0,0);

	// Lock FTL's data structure, since it is likely that it will be changed here
	enable_thread_lock("DB_thread");

	if(!dbopen())
	{
		logg("Failed to open DB in thread");
		return NULL;
	}

	int lasttimestamp = db_get_FTL_property(DB_LASTTIMESTAMP);
	int newlasttimestamp = lasttimestamp;

	unsigned int saved = 0, saved_error = 0;
	long int i;
	sqlite3_stmt* stmt;

	sqlite3_prepare_v2(db, "INSERT INTO queries VALUES (NULL,?,?,?,?,?,?)", -1, &stmt, NULL);
	dbquery("BEGIN TRANSACTION");

	for(i = lastdbindex; i < counters.queries; i++)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(queries[i].timestamp <= lasttimestamp || queries[i].db == true)
		{
			// Already in database
			// logg("Skipping %i",i);
			continue;
		}

		// Memory checks
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);

		// TIMESTAMP
		sqlite3_bind_int(stmt, 1, queries[i].timestamp);

		// TYPE
		sqlite3_bind_int(stmt, 2, queries[i].type);

		// STATUS
		sqlite3_bind_int(stmt, 3, queries[i].status);

		// DOMAIN
		sqlite3_bind_text(stmt, 4, domains[queries[i].domainID].domain, -1, SQLITE_TRANSIENT);

		// CLIENT
		if(strlen(clients[queries[i].clientID].name) > 0)
			sqlite3_bind_text(stmt, 5, clients[queries[i].clientID].name, -1, SQLITE_TRANSIENT);
		else
			sqlite3_bind_text(stmt, 5, clients[queries[i].clientID].ip, -1, SQLITE_TRANSIENT);

		// FORWARD
		if(queries[i].forwardID > -1)
		{
			validate_access("forwarded", queries[i].forwardID, true, __LINE__, __FUNCTION__, __FILE__);
			sqlite3_bind_text(stmt, 6, forwarded[queries[i].forwardID].ip, -1, SQLITE_TRANSIENT);
		}
		else
		{
			sqlite3_bind_null(stmt, 6);
		}

		// Step and check if successful
		int rc = sqlite3_step(stmt);
		sqlite3_clear_bindings(stmt);
		sqlite3_reset(stmt);

		if( rc != SQLITE_DONE ){
			logg("DB thread - SQL error: %s", sqlite3_errmsg(db));
			saved_error++;
			continue;
		}

		saved++;
		// Mark this query as saved in the database only if successful
		queries[i].db = true;

		// Update lasttimestamp variable with timestamp of the latest stored query
		if(queries[i].timestamp > lasttimestamp)
			newlasttimestamp = queries[i].timestamp;
	}

	// Finish prepared statement
	dbquery("END TRANSACTION");
	sqlite3_finalize(stmt);

	// Store index for next loop interation round and update last time stamp
	// in the database only if all queries have been saved successfully
	if(saved_error == 0)
	{
		lastdbindex = i;
		db_set_FTL_property(DB_LASTTIMESTAMP, newlasttimestamp);
	}

	// Close database
	dbclose();

	if(debug)
	{
		if(saved > 0)
			logg("Notice: Queries stored in DB: %u", saved);
		if(saved_error > 0)
			logg("        Queries NOT stored in DB: %u (due to an error)", saved_error);
	}

	// Release thread lock
	disable_thread_lock("DB_thread");

	return NULL;
}

void *DB_GC_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"DB-GC",0,0,0);

	// Need no lock on FTL's data structure, so this can work
	// in parallel w/o affecting FTL's core responsibilities

	// Disable any other DB accesses while doing this
	database = false;

	if(!dbopen())
	{
		logg("Failed to open DB in GC thread");
		database = true;
		return NULL;
	}

	float factor = 1.0;
	while(get_db_filesize() > factor*config.maxDBfilesize)
	{
		// If we run the database size reduction, make sure we remove a sufficient number
		// of queries to go below 90% of the set maximum database file size
		factor = 0.9;
		logg("Notice: DB filesize is %.2f MB (%i rows), limit is %i.00 MB", get_db_filesize(), number_of_queries_in_DB(), config.maxDBfilesize);

		if(!dbquery("DELETE FROM queries WHERE id in ( SELECT id FROM queries ORDER BY timestamp ASC LIMIT 10000);"))
		{
			dbclose();
			logg("ERROR: Deleting queries due to exceeded filesize of database failed!");
			database = true;
			return NULL;
		}

		// When a large amount of data is deleted from the database file
		// it leaves behind empty space, or "free" database pages. This
		// means the database file might be larger than strictly necessary.
		// Running VACUUM to rebuild the database reclaims this space and
		// reduces the size of the database file.
		// Furthermore, running VACUUM ensures that each table and index is
		// largely stored contiguously within the database file. In some
		// cases, VACUUM may also reduce the number of partially filled pages
		// in the database, reducing the size of the database file further.
		dbquery("VACUUM");
	}
	// Print final message
	logg("Notice: DB filesize is %.2f MB (%i rows), limit is %i.00 MB", get_db_filesize(), number_of_queries_in_DB(), config.maxDBfilesize);

	// Close database
	dbclose();

	// Sleep one second so that we don't immediately re-launch the DB GC thread
	sleepms(1000);

	// Re-enable database actions
	database = true;
	return NULL;
}
