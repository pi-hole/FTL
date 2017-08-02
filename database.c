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
bool DBdeleteoldqueries = false;
long int lastdbindex = 0;

pthread_mutex_t dblock;

enum { DB_VERSION, DB_LASTTIMESTAMP };

void dbclose(void)
{
	sqlite3_close(db);
	pthread_mutex_unlock(&dblock);
}

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
	pthread_mutex_lock(&dblock);
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE, NULL);
	if( rc ){
		logg("dbopen() - SQL error (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();
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
	va_end(args);

	if(query == NULL)
	{
		logg("Memory allocation failed in dbquery()");
		return false;
	}

	if(debugDB)
		rc = sqlite3_exec(db, query, callback, NULL, &zErrMsg);
	else
		rc = sqlite3_exec(db, query, NULL, NULL, &zErrMsg);

	if( rc != SQLITE_OK ){
		logg("dbquery(%s) - SQL error (%i): %s", query, rc, zErrMsg);
		sqlite3_free(zErrMsg);
		return false;
	}

	sqlite3_free(query);

	return true;

}

bool db_create(void)
{
	bool ret;
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if( rc ){
		logg("db_create() - SQL error (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();
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
		logg("db_init() - Cannot open database (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();

		logg("Creating new (empty) database");
		if (!db_create())
		{
			logg("Database not available");
			database = false;
			return;
		}
	}

	if (pthread_mutex_init(&dblock, NULL) != 0)
	{
		logg("FATAL: DB mutex init failed\n");
		// Return failure
		exit(EXIT_FAILURE);
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
		logg("db_get_FTL_property() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();
		return -1;
	}
	free(querystring);

	// Evaluate SQL statement
	rc = sqlite3_step(dbstmt);
	if( rc != SQLITE_ROW ){
		logg("db_get_FTL_property() - SQL error step (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();
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

	// Count number of rows using the index timestamp is faster than select(*)
	int rc = sqlite3_prepare_v2(db, "SELECT COUNT(timestamp) FROM queries", -1, &stmt, NULL);
	if( rc ){
		logg("number_of_queries_in_DB() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();
		return -1;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW ){
		logg("number_of_queries_in_DB() - SQL error step (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();
		return -1;
	}

	int result = sqlite3_column_int(stmt, 0);

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

void save_to_DB(void)
{
	// Open database
	if(!dbopen())
	{
		logg("save_to_DB() - failed to open DB");
		return;
	}

	int lasttimestamp = db_get_FTL_property(DB_LASTTIMESTAMP);
	if(lasttimestamp < 0)
	{
		logg("save_to_DB() - error in trying to get last time stamp from database");
		return;
	}
	int newlasttimestamp = lasttimestamp;

	unsigned int saved = 0, saved_error = 0;
	long int i;
	sqlite3_stmt* stmt;

	bool ret = dbquery("BEGIN TRANSACTION");
	if(!ret)
	{
		logg("save_to_DB() - unable to begin transaction (%i): %s", ret, sqlite3_errmsg(db));
		dbclose();
		return;
	}

	int rc = sqlite3_prepare_v2(db, "INSERT INTO queries VALUES (NULL,?,?,?,?,?,?)", -1, &stmt, NULL);
	if( rc )
	{
		logg("save_to_DB() - error in preparing SQL statement (%i): %s", ret, sqlite3_errmsg(db));
		dbclose();
		return;
	}

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
		rc = sqlite3_step(stmt);
		sqlite3_clear_bindings(stmt);
		sqlite3_reset(stmt);

		if( rc != SQLITE_DONE ){
			logg("save_to_DB() - SQL error (%i): %s", rc, sqlite3_errmsg(db));
			saved_error++;
			if(saved_error < 3)
			{
				continue;
			}
			else
			{
				logg("save_to_DB() - exiting due to too many errors");
				break;
			}
		}

		saved++;
		// Mark this query as saved in the database only if successful
		queries[i].db = true;

		// Update lasttimestamp variable with timestamp of the latest stored query
		if(queries[i].timestamp > lasttimestamp)
			newlasttimestamp = queries[i].timestamp;
	}

	// Finish prepared statement
	ret = dbquery("END TRANSACTION");
	if(!ret){ dbclose(); return; }
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
		logg("Notice: Queries stored in DB: %u", saved);
		if(saved_error > 0)
			logg("        There are queries that have not been saved", saved_error);
	}
}

void delete_old_queries_in_DB(void)
{
	// Open database
	if(!dbopen())
	{
		logg("Failed to open DB in delete_old_queries_in_DB()");
		return;
	}

	int timestamp = time(NULL) - config.maxDBdays * 86400;

	if(!dbquery("DELETE FROM queries WHERE timestamp <= %i", timestamp))
	{
		dbclose();
		logg("delete_old_queries_in_DB(): Deleting queries due to age of entries failed!");
		database = true;
		return;
	}

	// Get how many rows have been affected (deleted)
	int affected = sqlite3_changes(db);

	// Print final message only if there is a difference
	if(debug || affected)
		logg("Notice: Database size is %.2f MB, deleted %i rows", get_db_filesize(), affected);

	// Close database
	dbclose();

	// Re-enable database actions
	database = true;
}

void *DB_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"DB",0,0,0);

	if(!DBdeleteoldqueries)
	{
		// Lock FTL's data structure, since it is likely that it will be changed here
		enable_thread_lock("DB_thread");

		// Save data to database
		save_to_DB();

		// Release thread lock
		disable_thread_lock("DB_thread");
	}
	else
	{
		// No thread locks needed
		delete_old_queries_in_DB();
		DBdeleteoldqueries = false;
	}

	return NULL;
}
