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
#include "shmem.h"
#include "sqlite3.h"

static sqlite3 *db;
bool database = false;
bool DBdeleteoldqueries = false;
long int lastdbindex = 0;

static pthread_mutex_t dblock;

static bool db_set_counter(const unsigned int ID, const int value);
static int db_get_FTL_property(const unsigned int ID);

// defined in networktable.c
extern bool unify_hwaddr(sqlite3 *db);

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
	int rc = sqlite3_close(db);
	// Report any error
	if( rc != SQLITE_OK )
	{
		logg("dbclose() - SQL error (%i): %s", rc, sqlite3_errmsg(db));
	}

	// Unlock mutex on the database
	pthread_mutex_unlock(&dblock);
}

static double get_db_filesize(void)
{
	struct stat st;
	if(stat(FTLfiles.db, &st) != 0)
	{
		// stat() failed (maybe the DB file does not exist?)
		return 0;
	}
	return 1e-6*st.st_size;
}

static bool file_exists(const char *filename)
{
	struct stat st;
	return stat(filename, &st) == 0;
}

bool dbopen(void)
{
	pthread_mutex_lock(&dblock);
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK ){
		logg("dbopen() - SQL error (%i): %s", rc, sqlite3_errmsg(db));
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
		logg("dbquery: \"%s\"", query);

	int rc = sqlite3_exec(db, query, NULL, NULL, &zErrMsg);

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
	if(!db_set_counter(DB_TOTALQUERIES, 0)){ dbclose(); return false; }

	// ID 1 = total blocked queries
	if(!db_set_counter(DB_BLOCKEDQUERIES, 0)){ dbclose(); return false; }

	// Time stamp of creation of the counters database
	if(!db_set_FTL_property(DB_FIRSTCOUNTERTIMESTAMP, time(NULL))){ dbclose(); return false; }

	// Update database version to 2
	if(!db_set_FTL_property(DB_VERSION, 2)){ dbclose(); return false; }

	return true;
}

static bool db_create(void)
{
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if( rc != SQLITE_OK ){
		logg("db_create() - SQL error (%i): %s", rc, sqlite3_errmsg(db));
		check_database(rc);
		return false;
	}
	// Create Queries table in the database
	SQL_bool("CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );");

	// Add an index on the timestamps (not a unique index!)
	SQL_bool("CREATE INDEX idx_queries_timestamps ON queries (timestamp);");

	// Create FTL table in the database (holds properties like database version, etc.)
	SQL_bool("CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );");

	// Set DB version 1
	if(!dbquery("INSERT INTO ftl (ID,VALUE) VALUES(%i,1);", DB_VERSION))
		return false;

	// Most recent timestamp initialized to 00:00 1 Jan 1970
	if(!dbquery("INSERT INTO ftl (ID,VALUE) VALUES(%i,0);", DB_LASTTIMESTAMP))
		return false;

	// Create counter table
	// Will update DB version to 2
	if(!create_counter_table())
		return false;

	// Create network table
	// Will update DB version to 3
	if(!create_network_table())
		return false;

	// Done initializing the database
	// Close database handle
	dbclose();

	// Explicitly set permissions to 0644
	// 644 =            u+w       u+r       g+r       o+r
	const mode_t mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;
	chmod_file(FTLfiles.db, mode);

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
	if(FTLfiles.db == NULL || strlen(FTLfiles.db) == 0)
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
	if(!file_exists(FTLfiles.db))
	{
		logg("No database file found, creating new (empty) database");
		if (!db_create())
		{
			logg("Creation of database failed, database is not available");
			database = false;
			return;
		}
	}

	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE, NULL);
	if( rc ){
		logg("db_init() - Cannot open database (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();

		database = false;
		return;
	}

	// Test DB version and see if we need to upgrade the database file
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
		unify_hwaddr(db);
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
	sqlite3_close(db);

	if (pthread_mutex_init(&dblock, NULL) != 0)
	{
		logg("FATAL: DB mutex init failed\n");
		// Return failure
		exit(EXIT_FAILURE);
	}

	logg("Database successfully initialized");
	database = true;
}

static int db_get_FTL_property(const unsigned int ID)
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

static bool db_set_counter(const unsigned int ID, const int value)
{
	return dbquery("INSERT OR REPLACE INTO counters (id, value) VALUES ( %u, %i );", ID, value);
}

static bool db_update_counters(const int total, const int blocked)
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
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("db_query_int(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(db));
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
		logg("db_query_int(%s) - SQL error step (%i): %s", querystr, rc, sqlite3_errmsg(db));
		check_database(rc);
		return DB_FAILED;
	}

	sqlite3_finalize(stmt);

	return result;
}

static int number_of_queries_in_DB(void)
{
	sqlite3_stmt* stmt;

	// Count number of rows using the index timestamp is faster than select(*)
	int rc = sqlite3_prepare_v2(db, "SELECT COUNT(timestamp) FROM queries", -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("number_of_queries_in_DB() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(db));
		check_database(rc);
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW ){
		logg("number_of_queries_in_DB() - SQL error step (%i): %s", rc, sqlite3_errmsg(db));
		check_database(rc);
		return DB_FAILED;
	}

	int result = sqlite3_column_int(stmt, 0);

	sqlite3_finalize(stmt);

	return result;
}

static sqlite3_int64 last_ID_in_DB(void)
{
	sqlite3_stmt* stmt;

	int rc = sqlite3_prepare_v2(db, "SELECT MAX(ID) FROM queries", -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("last_ID_in_DB() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(db));
		check_database(rc);
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW ){
		logg("last_ID_in_DB() - SQL error step (%i): %s", rc, sqlite3_errmsg(db));
		check_database(rc);
		return DB_FAILED;
	}

	sqlite3_int64 result = sqlite3_column_int64(stmt, 0);

	sqlite3_finalize(stmt);

	return result;
}

int get_number_of_queries_in_DB(void)
{
	int result = DB_NODATA;

	if(!dbopen())
	{
		logg("Failed to open DB in get_number_of_queries_in_DB()");
		return DB_FAILED;
	}

	result = number_of_queries_in_DB();

	// Close database
	dbclose();

	return result;
}

void save_to_DB(void)
{
	// Don't save anything to the database if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Start database timer
	if(config.debug & DEBUG_DATABASE) timer_start(DATABASE_WRITE_TIMER);

	// Open database
	if(!dbopen())
	{
		logg("save_to_DB() - failed to open DB");
		return;
	}

	unsigned int saved = 0, saved_error = 0;
	sqlite3_stmt* stmt = NULL;

	// Get last ID stored in the database
	sqlite3_int64 lastID = last_ID_in_DB();

	SQL_void("BEGIN TRANSACTION");

	int rc = sqlite3_prepare_v2(db, "INSERT INTO queries VALUES (NULL,?,?,?,?,?,?)", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("save_to_DB() - error in preparing SQL statement (%i): %s", rc, sqlite3_errmsg(db));
		check_database(rc);
		return;
	}

	int total = 0, blocked = 0;
	time_t currenttimestamp = time(NULL);
	time_t newlasttimestamp = 0;
	long int queryID;
	for(queryID = MAX(0, lastdbindex); queryID < counters->queries; queryID++)
	{
		queriesData* query = getQuery(queryID, true);
		if(query->db != 0)
		{
			// Skip, already saved in database
			continue;
		}

		if(!query->complete && query->timestamp > currenttimestamp-2)
		{
			// Break if a brand new query (age < 2 seconds) is not yet completed
			// giving it a chance to be stored next time
			break;
		}

		if(query->privacylevel >= PRIVACY_MAXIMUM)
		{
			// Skip, we never store nor count queries recorded
			// while have been in maximum privacy mode in the database
			continue;
		}

		// TIMESTAMP
		sqlite3_bind_int(stmt, 1, query->timestamp);

		// TYPE
		sqlite3_bind_int(stmt, 2, query->type);

		// STATUS
		sqlite3_bind_int(stmt, 3, query->status);

		// DOMAIN
		const char *domain = getDomainString(queryID);
		sqlite3_bind_text(stmt, 4, domain, -1, SQLITE_STATIC);

		// CLIENT
		const char *client = getClientIPString(queryID);
		sqlite3_bind_text(stmt, 5, client, -1, SQLITE_STATIC);

		// FORWARD
		if(query->status == QUERY_FORWARDED && query->forwardID > -1)
		{
			// Get forward pointer
			const forwardedData* forward = getForward(query->forwardID, true);
			sqlite3_bind_text(stmt, 6, getstr(forward->ippos), -1, SQLITE_STATIC);
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
			// Check this error message
			check_database(rc);
		}

		saved++;
		// Mark this query as saved in the database by setting the corresponding ID
		query->db = ++lastID;

		// Total counter information (delta computation)
		total++;
		if(query->status == QUERY_GRAVITY ||
		   query->status == QUERY_BLACKLIST ||
		   query->status == QUERY_WILDCARD ||
		   query->status == QUERY_EXTERNAL_BLOCKED_IP ||
		   query->status == QUERY_EXTERNAL_BLOCKED_NULL ||
		   query->status == QUERY_EXTERNAL_BLOCKED_NXRA)
			blocked++;

		// Update lasttimestamp variable with timestamp of the latest stored query
		if(query->timestamp > newlasttimestamp)
			newlasttimestamp = query->timestamp;
	}

	// Finish prepared statement
	SQL_void("END TRANSACTION");
	int ret2 = sqlite3_finalize(stmt);
	if(ret2 != SQLITE_OK){ dbclose(); return; }

	// Store index for next loop interation round and update last time stamp
	// in the database only if all queries have been saved successfully
	if(saved > 0 && saved_error == 0)
	{
		lastdbindex = queryID;
		db_set_FTL_property(DB_LASTTIMESTAMP, newlasttimestamp);
	}

	// Update total counters in DB
	if(saved > 0 && !db_update_counters(total, blocked))
	{
		dbclose();
		return;
	}

	// Close database
	dbclose();

	if(config.debug & DEBUG_DATABASE)
	{
		logg("Notice: Queries stored in DB: %u (took %.1f ms, last SQLite ID %llu)", saved, timer_elapsed_msec(DATABASE_WRITE_TIMER), lastID);
		if(saved_error > 0)
			logg("        There are queries that have not been saved");
	}
}

static void delete_old_queries_in_DB(void)
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
		logg("delete_old_queries_in_DB(): Deleting queries due to age of entries failed!");
		return;
	}

	// Get how many rows have been affected (deleted)
	const int affected = sqlite3_changes(db);

	// Print final message only if there is a difference
	if((config.debug & DEBUG_DATABASE) || affected)
		logg("Notice: Database size is %.2f MB, deleted %i rows", get_db_filesize(), affected);

	// Close database
	dbclose();

	// Re-enable database actions
	database = true;
}

int lastDBsave = 0;
void *DB_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"database",0,0,0);

	// Save timestamp as we do not want to store immediately
	// to the database
	lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

	while(!killed && database)
	{
		if(time(NULL) - lastDBsave >= config.DBinterval)
		{
			// Update lastDBsave timer
			lastDBsave = time(NULL) - time(NULL)%config.DBinterval;

			// Lock FTL's data structures, since it is
			// likely that they will be changed here
			lock_shm();

			// Save data to database
			save_to_DB();

			// Release data lock
			unlock_shm();

			// Check if GC should be done on the database
			if(DBdeleteoldqueries)
			{
				// No thread locks needed
				delete_old_queries_in_DB();
				DBdeleteoldqueries = false;
			}

			// Parse neighbor cache (fill network table) if enabled
			if (config.parse_arp_cache)
				parse_neighbor_cache();
		}
		sleepms(100);
	}

	return NULL;
}

// Get most recent 24 hours data from long-term database
void read_data_from_DB(void)
{
	// Don't try to load anything to the database if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Open database file
	if(!dbopen())
	{
		logg("read_data_from_DB() - Failed to open DB");
		return;
	}

	// Prepare request
	char *rstr = NULL;
	// Get time stamp 24 hours in the past
	const time_t now = time(NULL);
	const time_t mintime = now - config.maxlogage;
	int rc = asprintf(&rstr, "SELECT * FROM queries WHERE timestamp >= %li", mintime);
	if(rc < 1)
	{
		logg("read_data_from_DB() - Allocation error (%i): %s", rc, sqlite3_errmsg(db));
		return;
	}
	// Log DB query string in debug mode
	if(config.debug & DEBUG_DATABASE) logg("%s", rstr);

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	rc = sqlite3_prepare_v2(db, rstr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("read_data_from_DB() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(db));
		check_database(rc);
		return;
	}

	// Loop through returned database rows
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const sqlite3_int64 dbid = sqlite3_column_int64(stmt, 0);
		const time_t queryTimeStamp = sqlite3_column_int(stmt, 1);
		// 1483228800 = 01/01/2017 @ 12:00am (UTC)
		if(queryTimeStamp < 1483228800)
		{
			logg("DB warn: TIMESTAMP should be larger than 01/01/2017 but is %li", queryTimeStamp);
			continue;
		}
		if(queryTimeStamp > now)
		{
			if(config.debug & DEBUG_DATABASE) logg("DB warn: Skipping query logged in the future (%li)", queryTimeStamp);
			continue;
		}

		const int type = sqlite3_column_int(stmt, 2);
		if(type < TYPE_A || type >= TYPE_MAX)
		{
			logg("DB warn: TYPE should not be %i", type);
			continue;
		}
		// Don't import AAAA queries from database if the user set
		// AAAA_QUERY_ANALYSIS=no in pihole-FTL.conf
		if(type == TYPE_AAAA && !config.analyze_AAAA)
		{
			continue;
		}

		const int status = sqlite3_column_int(stmt, 3);
		if(status < QUERY_UNKNOWN || status > QUERY_EXTERNAL_BLOCKED_NXRA)
		{
			logg("DB warn: STATUS should be within [%i,%i] but is %i", QUERY_UNKNOWN, QUERY_EXTERNAL_BLOCKED_NXRA, status);
			continue;
		}

		const char * domainname = (const char *)sqlite3_column_text(stmt, 4);
		if(domainname == NULL)
		{
			logg("DB warn: DOMAIN should never be NULL, %li", queryTimeStamp);
			continue;
		}

		const char * clientIP = (const char *)sqlite3_column_text(stmt, 5);
		if(clientIP == NULL)
		{
			logg("DB warn: CLIENT should never be NULL, %li", queryTimeStamp);
			continue;
		}

		// Check if user wants to skip queries coming from localhost
		if(config.ignore_localhost &&
		   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
		{
			continue;
		}

		const char *forwarddest = (const char *)sqlite3_column_text(stmt, 6);
		int forwardID = 0;
		// Determine forwardID only when status == 2 (forwarded) as the
		// field need not to be filled for other query status types
		if(status == QUERY_FORWARDED)
		{
			if(forwarddest == NULL)
			{
				logg("DB warn: FORWARD should not be NULL with status QUERY_FORWARDED, %li", queryTimeStamp);
				continue;
			}
			forwardID = findForwardID(forwarddest, true);
		}

		// Obtain IDs only after filtering which queries we want to keep
		const int timeidx = getOverTimeID(queryTimeStamp);
		const int domainID = findDomainID(domainname);
		const int clientID = findClientID(clientIP, true);

		// Ensure we have enough space in the queries struct
		memory_check(QUERIES);

		// Set index for this query
		const int queryIndex = counters->queries;

		// Store this query in memory
		queriesData* query = getQuery(queryIndex, false);
		query->magic = MAGICBYTE;
		query->timestamp = queryTimeStamp;
		query->type = type;
		query->status = status;
		query->domainID = domainID;
		query->clientID = clientID;
		query->forwardID = forwardID;
		query->timeidx = timeidx;
		query->db = dbid;
		query->id = 0;
		query->complete = true; // Mark as all information is available
		query->response = 0;
		query->dnssec = DNSSEC_UNKNOWN;
		query->reply = REPLY_UNKNOWN;

		// Set lastQuery timer and add one query for network table
		clientsData* client = getClient(clientID, true);
		client->lastQuery = queryTimeStamp;
		client->numQueriesARP++;

		// Handle type counters
		if(type >= TYPE_A && type < TYPE_MAX)
		{
			counters->querytype[type-1]++;
			overTime[timeidx].querytypedata[type-1]++;
		}

		// Update overTime data
		overTime[timeidx].total++;
		// Update overTime data structure with the new client
		client->overTime[timeidx]++;

		// Increase DNS queries counter
		counters->queries++;

		// Increment status counters
		switch(status)
		{
			case QUERY_UNKNOWN: // Unknown
				counters->unknown++;
				break;

			case QUERY_GRAVITY: // Blocked by gravity.list
			case QUERY_WILDCARD: // Blocked by regex filter
			case QUERY_BLACKLIST: // Blocked by black.list
			case QUERY_EXTERNAL_BLOCKED_IP: // Blocked by external provider
			case QUERY_EXTERNAL_BLOCKED_NULL: // Blocked by external provider
			case QUERY_EXTERNAL_BLOCKED_NXRA: // Blocked by external provider
				counters->blocked++;
				// Get domain pointer
				domainsData* domain = getDomain(domainID, true);
				domain->blockedcount++;
				client->blockedcount++;
				// Update overTime data structure
				overTime[timeidx].blocked++;
				break;

			case QUERY_FORWARDED: // Forwarded
				counters->forwardedqueries++;
				// Update overTime data structure
				overTime[timeidx].forwarded++;
				break;

			case QUERY_CACHE: // Cached or local config
				counters->cached++;
				// Update overTime data structure
				overTime[timeidx].cached++;
				break;

			default:
				logg("Error: Found unknown status %i in long term database!", status);
				logg("       Timestamp: %li", queryTimeStamp);
				logg("       Continuing anyway...");
				break;
		}
	}
	logg("Imported %i queries from the long-term database", counters->queries);

	// Update lastdbindex so that the next call to save_to_DB()
	// skips the queries that we just imported from the database
	lastdbindex = counters->queries;

	if( rc != SQLITE_DONE ){
		logg("read_data_from_DB() - SQL error step (%i): %s", rc, sqlite3_errmsg(db));
		dbclose();
		check_database(rc);
		return;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);
	dbclose();
	free(rstr);
}

// Returns ID of the most recent successful INSERT.
long db_lastID(void)
{
	long id = sqlite3_last_insert_rowid(db);
	if(config.debug & DEBUG_DATABASE)
		logg("db_lastID(): %ld", id);
	return id;
}
