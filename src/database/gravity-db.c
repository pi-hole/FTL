/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "gravity-db.h"
#include "config.h"
#include "log.h"
// global variable counters
#include "memory.h"
#include "sqlite3.h"

// Private variables
static sqlite3 *gravity_db = NULL;
static sqlite3_stmt* table_stmt = NULL;
static sqlite3_stmt* whitelist_stmt = NULL;
static sqlite3_stmt* audit_stmt = NULL;
bool gravity_database_avail = false;

// Prototypes from functions in dnsmasq's source
void rehash(int size);

// Open gravity database
bool gravityDB_open(void)
{
	struct stat st;
	if(stat(FTLfiles.gravity_db, &st) != 0)
	{
		// File does not exist
		logg("gravityDB_open(): %s does not exist", FTLfiles.gravity_db);
		return false;
	}

	int rc = sqlite3_open_v2(FTLfiles.gravity_db, &gravity_db, SQLITE_OPEN_READONLY, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open() - SQL error (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}

	// Tell SQLite3 to store temporary tables in memory. This speeds up read operations on
	// temporary tables, indices, and views.
	char *zErrMsg = NULL;
	rc = sqlite3_exec(gravity_db, "PRAGMA temp_store = MEMORY", NULL, NULL, &zErrMsg);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(PRAGMA temp_store) - SQL error (%i): %s", rc, zErrMsg);
		sqlite3_free(zErrMsg);
		gravityDB_close();
		return false;
	}

	// Prepare whitelist statement
	// We use SELECT EXISTS() as this is known to efficiently use the index
	// We are only interested in whether the domain exists or not in the
	// list but don't case about duplicates or similar. SELECT EXISTS(...)
	// returns true as soon as it sees the first row from the query inside
	// of EXISTS().
	rc = sqlite3_prepare_v2(gravity_db, "SELECT EXISTS(SELECT domain from vw_whitelist WHERE domain = ?);", -1, &whitelist_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT EXISTS(... vw_whitelist ...)\") - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}

	// Prepare audit statement
	rc = sqlite3_prepare_v2(gravity_db, "SELECT EXISTS(SELECT domain from auditlist WHERE domain = ?);", -1, &audit_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT EXISTS(... audit ...)\") - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}

	// Database connection is now open
	gravity_database_avail = true;
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Successfully opened gravity.db");

	return true;
}

void gravityDB_close(void)
{
	// Return early if gravity database is not available
	if(!gravity_database_avail)
		return;

	// Finalize whitelist scanning statement
	sqlite3_finalize(whitelist_stmt);

	// Finalize audit scanning statement
	sqlite3_finalize(audit_stmt);

	// Close table
	sqlite3_close(gravity_db);
	gravity_database_avail = false;
}

// Prepare a SQLite3 statement which can be used by
// gravityDB_getDomain() to get blocking domains from
// a table which is specified when calling this function
bool gravityDB_getTable(const unsigned char list)
{
	if(!gravity_database_avail)
	{
		logg("gravityDB_getTable(%d): Gravity database not available", list);
		return false;
	}

	// Select correct query string to be used depending on list to be read
	const char *querystr = NULL;
	switch(list)
	{
		case GRAVITY_LIST:
			querystr = "SELECT domain FROM vw_gravity;";
			break;
		case BLACK_LIST:
			querystr = "SELECT domain FROM vw_blacklist;";
			break;
		case REGEX_LIST:
			querystr = "SELECT domain FROM vw_regex;";
			break;
		default:
			logg("gravityDB_getTable(%i): Requested list is not known!", list);
			return false;
	}

	// Prepare SQLite3 statement
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if( rc )
	{
		logg("readGravity(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}

	return true;
}

// Get a single domain from a running SELECT operation
// This function returns a pointer to a string as long
// as there are domains available. Once we reached the
// end of the table, it returns NULL. It also returns
// NULL when it encounters an error (e.g., on reading
// errors). Errors are logged to pihole-FTL.log
// This function is performance critical as it might
// be called millions of times for large blocking lists
inline const char* gravityDB_getDomain(void)
{
	// Perform step
	const int rc = sqlite3_step(table_stmt);

	// Valid row
	if(rc == SQLITE_ROW)
	{
		const char* domain = (char*)sqlite3_column_text(table_stmt, 0);
		return domain;
	}

	// Check for error. An error happened when the result is neither
	// SQLITE_ROW (we returned earlier in this case), nor
	// SQLITE_DONE (we are finished reading the table)
	if(rc != SQLITE_DONE)
	{
		logg("gravityDB_getDomain() - SQL error step (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_finalizeTable();
		return NULL;
	}

	// Finished reading, nothing to get here
	return NULL;
}

// Finalize statement of a gravity database transaction
void gravityDB_finalizeTable(void)
{
	if(!gravity_database_avail)
		return;

	// Finalize statement
	sqlite3_finalize(table_stmt);
}

// Get number of domains in a specified table of the gravity database
// We return the constant DB_FAILED and log to pihole-FTL.log if we
// encounter any error
int gravityDB_count(const unsigned char list)
{
	if(!gravity_database_avail)
	{
		logg("gravityDB_count(%d): Gravity database not available", list);
		return DB_FAILED;
	}

	// Select correct query string to be used depending on list to be read
	const char* querystr = NULL;
	switch(list)
	{
		case GRAVITY_LIST:
			querystr = "SELECT COUNT(*) FROM vw_gravity;";
			break;
		case BLACK_LIST:
			querystr = "SELECT COUNT(*) FROM vw_blacklist;";
			break;
		case WHITE_LIST:
			querystr = "SELECT COUNT(*) FROM vw_whitelist;";
			break;
		case REGEX_LIST:
			querystr = "SELECT COUNT(*) FROM vw_regex;";
			break;
		default:
			logg("gravityDB_count(%i): Requested list is not known!", list);
			return DB_FAILED;
	}

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if( rc ){
		logg("gravityDB_count(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(gravity_db));
		sqlite3_finalize(table_stmt);
		gravityDB_close();
		return DB_FAILED;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	if( rc != SQLITE_ROW ){
		logg("gravityDB_count(%s) - SQL error step (%i): %s", querystr, rc, sqlite3_errmsg(gravity_db));
		sqlite3_finalize(table_stmt);
		gravityDB_close();
		return DB_FAILED;
	}

	// Get result when there was no error
	const int result = sqlite3_column_int(table_stmt, 0);

	// Finalize statement
	gravityDB_finalizeTable();

	return result;
}

static bool domain_in_list(const char *domain, sqlite3_stmt* stmt)
{
	int retval;
	// Bind domain to prepared statement
	// SQLITE_STATIC: Use the string without first duplicating it internally.
	// We can do this as domain has dynamic scope that exceeds that of the binding.
	if((retval = sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("domain_in_list(\"%s\"): Failed to bind domain (error %d) - %s",
		     domain, retval, sqlite3_errmsg(gravity_db));
		sqlite3_reset(stmt);
		return false;
	}

	// Perform step
	retval = sqlite3_step(stmt);
	if(retval == SQLITE_BUSY)
	{
		// Database is busy
		logg("domain_in_list(\"%s\"): Database is busy, assuming domain is NOT on list",
		     domain);
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return false;
	}
	else if(retval != SQLITE_ROW)
	{
		// Any return code that is neither SQLITE_BUSY not SQLITE_ROW
		// is a real error we should log
		logg("domain_in_list(\"%s\"): Failed to perform step (error %d) - %s",
		     domain, retval, sqlite3_errmsg(gravity_db));
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return false;
	}

	// Get result of query "SELECT EXISTS(...)"
	const int result = sqlite3_column_int(stmt, 0);

	if(config.debug & DEBUG_DATABASE)
		logg("domain_in_list(\"%s\"): %d", domain, result);

	// The sqlite3_reset() function is called to reset a prepared
	// statement object back to its initial state, ready to be
	// re-executed. Note: Any SQL statement variables that had values
	// bound to them using the sqlite3_bind_*() API retain their values.
	sqlite3_reset(stmt);

	// Contrary to the intuition of many, sqlite3_reset() does not reset
	// the bindings on a prepared statement. Use this routine to reset
	// all host parameters to NULL.
	sqlite3_clear_bindings(stmt);

	// Return result.
	// SELECT EXISTS(...) either returns 0 (false) or 1 (true).
	return result == 1;
}

bool in_whitelist(const char *domain)
{
	return domain_in_list(domain, whitelist_stmt);
}

bool in_auditlist(const char *domain)
{
	return domain_in_list(domain, audit_stmt);
}

