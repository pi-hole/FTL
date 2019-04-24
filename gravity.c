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
#include <sqlite3.h>

// Private variables
static sqlite3 *gravitydb = NULL;
static sqlite3_stmt* stmt = NULL;

// Prototypes from functions in dnsmasq's source
void rehash(int size);

static bool gravityDB_open(void)
{
	struct stat st;
	if(stat(FTLfiles.gravitydb, &st) != 0)
	{
		// File does not exist
		logg("readGravity(): %s does not exist", FTLfiles.gravitydb);
		return false;
	}

	int rc = sqlite3_open_v2(FTLfiles.gravitydb, &gravitydb, SQLITE_OPEN_READONLY, NULL);
	if( rc ){
		logg("readGravity() - SQL error (%i): %s", rc, sqlite3_errmsg(gravitydb));
		sqlite3_close(gravitydb);
		return false;
	}

	// Tell SQLite3 to store temporary tables in memory. This speeds up read operations on
	// temporary tables, indices, and views.
	char *zErrMsg = NULL;
	rc = sqlite3_exec(gravitydb, "PRAGMA temp_store = MEMORY", NULL, NULL, &zErrMsg);
	if( rc != SQLITE_OK ){
		logg("readGravity(PRAGMA temp_store) - SQL error (%i): %s", rc, zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(gravitydb);
		return false;
	}

	return true;
}

static void gravityDB_close(void)
{
	// Close database handle
	sqlite3_close(gravitydb);
}

bool gravityDB_getTable(const unsigned char list)
{
	// Open gravity database, fail is not possible
	// Possible if the database has not yet been created by gravity
	if(!gravityDB_open())
		return false;

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
		case WHITE_LIST:
			querystr = "SELECT domain FROM vw_whitelist;";
			break;
		case REGEX_LIST:
			querystr = "SELECT filter FROM vw_regex;";
			break;
		default:
			logg("gravityDB_getTable(%i): Requested list is not known!", list);
			return false;
	}

	// Prepare SQLite3 statement
	int rc = sqlite3_prepare_v2(gravitydb, querystr, -1, &stmt, NULL);
	if( rc ){
		logg("readGravity(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(gravitydb));
		sqlite3_close(gravitydb);
		return false;
	}

	return true;
}

inline const char* gravityDB_getDomain(void)
{
	// Perform step
	const int rc = sqlite3_step(stmt);

	// Valid row
	if(rc == SQLITE_ROW)
	{
		const char* domain = (char*)sqlite3_column_text(stmt, 0);
		return domain;
	}

	// Check for error. An error happened when the result is neither
	// SQLITE_ROW (we returned earlier in this case), nor
	// SQLITE_DONE (we are finished reading the table)
	if(rc != SQLITE_DONE)
	{
		logg("gravityDB_getDomain() - SQL error step (%i): %s", rc, sqlite3_errmsg(gravitydb));
		sqlite3_finalize(stmt);
		sqlite3_close(gravitydb);
		return NULL;
	}

	// Finished reading, nothing to get here
	return NULL;
}

void gravityDB_finalizeTable(void)
{
	// Finalize statement
	sqlite3_finalize(stmt);

	// Close database handle
	gravityDB_close();
}

int gravityDB_count(const unsigned char list)
{
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

	// Open database handle
	if(!gravityDB_open())
		return DB_FAILED;

	// Prepare query
	int rc = sqlite3_prepare_v2(gravitydb, querystr, -1, &stmt, NULL);
	if( rc ){
		logg("gravityDB_count(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(gravitydb));
		sqlite3_finalize(stmt);
		sqlite3_close(gravitydb);
		return DB_FAILED;
	}

	// Perform query
	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW ){
		logg("gravityDB_count(%s) - SQL error step (%i): %s", querystr, rc, sqlite3_errmsg(gravitydb));
		sqlite3_finalize(stmt);
		sqlite3_close(gravitydb);
		return DB_FAILED;
	}

	// Get result when there was no error
	const int result = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);

	gravityDB_close();

	return result;
}
