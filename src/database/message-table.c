/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Message table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "database/message-table.h"
#include "database/common.h"
#include "log.h"
// #include "shmem.h"
// #include "memory.h"
// #include "timers.h"
// #include "config.h"
// #include "datastructure.h"

// Create message table in the database
bool create_message_table(void)
{
	SQL_bool("CREATE TABLE message ( id INTEGER PRIMARY KEY AUTOINCREMENT, " \
	                                "timestamp INTEGER NOT NULL, " \
	                                "type TEXT NOT NULL, " \
	                                "message TEXT NOT NULL, " \
	                                "txt TEXT, "
	                                "int INTEGER );");

	// Update database version to 6
	if(!db_set_FTL_property(DB_VERSION, 6))
	{
		logg("create_message_table(): Failed to update database version!");
		return false;
	}

	return true;
}

// Flush message table
bool flush_message_table(void)
{
	SQL_bool("DELETE FROM message;");
	return true;
}

static bool add_message(enum message_type type, const char *message, const char *text, const int integer)
{
	// Prepare SQLite statement
	sqlite3_stmt* stmt = NULL;
	const char *querystr = "INSERT INTO message (timestamp, type, message, txt, int) VALUES ((cast(strftime('%%s', 'now') as int)),?,?,?,?);";
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("add_message(type=%u, message=%s, text=%s, integer=%i) - SQL error prepare: %s",
		     type, message, text, integer, sqlite3_errstr(rc));
		return false;
	}

	// Bind type to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, type)) != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s, text=%s, integer=%i) - Failed to bind type: %s",
		     type, message, text, integer, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind message to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s, text=%s, integer=%i) - Failed to bind message: %s",
		     type, message, text, integer, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind text to prepared statement
	if(text != NULL)
		rc = sqlite3_bind_text(stmt, 3, text, -1, SQLITE_STATIC);
	else
		rc = sqlite3_bind_null(stmt, 3);

	if(rc != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s, text=%s, integer=%i) - Failed to bind text: %s",
		     type, message, text, integer, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind integer to prepared statement
	if(integer != -1)
		rc = sqlite3_bind_int(stmt, 4, integer);
	else
		rc = sqlite3_bind_null(stmt, 4);

	if(rc != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s, text=%s, integer=%i) - Failed to bind integer: %s",
		     type, message, text, integer, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Step and check if successful
	rc = sqlite3_step(stmt);
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);

	if(rc != SQLITE_DONE)
	{
		logg("Encountered error while trying to store message in long-term database: %s", sqlite3_errstr(rc));
		return false;
	}

	return true;
}

void logg_regex_warning(const char *type, const char *warning, const int dbindex, const char *regex)
{
	// Log to pihole-FTL.log
	logg("REGEX WARNING: Invalid regex %s filter \"%s\": %s",
	     type, regex, warning);

	// Log to database
	add_message(REGEX_MESSAGE, warning, regex, dbindex);
}
