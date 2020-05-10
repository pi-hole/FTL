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

static unsigned char message_blob_types[MAX_MESSAGE][5] =
	{
		{	// REGEX_MESSAGE: The message column contains the regex warning text
			SQLITE_TEXT, // regex type ("blacklist", "whitelist")
			SQLITE_TEXT, // regex text (the erroring regex filter itself)
			SQLITE_INTEGER, // database index of regex (so the dashboard can show a link)
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		}
	};

// Create message table in the database
bool create_message_table(void)
{
	// The blob fields can hold arbitrary data. Their type is specified through the type.
	SQL_bool("CREATE TABLE message ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	                                "timestamp INTEGER NOT NULL, "
	                                "type TEXT NOT NULL, "
	                                "message TEXT NOT NULL, "
	                                "blob1 BLOB, "
	                                "blob2 BLOB, "
	                                "blob3 BLOB, "
	                                "blob4 BLOB, "
	                                "blob5 BLOB );");

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
	// Open database connection
	dbopen();

	// Flush message table
	SQL_bool("DELETE FROM message;");

	// Close database connection
	dbclose();

	return true;
}

static bool add_message(enum message_type type, const char *message,
                        const int count,...)
{
	// Open database connection
	dbopen();

	// Prepare SQLite statement
	sqlite3_stmt* stmt = NULL;
	const char *querystr = "INSERT INTO message (timestamp, type, message, blob1, blob2, blob3, blob4, blob5) "
	                       "VALUES ((cast(strftime('%%s', 'now') as int)),?,?,?,?,?,?,?);";
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("add_message(type=%u, message=%s) - SQL error prepare: %s",
		     type, message, sqlite3_errstr(rc));
		return false;
	}

	// Bind type to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, type)) != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s) - Failed to bind type: %s",
		     type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind message to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s) - Failed to bind message: %s",
		type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	va_list ap;
	va_start(ap, count);
	for (int j = 0; j < count; j++)
	{
		const unsigned char datatype = message_blob_types[type][j];
		switch (datatype)
		{
			case SQLITE_INTEGER:
				rc = sqlite3_bind_int(stmt, 3 + j, va_arg(ap, int));
				break;

			case SQLITE_TEXT:
				rc = sqlite3_bind_text(stmt, 3 + j, va_arg(ap, char*), -1, SQLITE_STATIC);
				break;

			case SQLITE_NULL: /* Fall through */
			default:
				rc = sqlite3_bind_null(stmt, 3 + j);
				break;
		}

		// Bind message to prepared statement
		if(rc != SQLITE_OK)
		{
			logg("add_message(type=%u, message=%s) - Failed to bind argument %u (type %u): %s",
			     type, message, 3 + j, datatype, sqlite3_errstr(rc));
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			return false;
		}
	}
	va_end(ap);

	// Step and check if successful
	rc = sqlite3_step(stmt);
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);

	// Close database connection
	dbclose();

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
	add_message(REGEX_MESSAGE, warning, 3, type, regex, dbindex);
}
