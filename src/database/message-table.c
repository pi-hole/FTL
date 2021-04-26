/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Message table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "message-table.h"
#include "common.h"
// logg()
#include "../log.h"
// get_group_names()
#include "gravity-db.h"
// cli_mode
#include "../args.h"
// cleanup()
#include "../daemon.h"
// main_pid()
#include "../signals.h"

static const char *message_types[MAX_MESSAGE] =
	{ "REGEX", "SUBNET", "HOSTNAME", "DNSMASQ_CONFIG" };

static unsigned char message_blob_types[MAX_MESSAGE][5] =
	{
		{	// REGEX_MESSAGE: The message column contains the regex warning text
			SQLITE_TEXT, // regex type ("deny", "allow")
			SQLITE_TEXT, // regex text (the erroring regex filter itself)
			SQLITE_INTEGER, // database index of regex (so the dashboard can show a link)
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		},
		{	// SUBNET_MESSAGE: The message column contains the IP address of the client in question
			SQLITE_INTEGER, // number of matching
			SQLITE_TEXT, // comma-separated list of matching subnets (text representation)
			SQLITE_TEXT, // comma-separated list of matching subnets (database IDs)
			SQLITE_TEXT, // chosen subnet (text representation)
			SQLITE_INTEGER // chosen subnet (database ID)
		},
		{	// HOSTNAME_MESSAGE: The message column contains the IP address of the device
			SQLITE_TEXT, // Obtained host name
			SQLITE_INTEGER, // Position of error in string
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		},
		{	// DNSMASQ_CONFIG_MESSAGE: The message column contains the full message itself
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL  // Not used
		},
	};
// Create message table in the database
bool create_message_table(sqlite3 *db)
{
	// The blob fields can hold arbitrary data. Their type is specified through the type.
	SQL_bool(db, "CREATE TABLE message ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	                                    "timestamp INTEGER NOT NULL, "
	                                    "type TEXT NOT NULL, "
	                                    "message TEXT NOT NULL, "
	                                    "blob1 BLOB, "
	                                    "blob2 BLOB, "
	                                    "blob3 BLOB, "
	                                    "blob4 BLOB, "
	                                    "blob5 BLOB );");

	// Update database version to 6
	if(!db_set_FTL_property(db, DB_VERSION, 6))
	{
		logg("create_message_table(): Failed to update database version!");
		return false;
	}

	return true;
}

// Flush message table
bool flush_message_table(void)
{
	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false)) == NULL)
	{
		logg("flush_message_table() - Failed to open DB");
		return false;
	}

	// Flush message table
	SQL_bool(db, "DELETE FROM message;");

	// Close database connection
	dbclose(&db);

	return true;
}

static bool add_message(enum message_type type,
                        const char *message, const int count,...)
{
	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false)) == NULL)
	{
		logg("flush_message_table() - Failed to open DB");
		return false;
	}

	// Ensure there are no duplicates when adding host name messages
	if(type == HOSTNAME_MESSAGE)
	{
		sqlite3_stmt* stmt = NULL;
		const char *querystr = "DELETE FROM message WHERE type = ?1 AND message = ?2";
		int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
		if( rc != SQLITE_OK ){
			logg("add_message(type=%u, message=%s) - SQL error prepare DELETE: %s",
			     type, message, sqlite3_errstr(rc));
			dbclose(&db);
			return false;
		}

		// Bind type to prepared statement
		if((rc = sqlite3_bind_text(stmt, 1, message_types[type], -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			logg("add_message(type=%u, message=%s) - Failed to bind type DELETE: %s",
			     type, message, sqlite3_errstr(rc));
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			dbclose(&db);
			return false;
		}

		// Bind message to prepared statement
		if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			logg("add_message(type=%u, message=%s) - Failed to bind message DELETE: %s",
			     type, message, sqlite3_errstr(rc));
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			dbclose(&db);
			return false;
		}

		// Execute and finalize
		if((rc = sqlite3_step(stmt)) != SQLITE_OK && rc != SQLITE_DONE)
		{
			logg("add_message(type=%u, message=%s) - SQL error step DELETE: %s",
			     type, message, sqlite3_errstr(rc));
			dbclose(&db);
			return false;
		}
		sqlite3_clear_bindings(stmt);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
	}

	// Prepare SQLite statement
	sqlite3_stmt* stmt = NULL;
	const char *querystr = "INSERT INTO message (timestamp,type,message,blob1,blob2,blob3,blob4,blob5) "
	                       "VALUES ((cast(strftime('%s', 'now') as int)),?,?,?,?,?,?,?);";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("add_message(type=%u, message=%s) - SQL error prepare: %s",
		     type, message, sqlite3_errstr(rc));
		dbclose(&db);
		return false;
	}

	// Bind type to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, message_types[type], -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s) - Failed to bind type: %s",
		     type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);
		return false;
	}

	// Bind message to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("add_message(type=%u, message=%s) - Failed to bind message: %s",
		     type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);
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
			dbclose(&db);
			return false;
		}
	}
	va_end(ap);

	// Step and check if successful
	rc = sqlite3_step(stmt);
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(rc != SQLITE_DONE)
	{
		logg("Encountered error while trying to store message in long-term database: %s", sqlite3_errstr(rc));
		dbclose(&db);
		return false;
	}

	// Close database connection
	dbclose(&db);

	return true;
}

void logg_regex_warning(const char *type, const char *warning, const int dbindex, const char *regex)
{
	if(warning == NULL)
		warning = "No further info available";

	// Only log regex errors/warnings in the main process to prevent errors
	// being added multiple times to the database when a TCP worker
	// (re)compiles a faulty regex
	if(getpid() != main_pid())
		return;

	// Log to pihole-FTL.log
	logg("REGEX WARNING: Invalid regex %s filter \"%s\": %s",
	     type, regex, warning);

	// Log to database only if not in CLI mode
	if(!cli_mode)
		add_message(REGEX_MESSAGE, warning, 3, type, regex, dbindex);
}

void logg_subnet_warning(const char *ip, const int matching_count, const char *matching_ids,
                         const int matching_bits, const char *chosen_match_text,
                         const int chosen_match_id)
{
	// Log to pihole-FTL.log
	logg("SUBNET WARNING: Client %s is managed by %i groups (IDs %s), all describing /%i subnets. "
	     "FTL chose the most recent entry %s (ID %i) for this client.",
	     ip, matching_count, matching_ids, matching_bits,
	     chosen_match_text, chosen_match_id);

	// Log to database
	char *names = get_client_names_from_ids(matching_ids);
	add_message(SUBNET_MESSAGE, ip, 5, matching_count, names, matching_ids, chosen_match_text, chosen_match_id);
	free(names);
}

void logg_hostname_warning(const char *ip, const char *name, const unsigned int pos)
{
	// Log to pihole-FTL.log
	logg("HOSTNAME WARNING: Host name of client \"%s\" => \"%s\" contains (at least) one invalid character at position %d",
	     ip, name, pos);

	// Log to database
	add_message(HOSTNAME_MESSAGE, ip, 2, name, (const int)pos);
}

void logg_fatal_dnsmasq_message(const char *message)
{
	// Log to pihole-FTL.log
	logg("FATAL ERROR in dnsmasq core: %s", message);

	// Log to database
	add_message(DNSMASQ_CONFIG_MESSAGE, message, 0);

	// FTL will dies after this point, so we should make sure to clean up
	// behind ourselves
	cleanup(EXIT_FAILURE);
}
