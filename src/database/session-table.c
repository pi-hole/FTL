/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Sessions table database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "database/session-table.h"
#include "database/common.h"
#include "config/config.h"
// get_memdb()
#include "database/query-table.h"

bool create_session_table(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION;");

	// Create session table
	SQL_bool(db, "CREATE TABLE session (id INTEGER PRIMARY KEY, "\
	                                   "login_at TIMESTAMP NOT NULL, "\
	                                   "valid_until TIMESTAMP NOT NULL, "\
	                                   "remote_addr TEXT NOT NULL, "\
	                                   "user_agent TEXT, "\
	                                   "sid TEXT NOT NULL, "\
	                                   "csrf TEXT NOT NULL, "\
	                                   "tls_login BOOL, "\
	                                   "tls_mixed BOOL);");

	// Update database version to 15
	if(!db_set_FTL_property(db, DB_VERSION, 15))
	{
		log_err("create_session_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "COMMIT");

	return true;
}

bool add_session_app_column(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION;");

	// Create session table
	SQL_bool(db, "ALTER TABLE session ADD COLUMN app BOOL;");

	// Update database version to 16
	if(!db_set_FTL_property(db, DB_VERSION, 16))
	{
		log_err("add_session_app_column(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "COMMIT");

	return true;
}

// Store all session in database
bool backup_db_sessions(struct session *sessions, const uint16_t max_sessions)
{
	if(!config.webserver.session.restore.v.b)
	{
		log_debug(DEBUG_API, "Session restore is disabled, not adding sessions to database");
		return true;
	}

	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
	{
		log_warn("Failed to open database in backup_db_sessions()");
		return false;
	}

	// Insert session into database
	sqlite3_stmt *stmt = NULL;
	if(sqlite3_prepare_v2(db, "INSERT INTO session (login_at, valid_until, remote_addr, user_agent, sid, csrf, tls_login, tls_mixed, app) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", -1, &stmt, 0) != SQLITE_OK)
	{
		log_err("SQL error in backup_db_sessions(): %s (%d)",
		        sqlite3_errmsg(db), sqlite3_errcode(db));
		return false;
	}

	unsigned int api_sessions = 0;
	for(unsigned int i = 0; i < max_sessions; i++)
	{
		// Get session
		struct session *sess = &sessions[i];

		// Skip unused sessions
		if(!sess->used)
			continue;

		// Bind values to statement
		// 1: login_at
		if(sqlite3_bind_int64(stmt, 1, sess->login_at) != SQLITE_OK)
		{
			log_err("Cannot bind login_at = %ld in backup_db_sessions(): %s (%d)",
					(long int)sess->login_at, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 2: valid_until
		if(sqlite3_bind_int64(stmt, 2, sess->valid_until) != SQLITE_OK)
		{
			log_err("Cannot bind valid_until = %ld in backup_db_sessions(): %s (%d)",
					(long int)sess->valid_until, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 3: remote_addr
		if(sqlite3_bind_text(stmt, 3, sess->remote_addr, -1, SQLITE_STATIC) != SQLITE_OK)
		{
			log_err("Cannot bind remote_addr = %s in backup_db_sessions(): %s (%d)",
					sess->remote_addr, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 4: user_agent
		if(sqlite3_bind_text(stmt, 4, sess->user_agent, -1, SQLITE_STATIC) != SQLITE_OK)
		{
			log_err("Cannot bind user_agent = %s in backup_db_sessions(): %s (%d)",
					sess->user_agent, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 5: sid
		if(sqlite3_bind_text(stmt, 5, sess->sid, -1, SQLITE_STATIC) != SQLITE_OK)
		{
			log_err("Cannot bind sid = %s in backup_db_sessions(): %s (%d)",
					sess->sid, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 6: csrf
		if(sqlite3_bind_text(stmt, 6, sess->csrf, -1, SQLITE_STATIC) != SQLITE_OK)
		{
			log_err("Cannot bind csrf = %s in backup_db_sessions(): %s (%d)",
					sess->csrf, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 7: tls_login
		if(sqlite3_bind_int(stmt, 7, sess->tls.login ? 1 : 0) != SQLITE_OK)
		{
			log_err("Cannot bind tls_login = %d in backup_db_sessions(): %s (%d)",
					sess->tls.login ? 1 : 0, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 8: tls_mixed
		if(sqlite3_bind_int(stmt, 8, sess->tls.mixed ? 1: 0) != SQLITE_OK)
		{
			log_err("Cannot bind tls_mixed = %d in backup_db_sessions(): %s (%d)",
					sess->tls.mixed ? 1 : 0, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}
		// 9: app
		if(sqlite3_bind_int(stmt, 8, sess->app ? 1: 0) != SQLITE_OK)
		{
			log_err("Cannot bind app = %d in backup_db_sessions(): %s (%d)",
					sess->app ? 1 : 0, sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}

		// Execute statement
		if(sqlite3_step(stmt) != SQLITE_DONE)
		{
			log_err("SQL error in backup_db_sessions(): %s (%d)",
					sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}

		// Clear bindings
		if(sqlite3_clear_bindings(stmt) != SQLITE_OK)
		{
			log_err("SQL error in backup_db_sessions(): %s (%d)",
					sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}

		// Reset statement
		if(sqlite3_reset(stmt) != SQLITE_OK)
		{
			log_err("SQL error in backup_db_sessions(): %s (%d)",
					sqlite3_errmsg(db), sqlite3_errcode(db));
			return false;
		}

		api_sessions++;
	}

	// Finalize statement
	if(sqlite3_finalize(stmt) != SQLITE_OK)
	{
		log_err("SQL error in backup_db_sessions(): %s (%d)",
		        sqlite3_errmsg(db), sqlite3_errcode(db));
		return false;
	}

	log_info("Stored %u API session%s in the database",
	         api_sessions, api_sessions == 1 ? "" : "s");

	// Close database connection
	dbclose(&db);

	return true;
}

// Restore all sessions found in the database
bool restore_db_sessions(struct session *sessions, const uint16_t max_sessions)
{
	if(!config.webserver.session.restore.v.b)
	{
		log_debug(DEBUG_API, "Session restore is disabled, not restoring sessions from database");
		return true;
	}

	sqlite3 *memdb = get_memdb();

	// Remove expired sessions from database
	SQL_bool(memdb, "DELETE FROM disk.session WHERE valid_until < strftime('%%s', 'now');");

	// Get all sessions from database
	sqlite3_stmt *stmt = NULL;
	if(sqlite3_prepare_v2(memdb, "SELECT login_at, valid_until, remote_addr, user_agent, sid, csrf, tls_login, tls_mixed, app FROM disk.session;", -1, &stmt, 0) != SQLITE_OK)
	{
		log_err("SQL error in restore_db_sessions(): %s (%d)",
		        sqlite3_errmsg(memdb), sqlite3_errcode(memdb));
		return false;
	}

	// Iterate over all still valid sessions
	unsigned int i = 0;
	while(sqlite3_step(stmt) == SQLITE_ROW && i < max_sessions)
	{
		// Allocate memory for new session
		struct session *sess = &sessions[i];

		// Get values from database
		// 1: login_at
		sess->login_at = sqlite3_column_int64(stmt, 0);

		// 2: valid_until
		sess->valid_until = sqlite3_column_int64(stmt, 1);

		// 3: remote_addr
		const char *remote_addr = (const char *)sqlite3_column_text(stmt, 2);
		if(remote_addr != NULL)
		{
			strncpy(sess->remote_addr, remote_addr, sizeof(sess->remote_addr)-1);
			sess->remote_addr[sizeof(sess->remote_addr)-1] = '\0';
		}

		// 4: user_agent
		const char *user_agent = (const char *)sqlite3_column_text(stmt, 3);
		if(user_agent != NULL)
		{
			strncpy(sess->user_agent, user_agent, sizeof(sess->user_agent)-1);
			sess->user_agent[sizeof(sess->user_agent)-1] = '\0';
		}

		// 5: sid
		const char *sid = (const char *)sqlite3_column_text(stmt, 4);
		if(sid != NULL)
		{
			strncpy(sess->sid, sid, sizeof(sess->sid)-1);
			sess->sid[sizeof(sess->sid)-1] = '\0';
		}

		// 6: csrf
		const char *csrf = (const char *)sqlite3_column_text(stmt, 5);
		if(csrf != NULL)
		{
			strncpy(sess->csrf, csrf, sizeof(sess->csrf)-1);
			sess->csrf[sizeof(sess->csrf)-1] = '\0';
		}

		// 7: tls_login
		sess->tls.login = sqlite3_column_int(stmt, 6) == 1 ? true : false;

		// 8: tls_mixed
		sess->tls.mixed = sqlite3_column_int(stmt, 7) == 1 ? true : false;

		// 8: app
		sess->app = sqlite3_column_int(stmt, 8) == 1 ? true : false;

		// Mark session as used
		sess->used = true;

		i++;
	}

	log_info("Restored %u API session%s from the database",
	         i, i == 1 ? "" : "s");

	// Finalize statement
	if(sqlite3_finalize(stmt) != SQLITE_OK)
	{
		log_err("SQL error in restore_db_sessions(): %s (%d)",
		        sqlite3_errmsg(memdb), sqlite3_errcode(memdb));
		return false;
	}

	// Delete all sessions from database after restoring them
	// We use secure_delete to make sure the sessions are really gone
	// In this mode, SQLite overwrites the deleted content with zeros
	// (https://www.sqlite.org/pragma.html#pragma_secure_delete)
	SQL_bool(memdb, "PRAGMA secure_delete = ON;");
	SQL_bool(memdb, "DELETE FROM disk.session;");
	SQL_bool(memdb, "PRAGMA secure_delete = OFF;");

	return true;
}
