/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "query-table.h"
#include "common.h"
// get[Domain,ClientIP,Forward]String(), etc.
#include "../datastructure.h"
// getOverTimeID()
#include "../overTime.h"
// get_FTL_db_filesize()
#include "../files.h"
// timer_elapsed_msec()
#include "../timers.h"
// logg()
#include "../log.h"
// struct config
#include "../config.h"
// getstr()
#include "../shmem.h"

static bool saving_failed_before = false;

int get_number_of_queries_in_DB(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false)) == NULL)
		{
			logg("get_number_of_queries_in_DB() - Failed to open DB");
			return DB_FAILED;
		}

		// Successful
		db_opened = true;
	}

	// Count number of rows using the index timestamp is faster than select(*)
	int result = db_query_int(db, "SELECT COUNT(timestamp) FROM query_storage");

	if(db_opened) dbclose(&db);

	return result;
}

int DB_save_queries(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	// Start database timer
	if(config.debug & DEBUG_DATABASE)
		timer_start(DATABASE_WRITE_TIMER);

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false)) == NULL)
		{
			logg("DB_save_queries() - Failed to open DB");
			return DB_FAILED;
		}

		// Successful
		db_opened = true;
	}

	int saved = 0;
	bool error = false;
	sqlite3_stmt *query_stmt = NULL;
	sqlite3_stmt *domain_stmt = NULL;
	sqlite3_stmt *client_stmt = NULL;
	sqlite3_stmt *forward_stmt = NULL;
	sqlite3_stmt *addinfo_stmt = NULL;

	int rc = dbquery(db, "BEGIN TRANSACTION IMMEDIATE");
	if( rc != SQLITE_OK )
	{
		const char *text;
		if( rc == SQLITE_BUSY )
			text = "WARNING";
		else
			text = "ERROR";

		logg("%s: Storing queries in long-term database failed: %s", text, sqlite3_errstr(rc));
		checkFTLDBrc(rc);

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	// Prepare statements
	rc  = sqlite3_prepare_v3(db, "INSERT INTO query_storage "
	                                 "(timestamp,type,status,domain,client,forward,additional_info,reply_type,reply_time,dnssec) "
	                                 "VALUES "
	                                 "(?1,?2,?3,"
	                                 "(SELECT id FROM domain_by_id WHERE domain = ?4),"
	                                 "(SELECT id FROM client_by_id WHERE ip = ?5 AND name = ?6),"
	                                 "(SELECT id FROM forward_by_id WHERE forward = ?7),"
	                                 "(SELECT id FROM addinfo_by_id WHERE type = ?8 AND content = ?9),"
	                                 "?10,?11,?12)",
	                         -1, SQLITE_PREPARE_PERSISTENT, &query_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		const char *text, *spaces;
		if( rc == SQLITE_BUSY )
		{
			text   = "WARNING";
			spaces = "       ";
		}
		else
		{
			text   = "ERROR";
			spaces = "     ";
		}

		logg("%s: Storing queries in long-term database failed: %s\n", text, sqlite3_errstr(rc));
		if(!checkFTLDBrc(rc))
			logg("%s  Keeping queries in memory for later new attempt", spaces);
		saving_failed_before = true;

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	rc = sqlite3_prepare_v3(db, "INSERT OR IGNORE INTO domain_by_id (domain) VALUES (?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &domain_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		const char *text, *spaces;
		if( rc == SQLITE_BUSY )
		{
			text   = "WARNING";
			spaces = "       ";
		}
		else
		{
			text   = "ERROR";
			spaces = "     ";
		}

		logg("%s: Storing queries in long-term database failed: %s\n", text, sqlite3_errstr(rc));
		if(!checkFTLDBrc(rc))
			logg("%s  Keeping queries in memory for later new attempt", spaces);
		saving_failed_before = true;

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	rc = sqlite3_prepare_v3(db, "INSERT OR IGNORE INTO client_by_id (ip,name) VALUES (?,?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &client_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		const char *text, *spaces;
		if( rc == SQLITE_BUSY )
		{
			text   = "WARNING";
			spaces = "       ";
		}
		else
		{
			text   = "ERROR";
			spaces = "     ";
		}

		logg("%s: Storing queries in long-term database failed: %s\n", text, sqlite3_errstr(rc));
		if(!checkFTLDBrc(rc))
			logg("%s  Keeping queries in memory for later new attempt", spaces);
		saving_failed_before = true;

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	rc = sqlite3_prepare_v3(db, "INSERT OR IGNORE INTO forward_by_id (forward) VALUES (?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &forward_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		const char *text, *spaces;
		if( rc == SQLITE_BUSY )
		{
			text   = "WARNING";
			spaces = "       ";
		}
		else
		{
			text   = "ERROR";
			spaces = "     ";
		}

		logg("%s: Storing queries in long-term database failed: %s\n", text, sqlite3_errstr(rc));
		if(!checkFTLDBrc(rc))
			logg("%s  Keeping queries in memory for later new attempt", spaces);
		saving_failed_before = true;

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	rc = sqlite3_prepare_v3(db, "INSERT OR IGNORE INTO addinfo_by_id (type,content) VALUES (?,?)",
	                        -1, SQLITE_PREPARE_PERSISTENT, &addinfo_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		const char *text, *spaces;
		if( rc == SQLITE_BUSY )
		{
			text   = "WARNING";
			spaces = "       ";
		}
		else
		{
			text   = "ERROR";
			spaces = "     ";
		}

		logg("%s: Storing queries in long-term database failed: %s\n", text, sqlite3_errstr(rc));
		if(!checkFTLDBrc(rc))
			logg("%s  Keeping queries in memory for later new attempt", spaces);
		saving_failed_before = true;

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	// Get last ID stored in the database
	long int lastID = get_max_query_ID(db);

	int total = 0, blocked = 0;
	time_t currenttimestamp = time(NULL);
	time_t newlasttimestamp = 0;
	long int queryID;
	for(queryID = MAX(0, lastdbindex); queryID < counters->queries; queryID++)
	{
		queriesData* query = getQuery(queryID, true);
		if(!query)
		{
			// Memory error
			continue;
		}

		if(query->flags.database)
		{
			// Skip, already saved in database
			continue;
		}

		if(!query->flags.complete && query->timestamp > currenttimestamp-2)
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
		sqlite3_bind_int(query_stmt, 1, query->timestamp);

		// TYPE
		if(query->type != TYPE_OTHER)
		{
			// Store mapped type if query->type is not OTHER
			sqlite3_bind_int(query_stmt, 2, query->type);
		}
		else
		{
			// Store query type + offset if query-> type is OTHER
			sqlite3_bind_int(query_stmt, 2, query->qtype + 100);
		}

		// STATUS
		sqlite3_bind_int(query_stmt, 3, query->status);

		// DOMAIN
		const char *domain = getDomainString(query);
		sqlite3_bind_text(domain_stmt, 1, domain, -1, SQLITE_STATIC);
		sqlite3_bind_text(query_stmt, 4, domain, -1, SQLITE_STATIC);

		// Execute prepare client statement and check if successful
		if(sqlite3_step(domain_stmt) != SQLITE_DONE)
		{
			logg("Encountered error while trying to store client in long-term database");
			error = true;
			break;
		}
		sqlite3_clear_bindings(domain_stmt);
		sqlite3_reset(domain_stmt);

		// CLIENT
		const char *clientIP = getClientIPString(query);
		sqlite3_bind_text(query_stmt, 5, clientIP, -1, SQLITE_STATIC);
		sqlite3_bind_text(client_stmt, 1, clientIP, -1, SQLITE_STATIC);
		const char *clientName = getClientNameString(query);
		sqlite3_bind_text(query_stmt, 6, clientName, -1, SQLITE_STATIC);
		sqlite3_bind_text(client_stmt, 2, clientName, -1, SQLITE_STATIC);

		// Execute prepare client statement and check if successful
		if(sqlite3_step(client_stmt) != SQLITE_DONE)
		{
			logg("Encountered error while trying to store client in long-term database");
			error = true;
			break;
		}
		sqlite3_clear_bindings(client_stmt);
		sqlite3_reset(client_stmt);

		// FORWARD
		if(query->upstreamID > -1)
		{
			// Get forward pointer
			const upstreamsData* upstream = getUpstream(query->upstreamID, true);
			const char *forwardIP = getstr(upstream->ippos);
			if(upstream && forwardIP)
			{
				char *buffer = NULL;
				int len = 0; // The length of the string WITHOUT the NUL byte. This is what sqlite3_bind_text() expects.
				if((len = asprintf(&buffer, "%s#%u", forwardIP, upstream->port)) > 0)
				{
					// Use transient here as we step only after the buffer is freed below
					sqlite3_bind_text(query_stmt, 7, buffer, len, SQLITE_TRANSIENT);
					// Use static here as we insert right away
					sqlite3_bind_text(forward_stmt, 1, buffer, len, SQLITE_STATIC);

					// Execute prepared forward statement and check if successful
					if(sqlite3_step(forward_stmt) != SQLITE_DONE)
					{
						logg("Encountered error while trying to store forward destination in long-term database");
						error = true;
						break;
					}
					sqlite3_clear_bindings(forward_stmt);
					sqlite3_reset(forward_stmt);
				}
				else
				{
					// Memory error: Do not store the forward destination
					sqlite3_bind_null(query_stmt, 7);
				}

				if(buffer) free(buffer);
			}
		}
		else
		{
			// No forward destination
			sqlite3_bind_null(query_stmt, 7);
		}

		const int cacheID = findCacheID(query->domainID, query->clientID, query->type, false);
		DNSCacheData *cache = getDNSCache(cacheID, true);

		// ADDITIONAL_INFO
		if(query->status == QUERY_GRAVITY_CNAME ||
		   query->status == QUERY_REGEX_CNAME ||
		   query->status == QUERY_BLACKLIST_CNAME)
		{
			// Save domain blocked during deep CNAME inspection
			const char *cname = getCNAMEDomainString(query);
			const int len = strlen(cname);
			sqlite3_bind_int(query_stmt, 8, ADDINFO_CNAME_DOMAIN);
			sqlite3_bind_text(query_stmt, 9, cname, len, SQLITE_STATIC);

			// Execute prepared addinfo statement and check if successful
			sqlite3_bind_int(addinfo_stmt, 1, ADDINFO_CNAME_DOMAIN);
			sqlite3_bind_text(addinfo_stmt, 2, cname, len, SQLITE_STATIC);
			if(sqlite3_step(addinfo_stmt) != SQLITE_DONE)
			{
				logg("Encountered error while trying to store addinfo in long-term database (CNAME)");
				error = true;
				break;
			}
			sqlite3_clear_bindings(addinfo_stmt);
			sqlite3_reset(addinfo_stmt);
		}
		else if(cache != NULL && cache->domainlist_id > -1)
		{
			sqlite3_bind_int(query_stmt, 8, ADDINFO_REGEX_ID);
			sqlite3_bind_int(query_stmt, 9, cache->domainlist_id);

			// Execute prepared addinfo statement and check if successful
			sqlite3_bind_int(addinfo_stmt, 1, ADDINFO_REGEX_ID);
			sqlite3_bind_int(addinfo_stmt, 2, cache->domainlist_id);
			if(sqlite3_step(addinfo_stmt) != SQLITE_DONE)
			{
				logg("Encountered error while trying to store addinfo in long-term database (domainlist_id)");
				error = true;
				break;
			}
			sqlite3_clear_bindings(addinfo_stmt);
			sqlite3_reset(addinfo_stmt);
		}
		else
		{
			// Nothing to add here
			sqlite3_bind_null(query_stmt, 8);
			sqlite3_bind_null(query_stmt, 9);
		}

		// REPLY_TYPE
		sqlite3_bind_int(query_stmt, 10, query->reply);

		// REPLY_TIME (stored in units of seconds) if available, NULL otherwise
		if(query->flags.response_calculated)
			sqlite3_bind_double(query_stmt, 11, 1e-4*query->response);
		else
			sqlite3_bind_null(query_stmt, 11);

		// DNSSEC
		sqlite3_bind_int(query_stmt, 12, query->dnssec);

		// Step and check if successful
		if(sqlite3_step(query_stmt) != SQLITE_DONE)
		{
			logg("Encountered error while trying to store queries in long-term database");
			error = true;
			break;
		}
		sqlite3_clear_bindings(query_stmt);
		sqlite3_reset(query_stmt);

		// Increment counters
		saved++;
		lastID++;

		// Mark this query as saved in the database
		query->flags.database = true;

		// Total counter information (delta computation)
		total++;
		if(query->flags.blocked)
			blocked++;

		// Update lasttimestamp variable with timestamp of the latest stored query
		if(query->timestamp > newlasttimestamp)
			newlasttimestamp = query->timestamp;
	}

	if(sqlite3_finalize(query_stmt) != SQLITE_OK ||
	   sqlite3_finalize(domain_stmt) != SQLITE_OK ||
	   sqlite3_finalize(client_stmt) != SQLITE_OK ||
	   sqlite3_finalize(forward_stmt) != SQLITE_OK ||
	   sqlite3_finalize(addinfo_stmt) != SQLITE_OK)
	{
		logg("Statement finalization failed when trying to store queries to long-term database");

		if(!checkFTLDBrc(rc) && rc == SQLITE_BUSY)
		{
			logg("Keeping queries in memory for later new attempt");
			saving_failed_before = true;
		}

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	// Store index for next loop iteration round and update last time stamp
	// in the database only if all queries have been saved successfully
	if(saved > 0 && !error)
	{
		lastdbindex = queryID;
		db_set_FTL_property(db, DB_LASTTIMESTAMP, newlasttimestamp);
		db_update_counters(db, total, blocked);
	}

	// Finish prepared statement
	if((rc = dbquery(db,"END TRANSACTION")) != SQLITE_OK)
	{
		// No need to log the error string here, dbquery() did that already above
		logg("END TRANSACTION failed when trying to store queries to long-term database");

		if(!checkFTLDBrc(rc) && rc == SQLITE_BUSY)
		{
			logg("Keeping queries in memory for later new attempt");
			saving_failed_before = true;
		}

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	if(config.debug & DEBUG_DATABASE || saving_failed_before)
	{
		logg("Notice: Queries stored in long-term database: %u (took %.1f ms, last SQLite ID %li)",
		     saved, timer_elapsed_msec(DATABASE_WRITE_TIMER), lastID);
		if(saving_failed_before)
		{
			logg("        Queries from earlier attempt(s) stored successfully");
			saving_failed_before = false;
		}
	}

	if(db_opened) dbclose(&db);

	return saved;
}

void delete_old_queries_in_DB(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return;

	int timestamp = time(NULL) - config.maxDBdays * 86400;

	if(dbquery(db, "DELETE FROM query_storage WHERE timestamp <= %i", timestamp) != SQLITE_OK)
	{
		logg("delete_old_queries_in_DB(): Deleting queries due to age of entries failed!");
		return;
	}

	// Get how many rows have been affected (deleted)
	const int affected = sqlite3_changes(db);

	// Print final message only if there is a difference
	if((config.debug & DEBUG_DATABASE) || affected)
		logg("Notice: Database size is %.2f MB, deleted %i rows", 1e-6*get_FTL_db_filesize(), affected);
}

bool add_additional_info_column(sqlite3 *db)
{
	// Add column additinal_info to queries table
	SQL_bool(db, "ALTER TABLE queries ADD COLUMN additional_info TEXT;");

	// Update the database version to 7
	SQL_bool(db, "INSERT OR REPLACE INTO ftl (id, value) VALUES ( %u, %i );", DB_VERSION, 7);

	return true;
}

bool add_query_storage_columns(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION");

	// Add additional columns to the query_storage table
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN reply_type INTEGER");
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN reply_time REAL");
	SQL_bool(db, "ALTER TABLE query_storage ADD COLUMN dnssec INTEGER");

	// Update VIEW queries
	SQL_bool(db, "DROP VIEW queries");
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "CASE typeof(additional_info) WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info, "
	                       "reply_type, reply_time, dnssec "
	                       "FROM query_storage q");

	// Update database version to 12
	if(!db_set_FTL_property(db, DB_VERSION, 12))
	{
		logg("add_query_storage_columns(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "COMMIT");

	return true;
}

bool optimize_queries_table(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION;");

	// Create link tables for domain, client, and forward strings
	SQL_bool(db, "CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);");
	SQL_bool(db, "CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);");
	SQL_bool(db, "CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT NOT NULL);");

	// Create UNIQUE index for the new tables
	SQL_bool(db, "CREATE UNIQUE INDEX domain_by_id_domain_idx ON domain_by_id(domain);");
	SQL_bool(db, "CREATE UNIQUE INDEX client_by_id_client_idx ON client_by_id(ip,name);");
	SQL_bool(db, "CREATE UNIQUE INDEX forward_by_id_forward_idx ON forward_by_id(forward);");

	// Rename current queries table
	SQL_bool(db, "ALTER TABLE queries RENAME TO query_storage;");

	// Change column definitions of the queries_storage table to allow
	// integer IDs. If we would leave the column definitions as TEXT, we
	// could not tell apart integer IDs easily as everything INSERTed would
	// be converted to TEXT form (this is very inefficient)
	// We have to turn off defensive mode to do this.
	SQL_bool(db, "PRAGMA writable_schema = ON;");
	SQL_bool(db, "UPDATE sqlite_master SET sql = 'CREATE TABLE \"query_storage\" (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL, forward INTEGER , additional_info TEXT)' WHERE type = 'table' AND name = 'query_storage';");
	SQL_bool(db, "PRAGMA writable_schema = OFF;");

	// Create VIEW queries so user scripts continue to work despite our
	// optimization here. The VIEW will pull the strings from the linked
	// tables when needed to always server the strings.
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "additional_info FROM query_storage q;");

	// Update database version to 10
	if(!db_set_FTL_property(db, DB_VERSION, 10))
	{
		logg("optimize_queries_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "COMMIT");

	return true;
}

bool create_addinfo_table(sqlite3 *db)
{
	// Start transaction of database update
	SQL_bool(db, "BEGIN TRANSACTION;");

	// Create link table for additional_info column
	SQL_bool(db, "CREATE TABLE addinfo_by_id (id INTEGER PRIMARY KEY, type INTEGER NOT NULL, content NOT NULL);");

	// Create UNIQUE index for the new tables
	SQL_bool(db, "CREATE UNIQUE INDEX addinfo_by_id_idx ON addinfo_by_id(type,content);");

	// Change column definitions of the queries_storage table to allow
	// integer IDs. If we would leave the column definitions as TEXT, we
	// could not tell apart integer IDs easily as everything INSERTed would
	// be converted to TEXT form (this is very inefficient)
	// We have to turn off defensive mode to do this.
	SQL_bool(db, "PRAGMA writable_schema = ON;");
	SQL_bool(db, "UPDATE sqlite_master SET sql = 'CREATE TABLE \"query_storage\" (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL, forward INTEGER, additional_info INTEGER)' WHERE type = 'table' AND name = 'query_storage';");
	SQL_bool(db, "PRAGMA writable_schema = OFF;");

	// Create VIEW queries so user scripts continue to work despite our
	// optimization here. The VIEW will pull the strings from the linked
	// tables when needed to always server the strings.
	SQL_bool(db, "DROP VIEW queries");
	SQL_bool(db, "CREATE VIEW queries AS "
	                     "SELECT id, timestamp, type, status, "
	                       "CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,"
	                       "CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,"
	                       "CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,"
	                       "CASE typeof(additional_info) WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info "
	                       "FROM query_storage q;");

	// Update database version to 11
	if(!db_set_FTL_property(db, DB_VERSION, 11))
	{
		logg("create_addinfo_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "COMMIT");

	return true;
}

// Get most recent 24 hours data from long-term database
void DB_read_queries(void)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return;

	// Open database
	sqlite3 *db;
	if((db = dbopen(false)) == NULL)
	{
		logg("DB_read_queries() - Failed to open DB");
		return;
	}

	// Prepare request
	// Get time stamp 24 hours in the past
	const time_t now = time(NULL);
	const time_t mintime = now - config.maxlogage;
	const char *querystr = "SELECT id,timestamp,type,status,domain,client,forward,additional_info,reply_type,reply_time,dnssec FROM queries WHERE timestamp >= ?";
	// Log FTL_db query string in debug mode
	if(config.debug & DEBUG_DATABASE)
		logg("DB_read_queries(): \"%s\" with ? = %lli", querystr, (long long)mintime);

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v3(db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("DB_read_queries() - SQL error prepare: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		goto end_of_DB_read_queries;
	}

	// Bind limit
	if((rc = sqlite3_bind_int(stmt, 1, mintime)) != SQLITE_OK)
	{
		logg("DB_read_queries() - Failed to bind type mintime: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		goto end_of_DB_read_queries;
	}

	// Lock shared memory
	lock_shm();

	// Loop through returned database rows
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const time_t queryTimeStamp = sqlite3_column_int(stmt, 1);
		// 1483228800 = 01/01/2017 @ 12:00am (UTC)
		if(queryTimeStamp < 1483228800)
		{
			logg("DB warn: TIMESTAMP should be larger than 01/01/2017 but is %lli", (long long)queryTimeStamp);
			continue;
		}
		if(queryTimeStamp > now)
		{
			if(config.debug & DEBUG_DATABASE) logg("DB warn: Skipping query logged in the future (%lli)", (long long)queryTimeStamp);
			continue;
		}

		const int type = sqlite3_column_int(stmt, 2);
		const bool mapped_type = type >= TYPE_A && type < TYPE_MAX;
		const bool offset_type = type > 100 && type < (100 + UINT16_MAX);
		if(!mapped_type && !offset_type)
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

		const int status_int = sqlite3_column_int(stmt, 3);
		if(status_int < QUERY_UNKNOWN || status_int > QUERY_STATUS_MAX)
		{
			logg("DB warn: STATUS should be within [%i,%i] but is %i", QUERY_UNKNOWN, QUERY_STATUS_MAX-1, status_int);
			continue;
		}
		const enum query_status status = status_int;

		const char * domainname = (const char *)sqlite3_column_text(stmt, 4);
		if(domainname == NULL)
		{
			logg("DB warn: DOMAIN should never be NULL, %lli", (long long)queryTimeStamp);
			continue;
		}

		const char * clientIP = (const char *)sqlite3_column_text(stmt, 5);
		if(clientIP == NULL)
		{
			logg("DB warn: CLIENT should never be NULL, %lli", (long long)queryTimeStamp);
			continue;
		}

		// Check if user wants to skip queries coming from localhost
		if(config.ignore_localhost &&
		   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
		{
			continue;
		}

		// Ensure we have enough shared memory available for new data
		shm_ensure_size();

		const char *buffer = NULL;
		int upstreamID = -1; // Default if not forwarded
		// Try to extract the upstream from the "forward" column if non-empty
		if(sqlite3_column_bytes(stmt, 6) > 0 &&
		   (buffer = (const char *)sqlite3_column_text(stmt, 6)) != NULL)
		{
			// Get IP address and port of upstream destination
			char serv_addr[INET6_ADDRSTRLEN] = { 0 };
			unsigned int serv_port = 53;
			// We limit the number of bytes written into the serv_addr buffer
			// to prevent buffer overflows. If there is no port available in
			// the database, we skip extracting them and use the default port
			sscanf(buffer, "%"xstr(INET6_ADDRSTRLEN)"[^#]#%u", serv_addr, &serv_port);
			serv_addr[INET6_ADDRSTRLEN-1] = '\0';
			upstreamID = findUpstreamID(serv_addr, (in_port_t)serv_port);
		}

		int reply_type = REPLY_UNKNOWN;
		if(sqlite3_column_type(stmt, 8) == SQLITE_INTEGER)
		{
			// The field has been added for database version 12
			reply_type = sqlite3_column_int(stmt, 8);
			if(reply_type < REPLY_UNKNOWN || reply_type >= QUERY_REPLY_MAX)
			{
				logg("DB warn: REPLY value %i is invalid, %lli", reply_type, (long long)queryTimeStamp);
				continue;
			}
		}

		double reply_time = 0.0;
		bool reply_time_avail = false;
		if(sqlite3_column_type(stmt, 9) == SQLITE_FLOAT)
		{
			// The field has been added for database version 12
			reply_time = sqlite3_column_double(stmt, 9);
			reply_time_avail = true;
			if(reply_time < 0.0)
			{
				logg("DB warn: REPLY_TIME value %f is invalid, %lli", reply_time, (long long)queryTimeStamp);
				continue;
			}
		}

		int dnssec = DNSSEC_UNSPECIFIED;
		if(sqlite3_column_type(stmt, 10) == SQLITE_INTEGER)
		{
			// The field has been added for database version 12
			dnssec = sqlite3_column_int(stmt, 10);
			if(dnssec < DNSSEC_UNSPECIFIED || dnssec >= DNSSEC_ABANDONED)
			{
				logg("DB warn: DNSSEC value %i is invalid, %lli", dnssec, (long long)queryTimeStamp);
				continue;
			}
		}

		// Obtain IDs only after filtering which queries we want to keep
		const int timeidx = getOverTimeID(queryTimeStamp);
		const int domainID = findDomainID(domainname, true);
		const int clientID = findClientID(clientIP, true, false);

		// Set index for this query
		const int queryIndex = counters->queries;

		// Store this query in memory
		queriesData* query = getQuery(queryIndex, false);
		query->magic = MAGICBYTE;
		query->timestamp = queryTimeStamp;
		if(type < 100)
		{
			// Mapped query type
			if(type >= TYPE_A && type < TYPE_MAX)
				query->type = type;
			else
			{
				// Invalid query type
				logg("DB warn: Query type %d is invalid.", type);
				continue;
			}
		}
		else
		{
			// Offset query type
			query->type = TYPE_OTHER;
			query->qtype = type - 100;
		}

		// Status is set below
		query->domainID = domainID;
		query->clientID = clientID;
		query->upstreamID = upstreamID;
		query->id = 0;
		query->response = 0;
		query->flags.response_calculated = reply_time_avail;
		query->dnssec = dnssec;
		query->reply = reply_type;
		counters->reply[query->reply]++;
		query->response = reply_time * 1e4; // convert to tenth-millisecond unit
		query->CNAME_domainID = -1;
		// Initialize flags
		query->flags.complete = true; // Mark as all information is available
		query->flags.blocked = false;
		query->flags.whitelisted = false;
		query->flags.database = true;
		query->ede = -1; // EDE_UNSET == -1

		// Set lastQuery timer for network table
		clientsData* client = getClient(clientID, true);
		client->lastQuery = queryTimeStamp;

		// Handle type counters
		counters->querytype[query->type-1]++;

		// Update overTime data
		overTime[timeidx].total++;
		// Update overTime data structure with the new client
		change_clientcount(client, 0, 0, timeidx, 1);

		// Increase DNS queries counter
		counters->queries++;

		// Get additional information from the additional_info column if applicable
		if(status == QUERY_GRAVITY_CNAME ||
		   status == QUERY_REGEX_CNAME ||
		   status == QUERY_BLACKLIST_CNAME)
		{
			// QUERY_*_CNAME: Get domain causing the blocking
			const char *CNAMEdomain = (const char *)sqlite3_column_text(stmt, 7);
			if(CNAMEdomain != NULL && strlen(CNAMEdomain) > 0)
			{
				// Add domain to FTL's memory but do not count it. Seeing a
				// domain in the middle of a CNAME trajectory does not mean
				// it was queried intentionally.
				const int CNAMEdomainID = findDomainID(CNAMEdomain, false);
				query->CNAME_domainID = CNAMEdomainID;
			}
		}
		else if(sqlite3_column_bytes(stmt, 7) != 0)
		{
			// Set ID of the domainlist entry that was the reason for permitting/blocking this query
			// We assume the value in this field is said ID when it is not a CNAME-related domain
			// (checked above) and the value of additional_info is not NULL (0 bytes storage size)
			const int cacheID = findCacheID(query->domainID, query->clientID, query->type, true);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			// Only load if
			//  a) we have a cache entry
			if(cache != NULL)
				cache->domainlist_id = sqlite3_column_int(stmt, 7);
		}

		// Increment status counters, we first have to add one to the count of
		// unknown queries because query_set_status() will subtract from there
		// when setting a different status
		counters->status[QUERY_UNKNOWN]++;
		query_set_status(query, status);

		// Do further processing based on the query status we read from the database
		switch(status)
		{
			case QUERY_UNKNOWN: // Unknown
				break;

			case QUERY_GRAVITY: // Blocked by gravity
			case QUERY_REGEX: // Blocked by regex blacklist
			case QUERY_BLACKLIST: // Blocked by exact blacklist
			case QUERY_EXTERNAL_BLOCKED_IP: // Blocked by external provider
			case QUERY_EXTERNAL_BLOCKED_NULL: // Blocked by external provider
			case QUERY_EXTERNAL_BLOCKED_NXRA: // Blocked by external provider
			case QUERY_GRAVITY_CNAME: // Blocked by gravity (inside CNAME path)
			case QUERY_REGEX_CNAME: // Blocked by regex blacklist (inside CNAME path)
			case QUERY_BLACKLIST_CNAME: // Blocked by exact blacklist (inside CNAME path)
			case QUERY_DBBUSY: // Blocked because gravity database was busy
			case QUERY_SPECIAL_DOMAIN: // Blocked by special domain handling
				query->flags.blocked = true;
				// Get domain pointer
				domainsData* domain = getDomain(domainID, true);
				domain->blockedcount++;
				change_clientcount(client, 0, 1, -1, 0);
				break;

			case QUERY_FORWARDED: // Forwarded
			case QUERY_RETRIED: // (fall through)
			case QUERY_RETRIED_DNSSEC: // (fall through)
				// Only update upstream if there is one (there
				// won't be one for retried DNSSEC queries)
				if(upstreamID > -1)
				{
					upstreamsData *upstream = getUpstream(upstreamID, true);
					if(upstream != NULL)
					{
						upstream->overTime[timeidx]++;
						upstream->lastQuery = queryTimeStamp;
					}
				}
				break;

			case QUERY_CACHE: // Cached or local config
				// Nothing to be done here
				break;

			case QUERY_IN_PROGRESS:
				// Nothing to be done here
				break;

			case QUERY_STATUS_MAX:
			default:
				logg("Warning: Found unknown status %i in long term database!", status);
				break;
		}
	}

	unlock_shm();
	logg("Imported %i queries from the long-term database", counters->queries);

	// Update lastdbindex so that the next call to DB_save_queries()
	// skips the queries that we just imported from the database
	lastdbindex = counters->queries;

	if( rc != SQLITE_DONE ){
		logg("DB_read_queries() - SQL error step: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		goto end_of_DB_read_queries;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);

end_of_DB_read_queries:	// Close database here, we have to reopen it later (after forking)
	dbclose(&db);
}
