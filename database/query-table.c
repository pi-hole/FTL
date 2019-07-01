/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "query-table.h"
#include "common.h"
#include "sqlite3.h"
#include "datastructure.h"
#include "overTime.h"
#include "files.h"
#include "memory.h"
#include "timers.h"
#include "log.h"
#include "config.h"
#include "shmem.h"

static int number_of_queries_in_DB(void)
{
	sqlite3_stmt* stmt;

	// Count number of rows using the index timestamp is faster than select(*)
	int rc = sqlite3_prepare_v2(FTL_db, "SELECT COUNT(timestamp) FROM queries", -1, &stmt, NULL);
	if( rc ){
		logg("number_of_queries_in_DB() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();
		check_database(rc);
		return DB_FAILED;
	}

	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW ){
		logg("number_of_queries_in_DB() - SQL error step (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();
		check_database(rc);
		return DB_FAILED;
	}

	int result = sqlite3_column_int(stmt, 0);

	sqlite3_finalize(stmt);

	return result;
}

int get_number_of_queries_in_DB(void)
{
	int result = DB_NODATA;

	if(!dbopen())
	{
		logg("Failed to open FTL_db in get_number_of_queries_in_DB()");
		return DB_FAILED;
	}

	result = number_of_queries_in_DB();

	// Close database
	dbclose();

	return result;
}

void DB_save_queries(void)
{
	// Don't save anything to the database if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Start database timer
	if(config.debug & DEBUG_DATABASE) timer_start(DATABASE_WRITE_TIMER);

	// Open database
	if(!dbopen())
	{
		logg("save_to_DB() - failed to open FTL_db");
		return;
	}

	unsigned int saved = 0, saved_error = 0;
	sqlite3_stmt* stmt = NULL;

	// Get last ID stored in the database
	sqlite3_int64 lastID = last_ID_in_DB();

	bool ret = dbquery("BEGIN TRANSACTION");
	if(!ret)
	{
		logg("save_to_DB() - unable to begin transaction (%i): %s", ret, sqlite3_errmsg(FTL_db));
		dbclose();
		return;
	}

	int rc = sqlite3_prepare_v2(FTL_db, "INSERT INTO queries VALUES (NULL,?,?,?,?,?,?)", -1, &stmt, NULL);
	if( rc )
	{
		logg("save_to_DB() - error in preparing SQL statement (%i): %s", ret, sqlite3_errmsg(FTL_db));
		dbclose();
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
		sqlite3_bind_text(stmt, 4, domain, -1, SQLITE_TRANSIENT);

		// CLIENT
		const char *client = getClientIPString(queryID);
		sqlite3_bind_text(stmt, 5, client, -1, SQLITE_TRANSIENT);

		// FORWARD
		if(query->status == QUERY_FORWARDED && query->forwardID > -1)
		{
			// Get forward pointer
			const forwardedData* forward = getForward(query->forwardID, true);
			sqlite3_bind_text(stmt, 6, getstr(forward->ippos), -1, SQLITE_TRANSIENT);
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
			logg("save_to_DB() - SQL error (%i): %s", rc, sqlite3_errmsg(FTL_db));
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
	ret = dbquery("END TRANSACTION");
	int ret2 = sqlite3_finalize(stmt);
	if(!ret || ret2 != SQLITE_OK){ dbclose(); return; }

	// Store index for next loop interation round and update last time stamp
	// in the database only if all queries have been saved successfully
	if(saved > 0 && saved_error == 0)
	{
		lastdbindex = queryID;
		db_set_FTL_property(DB_LASTTIMESTAMP, newlasttimestamp);
	}

	// Update total counters in FTL_db
	if(saved > 0 && !db_update_counters(total, blocked))
	{
		dbclose();
		return;
	}

	// Close database
	dbclose();

	if(config.debug & DEBUG_DATABASE)
	{
		logg("Notice: Queries stored in FTL_db: %u (took %.1f ms, last SQLite ID %llu)", saved, timer_elapsed_msec(DATABASE_WRITE_TIMER), lastID);
		if(saved_error > 0)
			logg("        There are queries that have not been saved");
	}
}

void delete_old_queries_in_DB(void)
{
	// Open database
	if(!dbopen())
	{
		logg("Failed to open FTL_db in delete_old_queries_in_DB()");
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
	const int affected = sqlite3_changes(FTL_db);

	// Print final message only if there is a difference
	if((config.debug & DEBUG_DATABASE) || affected)
		logg("Notice: Database size is %.2f MB, deleted %i rows", get_FTL_db_filesize(), affected);

	// Close database
	dbclose();

	// Re-enable database actions
	database = true;
}

// Get most recent 24 hours data from long-term database
void DB_read_queries(void)
{
	// Don't try to load anything to the database if in PRIVACY_NOSTATS mode
	if(config.privacylevel >= PRIVACY_NOSTATS)
		return;

	// Open database file
	if(!dbopen())
	{
		logg("read_data_from_DB() - Failed to open FTL_db");
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
		logg("read_data_from_DB() - Allocation error (%i): %s", rc, sqlite3_errmsg(FTL_db));
		return;
	}
	// Log FTL_db query string in debug mode
	if(config.debug & DEBUG_DATABASE) logg("%s", rstr);

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	rc = sqlite3_prepare_v2(FTL_db, rstr, -1, &stmt, NULL);
	if( rc ){
		logg("read_data_from_DB() - SQL error prepare (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();
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
			logg("FTL_db warn: TIMESTAMP should be larger than 01/01/2017 but is %li", queryTimeStamp);
			continue;
		}
		if(queryTimeStamp > now)
		{
			if(config.debug & DEBUG_DATABASE) logg("FTL_db warn: Skipping query logged in the future (%li)", queryTimeStamp);
			continue;
		}

		const int type = sqlite3_column_int(stmt, 2);
		if(type < TYPE_A || type >= TYPE_MAX)
		{
			logg("FTL_db warn: TYPE should not be %i", type);
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
			logg("FTL_db warn: STATUS should be within [%i,%i] but is %i", QUERY_UNKNOWN, QUERY_EXTERNAL_BLOCKED_NXRA, status);
			continue;
		}

		const char * domainname = (const char *)sqlite3_column_text(stmt, 4);
		if(domainname == NULL)
		{
			logg("FTL_db warn: DOMAIN should never be NULL, %li", queryTimeStamp);
			continue;
		}

		const char * clientIP = (const char *)sqlite3_column_text(stmt, 5);
		if(clientIP == NULL)
		{
			logg("FTL_db warn: CLIENT should never be NULL, %li", queryTimeStamp);
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
				logg("FTL_db warn: FORWARD should not be NULL with status QUERY_FORWARDED, %li", queryTimeStamp);
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
		logg("read_data_from_DB() - SQL error step (%i): %s", rc, sqlite3_errmsg(FTL_db));
		dbclose();
		check_database(rc);
		return;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);
	dbclose();
	free(rstr);
}
