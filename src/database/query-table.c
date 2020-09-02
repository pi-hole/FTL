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

int get_number_of_queries_in_DB(void)
{
	// This routine is used by the API routines.
	// We need to handle opening/closing of the database herein.
	if(!dbopen())
	{
		return DB_FAILED;
	}

	// Count number of rows using the index timestamp is faster than select(*)
	int result = db_query_int("SELECT COUNT(timestamp) FROM queries");

	// Close pihole-FTL.db database connection
	dbclose();

	return result;
}

void DB_save_queries(void)
{
	// Start database timer
	if(config.debug & DEBUG_DATABASE)
		timer_start(DATABASE_WRITE_TIMER);

	// Open database
	if(!dbopen())
	{
		logg("Failed to open long-term database when trying to store queries");
		return;
	}

	unsigned int saved = 0;
	bool error = false;
	sqlite3_stmt* stmt = NULL;

	int rc = dbquery("BEGIN TRANSACTION IMMEDIATE");
	if( rc != SQLITE_OK )
	{
		const char *text;
		if( rc == SQLITE_BUSY )
		{
			text = "WARNING";
		}
		else
		{
			text = "ERROR";
			// We shall not use the database any longer
			database = false;
		}

		logg("%s: Storing queries in long-term database failed: %s", text, sqlite3_errstr(rc));
		dbclose();
		return;
	}

	rc = sqlite3_prepare_v2(FTL_db, "INSERT INTO queries VALUES (NULL,?,?,?,?,?,?,?)", -1, &stmt, NULL);
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
			// We shall not use the database any longer
			database = false;
		}

		// dbquery() above already logs the reson for why the query failed
		logg("%s: Storing queries in long-term database failed: %s\n", text, sqlite3_errstr(rc));
		logg("%s  Keeping queries in memory for later new attempt", spaces);
		saving_failed_before = true;
		dbclose();
		return;
	}

	// Get last ID stored in the database
	long int lastID = get_max_query_ID();

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
		const char *domain = getDomainString(query);
		sqlite3_bind_text(stmt, 4, domain, -1, SQLITE_STATIC);

		// CLIENT
		const char *client = getClientIPString(query);
		sqlite3_bind_text(stmt, 5, client, -1, SQLITE_STATIC);

		// FORWARD
		if(query->status == QUERY_FORWARDED && query->upstreamID > -1)
		{
			// Get forward pointer
			const upstreamsData* upstream = getUpstream(query->upstreamID, true);
			sqlite3_bind_text(stmt, 6, getstr(upstream->ippos), -1, SQLITE_STATIC);
		}
		else
		{
			sqlite3_bind_null(stmt, 6);
		}

		// ADDITIONAL_INFO
		if(query->status == QUERY_GRAVITY_CNAME ||
		   query->status == QUERY_REGEX_CNAME ||
		   query->status == QUERY_BLACKLIST_CNAME)
		{
			// Restore domain blocked during deep CNAME inspection if applicable
			const char* cname = getCNAMEDomainString(query);
			sqlite3_bind_text(stmt, 7, cname, -1, SQLITE_STATIC);
		}
		else if(query->status == QUERY_REGEX)
		{
			// Restore regex ID if applicable
			const int cacheID = findCacheID(query->domainID, query->clientID, query->type);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			if(cache != NULL)
				sqlite3_bind_int(stmt, 7, cache->black_regex_idx);
			else
				sqlite3_bind_null(stmt, 7);
		}
		else
		{
			// Nothing to add here
			sqlite3_bind_null(stmt, 7);
		}

		// Step and check if successful
		rc = sqlite3_step(stmt);
		sqlite3_clear_bindings(stmt);
		sqlite3_reset(stmt);

		if( rc != SQLITE_DONE )
		{
			logg("Encountered error while trying to store queries in long-term database: %s", sqlite3_errstr(rc));
			error = true;
			break;
		}

		saved++;
		// Mark this query as saved in the database by setting the corresponding ID
		query->db = ++lastID;

		// Total counter information (delta computation)
		total++;
		if(query->status == QUERY_GRAVITY ||
		   query->status == QUERY_BLACKLIST ||
		   query->status == QUERY_REGEX ||
		   query->status == QUERY_EXTERNAL_BLOCKED_IP ||
		   query->status == QUERY_EXTERNAL_BLOCKED_NULL ||
		   query->status == QUERY_EXTERNAL_BLOCKED_NXRA ||
		   query->status == QUERY_GRAVITY_CNAME ||
		   query->status == QUERY_REGEX_CNAME ||
		   query->status == QUERY_BLACKLIST_CNAME)
			blocked++;

		// Update lasttimestamp variable with timestamp of the latest stored query
		if(query->timestamp > newlasttimestamp)
			newlasttimestamp = query->timestamp;
	}

	if((rc = sqlite3_finalize(stmt)) != SQLITE_OK)
	{
		logg("Statement finalization failed when trying to store queries to long-term database: %s",
		     sqlite3_errstr(rc));

		if( rc == SQLITE_BUSY )
		{
			logg("Keeping queries in memory for later new attempt");
			saving_failed_before = true;
		}
		else
		{
			database = false;
		}

		dbclose();
		return;
	}

	// Finish prepared statement
	if((rc = dbquery("END TRANSACTION")) != SQLITE_OK)
	{
		// No need to log the error string here, dbquery() did that already above
		logg("END TRANSACTION failed when trying to store queries to long-term database");

		if( rc == SQLITE_BUSY )
		{
			logg("Keeping queries in memory for later new attempt");
			saving_failed_before = true;
		}
		else
		{
			database = false;
		}

		dbclose();
		return;
	}

	// Store index for next loop interation round and update last time stamp
	// in the database only if all queries have been saved successfully
	if(saved > 0 && !error)
	{
		lastdbindex = queryID;
		db_set_FTL_property(DB_LASTTIMESTAMP, newlasttimestamp);
		db_update_counters(total, blocked);
	}

	// Close database
	dbclose();

	if(config.debug & DEBUG_DATABASE || saving_failed_before)
	{
		logg("Notice: Queries stored in long-term database: %u (took %.1f ms, last SQLite ID %li)", saved, timer_elapsed_msec(DATABASE_WRITE_TIMER), lastID);
		if(saving_failed_before)
		{
			logg("        Queries from earlier attempt(s) stored successfully");
			saving_failed_before = false;
		}
	}
}

void delete_old_queries_in_DB(void)
{
	// Open database
	if(!dbopen())
	{
		logg("Failed to open long-term database when trying to delete old queries");
		return;
	}

	int timestamp = time(NULL) - config.maxDBdays * 86400;

	if(dbquery("DELETE FROM queries WHERE timestamp <= %i", timestamp) != SQLITE_OK)
	{
		logg("delete_old_queries_in_DB(): Deleting queries due to age of entries failed!");
		return;
	}

	// Get how many rows have been affected (deleted)
	const int affected = sqlite3_changes(FTL_db);

	// Print final message only if there is a difference
	if((config.debug & DEBUG_DATABASE) || affected)
		logg("Notice: Database size is %.2f MB, deleted %i rows", 1e-6*get_FTL_db_filesize(), affected);

	// Close database
	dbclose();
}

// Get most recent 24 hours data from long-term database
void DB_read_queries(void)
{
	// Open database file
	if(!dbopen())
	{
		logg("Failed to open long-term database when trying to read queries");
		return;
	}

	// Prepare request
	// Get time stamp 24 hours in the past
	const time_t now = time(NULL);
	const time_t mintime = now - config.maxlogage;
	const char *querystr = "SELECT * FROM queries WHERE timestamp >= ?";
	// Log FTL_db query string in debug mode
	if(config.debug & DEBUG_DATABASE)
		logg("DB_read_queries(): \"%s\" with ? = %lli", querystr, (long long)mintime);

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("DB_read_queries() - SQL error prepare: %s", sqlite3_errstr(rc));
		dbclose();
		return;
	}

	// Bind limit
	if((rc = sqlite3_bind_int(stmt, 1, mintime)) != SQLITE_OK)
	{
		logg("DB_read_queries() - Failed to bind type mintime: %s", sqlite3_errstr(rc));
		dbclose();
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
			logg("FTL_db warn: TIMESTAMP should be larger than 01/01/2017 but is %lli", (long long)queryTimeStamp);
			continue;
		}
		if(queryTimeStamp > now)
		{
			if(config.debug & DEBUG_DATABASE) logg("FTL_db warn: Skipping query logged in the future (%lli)", (long long)queryTimeStamp);
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
		if(status < QUERY_UNKNOWN || status >= QUERY_STATUS_MAX)
		{
			logg("FTL_db warn: STATUS should be within [%i,%i] but is %i", QUERY_UNKNOWN, QUERY_STATUS_MAX-1, status);
			continue;
		}

		const char * domainname = (const char *)sqlite3_column_text(stmt, 4);
		if(domainname == NULL)
		{
			logg("FTL_db warn: DOMAIN should never be NULL, %lli", (long long)queryTimeStamp);
			continue;
		}

		const char * clientIP = (const char *)sqlite3_column_text(stmt, 5);
		if(clientIP == NULL)
		{
			logg("FTL_db warn: CLIENT should never be NULL, %lli", (long long)queryTimeStamp);
			continue;
		}

		// Check if user wants to skip queries coming from localhost
		if(config.ignore_localhost &&
		   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
		{
			continue;
		}

		const char *upstream = (const char *)sqlite3_column_text(stmt, 6);
		int upstreamID = 0;
		// Determine upstreamID only when status == 2 (forwarded) as the
		// field need not to be filled for other query status types
		if(status == QUERY_FORWARDED)
		{
			if(upstream == NULL)
			{
				logg("WARN (during database import): FORWARD should not be NULL with status QUERY_FORWARDED (timestamp: %lli), skipping entry",
				     (long long)queryTimeStamp);
				continue;
			}
			upstreamID = findUpstreamID(upstream, true);
		}

		// Obtain IDs only after filtering which queries we want to keep
		const int timeidx = getOverTimeID(queryTimeStamp);
		const int domainID = findDomainID(domainname, true);
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
		query->upstreamID = upstreamID;
		query->timeidx = timeidx;
		query->db = dbid;
		query->id = 0;
		query->complete = true; // Mark as all information is available
		query->response = 0;
		query->dnssec = DNSSEC_UNSPECIFIED;
		query->reply = REPLY_UNKNOWN;
		query->CNAME_domainID = -1;

		// Set lastQuery timer for network table
		clientsData* client = getClient(clientID, true);
		client->lastQuery = queryTimeStamp;

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

		// Get additional information from the additional_info column if applicable
		if(status == QUERY_GRAVITY_CNAME ||
		   status == QUERY_REGEX_CNAME ||
		   status == QUERY_BLACKLIST_CNAME)
		{
			// QUERY_*_CNAME: Getdomain causing the blocking
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
		else if(status == QUERY_REGEX)
		{
			// QUERY_REGEX: Set ID regex which was the reson for blocking
			const int cacheID = findCacheID(query->domainID, query->clientID, query->type);
			DNSCacheData *cache = getDNSCache(cacheID, true);
			// Only load if
			//  a) we have a chace entry
			//  b) the value of additional_info is not NULL (0 bytes storage size)
			if(cache != NULL && sqlite3_column_bytes(stmt, 7) != 0)
				cache->black_regex_idx = sqlite3_column_int(stmt, 7);
		}

		// Increment status counters
		switch(status)
		{
			case QUERY_UNKNOWN: // Unknown
				counters->unknown++;
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
				counters->blocked++;
				// Get domain pointer
				domainsData* domain = getDomain(domainID, true);
				domain->blockedcount++;
				client->blockedcount++;
				// Update overTime data structure
				overTime[timeidx].blocked++;
				break;

			case QUERY_FORWARDED: // Forwarded
				counters->forwarded++;
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
				logg("       Timestamp: %lli", (long long)queryTimeStamp);
				logg("       Continuing anyway...");
				break;
		}
	}
	logg("Imported %i queries from the long-term database", counters->queries);

	// Update lastdbindex so that the next call to DB_save_queries()
	// skips the queries that we just imported from the database
	lastdbindex = counters->queries;

	if( rc != SQLITE_DONE ){
		logg("DB_read_queries() - SQL error step: %s", sqlite3_errstr(rc));
		dbclose();
		return;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);
	dbclose();
}
