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
	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false)) == NULL)
		{
			logg("get_number_of_queries_in_DB() - Failed to open DB");
			return -1;
		}

		// Successful
		db_opened = true;
	}

	// Count number of rows using the index timestamp is faster than select(*)
	int result = db_query_int(db, "SELECT COUNT(timestamp) FROM queries");

	if(db_opened)
		dbclose(&db);

	return result;
}

int DB_save_queries(sqlite3 *db)
{
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
			return -1;
		}

		// Successful
		db_opened = true;
	}

	int saved = 0;
	bool error = false;
	sqlite3_stmt* stmt = NULL;

	int rc = dbquery(db, "BEGIN TRANSACTION IMMEDIATE");
	if( rc != SQLITE_OK )
	{
		const char *text;
		if( rc == SQLITE_BUSY )
			text = "WARNING";
		else
			text = "ERROR";

		logg("%s: Storing queries in long-term database failed: %s", text, sqlite3_errstr(rc));
		if(db_opened)
			dbclose(&db);
		return -1;
	}

	rc = sqlite3_prepare_v2(db, "INSERT INTO queries VALUES (NULL,?,?,?,?,?,?,?)", -1, &stmt, NULL);
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

		// dbquery() above already logs the reson for why the query failed
		logg("%s: Storing queries in long-term database failed: %s\n", text, sqlite3_errstr(rc));
		logg("%s  Keeping queries in memory for later new attempt", spaces);
		saving_failed_before = true;
		if(db_opened)
			dbclose(&db);
		return -1;
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
		sqlite3_bind_int(stmt, 1, query->timestamp);

		// TYPE
		if(query->type != TYPE_OTHER)
		{
			// Store mapped type if query->type is not OTHER
			sqlite3_bind_int(stmt, 2, query->type);
		}
		else
		{
			// Store query type + offset if query-> type is OTHER
			sqlite3_bind_int(stmt, 2, query->qtype + 100);
		}

		// STATUS
		sqlite3_bind_int(stmt, 3, query->status);

		// DOMAIN
		const char *domain = getDomainString(query);
		sqlite3_bind_text(stmt, 4, domain, -1, SQLITE_STATIC);

		// CLIENT
		const char *client = getClientIPString(query);
		sqlite3_bind_text(stmt, 5, client, -1, SQLITE_STATIC);

		// FORWARD
		if(query->upstreamID > -1)
		{
			// Get forward pointer
			const upstreamsData* upstream = getUpstream(query->upstreamID, true);
			char *buffer = NULL;
			if(asprintf(&buffer, "%s#%u", getstr(upstream->ippos), upstream->port) > 0)
				sqlite3_bind_text(stmt, 6, buffer, -1, SQLITE_TRANSIENT);
			else
				sqlite3_bind_null(stmt, 6);

			if(buffer != NULL)
				free(buffer);
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

	if((rc = sqlite3_finalize(stmt)) != SQLITE_OK)
	{
		logg("Statement finalization failed when trying to store queries to long-term database: %s",
		     sqlite3_errstr(rc));

		if( rc == SQLITE_BUSY )
		{
			logg("Keeping queries in memory for later new attempt");
			saving_failed_before = true;
		}

		if(db_opened)
			dbclose(&db);

		return -1;
	}

	// Finish prepared statement
	if((rc = dbquery(db,"END TRANSACTION")) != SQLITE_OK)
	{
		// No need to log the error string here, dbquery() did that already above
		logg("END TRANSACTION failed when trying to store queries to long-term database");

		if( rc == SQLITE_BUSY )
		{
			logg("Keeping queries in memory for later new attempt");
			saving_failed_before = true;
		}

		if(db_opened)
			dbclose(&db);

		return -1;
	}

	// Store index for next loop interation round and update last time stamp
	// in the database only if all queries have been saved successfully
	if(saved > 0 && !error)
	{
		lastdbindex = queryID;
		db_set_FTL_property(db, DB_LASTTIMESTAMP, newlasttimestamp);
		db_update_counters(db, total, blocked);
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

	if(db_opened)
		dbclose(&db);

	return saved;
}

void delete_old_queries_in_DB(sqlite3 *db)
{
	int timestamp = time(NULL) - config.maxDBdays * 86400;

	if(dbquery(db, "DELETE FROM queries WHERE timestamp <= %i", timestamp) != SQLITE_OK)
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

// Get most recent 24 hours data from long-term database
void DB_read_queries(void)
{
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
	const char *querystr = "SELECT * FROM queries WHERE timestamp >= ?";
	// Log FTL_db query string in debug mode
	if(config.debug & DEBUG_DATABASE)
		logg("DB_read_queries(): \"%s\" with ? = %lli", querystr, (long long)mintime);

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("DB_read_queries() - SQL error prepare: %s", sqlite3_errstr(rc));
		dbclose(&db);
		return;
	}

	// Bind limit
	if((rc = sqlite3_bind_int(stmt, 1, mintime)) != SQLITE_OK)
	{
		logg("DB_read_queries() - Failed to bind type mintime: %s", sqlite3_errstr(rc));
		dbclose(&db);
		return;
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
		if(status_int < QUERY_UNKNOWN || status_int >= QUERY_STATUS_MAX)
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
			query->type = type;
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
		query->dnssec = DNSSEC_UNSPECIFIED;
		query->reply = REPLY_UNKNOWN;
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
		if(type >= TYPE_A && type < TYPE_MAX)
			counters->querytype[type-1]++;

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
		dbclose(&db);
		return;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);

	// Close database here, we have to reopen it later (after forking)
	dbclose(&db);
}
