/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#define QUERY_TABLE_PRIVATE
#include "query-table.h"
#include "sqlite3.h"
#include "../log.h"
#include "../config.h"
#include "../enums.h"
#include "../config.h"
// counters
#include "../shmem.h"
#include "../overTime.h"
#include "common.h"
#include "../timers.h"

static sqlite3 *memdb = NULL;
static double new_last_timestamp = 0;
static unsigned int new_total = 0, new_blocked = 0;
static long last_mem_db_idx = 0, last_disk_db_idx = 0;

// Initialize in-memory database and add queries table
bool init_memory_database(void)
{
	int rc;

	// Try to open database
	rc = sqlite3_open_v2(":memory:", &memdb, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK )
	{
		logg("init_memory_database(): Step error while trying to open in-memory database: %s",
			 sqlite3_errstr(rc));
		return false;
	}

	// Explicitly set busy handler to value defined in FTL.h
	rc = sqlite3_busy_timeout(memdb, DATABASE_BUSY_TIMEOUT);
	if( rc != SQLITE_OK )
	{
		logg("init_memory_database(): Step error while trying to set busy timeout (%d ms) on in-memory database: %s",
			 DATABASE_BUSY_TIMEOUT, sqlite3_errstr(rc));
		sqlite3_close(memdb);
		return false;
	}

	// Create queries table in the database
	rc = sqlite3_exec(memdb, CREATE_QUERIES_TABLE_V7, NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		logg("init_memory_database(\"%s\") failed: %s",
			 CREATE_QUERIES_TABLE_V7, sqlite3_errstr(rc));
		sqlite3_close(memdb);
		return false;
	}

	// Add indices on all columns of the in-memory database
	for(unsigned int i = 0; i < ArraySize(index_creation); i++)
	{
		rc = sqlite3_exec(memdb, index_creation[i], NULL, NULL, NULL);
		if( rc != SQLITE_OK ){
			logg("init_memory_database(\"%s\") failed: %s",
				 index_creation[i], sqlite3_errstr(rc));
			sqlite3_close(memdb);
			return false;
		}
	}

	return true;
}

static bool get_memdb_size(size_t *memsize, unsigned int *queries)
{
	int rc;
	sqlite3_stmt* stmt = NULL;
	size_t page_count, page_size;

	// PRAGMA page_count
	rc = sqlite3_prepare_v2(memdb, "PRAGMA page_count", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			logg("init_memory_database(PRAGMA page_count): Prepare error: %s",
				 sqlite3_errstr(rc));

		return false;
	}
	rc = sqlite3_step(stmt);
	if( rc == SQLITE_ROW )
		page_count = sqlite3_column_int(stmt, 0);
	else
	{
		logg("init_memory_database(PRAGMA page_count): Step error: %s",
			 sqlite3_errstr(rc));
		return false;
	}
	sqlite3_finalize(stmt);

	// PRAGMA page_size
	rc = sqlite3_prepare_v2(memdb, "PRAGMA page_size", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			logg("init_memory_database(PRAGMA page_size): Prepare error: %s",
				 sqlite3_errstr(rc));

		return false;
	}
	rc = sqlite3_step(stmt);
	if( rc == SQLITE_ROW )
		page_size = sqlite3_column_int(stmt, 0);
	else
	{
		logg("init_memory_database(PRAGMA page_size): Step error: %s",
			 sqlite3_errstr(rc));
		return false;
	}
	sqlite3_finalize(stmt);

	*memsize = page_count * page_size;

	// Get number of queries in the memory table
	const char *querystr = "SELECT COUNT(timestamp) FROM queries";
	rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			logg("init_memory_database (%s): Prepare error: %s",
				 querystr, sqlite3_errstr(rc));

		return false;
	}
	rc = sqlite3_step(stmt);
	if( rc == SQLITE_ROW )
		*queries = sqlite3_column_int(stmt, 0);
	else
	{
		logg("init_memory_database (%s): Step error: %s",
			 querystr, sqlite3_errstr(rc));
		return false;
	}
	sqlite3_finalize(stmt);

	return true;
}

static bool attach_disk_database(void)
{
	int rc;
	bool okay = false;
	sqlite3_stmt* stmt = NULL;

	// ATTACH database file on-disk
	rc = sqlite3_prepare_v2(memdb, "ATTACH :path AS disk", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		if( rc != SQLITE_BUSY )
			logg("attach_disk_database(): Prepare error: %s", sqlite3_errstr(rc));

		return false;
	}
	// Bind type to prepared statement (if requested)
	const int path_idx = sqlite3_bind_parameter_index(stmt, ":path");
	if((rc = sqlite3_bind_text(stmt, path_idx, FTLfiles.FTL_db, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("attach_disk_database(): Failed to bind path: %s",
			 sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		logg("attach_disk_database(): Failed to attach database: %s",
			 sqlite3_errstr(rc));

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return okay;
}

static bool detach_disk_database(void)
{
	int rc;

	// Detach database
	rc = sqlite3_exec(memdb, "DETACH disk", NULL, NULL, NULL);
	if( rc != SQLITE_OK ){
		logg("detach_disk_database() failed: %s",
			 sqlite3_errstr(rc));
		sqlite3_close(memdb);
		return false;
	}

	size_t memsize = 0;
	unsigned int queries = 0;
	if((config.debug & DEBUG_DATABASE) && get_memdb_size(&memsize, &queries))
	{
		char prefix[2] = { 0 };
		double num = 0.0;
		format_memory_size(prefix, memsize, &num);
		logg("In-memory database size: %.1f%s (%u queries)",
		     num, prefix, queries);
	}

	return true;
}

// Get number of queries either in the in-memory or in the on-diks database
// This routine is used by the API routines.
int get_number_of_queries_in_DB(bool disk)
{
	// Attach disk database if required
	if(disk && !attach_disk_database())
		return DB_FAILED;

	// Count number of rows using the index timestamp is faster than select(*)
	const char *querystr = disk ? "SELECT COUNT(timestamp) FROM disk.queries" : "SELECT COUNT(timestamp) FROM queries";
	int result = db_query_int(querystr);

	if(disk && !detach_disk_database())
		return DB_FAILED;

	return result;
}

bool import_queries_from_disk(void)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const double now = double_time();
	const double mintime = now - config.maxlogage;
	const char *querystr = "INSERT INTO queries SELECT * FROM disk.queries WHERE timestamp >= ?";

	// Attach disk database
	if(!attach_disk_database())
		return false;

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("import_queries_from_disk(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind limit
	if((rc = sqlite3_bind_double(stmt, 1, mintime)) != SQLITE_OK)
	{
		logg("import_queries_from_disk(): Failed to bind type mintime: %s", sqlite3_errstr(rc));
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		logg("import_queries_from_disk(): Failed to import queries: %s",
			 sqlite3_errstr(rc));

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(!detach_disk_database())
		return false;
	
	return okay;
}

bool export_queries_to_disk(bool final)
{
	// Get time stamp 24 hours (or what was configured) in the past
	bool okay = false;
	const char *querystr = "INSERT INTO disk.queries SELECT * FROM queries WHERE id > ? AND timestamp < ?";

	// Start database timer
	if(config.debug & DEBUG_DATABASE)
		timer_start(DATABASE_WRITE_TIMER);

	// Attach disk database
	if(!attach_disk_database())
		return false;

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("import_queries_from_disk(): SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind index
	if((rc = sqlite3_bind_int64(stmt, 1, last_disk_db_idx)) != SQLITE_OK)
	{
		logg("import_queries_from_disk(): Failed to bind type id: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind upper time limit
	
	// This prevents queries from the last 30 seconds from being stored
	// immediately on-disk to give them some time to complete before finally
	// exported. We do not limit anything when storing during termination.
	const double time = double_time() - (final ? 0.0 : 30.0);
	if((rc = sqlite3_bind_int64(stmt, 2, time)) != SQLITE_OK)
	{
		logg("import_queries_from_disk(): Failed to bind type time: %s", sqlite3_errstr(rc));
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
		okay = true;
	else
		logg("import_queries_from_disk(): Failed to import queries: %s",
			 sqlite3_errstr(rc));

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(!detach_disk_database())
		return false;

	// All in-memory queries were stored to disk, update the IDs
	unsigned int saved = last_mem_db_idx - last_disk_db_idx;
	last_disk_db_idx = last_mem_db_idx;

	if(saved > 0)
	{
		db_set_FTL_property_double(DB_LASTTIMESTAMP, new_last_timestamp);
		db_update_counters(new_total, new_blocked);
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("Notice: Queries stored in long-term database: %u (took %.1f ms, last SQLite ID %li)",
		     saved, timer_elapsed_msec(DATABASE_WRITE_TIMER), last_disk_db_idx);
	}
	
	return okay;
}

// Get most recent 24 hours data from in-memory long-term database
void DB_read_queries(void)
{
	// Prepare request
	// Get time stamp 24 hours in the past
	const char *querystr = "SELECT * FROM queries";

	// Prepare SQLite3 statement
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("DB_read_queries() - SQL error prepare: %s", sqlite3_errstr(rc));
		dbclose();
		return;
	}

	// Loop through returned database rows
	sqlite3_int64 dbid = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		dbid = sqlite3_column_int64(stmt, 0);
		const double queryTimeStamp = sqlite3_column_double(stmt, 1);
		// 1483228800 = 01/01/2017 @ 12:00am (UTC)
		if(queryTimeStamp < 1483228800)
		{
			logg("FTL_db warn: TIMESTAMP should be larger than 01/01/2017 but is %f", queryTimeStamp);
			continue;
		}

		const int type = sqlite3_column_int(stmt, 2);
		const bool mapped_type = type >= TYPE_A && type < TYPE_MAX;
		const bool offset_type = type > 100 && type < (100 + UINT16_MAX);
		if(!mapped_type && !offset_type)
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

		const int status_int = sqlite3_column_int(stmt, 3);
		if(status_int < QUERY_UNKNOWN || status_int >= QUERY_STATUS_MAX)
		{
			logg("FTL_db warn: STATUS should be within [%i,%i] but is %i", QUERY_UNKNOWN, QUERY_STATUS_MAX-1, status_int);
			continue;
		}
		const enum query_status status = status_int;

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

		// Ensure we have enough space in the queries struct
		memory_check(QUERIES);

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

		query->status = status;
		query->domainID = domainID;
		query->clientID = clientID;
		query->upstreamID = upstreamID;
		query->timeidx = timeidx;
		query->db = dbid;
		query->id = 0;
		query->response = 0;
		query->dnssec = DNSSEC_UNKNOWN;
		query->reply = REPLY_UNKNOWN;
		query->CNAME_domainID = -1;
		// Initialize flags
		query->flags.complete = true; // Mark as all information is available
		query->flags.blocked = false;
		query->flags.whitelisted = false;

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
				cache->deny_regex_id = sqlite3_column_int(stmt, 7);
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
				query->flags.blocked = true;
				// Get domain pointer
				domainsData* domain = getDomain(domainID, true);
				domain->blockedcount++;
				change_clientcount(client, 0, 1, -1, 0);
				// Update overTime data structure
				overTime[timeidx].blocked++;
				break;

			case QUERY_FORWARDED: // Forwarded
			case QUERY_RETRIED: // (fall through)
			case QUERY_RETRIED_DNSSEC: // (fall through)
				counters->forwarded++;
				upstreamsData *upstream = getUpstream(upstreamID, true);
				if(upstream != NULL)
				{
					upstream->count++;
					upstream->lastQuery = queryTimeStamp;
				}
				// Update overTime data structure
				overTime[timeidx].forwarded++;
				break;

			case QUERY_CACHE: // Cached or local config
				counters->cached++;
				// Update overTime data structure
				overTime[timeidx].cached++;
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
	logg("Imported %i queries from the long-term database", counters->queries);

	// Update lastdbindex so that the next call to DB_save_queries()
	// skips the queries that we just imported from the database
	last_disk_db_idx = dbid;
	last_mem_db_idx = dbid;

	if( rc != SQLITE_DONE ){
		logg("DB_read_queries() - SQL error step: %s", sqlite3_errstr(rc));
		dbclose();
		return;
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);

	// Close database here, we have to reopen it later (after forking)
	dbclose();
}

bool query_to_database(queriesData* query)
{
	int rc;
	sqlite3_int64 idx = 0;
	sqlite3_stmt* stmt = NULL;


	if(query->privacylevel >= PRIVACY_MAXIMUM)
	{
		// Skip, we never store nor count queries recorded
		// while have been in maximum privacy mode in the database
		if(config.debug & DEBUG_DATABASE)
			logg("Storing storing in database due to privacy level");
		return true;
	}

	// Start preparing INSERT query
	rc = sqlite3_prepare_v2(FTL_db, "REPLACE INTO queries VALUES (?,?,?,?,?,?,?,?)", -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("query_to_database() - SQL error step: %s", sqlite3_errstr(rc));
		return false;
	}

	// Explicitly set ID to match what is in the on-disk database
	if(query->db != 0)
	{
		// We update an existing query
		idx = query->db;
	}
	else
	{
		// We create a new query
		idx = last_mem_db_idx + 1;
	}
	// INDEX
	sqlite3_bind_int64(stmt, 1, idx);

	// TIMESTAMP
	sqlite3_bind_double(stmt, 2, query->timestamp);

	// TYPE
	if(query->type != TYPE_OTHER)
	{
		// Store mapped type if query->type is not OTHER
		sqlite3_bind_int(stmt, 3, query->type);
	}
	else
	{
		// Store query type + offset if query-> type is OTHER
		sqlite3_bind_int(stmt, 3, query->qtype + 100);
	}

	// STATUS
	sqlite3_bind_int(stmt, 4, query->status);

	// DOMAIN
	const char *domain = getDomainString(query);
	sqlite3_bind_text(stmt, 5, domain, -1, SQLITE_STATIC);

	// CLIENT
	const char *client = getClientIPString(query);
	sqlite3_bind_text(stmt, 6, client, -1, SQLITE_STATIC);

	// FORWARD
	if(query->upstreamID > -1)
	{
		// Get forward pointer
		const upstreamsData* upstream = getUpstream(query->upstreamID, true);
		char *buffer = NULL;
		if(asprintf(&buffer, "%s#%u", getstr(upstream->ippos), upstream->port) > 0)
			sqlite3_bind_text(stmt, 7, buffer, -1, SQLITE_TRANSIENT);
		else
			sqlite3_bind_null(stmt, 7);

		if(buffer != NULL)
			free(buffer);
	}
	else
	{
		sqlite3_bind_null(stmt, 7);
	}

	// ADDITIONAL_INFO
	if(query->status == QUERY_GRAVITY_CNAME ||
		query->status == QUERY_REGEX_CNAME ||
		query->status == QUERY_BLACKLIST_CNAME)
	{
		// Restore domain blocked during deep CNAME inspection if applicable
		const char *cname = getCNAMEDomainString(query);
		sqlite3_bind_text(stmt, 8, cname, -1, SQLITE_STATIC);
	}
	else if(query->status == QUERY_REGEX)
	{
		// Restore regex ID if applicable
		const int cacheID = findCacheID(query->domainID, query->clientID, query->type);
		DNSCacheData *cache = getDNSCache(cacheID, true);
		if(cache != NULL)
			sqlite3_bind_int(stmt, 8, cache->deny_regex_id);
		else
			sqlite3_bind_null(stmt, 8);
	}
	else
	{
		// Nothing to add here
		sqlite3_bind_null(stmt, 8);
	}

	// Step and check if successful
	rc = sqlite3_step(stmt);
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);

	if( rc != SQLITE_DONE )
	{
		logg("Encountered error while trying to store queries in in-memory database: %s",
		     sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return false;
	}

	// Update fields if this is a new query (skip if we are only updating an
	// existing entry)
	if(query->db == 0)
	{
		// Store database index for this query (in case we need to
		// update it later on)
		query->db = ++last_mem_db_idx;

		// Total counter information (delta computation)
		new_total++;
		if(query->flags.blocked)
			new_blocked++;

		// Update lasttimestamp variable with timestamp of the latest stored query
		if(query->timestamp > new_last_timestamp)
			new_last_timestamp = query->timestamp;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("Stored query in internal database (ID %lli)", idx);

	if((rc = sqlite3_finalize(stmt)) != SQLITE_OK)
	{
		logg("Statement finalization failed when trying to store queries to in-memory database: %s",
		     sqlite3_errstr(rc));
		return false;
	}

	return true;
}
