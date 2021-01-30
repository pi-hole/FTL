/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API database statistics implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
#include "../shmem.h"
// querytypes[]
#include "../datastructure.h"
// logg()
#include "log.h"
// FTL_db
#include "../database/common.h"

int api_stats_database_overTime_history(struct ftl_conn *api)
{
	unsigned int from = 0, until = 0;
	const int interval = 600;
	if(api->request->query_string != NULL)
	{
		get_uint_var(api->request->query_string, "from", &from);
		get_uint_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(until == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify \"until\" in the request.",
		                       json);
	}

	// Unlock shared memory (DNS resolver can continue to work while we're preforming database queries)
	unlock_shm();

	// Open the database (this also locks the database)
	dbopen();

	// Build SQL string
	const char *querystr = "SELECT (timestamp/:interval)*:interval interval,status,COUNT(*) FROM queries "
	                       "WHERE (status != 0) AND timestamp >= :from AND timestamp <= :until "
	                       "GROUP by interval,status ORDER by interval";


	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("api_stats_database_overTime_history() - SQL error prepare (%i): %s",
		     rc, sqlite3_errmsg(FTL_db));
		return false;
	}

	// Bind interval to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, interval)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_history(): Failed to bind interval (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind interval",
		                       json);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_int(stmt, 2, from)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_history(): Failed to bind from (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       json);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_int(stmt, 3, until)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_history(): Failed to bind until (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       json);
	}

	// Loop over and accumulate results
	cJSON *json = JSON_NEW_ARRAY();
	cJSON *item = NULL;
	int previous_timestamp = 0, blocked = 0, total = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const int timestamp = sqlite3_column_int(stmt, 0);
		// Begin new array item for each new timestamp
		if(timestamp != previous_timestamp)
		{
			previous_timestamp = timestamp;
			if(item != NULL)
			{
				JSON_OBJ_ADD_NUMBER(item, "total_queries", total);
				total = 0;
				JSON_OBJ_ADD_NUMBER(item, "blocked_queries", blocked);
				blocked = 0;
				JSON_ARRAY_ADD_ITEM(json, item);
			}

			item = JSON_NEW_OBJ();
			JSON_OBJ_ADD_NUMBER(item, "timestamp", timestamp);
		}

		const int status = sqlite3_column_int(stmt, 1);
		const int count = sqlite3_column_int(stmt, 2);
		// Always add to total count
		total += count;

		// Add to blocked count if this is the result for a blocked status
		switch (status)
		{
		case QUERY_GRAVITY:
		case QUERY_REGEX:
		case QUERY_BLACKLIST:
		case QUERY_EXTERNAL_BLOCKED_IP:
		case QUERY_EXTERNAL_BLOCKED_NULL:
		case QUERY_EXTERNAL_BLOCKED_NXRA:
			blocked += count;
			break;
		
		default:
			break;
		}
	}

	// Finalize statement and close (= unlock) database connection
	sqlite3_finalize(stmt);
	dbclose();

	// Re-lock shared memory before returning back to router subroutine
	lock_shm();
	JSON_SEND_OBJECT(json);
}

int api_stats_database_top_items(bool blocked, bool domains, struct ftl_conn *api)
{
	unsigned int from = 0, until = 0, show = 10;
	if(api->request->query_string != NULL)
	{
		get_uint_var(api->request->query_string, "from", &from);
		get_uint_var(api->request->query_string, "until", &until);

		// Get blocked queries not only for .../top_blocked
		// but also for .../top_domains?blocked=true
		// Note: this may overwrite the blocked propery from the URL
		get_bool_var(api->request->query_string, "blocked", &blocked);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_uint_var(api->request->query_string, "show", &show);
	}

	// Check if we received the required information
	if(from == 0 || until == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       json);
	}

	// Unlock shared memory (DNS resolver can continue to work while we're preforming database queries)
	unlock_shm();

	// Open the database (this also locks the database)
	dbopen();

	// Build SQL string
	const char *querystr;
	if(domains)
	{
		if(!blocked)
		{
			querystr = "SELECT domain,COUNT(*) AS cnt FROM queries "
			           "WHERE (status == 2 OR status == 3) "
			           "AND timestamp >= :from AND timestamp <= :until "
			           "GROUP by domain ORDER by cnt DESC "
			           "LIMIT :show";
		}
		else
		{
			querystr = "SELECT domain,COUNT(*) AS cnt FROM queries "
			           "WHERE status != 0 AND status != 2 AND status != 3 "
			           "AND timestamp >= :from AND timestamp <= :until "
			           "GROUP by domain ORDER by cnt DESC "
			           "LIMIT :show";
		}
	}
	else
	{
		if(!blocked)
		{
			querystr = "SELECT client,COUNT(*) AS cnt FROM queries "
			           "WHERE (status == 2 OR status == 3) "
			           "AND timestamp >= :from AND timestamp <= :until "
			           "GROUP by client ORDER by cnt DESC "
			           "LIMIT :show";
		}
		else
		{
			querystr = "SELECT client,COUNT(*) AS cnt FROM queries "
			           "WHERE status != 0 AND status != 2 AND status != 3 "
			           "AND timestamp >= :from AND timestamp <= :until "
			           "GROUP by client ORDER by cnt DESC "
			           "LIMIT :show";
		}
	}
	
	
	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("api_stats_database_overTime_history() - SQL error prepare (%i): %s",
		     rc, sqlite3_errmsg(FTL_db));

		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		JSON_OBJ_REF_STR(json, "querystr", querystr);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare query string",
		                       json);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, from)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_history(): Failed to bind from (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       json);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_int(stmt, 2, until)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_history(): Failed to bind until (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       json);
	}

	// Bind show to prepared statement
	if((rc = sqlite3_bind_int(stmt, 3, show)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_history(): Failed to bind show (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind show",
		                       json);
	}

	// Loop over and accumulate results
	cJSON *top_items = JSON_NEW_ARRAY();
	int total = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const char* string = (char*)sqlite3_column_text(stmt, 0);
		const int count = sqlite3_column_int(stmt, 1);
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(item, (domains ? "domain" : "ip"), string);
		// Add empty name field for top_client requests
		if(!domains)
		{
			JSON_OBJ_REF_STR(item, "name", "");
		}
		JSON_OBJ_ADD_NUMBER(item, "count", count);
		JSON_ARRAY_ADD_ITEM(top_items, item);
		total += count;
	}

	// Finalize statement and close (= unlock) database connection
	sqlite3_finalize(stmt);
	dbclose();

	// Re-lock shared memory before returning back to router subroutine
	lock_shm();

	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, (domains ? "top_domains" : "top_clients"), top_items);
	JSON_OBJ_ADD_NUMBER(json, (blocked ? "blocked_queries" : "total_queries"), total);
	JSON_SEND_OBJECT(json);
}

int api_stats_database_summary(struct ftl_conn *api)
{
	unsigned int from = 0, until = 0;
	if(api->request->query_string != NULL)
	{
		get_uint_var(api->request->query_string, "from", &from);
		get_uint_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from == 0 || until == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       json);
	}

	// Unlock shared memory (DNS resolver can continue to work while we're preforming database queries)
	unlock_shm();

	// Open the database (this also locks the database)
	dbopen();

	// Perform SQL queries
	const char *querystr;
	querystr = "SELECT COUNT(*) FROM queries "
	           "WHERE timestamp >= :from AND timestamp <= :until";
	int sum_queries = db_query_int_from_until(querystr, from, until);

	querystr = "SELECT COUNT(*) FROM queries "
	           "WHERE timestamp >= :from AND timestamp <= :until "
		   "AND status != 0 AND status != 2 AND status != 3";
	int blocked_queries = db_query_int_from_until(querystr, from, until);

	querystr = "SELECT COUNT(DISTINCT client) FROM queries "
	           "WHERE timestamp >= :from AND timestamp <= :until";
	int total_clients = db_query_int_from_until(querystr, from, until);

	float percent_blocked = 1e2f*blocked_queries/sum_queries;

	if(sum_queries < 0 || blocked_queries < 0 || total_clients < 0)
	{

		// Close (= unlock) database connection
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error",
		                       json);
	}

	// Loop over and accumulate results
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "gravity_size", "?");
	JSON_OBJ_ADD_NUMBER(json, "sum_queries", sum_queries);
	JSON_OBJ_ADD_NUMBER(json, "blocked_queries", blocked_queries);
	JSON_OBJ_ADD_NUMBER(json, "percent_blocked", percent_blocked);
	JSON_OBJ_ADD_NUMBER(json, "total_clients", total_clients);

	// Close (= unlock) database connection
	dbclose();

	// Re-lock shared memory before returning back to router subroutine
	lock_shm();

	// Send JSON object
	JSON_SEND_OBJECT(json);
}

int api_stats_database_overTime_clients(struct ftl_conn *api)
{
	unsigned int from = 0, until = 0;
	const int interval = 600;
	if(api->request->query_string != NULL)
	{
		get_uint_var(api->request->query_string, "from", &from);
		get_uint_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from == 0 || until == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       json);
	}

	// Unlock shared memory (DNS resolver can continue to work while we're preforming database queries)
	unlock_shm();

	// Open the database (this also locks the database)
	dbopen();

	const char *querystr = "SELECT DISTINCT client FROM queries "
	                       "WHERE timestamp >= :from AND timestamp <= :until "
	                       "ORDER BY client DESC";

	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("api_stats_database_overTime_clients() - SQL error prepare outer (%i): %s",
		     rc, sqlite3_errmsg(FTL_db));

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare outer statement",
		                       json);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, from)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_clients(): Failed to bind from (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       json);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_int(stmt, 2, until)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_clients(): Failed to bind until (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       json);
	}

	// Loop over clients and accumulate results
	cJSON *clients = JSON_NEW_ARRAY();
	unsigned int num_clients = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const char* client = (char*)sqlite3_column_text(stmt, 0);
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(item, "ip", client);
		JSON_OBJ_REF_STR(item, "name", "");
		JSON_ARRAY_ADD_ITEM(clients, item);
		num_clients++;
	}
	sqlite3_finalize(stmt);

	// Build SQL string
	querystr = "SELECT (timestamp/:interval)*:interval interval,client,COUNT(*) FROM queries "
	           "WHERE timestamp >= :from AND timestamp <= :until "
	           "GROUP BY interval,client ORDER BY interval DESC, client DESC";

	// Prepare SQLite statement
	rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("api_stats_database_overTime_clients() - SQL error prepare (%i): %s",
		rc, sqlite3_errmsg(FTL_db));

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
					"internal_error",
					"Failed to prepare inner statement",
					json);
	}

	// Bind interval to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, interval)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_clients(): Failed to bind interval (error %d) - %s",
		rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
					"internal_error",
					"Failed to bind interval",
					json);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_int(stmt, 2, from)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_clients(): Failed to bind from (error %d) - %s",
		rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
					"internal_error",
					"Failed to bind from",
					json);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_int(stmt, 3, until)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_clients(): Failed to bind until (error %d) - %s",
		rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
					"internal_error",
					"Failed to bind until",
					json);
	}

	cJSON *over_time = JSON_NEW_ARRAY();
	cJSON *item = NULL;
	cJSON *data = NULL;
	int previous_timestamp = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const int timestamp = sqlite3_column_int(stmt, 0);
		// Begin new array item for each new timestamp
		if(timestamp != previous_timestamp)
		{
			previous_timestamp = timestamp;
			if(item != NULL && data != NULL)
			{
				JSON_OBJ_ADD_ITEM(item, "data", data);
				JSON_ARRAY_ADD_ITEM(over_time, item);
			}

			item = JSON_NEW_OBJ();
			data = JSON_NEW_ARRAY();
			// Prefill data with zeroes
			// We have to do this as not all clients may have
			// have been active in any time interval we're
			// querying
			for(unsigned int i = 0; i < num_clients; i++)
			{
				JSON_ARRAY_ADD_NUMBER(data, 0);
			}
			JSON_OBJ_ADD_NUMBER(item, "timestamp", timestamp);
		}

		const char *client = (char*)sqlite3_column_text(stmt, 1);
		const int count = sqlite3_column_int(stmt, 2);

		// Find index of this client in known clients...
		unsigned int idx = 0;
		for(; idx < num_clients; idx++)
		{
			const char *array_client = cJSON_GetStringValue(
			                              cJSON_GetObjectItem(
			                                 cJSON_GetArrayItem(clients, idx), "ip"));
			if(array_client != NULL && 
			   strcmp(client, array_client) == 0)
			{
				break;
			}
		}

		if(idx == num_clients)
		{
			// Not found
			continue;
		}

		// ... and replace corresponding number in data array
		JSON_ARRAY_REPLACE_NUMBER(data, idx, count);
	}

	// Finalize statement and close (= unlock) database connection
	sqlite3_finalize(stmt);
	dbclose();

	// Re-lock shared memory before returning back to router subroutine
	lock_shm();
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "over_time", over_time);
	JSON_OBJ_ADD_ITEM(json, "clients", clients);
	JSON_SEND_OBJECT(json);
}

int api_stats_database_query_types(struct ftl_conn *api)
{
	unsigned int from = 0, until = 0;
	if(api->request->query_string != NULL)
	{
		get_uint_var(api->request->query_string, "from", &from);
		get_uint_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from == 0 || until == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       json);
	}

	// Unlock shared memory (DNS resolver can continue to work while we're preforming database queries)
	unlock_shm();

	// Open the database (this also locks the database)
	dbopen();

	// Perform SQL queries
	cJSON *types = JSON_NEW_ARRAY();
	queriesData q = { 0 };
	for(int i = TYPE_A; i < TYPE_MAX; i++)
	{
		const char *querystr = "SELECT COUNT(*) FROM queries "
		                       "WHERE timestamp >= :from AND timestamp <= :until "
		                       "AND type = :type";
		// Add 1 as type is stored one-based in the database for historical reasons
		int count = db_query_int_from_until_type(querystr, from, until, i+1);
		q.type = i;
		JSON_OBJ_ADD_NUMBER(types, get_query_type_str(&q, NULL), count);
	}

	// Close (= unlock) database connection
	dbclose();

	// Re-lock shared memory before returning back to router subroutine
	lock_shm();

	// Send JSON object
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "types", types);
	JSON_SEND_OBJECT(json);
}


int api_stats_database_upstreams(struct ftl_conn *api)
{
	unsigned int from = 0, until = 0;
	if(api->request->query_string != NULL)
	{
		get_uint_var(api->request->query_string, "from", &from);
		get_uint_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from == 0 || until == 0)
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       json);
	}

	// Unlock shared memory (DNS resolver can continue to work while we're preforming database queries)
	unlock_shm();

	// Open the database (this also locks the database)
	dbopen();

	// Perform simple SQL queries
	unsigned int sum_queries = 0;
	const char *querystr;
	querystr = "SELECT COUNT(*) FROM queries "
	           "WHERE timestamp >= :from AND timestamp <= :until "
	           "AND status = 3";
	int cached_queries = db_query_int_from_until(querystr, from, until);
	sum_queries += cached_queries;

	querystr = "SELECT COUNT(*) FROM queries "
	           "WHERE timestamp >= :from AND timestamp <= :until "
		   "AND status != 0 AND status != 2 AND status != 3";
	int blocked_queries = db_query_int_from_until(querystr, from, until);
	sum_queries += blocked_queries;

	querystr = "SELECT forward,COUNT(*) FROM queries "
	           "WHERE timestamp >= :from AND timestamp <= :until "
		   "AND forward IS NOT NULL "
	           "GROUP BY forward ORDER BY forward";

	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("api_stats_database_overTime_clients() - SQL error prepare (%i): %s",
		     rc, sqlite3_errmsg(FTL_db));

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare statement",
		                       json);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, from)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_clients(): Failed to bind from (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       json);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_int(stmt, 2, until)) != SQLITE_OK)
	{
		logg("api_stats_database_overTime_clients(): Failed to bind until (error %d) - %s",
		     rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose();

		// Relock shared memory
		lock_shm();

		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(json, "from", from);
		JSON_OBJ_ADD_NUMBER(json, "until", until);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       json);
	}

	// Loop over clients and accumulate results
	cJSON *upstreams = JSON_NEW_ARRAY();
	int forwarded_queries = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const char* upstream = (char*)sqlite3_column_text(stmt, 0);
		const int count = sqlite3_column_int(stmt, 1);
		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(item, "ip", upstream);
		JSON_OBJ_REF_STR(item, "name", "");
		JSON_OBJ_ADD_NUMBER(item, "count", count);
		JSON_ARRAY_ADD_ITEM(upstreams, item);
		forwarded_queries += count;
	}
	sqlite3_finalize(stmt);

	// Add number of forwarded queries to total query count
	sum_queries += forwarded_queries;

	// Add cache and blocklist as upstreams
	cJSON *cached = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(cached, "ip", "");
	JSON_OBJ_REF_STR(cached, "name", "cache");
	JSON_OBJ_ADD_NUMBER(cached, "count", cached_queries);
	JSON_ARRAY_ADD_ITEM(upstreams, cached);

	cJSON *blocked = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(blocked, "ip", "");
	JSON_OBJ_REF_STR(blocked, "name", "blocklist");
	JSON_OBJ_ADD_NUMBER(blocked, "count", blocked_queries);
	JSON_ARRAY_ADD_ITEM(upstreams, blocked);

	// Close (= unlock) database connection
	dbclose();

	// Re-lock shared memory before returning back to router subroutine
	lock_shm();

	// Send JSON object
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "upstreams", upstreams);
	JSON_OBJ_ADD_NUMBER(json, "forwarded_queries", forwarded_queries);
	JSON_OBJ_ADD_NUMBER(json, "total_queries", sum_queries);
	JSON_SEND_OBJECT(json);
}
