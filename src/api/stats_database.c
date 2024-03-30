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
#include "api.h"
// querytypes[]
#include "../datastructure.h"
// logging routines
#include "log.h"
// db
#include "../database/common.h"

// SQL Query type filters for the database
#define FILTER_STATUS_NOT_BLOCKED "status IN (0,2,3,12,13,14,17)"
#define FILTER_STATUS_BLOCKED "status NOT IN (0,2,3,12,13,14,17)"

int api_history_database(struct ftl_conn *api)
{
	double from = 0, until = 0;
	const int interval = 600;
	if(api->request->query_string != NULL)
	{
		get_double_var(api->request->query_string, "from", &from);
		get_double_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from < 1.0 || until < 1.0)
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       NULL);
	}

	// Open the database
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to open long-term database",
		                       NULL);

	// Build SQL string
	const char *querystr = "SELECT (timestamp/:interval)*:interval interval,status,COUNT(*) FROM query_storage "
	                       "WHERE (status != 0) AND timestamp >= :from AND timestamp <= :until "
	                       "GROUP by interval,status ORDER by interval";


	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("api_stats_database_history() - SQL error prepare (%i): %s",
		        rc, sqlite3_errstr(rc));
		return false;
	}

	// Bind interval to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, interval)) != SQLITE_OK)
	{
		log_err("api_stats_database_history(): Failed to bind interval (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind interval",
		                       NULL);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_double(stmt, 2, from)) != SQLITE_OK)
	{
		log_err("api_stats_database_history(): Failed to bind from (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       NULL);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_double(stmt, 3, until)) != SQLITE_OK)
	{
		log_err("api_stats_database_history(): Failed to bind until (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       NULL);
	}

	// Loop over returned data and accumulate results
	cJSON *history = JSON_NEW_ARRAY();
	cJSON *item = NULL;
	unsigned int previous_timeslot = 0u, blocked = 0u, total = 0u, cached = 0u;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// Get timestamp and derive timeslot from it
		const unsigned int timestamp = sqlite3_column_int(stmt, 0);
		const unsigned int timeslot = timestamp - timestamp % interval;
		// Begin new array item for each new timeslot
		if(timeslot != previous_timeslot)
		{
			previous_timeslot = timeslot;
			if(item != NULL)
			{
				// Add and reset total counter
				JSON_ADD_NUMBER_TO_OBJECT(item, "total", total);
				total = 0;
				// Add and reset totacachedl counter
				JSON_ADD_NUMBER_TO_OBJECT(item, "cached", cached);
				cached = 0;
				// Add and reset blocked counter
				JSON_ADD_NUMBER_TO_OBJECT(item, "blocked", blocked);
				blocked = 0;
				JSON_ADD_ITEM_TO_ARRAY(history, item);
			}

			item = JSON_NEW_OBJECT();
			JSON_ADD_NUMBER_TO_OBJECT(item, "timestamp", previous_timeslot);
		}

		const int status = sqlite3_column_int(stmt, 1);
		const int count = sqlite3_column_int(stmt, 2);
		// Always add to total count
		total += count;

		// Add to blocked / cached count if applicable
		if(is_blocked(status))
			blocked += count;
		else if(is_cached(status))
			cached += count;
	}

	// Append final timeslot at the end if applicable
	if(total > 0 && item != NULL)
	{
		// Add total counter
		JSON_ADD_NUMBER_TO_OBJECT(item, "total", total);
		// Add cached counter
		JSON_ADD_NUMBER_TO_OBJECT(item, "cached", cached);
		// Add blocked counter
		JSON_ADD_NUMBER_TO_OBJECT(item, "blocked", blocked);
		JSON_ADD_ITEM_TO_ARRAY(history, item);
	}

	// Finalize statement and close (= unlock) database connection
	sqlite3_finalize(stmt);
	dbclose(&db);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "history", history);
	JSON_SEND_OBJECT(json);
}

int api_stats_database_top_items(struct ftl_conn *api)
{
	unsigned int count = 10;
	double from = 0.0, until = 0.0;

	// Get options from API struct
	bool blocked = false; // Can be overwritten by query string
	const bool domains = api->opts.flags & API_DOMAINS;

	// Get parameters from query string
	if(api->request->query_string != NULL)
	{
		// Get time interval from query string
		get_double_var(api->request->query_string, "from", &from);
		get_double_var(api->request->query_string, "until", &until);

		// Get blocked queries not only for .../top_blocked
		// but also for .../top_domains?blocked=true
		// Note: this may overwrite the blocked property from the URL
		get_bool_var(api->request->query_string, "blocked", &blocked);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_uint_var(api->request->query_string, "count", &count);
	}

	// Check if we received the required information
	if(from < 1.0 || until < 1.0)
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       NULL);
	}

	// Open the database
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to open long-term database",
		                       NULL);

	// Build SQL string
	const char *querystr, *count_total_str, *count_blocked_str;
	if(domains)
	{
		if(blocked)
		{
			// Get domains and count of queries (blocked)
			querystr = "SELECT COUNT(*),d.domain AS cnt FROM query_storage q "
			           "JOIN domain_by_id d ON d.id = q.domain "
			           "WHERE timestamp >= :from AND timestamp <= :until "
			           "AND " FILTER_STATUS_BLOCKED " "
			           "GROUP by q.domain";
		}
		else
		{
			// Get domains and count of queries (not blocked)
			querystr = "SELECT COUNT(*),d.domain AS cnt FROM query_storage q "
			           "JOIN domain_by_id d ON d.id = q.domain "
			           "WHERE timestamp >= :from AND timestamp <= :until "
			           "AND " FILTER_STATUS_NOT_BLOCKED " "
			           "GROUP by q.domain";
		}

		// Count total number of queries for domains
		count_total_str = "SELECT COUNT(DISTINCT domain) FROM query_storage "
		                  "WHERE timestamp >= :from AND timestamp <= :until";

		// Count total number of blocked queries for domains
		count_blocked_str = "SELECT COUNT(DISTINCT domain) FROM query_storage "
		                    "WHERE timestamp >= :from AND timestamp <= :until "
			            "AND " FILTER_STATUS_BLOCKED;
	}
	else
	{
		if(blocked)
		{
			// Get clients and count of queries (blocked)
			querystr = "SELECT COUNT(*),c.ip,c.name AS cnt FROM query_storage q "
			           "JOIN client_by_id c ON c.id = q.client"
			           "WHERE timestamp >= :from AND timestamp <= :until "
			           "AND " FILTER_STATUS_BLOCKED " "
			           "GROUP by q.client";
		}
		else
		{
			// Get clients and count of queries (not blocked)
			querystr = "SELECT COUNT(*),c.ip,c.name AS cnt FROM query_storage q "
			           "JOIN client_by_id c ON c.id = q.client "
			           "WHERE timestamp >= :from AND timestamp <= :until "
			           "AND " FILTER_STATUS_NOT_BLOCKED " "
			           "GROUP by q.client";
		}

		// Count total number of queries for clients
		count_total_str = "SELECT COUNT(DISTINCT client) FROM query_storage "
		                  "WHERE timestamp >= :from AND timestamp <= :until";

		// Count number of blocked queries for clients
		count_blocked_str = "SELECT COUNT(DISTINCT client) FROM query_storage "
		                    "WHERE timestamp >= :from AND timestamp <= :until "
			            "AND " FILTER_STATUS_BLOCKED;
	}


	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("api_stats_database_history() - SQL error prepare (%i): %s",
		        rc, sqlite3_errstr(rc));

		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare query string",
		                       querystr);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_double(stmt, 1, from)) != SQLITE_OK)
	{
		log_err("api_stats_database_history(): Failed to bind from (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       NULL);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_double(stmt, 2, until)) != SQLITE_OK)
	{
		log_err("api_stats_database_history(): Failed to bind until (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       NULL);
	}

	// Loop over and accumulate results
	cJSON *top_items = JSON_NEW_ARRAY();
	unsigned int total = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW &&
	       ++total < count)
	{
		// Get count
		const int cnt = sqlite3_column_int(stmt, 0);
		cJSON *item = JSON_NEW_OBJECT();
		if(domains)
		{
			// Add domain to item
			JSON_COPY_STR_TO_OBJECT(item, "domain", sqlite3_column_text(stmt, 1));
		}
		else
		{
			// Add client to item
			JSON_COPY_STR_TO_OBJECT(item, "ip", sqlite3_column_text(stmt, 1));
			JSON_COPY_STR_TO_OBJECT(item, "name", sqlite3_column_text(stmt, 2));
		}
		JSON_ADD_NUMBER_TO_OBJECT(item, "count", cnt);
		JSON_ADD_ITEM_TO_ARRAY(top_items, item);
	}

	// Finalize statement and close (= unlock) database connection
	sqlite3_finalize(stmt);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, (domains ? "domains" : "clients"), top_items);
	const int total_num = db_query_int_from_until(db, count_total_str, from, until);
	const int blocked_num = db_query_int_from_until(db, count_blocked_str, from, until);
	JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", total_num);
	JSON_ADD_NUMBER_TO_OBJECT(json, "blocked_queries", blocked_num);

	dbclose(&db);
	JSON_SEND_OBJECT(json);
}

int api_stats_database_summary(struct ftl_conn *api)
{
	double from = 0, until = 0;
	if(api->request->query_string != NULL)
	{
		get_double_var(api->request->query_string, "from", &from);
		get_double_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from < 1.0 || until < 1.0)
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       NULL);
	}

	// Open the database
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to open long-term database",
		                       NULL);

	// Perform SQL queries
	const char *querystr;
	querystr = "SELECT COUNT(*) FROM query_storage "
	           "WHERE timestamp >= :from AND timestamp <= :until";
	const int sum_queries = db_query_int_from_until(db, querystr, from, until);

	querystr = "SELECT COUNT(*) FROM query_storage "
	           "WHERE timestamp >= :from AND timestamp <= :until "
	           "AND " FILTER_STATUS_BLOCKED;
	const int sum_blocked = db_query_int_from_until(db, querystr, from, until);

	querystr = "SELECT COUNT(DISTINCT client) FROM query_storage "
	           "WHERE timestamp >= :from AND timestamp <= :until";
	const int total_clients = db_query_int_from_until(db, querystr, from, until);

	// Calculate percentage of blocked queries, substituting 0.0 if there
	// are no blocked queries
	float percent_blocked = 0.0;
	if(sum_queries > 0.0)
		percent_blocked = 1e2f*sum_blocked/sum_queries;

	if(sum_queries < 0 || sum_blocked < 0 || total_clients < 0)
	{

		// Close (= unlock) database connection
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error",
		                       NULL);
	}

	// Loop over and accumulate results
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(json, "sum_queries", sum_queries);
	JSON_ADD_NUMBER_TO_OBJECT(json, "sum_blocked", sum_blocked);
	JSON_ADD_NUMBER_TO_OBJECT(json, "percent_blocked", percent_blocked);
	JSON_ADD_NUMBER_TO_OBJECT(json, "total_clients", total_clients);

	// Close (= unlock) database connection
	dbclose(&db);

	// Send JSON object
	JSON_SEND_OBJECT(json);
}

int api_history_database_clients(struct ftl_conn *api)
{
	double from = 0, until = 0;
	const int interval = 600;
	if(api->request->query_string != NULL)
	{
		get_double_var(api->request->query_string, "from", &from);
		get_double_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from < 1.0 || until < 1.0)
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       NULL);
	}

	// Open the database
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to open long-term database",
		                       NULL);

	const char *querystr = "SELECT DISTINCT(client),ip,name FROM query_storage "
	                       "JOIN client_by_id ON client_by_id.id = client "
	                       "WHERE timestamp >= :from AND timestamp <= :until "
	                       "ORDER BY client DESC";

	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("api_stats_database_clients() - SQL error prepare outer (%i): %s",
		        rc, sqlite3_errstr(rc));

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare outer statement",
		                       NULL);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_double(stmt, 1, from)) != SQLITE_OK)
	{
		log_err("api_stats_database_clients(): Failed to bind from (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       NULL);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_double(stmt, 2, until)) != SQLITE_OK)
	{
		log_err("api_stats_database_clients(): Failed to bind until (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       NULL);
	}

	// Loop over clients and accumulate results
	cJSON *clients = JSON_NEW_OBJECT();
	unsigned int num_clients = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(item, "name", sqlite3_column_text(stmt, 2));
		JSON_ADD_ITEM_TO_OBJECT(clients, (const char*)sqlite3_column_text(stmt, 1), item);
		num_clients++;
	}
	sqlite3_finalize(stmt);

	// Build SQL string
	querystr = "SELECT (timestamp/:interval)*:interval interval,client,COUNT(*) FROM query_storage "
	           "WHERE timestamp >= :from AND timestamp <= :until "
	           "GROUP BY interval,client ORDER BY interval DESC, client DESC";

	// Prepare SQLite statement
	rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("api_stats_database_clients() - SQL error prepare (%i): %s",
		   rc, sqlite3_errstr(rc));

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare inner statement",
		                       NULL);
	}

	// Bind interval to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, interval)) != SQLITE_OK)
	{
		log_err("api_stats_database_clients(): Failed to bind interval (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind interval",
		                       NULL);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_int(stmt, 2, from)) != SQLITE_OK)
	{
		log_err("api_stats_database_clients(): Failed to bind from (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       NULL);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_int(stmt, 3, until)) != SQLITE_OK)
	{
		log_err("api_stats_database_clients(): Failed to bind until (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       NULL);
	}

	cJSON *item = NULL;
	cJSON *data = NULL;
	unsigned int previous_timeslot = 0u;
	cJSON *over_time = JSON_NEW_ARRAY();
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// Get timestamp and derive timeslot from it
		const unsigned int timestamp = sqlite3_column_int(stmt, 0);
		const unsigned int timeslot = timestamp - timestamp % interval;
		// Begin new array item for each new timeslot
		if(timeslot != previous_timeslot)
		{
			previous_timeslot = timeslot;
			if(item != NULL && data != NULL)
			{
				JSON_ADD_ITEM_TO_OBJECT(item, "data", data);
				JSON_ADD_ITEM_TO_ARRAY(over_time, item);
			}

			item = JSON_NEW_OBJECT();
			data = JSON_NEW_OBJECT();

			JSON_ADD_NUMBER_TO_OBJECT(item, "timestamp", previous_timeslot);
		}

		const char *client = (char*)sqlite3_column_text(stmt, 1);
		const int count = sqlite3_column_int(stmt, 2);

		JSON_ADD_NUMBER_TO_OBJECT(data, client, count);
	}

	// Append final timeslot at the end if applicable
	if(item != NULL && data != NULL)
	{
		JSON_ADD_ITEM_TO_OBJECT(item, "data", data);
		JSON_ADD_ITEM_TO_ARRAY(over_time, item);
	}

	// Finalize statement and close (= unlock) database connection
	sqlite3_finalize(stmt);
	dbclose(&db);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "history", over_time);
	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_SEND_OBJECT(json);
}

int api_stats_database_query_types(struct ftl_conn *api)
{
	double from = 0, until = 0;
	if(api->request->query_string != NULL)
	{
		get_double_var(api->request->query_string, "from", &from);
		get_double_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from < 1.0 || until < 1.0)
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       NULL);
	}

	// Open the database
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to open long-term database",
		                       NULL);

	// Perform SQL queries
	cJSON *types = JSON_NEW_OBJECT();
	for(int i = TYPE_A; i < TYPE_MAX; i++)
	{
		const char *querystr = "SELECT COUNT(*) FROM query_storage "
		                       "WHERE timestamp >= :from AND timestamp <= :until "
		                       "AND type = :type";
		// Add 1 as type is stored one-based in the database for historical reasons
		int count = db_query_int_from_until_type(db, querystr, from, until, i+1);
		JSON_ADD_NUMBER_TO_OBJECT(types, get_query_type_str(i, NULL, NULL), count);
	}

	// Close (= unlock) database connection
	dbclose(&db);

	// Send JSON object
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "types", types);
	JSON_SEND_OBJECT(json);
}


int api_stats_database_upstreams(struct ftl_conn *api)
{
	double from = 0, until = 0;
	if(api->request->query_string != NULL)
	{
		get_double_var(api->request->query_string, "from", &from);
		get_double_var(api->request->query_string, "until", &until);
	}

	// Check if we received the required information
	if(from < 1.0 || until < 1.0)
	{
		return send_json_error(api, 400,
		                       "bad_request",
		                       "You need to specify both \"from\" and \"until\" in the request.",
		                       NULL);
	}

	// Open the database
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to open long-term database",
		                       NULL);

	// Perform simple SQL queries
	unsigned int sum_queries = 0;
	const char *querystr;
	querystr = "SELECT COUNT(*) FROM query_storage "
	           "WHERE timestamp >= :from AND timestamp <= :until "
	           "AND status = 3";
	int cached_queries = db_query_int_from_until(db, querystr, from, until);
	sum_queries += cached_queries;

	querystr = "SELECT COUNT(*) FROM query_storage "
	           "WHERE timestamp >= :from AND timestamp <= :until "
		   "AND status != 0 AND status != 2 AND status != 3";
	int blocked_queries = db_query_int_from_until(db, querystr, from, until);
	sum_queries += blocked_queries;

	querystr = "SELECT forward,COUNT(*) FROM query_storage "
	           "WHERE timestamp >= :from AND timestamp <= :until "
		   "AND forward IS NOT NULL "
	           "GROUP BY forward ORDER BY forward";

	// Prepare SQLite statement
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("api_stats_database_clients() - SQL error prepare (%i): %s",
		        rc, sqlite3_errstr(rc));

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare statement",
		                       NULL);
	}

	// Bind from to prepared statement
	if((rc = sqlite3_bind_double(stmt, 1, from)) != SQLITE_OK)
	{
		log_err("api_stats_database_clients(): Failed to bind from (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind from",
		                       NULL);
	}

	// Bind until to prepared statement
	if((rc = sqlite3_bind_double(stmt, 2, until)) != SQLITE_OK)
	{
		log_err("api_stats_database_clients(): Failed to bind until (error %d) - %s",
		        rc, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		dbclose(&db);

		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to bind until",
		                       NULL);
	}

	// Loop over clients and accumulate results
	cJSON *upstreams = JSON_NEW_ARRAY();
	int forwarded_queries = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const char *upstream = (char*)sqlite3_column_text(stmt, 0);
		const int count = sqlite3_column_int(stmt, 1);

		cJSON *item = JSON_NEW_OBJECT();
		unsigned int port = -1;
		char buffer[512] =  { 0 };
		if(sscanf(upstream, "%511[^#]#%u", buffer, &port) == 2)
		{
			buffer[sizeof(buffer)-1] = '\0';
			JSON_COPY_STR_TO_OBJECT(item, "ip", buffer);
		}
		else
			JSON_COPY_STR_TO_OBJECT(item, "ip", upstream);
		JSON_REF_STR_IN_OBJECT(item, "name", "");
		JSON_ADD_NUMBER_TO_OBJECT(item, "port", port);
		JSON_ADD_NUMBER_TO_OBJECT(item, "count", count);

		cJSON *statistics = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(statistics, "response", 0);
		JSON_ADD_NUMBER_TO_OBJECT(statistics, "variance", 0);
		JSON_ADD_ITEM_TO_OBJECT(item, "statistics", statistics);

		JSON_ADD_ITEM_TO_ARRAY(upstreams, item);
		forwarded_queries += count;
	}
	sqlite3_finalize(stmt);

	// Add number of forwarded queries to total query count
	sum_queries += forwarded_queries;

	// Add cache and blocklist as upstreams
	cJSON *cached = JSON_NEW_OBJECT();
	JSON_REF_STR_IN_OBJECT(cached, "ip", "cache");
	JSON_REF_STR_IN_OBJECT(cached, "name", "cache");
	JSON_ADD_NUMBER_TO_OBJECT(cached, "port", -1);
	JSON_ADD_NUMBER_TO_OBJECT(cached, "count", cached_queries);
	cJSON *statistics = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(statistics, "response", 0);
	JSON_ADD_NUMBER_TO_OBJECT(statistics, "variance", 0);
	JSON_ADD_ITEM_TO_OBJECT(cached, "statistics", statistics);
	JSON_ADD_ITEM_TO_ARRAY(upstreams, cached);

	cJSON *blocked = JSON_NEW_OBJECT();
	JSON_REF_STR_IN_OBJECT(blocked, "ip", "blocklist");
	JSON_REF_STR_IN_OBJECT(blocked, "name", "blocklist");
	JSON_ADD_NUMBER_TO_OBJECT(blocked, "port", -1);
	JSON_ADD_NUMBER_TO_OBJECT(blocked, "count", blocked_queries);
	statistics = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(statistics, "response", 0);
	JSON_ADD_NUMBER_TO_OBJECT(statistics, "variance", 0);
	JSON_ADD_ITEM_TO_OBJECT(cached, "statistics", statistics);
	JSON_ADD_ITEM_TO_ARRAY(upstreams, blocked);

	// Close (= unlock) database connection
	dbclose(&db);

	// Send JSON object
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "upstreams", upstreams);
	JSON_ADD_NUMBER_TO_OBJECT(json, "forwarded_queries", forwarded_queries);
	JSON_ADD_NUMBER_TO_OBJECT(json, "total_queries", sum_queries);
	JSON_SEND_OBJECT(json);
}
