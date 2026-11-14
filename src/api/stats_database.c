/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API database statistics implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
// querytypes[]
#include "datastructure.h"
// logging routines
#include "log.h"
// db
#include "database/common.h"
// INT_MAX
#include <limits.h>

// is_blocked() for the stored status in column <col>. Any other value counts
// as blocked, as it would for SQL's NOT IN the list of unblocked statuses
static bool status_blocked(sqlite3_stmt *stmt, const int col)
{
	const int status = sqlite3_column_int(stmt, col);
	return sqlite3_column_type(stmt, col) != SQLITE_INTEGER ||
	       status < 0 || status >= QUERY_STATUS_MAX || is_blocked(status);
}

// Prepare a scan of the queries in [from, until]. The callers count the rows
// themselves, a GROUP BY would make SQLite sort every row of the range first
static sqlite3_stmt *range_scan(sqlite3 *db, const char *querystr, const double from, const double until)
{
	sqlite3_stmt *stmt = NULL;
	int rc;
	if((rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL)) != SQLITE_OK ||
	   (rc = sqlite3_bind_double(stmt, 1, from)) != SQLITE_OK ||
	   (rc = sqlite3_bind_double(stmt, 2, until)) != SQLITE_OK)
	{
		log_web(LOG_ERR, "range_scan(\"%s\") - SQL error (%i): %s", querystr, rc, sqlite3_errstr(rc));
		sqlite3_finalize(stmt);
		return NULL;
	}
	return stmt;
}

// The linking table ID in column <col>, or -1 if it cannot have a row in
// [0, max]. Legacy rows store the text itself, which no JOIN on the ID matches
static sqlite3_int64 row_id(sqlite3_stmt *stmt, const int col, const sqlite3_int64 max)
{
	if(sqlite3_column_type(stmt, col) != SQLITE_INTEGER)
		return -1;
	const sqlite3_int64 id = sqlite3_column_int64(stmt, col);
	return id >= 0 && id <= max ? id : -1;
}

int api_history_database(struct ftl_conn *api)
{
	double from = 0, until = 0;
	const int interval = 600;

	// Check if we received the required information
	if(api->request->query_string == NULL ||
	  (!get_double_var(api->request->query_string, "from", &from) ||
	   !get_double_var(api->request->query_string, "until", &until)))
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

	// Read the rows in time order and count them below, a GROUP BY would
	// sort every row of the range first
	const char *querystr = "SELECT (CAST(timestamp AS INTEGER)/:interval)*:interval interval,status,1 FROM query_storage "
	                       "WHERE (status != 0) AND timestamp >= :from AND timestamp <= :until "
	                       "ORDER BY timestamp";


	// Prepare SQLite statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_web(LOG_ERR, "api_stats_database_history() - SQL error prepare (%i): %s",
		        rc, sqlite3_errstr(rc));
		dbclose(&db);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare statement",
		                       NULL);
	}

	// Bind interval to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, interval)) != SQLITE_OK)
	{
		log_web(LOG_ERR, "api_stats_database_history(): Failed to bind interval (error %d) - %s",
		        rc, sqlite3_errstr(rc));
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
		log_web(LOG_ERR, "api_stats_database_history(): Failed to bind from (error %d) - %s",
		        rc, sqlite3_errstr(rc));
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
		log_web(LOG_ERR, "api_stats_database_history(): Failed to bind until (error %d) - %s",
		        rc, sqlite3_errstr(rc));
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
	time_t previous_timeslot = 0u;
	unsigned int blocked = 0u, total = 0u, cached = 0u, forwarded = 0u;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// Get timestamp and derive timeslot from it
		const time_t timestamp = sqlite3_column_int64(stmt, 0);
		const time_t timeslot = timestamp - timestamp % interval;
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
				// Add and reset forwarded counter
				JSON_ADD_NUMBER_TO_OBJECT(item, "forwarded", forwarded);
				forwarded = 0;
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
		else if(is_forwarded(status))
			forwarded += count;
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
		// Add forwarded counter
		JSON_ADD_NUMBER_TO_OBJECT(item, "forwarded", forwarded);
		JSON_ADD_ITEM_TO_ARRAY(history, item);
	}

	// Finalize statement and close (= unlock) database connection
	sqlite3_finalize(stmt);
	dbclose(&db);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "history", history);
	JSON_SEND_OBJECT(json);
}

// Most queries first, ties in ID order as the GROUP BY returned them
struct top_entry { unsigned int cnt; int id; };
static int cmp_top(const void *a, const void *b)
{
	const struct top_entry *x = a, *y = b;
	if(x->cnt != y->cnt)
		return x->cnt < y->cnt ? 1 : -1;
	return x->id - y->id;
}

// A row of client_by_id, its group of rows with the same address and its
// number of queries in the range
struct lt_client { sqlite3_int64 id; char *ip, *name; unsigned int group, cnt; };

// FTL's free() warns on NULL, some of these were never allocated
static void free_lt(struct lt_client *c, const unsigned int n_c, void *slots, void *group_row)
{
	for(unsigned int i = 0; i < n_c; i++)
	{
		free(c[i].ip);
		if(c[i].name != NULL)
			free(c[i].name);
	}
	if(c != NULL)
		free(c);
	if(slots != NULL)
		free(slots);
	if(group_row != NULL)
		free(group_row);
}

static int cmp_uint(const void *a, const void *b)
{
	const unsigned int x = *(const unsigned int *)a, y = *(const unsigned int *)b;
	return (x > y) - (x < y);
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

	// Highest ID of the linking table, the counts are indexed by it
	const int max_id = db_query_int(db, domains ? "SELECT IFNULL(MAX(id),0) FROM domain_by_id" :
	                                              "SELECT IFNULL(MAX(id),0) FROM client_by_id");
	unsigned int *counts = max_id >= 0 ? calloc((size_t)max_id + 1, sizeof(*counts)) : NULL;
	sqlite3_stmt *stmt = counts == NULL ? NULL :
	                     range_scan(db, domains ? "SELECT status,domain FROM query_storage "
	                                              "WHERE timestamp >= ?1 AND timestamp <= ?2" :
	                                              "SELECT status,client FROM query_storage "
	                                              "WHERE timestamp >= ?1 AND timestamp <= ?2", from, until);
	if(stmt == NULL)
	{
		if(counts != NULL)
			free(counts);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare query string",
		                       NULL);
	}

	// Count the queries of each domain or client, and the totals
	int total_num = 0, blocked_num = 0, rc;
	unsigned int n_top = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const bool row_blocked = status_blocked(stmt, 0);
		total_num++;
		if(row_blocked)
			blocked_num++;
		const sqlite3_int64 id = row_blocked == blocked ? row_id(stmt, 1, max_id) : -1;
		if(id >= 0 && counts[id]++ == 0)
			n_top++;
	}
	sqlite3_finalize(stmt);
	if(rc != SQLITE_DONE)
		total_num = blocked_num = DB_FAILED;

	struct top_entry *top = calloc(n_top + 1, sizeof(*top));
	if(top == NULL)
	{
		free(counts);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to allocate memory",
		                       NULL);
	}
	for(int id = 0, i = 0; id <= max_id; id++)
		if(counts[id] > 0)
			top[i++] = (struct top_entry){ counts[id], id };
	free(counts);
	qsort(top, n_top, sizeof(*top), cmp_top);

	// Look up the names, an ID without a row is left out like the JOIN did.
	// A count above INT_MAX means no limit, like the LIMIT it replaces
	stmt = NULL;
	if(sqlite3_prepare_v2(db, domains ? "SELECT domain FROM domain_by_id WHERE id = ?1" :
	                                    "SELECT ip,name FROM client_by_id WHERE id = ?1",
	                      -1, &stmt, NULL) != SQLITE_OK)
	{
		free(top);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare query string",
		                       NULL);
	}
	const int limit = (int)count;
	int n = 0;
	cJSON *top_items = JSON_NEW_ARRAY();
	for(unsigned int i = 0; i < n_top && (limit < 0 || n < limit); i++)
	{
		sqlite3_bind_int(stmt, 1, top[i].id);
		if(sqlite3_step(stmt) == SQLITE_ROW)
		{
			cJSON *item = JSON_NEW_OBJECT();
			if(domains)
			{
				// Add domain to item
				JSON_COPY_STR_TO_OBJECT(item, "domain", sqlite3_column_text(stmt, 0));
			}
			else
			{
				// Add client to item
				JSON_COPY_STR_TO_OBJECT(item, "ip", sqlite3_column_text(stmt, 0));
				JSON_COPY_STR_TO_OBJECT(item, "name", sqlite3_column_text(stmt, 1));
			}
			JSON_ADD_NUMBER_TO_OBJECT(item, "count", top[i].cnt);
			JSON_ADD_ITEM_TO_ARRAY(top_items, item);
			n++;
		}
		sqlite3_reset(stmt);
	}
	sqlite3_finalize(stmt);
	free(top);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, (domains ? "domains" : "clients"), top_items);
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

	// Count the queries, the blocked ones and the distinct clients in one
	// scan. The clients are marked by their ID, any other value of the
	// column (legacy text rows) needs SQLite's COUNT(DISTINCT) after all
	int sum_queries = 0, sum_blocked = 0, total_clients = 0, rc = SQLITE_ERROR;
	bool distinct_sql = false;
	unsigned char *seen = NULL;
	size_t n_seen = 0;
	sqlite3_stmt *stmt = range_scan(db, "SELECT status,client FROM query_storage "
	                                    "WHERE timestamp >= ?1 AND timestamp <= ?2", from, until);
	while(stmt != NULL && (rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		sum_queries++;
		if(status_blocked(stmt, 0))
			sum_blocked++;
		const sqlite3_int64 id = row_id(stmt, 1, 1 << 24);
		if(id < 0)
		{
			distinct_sql = true;
			continue;
		}
		if((size_t)id >= n_seen)
		{
			const size_t n = (size_t)id + 1 > 2 * n_seen ? (size_t)id + 1 : 2 * n_seen;
			unsigned char *grown = realloc(seen, n);
			if(grown == NULL)
			{
				rc = SQLITE_NOMEM;
				break;
			}
			memset(grown + n_seen, 0, n - n_seen);
			seen = grown;
			n_seen = n;
		}
		if(!seen[id])
		{
			seen[id] = 1;
			total_clients++;
		}
	}
	sqlite3_finalize(stmt);
	if(seen != NULL)
		free(seen);
	if(rc != SQLITE_DONE)
		sum_queries = DB_FAILED;
	else if(distinct_sql)
		total_clients = db_query_int_from_until(db, "SELECT COUNT(DISTINCT client) FROM query_storage "
		                                            "WHERE timestamp >= :from AND timestamp <= :until",
		                                        from, until);

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

	// All clients in IP order, the order of the reply. The same address can
	// have several rows (one per name seen), they form one group
	struct lt_client *c = NULL;
	unsigned int n_c = 0, n_groups = 0, *group_row = NULL;
	sqlite3_int64 max_id = -1;
	int *row_of = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, "SELECT id,ip,name FROM client_by_id ORDER BY ip,id", -1, &stmt, NULL);
	while(stmt != NULL && (rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		struct lt_client *grown = realloc(c, (n_c + 1) * sizeof(*c));
		if(grown == NULL)
			break;
		c = grown;
		const char *ip = (const char *)sqlite3_column_text(stmt, 1);
		const char *name = (const char *)sqlite3_column_text(stmt, 2);
		c[n_c].id = sqlite3_column_int64(stmt, 0);
		c[n_c].ip = strdup(ip != NULL ? ip : "");
		c[n_c].name = name != NULL ? strdup(name) : NULL;
		c[n_c].cnt = 0;
		if(n_c == 0 || strcmp(c[n_c].ip, c[n_c - 1].ip) != 0)
			n_groups++;
		c[n_c].group = n_groups - 1;
		if(c[n_c].id > max_id)
			max_id = c[n_c].id;
		n_c++;
	}
	sqlite3_finalize(stmt);
	if(rc == SQLITE_DONE && max_id < INT_MAX &&
	   (row_of = malloc(((size_t)max_id + 2) * sizeof(*row_of))) != NULL &&
	   (group_row = calloc(n_groups + 1, sizeof(*group_row))) != NULL)
	{
		for(sqlite3_int64 id = 0; id <= max_id; id++)
			row_of[id] = -1;
		for(unsigned int i = n_c; i-- > 0;)
		{
			if(c[i].id >= 0)
				row_of[c[i].id] = i;
			group_row[c[i].group] = i;
		}
	}

	// Count each client per time slot. The rows come in time order, so a
	// slot is done when the next one begins. A slot's counts are kept in IP
	// order, the slots are reversed for the reply below
	struct lt_slot { time_t timestamp; unsigned int group, cnt; } *slots = NULL;
	size_t n_slots = 0, cap_slots = 0;
	unsigned int *slot_cnt = calloc(n_groups + 1, sizeof(*slot_cnt));
	unsigned int *touched = calloc(n_groups + 1, sizeof(*touched));
	unsigned int n_touched = 0;
	time_t current = 0;
	stmt = group_row == NULL || slot_cnt == NULL || touched == NULL ? NULL :
	       range_scan(db, "SELECT CAST(timestamp AS INTEGER),client FROM query_storage "
	                      "WHERE timestamp >= ?1 AND timestamp <= ?2 ORDER BY timestamp", from, until);
	rc = stmt == NULL ? SQLITE_ERROR : SQLITE_ROW;
	while(rc == SQLITE_ROW)
	{
		rc = sqlite3_step(stmt);
		const time_t timestamp = rc == SQLITE_ROW ? sqlite3_column_int64(stmt, 0) : 0;
		const time_t timeslot = timestamp - timestamp % interval;
		if(timeslot != current || rc != SQLITE_ROW)
		{
			qsort(touched, n_touched, sizeof(*touched), cmp_uint);
			if(n_slots + n_touched > cap_slots)
			{
				cap_slots = 2 * (n_slots + n_touched);
				struct lt_slot *grown = realloc(slots, cap_slots * sizeof(*slots));
				if(grown == NULL)
				{
					rc = SQLITE_NOMEM;
					break;
				}
				slots = grown;
			}
			for(unsigned int i = 0; i < n_touched; i++)
			{
				slots[n_slots++] = (struct lt_slot){ current, touched[i], slot_cnt[touched[i]] };
				slot_cnt[touched[i]] = 0;
			}
			n_touched = 0;
			current = timeslot;
		}
		if(rc != SQLITE_ROW)
			break;
		const sqlite3_int64 id = row_id(stmt, 1, max_id);
		if(id < 0 || row_of[id] < 0)
			continue;
		struct lt_client *client = &c[row_of[id]];
		client->cnt++;
		if(slot_cnt[client->group]++ == 0)
			touched[n_touched++] = client->group;
	}
	sqlite3_finalize(stmt);
	if(slot_cnt != NULL)
		free(slot_cnt);
	if(touched != NULL)
		free(touched);
	if(row_of != NULL)
		free(row_of);
	dbclose(&db);

	if(rc != SQLITE_DONE)
	{
		free_lt(c, n_c, slots, group_row);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to read the queries",
		                       NULL);
	}

	// Clients with queries in the range, by IP address, with the largest
	// of their names
	cJSON *clients = JSON_NEW_OBJECT();
	for(unsigned int i = 0; i < n_c;)
	{
		unsigned int total = 0;
		const char *name = NULL;
		const unsigned int group = c[i].group;
		for(; i < n_c && c[i].group == group; i++)
		{
			total += c[i].cnt;
			if(c[i].cnt > 0 && c[i].name != NULL && (name == NULL || strcmp(c[i].name, name) > 0))
				name = c[i].name;
		}
		if(total == 0)
			continue;
		cJSON *item = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(item, "name", name);
		JSON_ADD_NUMBER_TO_OBJECT(item, "total", total);
		JSON_ADD_ITEM_TO_OBJECT(clients, c[i - 1].ip, item);
	}

	// Newest slot first, each with its clients in IP order
	cJSON *over_time = JSON_NEW_ARRAY();
	for(size_t end = n_slots; end > 0;)
	{
		size_t start = end;
		while(start > 0 && slots[start - 1].timestamp == slots[end - 1].timestamp)
			start--;
		cJSON *item = JSON_NEW_OBJECT();
		cJSON *data = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(item, "timestamp", slots[start].timestamp);
		for(size_t i = start; i < end; i++)
		{
			JSON_ADD_NUMBER_TO_OBJECT(data, c[group_row[slots[i].group]].ip, slots[i].cnt);
		}
		JSON_ADD_ITEM_TO_OBJECT(item, "data", data);
		JSON_ADD_ITEM_TO_ARRAY(over_time, item);
		end = start;
	}

	free_lt(c, n_c, slots, group_row);

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

	// Count all types in one pass over the range
	sqlite3_stmt *stmt = range_scan(db, "SELECT type FROM query_storage "
	                                    "WHERE timestamp >= ?1 AND timestamp <= ?2", from, until);
	if(stmt == NULL)
	{
		dbclose(&db);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to prepare statement",
		                       NULL);
	}

	// The database stores the enum value for the mapped types and
	// 100 + the DNS type for everything else (TYPE_OTHER)
	unsigned int counts[TYPE_MAX] = { 0 };
	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		int type = sqlite3_column_int(stmt, 0);
		if(type >= 100)
			type = TYPE_OTHER;
		if(type >= TYPE_A && type < TYPE_MAX)
			counts[type]++;
	}

	sqlite3_finalize(stmt);

	// Same layout as the in-memory endpoint: OTHER comes last
	cJSON *types = JSON_NEW_OBJECT();
	for(int i = TYPE_A; i < TYPE_MAX; i++)
	{
		if(i == TYPE_OTHER)
			continue;
		JSON_ADD_NUMBER_TO_OBJECT(types, get_query_type_str(i, NULL, NULL), counts[i]);
	}
	JSON_ADD_NUMBER_TO_OBJECT(types, "OTHER", counts[TYPE_OTHER]);

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

	// Count the queries, the cached and blocked ones and those of each
	// upstream in one scan of the range. Only queries an upstream answered
	// (or is retrying) count for it, like the in-memory upstream counters: a
	// forwarded query that ended up blocked keeps its upstream for the record
	// but is not counted here
	const int max_id = db_query_int(db, "SELECT IFNULL(MAX(id),0) FROM forward_by_id");
	unsigned int *counts = max_id >= 0 ? calloc((size_t)max_id + 1, sizeof(*counts)) : NULL;
	sqlite3_stmt *stmt = counts == NULL ? NULL :
	                     range_scan(db, "SELECT status,forward FROM query_storage "
	                                    "WHERE timestamp >= ?1 AND timestamp <= ?2", from, until);
	int sum_queries = 0, cached_queries = 0, blocked_queries = 0, rc = SQLITE_ERROR;
	while(stmt != NULL && (rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const int status = sqlite3_column_int(stmt, 0);
		sum_queries++;
		if(status_blocked(stmt, 0))
			blocked_queries++;
		else if(is_cached(status))
			cached_queries++;
		else if(is_forwarded(status))
		{
			const sqlite3_int64 id = row_id(stmt, 1, max_id);
			if(id >= 0)
				counts[id]++;
		}
	}
	sqlite3_finalize(stmt);

	// The upstreams in ID order, an ID without queries or without a row is
	// left out like the JOIN did
	stmt = NULL;
	if(rc != SQLITE_DONE ||
	   sqlite3_prepare_v2(db, "SELECT id,forward FROM forward_by_id ORDER BY id", -1, &stmt, NULL) != SQLITE_OK)
	{
		if(counts != NULL)
			free(counts);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error",
		                       NULL);
	}

	cJSON *upstreams = JSON_NEW_ARRAY();
	int forwarded_queries = 0;
	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		const sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
		if(id < 0 || id > max_id || counts[id] == 0)
			continue;
		const char *upstream = (char*)sqlite3_column_text(stmt, 1);
		// A broken row can carry a NULL upstream, which neither sscanf()
		// nor the JSON output below would survive
		if(upstream == NULL)
			upstream = "";
		const int count = counts[id];

		cJSON *item = JSON_NEW_OBJECT();
		// Needs a signed data type here as -1 means: no port applicable
		int port = -1;
		unsigned int parsed_port = 0;
		char buffer[512] =  { 0 };
		if(sscanf(upstream, "%511[^#]#%u", buffer, &parsed_port) == 2)
		{
			buffer[sizeof(buffer)-1] = '\0';
			port = (int)parsed_port;
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
	free(counts);

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
	JSON_ADD_ITEM_TO_OBJECT(blocked, "statistics", statistics);
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
