/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
#include "datastructure.h"
// config struct
#include "config/config.h"
// get_aliasclient_list()
#include "database/aliasclients.h"
// get_memdb()
#include "database/query-table.h"

// dbopen(false, ), dbclose()
#include "database/common.h"

static int add_strings_to_array(struct ftl_conn *api, cJSON *array, const char *querystr, const int max_count)
{

	sqlite3 *memdb = get_memdb();
	if(memdb == NULL)
	{
		return send_json_error(api, 500, // 500 Internal error
		                       "database_error",
		                       "Could not read from in-memory database",
		                       NULL);
	}
	sqlite3_stmt *stmt;

	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		return send_json_error(api, 500, // 500 Internal error
		                       "database_error",
		                       "Could not prepare in-memory database",
		                       sqlite3_errstr(rc));
	}

	// Loop through returned rows
	int counter = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW &&
	      (max_count < 0 || ++counter < max_count))
		JSON_COPY_STR_TO_ARRAY(array, (const char*)sqlite3_column_text(stmt, 0));

	// Acceptable return codes are either
	// - SQLITE_DONE: We read all lines, or
	// - SQLITE_ROW: We ended reading early because of set limit
	if( rc != SQLITE_DONE && rc != SQLITE_ROW )
	{
		sqlite3_finalize(stmt);
		return send_json_error(api, 500, // 500 Internal error
		                       "database_error",
		                       "Could not step in-memory database",
		                       sqlite3_errstr(rc));
	}

	// Finalize SQLite3 statement
	sqlite3_finalize(stmt);

	return 0;
}

int api_queries_suggestions(struct ftl_conn *api)
{
	int rc;
	// Does the user request a custom number of records to be included?
	int count = 30;
	get_int_var(api->request->query_string, "count", &count);

	// Get domains
	cJSON *domain = JSON_NEW_ARRAY();
	rc = add_strings_to_array(api, domain, "SELECT domain FROM domain_by_id", count);
	if(rc != 0)
	{
		log_err("Cannot read domains from database");
		cJSON_Delete(domain);
		return rc;
	}

	// Get clients, both by IP and names
	// We have to call DISTINCT() here as multiple IPs can map to and name and
	// vice versa
	cJSON *client_ip = JSON_NEW_ARRAY();
	rc = add_strings_to_array(api, client_ip, "SELECT DISTINCT(ip) FROM client_by_id", count);
	if(rc != 0)
	{
		log_err("Cannot read client IPs from database");
		cJSON_Delete(domain);
		cJSON_Delete(client_ip);
		return rc;
	}
	cJSON *client_name = JSON_NEW_ARRAY();
	rc = add_strings_to_array(api, client_name, "SELECT DISTINCT(name) FROM client_by_id", count);
	if(rc != 0)
	{
		log_err("Cannot read client names from database");
		cJSON_Delete(domain);
		cJSON_Delete(client_ip);
		cJSON_Delete(client_name);
		return rc;
	}

	// Get upstreams
	cJSON *upstream = JSON_NEW_ARRAY();
	rc = add_strings_to_array(api, upstream, "SELECT forward FROM forward_by_id", count);
	if(rc != 0)
	{
		log_err("Cannot read forward from database");
		cJSON_Delete(domain);
		cJSON_Delete(client_ip);
		cJSON_Delete(client_name);
		cJSON_Delete(upstream);
		return rc;
	}

	// Get types
	cJSON *type = JSON_NEW_ARRAY();
	queriesData query = { 0 };
	for(enum query_type t = TYPE_A; t < TYPE_MAX; t++)
	{
		query.type = t;
		const char *string = get_query_type_str(t, &query, NULL);
		JSON_REF_STR_IN_ARRAY(type, string);
	}

	// Get status
	cJSON *status = JSON_NEW_ARRAY();
	for(enum query_status s = QUERY_UNKNOWN; s <QUERY_STATUS_MAX; s++)
	{
		query.status = s;
		const char *string = get_query_status_str(query.status);
		JSON_REF_STR_IN_ARRAY(status, string);
	}

	// Get reply types
	cJSON *reply = JSON_NEW_ARRAY();
	for(enum reply_type r = REPLY_UNKNOWN; r <QUERY_REPLY_MAX; r++)
	{
		query.reply = r;
		const char *string = get_query_reply_str(query.reply);
		JSON_REF_STR_IN_ARRAY(reply, string);
	}

	// Get dnssec status
	cJSON *dnssec = JSON_NEW_ARRAY();
	for(enum dnssec_status d = DNSSEC_UNKNOWN; d < DNSSEC_MAX; d++)
	{
		query.dnssec = d;
		const char *string = get_query_dnssec_str(query.dnssec);
		JSON_REF_STR_IN_ARRAY(dnssec, string);
	}

	cJSON *suggestions = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "domain", domain);
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "client_ip", client_ip);
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "client_name", client_name);
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "upstream", upstream);
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "type", type);
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "status", status);
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "reply", reply);
	JSON_ADD_ITEM_TO_OBJECT(suggestions, "dnssec", dnssec);
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "suggestions", suggestions);

	JSON_SEND_OBJECT(json);
}

#define QUERYSTR "SELECT q.id,timestamp,q.type,status,d.domain,f.forward,additional_info,reply_type,reply_time,dnssec,c.ip,c.name,a.content" // ttl, regex_id
// JOIN: Only return rows where there is a match in BOTH tables
// LEFT JOIN: Return all rows from the left table, and the matched rows from the right table
#define JOINSTR "JOIN client_by_id c ON q.client = c.id JOIN domain_by_id d ON q.domain = d.id LEFT JOIN forward_by_id f ON q.forward = f.id LEFT JOIN addinfo_by_id a ON a.id = q.additional_info"
#define QUERYSTRORDER "ORDER BY q.id DESC"
#define QUERYSTRBUFFERLEN 4096
static void add_querystr_double(struct ftl_conn *api, char *querystr, const char *sql, const char *uripart, bool *where)
{
	double val;
	if(!get_double_var(api->request->query_string, uripart, &val))
		return;

	const size_t strpos = strlen(querystr);
	const char *glue = *where ? "AND" : "WHERE";
	*where = true;
	snprintf(querystr + strpos, QUERYSTRBUFFERLEN - strpos, " %s %s%f", glue, sql, val);
}

static void add_querystr_string(struct ftl_conn *api, char *querystr, const char *sql, const char *val, bool *where)
{
	const size_t strpos = strlen(querystr);
	const char *glue = *where ? "AND" : "WHERE";
	*where = true;
	snprintf(querystr + strpos, QUERYSTRBUFFERLEN - strpos, " %s (%s%s)", glue, sql, val);
}

static void querystr_finish(char *querystr)
{
	const size_t strpos = strlen(querystr);
	snprintf(querystr + strpos, QUERYSTRBUFFERLEN - strpos, " %s", QUERYSTRORDER);
}

int api_queries(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_MAXIMUM)
	{
		// Minimum structure is
		// {"queries":[], "cursor": null}
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *queries = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);
		// There are no more queries available, send NULL cursor
		JSON_ADD_NULL_TO_OBJECT(json, "cursor");
		JSON_SEND_OBJECT(json);
	}

	// On-disk database lookup requested?
	bool disk = false;
	if(api->request->query_string != NULL)
		get_bool_var(api->request->query_string, "disk", &disk);

	// Start building database query string
	char querystr[QUERYSTRBUFFERLEN] = { 0 };
	sprintf(querystr, "%s FROM %s q %s", QUERYSTR, disk ? "disk.query_storage" : "query_storage", JOINSTR);
	int draw = 0;

	char domainname[512] = { 0 };
	char clientip[512] = { 0 };
	char clientname[512] = { 0 };
	char upstreamname[256] = { 0 };
	char typename[32] = { 0 };
	char statusname[32] = { 0 };
	char replyname[32] = { 0 };
	char dnssecname[32] = { 0 };

	// We start with the most recent query at the beginning (until the cursor is changed)
	unsigned long cursor, largest_db_index, mem_dbnum, disk_dbnum;
	db_counts(&largest_db_index, &mem_dbnum, &disk_dbnum);
	cursor = largest_db_index;

	// We send 100 queries (unless the API is asked for a different limit)
	int length = 100;
	unsigned int start = 0;
	bool cursor_set = false, where = false;

	// Filtering based on GET parameters?
	if(api->request->query_string != NULL)
	{
		// Time filtering?
		add_querystr_double(api, querystr, "timestamp>=", "from", &where);
		add_querystr_double(api, querystr, "timestamp<", "until", &where);

		// Domain filtering?
		if(GET_STR("domain", domainname, api->request->query_string) > 0)
			add_querystr_string(api, querystr, "d.domain=", ":domain", &where);

		// Upstream filtering?
		if(GET_STR("upstream", upstreamname, api->request->query_string) > 0)
		{
			if(strcmp(upstreamname, "blocklist") == 0)
				// Pseudo-upstream for blocked queries
				add_querystr_string(api, querystr, "q.status IN ", get_blocked_statuslist(), &where);
			else if(strcmp(upstreamname, "cache") == 0)
				// Pseudo-upstream for cached queries
				add_querystr_string(api, querystr, "q.status IN ", get_cached_statuslist(), &where);
			else
				add_querystr_string(api, querystr, "f.forward=", ":upstream", &where);
		}

		// Client IP filtering?
		if(GET_STR("client_ip", clientip, api->request->query_string) > 0)
			add_querystr_string(api, querystr, "c.ip=", ":cip", &where);

		// Client filtering?
		if(GET_STR("client_name", clientname, api->request->query_string) > 0)
			add_querystr_string(api, querystr, "c.name=", ":cname", &where);

		// DataTables server-side processing protocol
		// Draw counter: This is used by DataTables to ensure that the
		//               Ajax returns from server-side processing
		//               requests are drawn in sequence by DataTables
		//               (Ajax requests are asynchronous and thus can
		//               return out of sequence).
		get_int_var(api->request->query_string, "draw", &draw);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(api->request->query_string, "length", &length);

		// Does the user request an offset from the cursor?
		get_uint_var(api->request->query_string, "start", &start);

		unsigned long long unum = 0u;
		const char *msg = NULL;
		if(get_ullong_var_msg(api->request->query_string, "cursor", &unum, &msg) ||
		   msg != NULL)
		{
			// Do not start at the most recent, but at an older
			// query (so new queries do not show up suddenly in the
			// log and shift pages)
			if(unum <= largest_db_index && msg == NULL)
			{
				cursor = unum;
				cursor_set = true;
			}
			else
			{
				if(msg == NULL)
					msg = "Cursor larger than largest database index";
				// Cursors larger than the current known number
				// of queries are invalid
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested cursor is invalid",
				                       msg);
			}
		}

		// Query type filtering?
		if(GET_STR("type", typename, api->request->query_string) > 0)
			add_querystr_string(api, querystr, "q.type=", ":type", &where);

		// Query status filtering?
		if(GET_STR("status", statusname, api->request->query_string) > 0)
			add_querystr_string(api, querystr, "q.status=", ":status", &where);

		// Reply type filtering?
		if(GET_STR("reply", replyname, api->request->query_string) > 0)
			add_querystr_string(api, querystr, "q.reply_type=", ":reply_type", &where);

		// DNSSEC status filtering?
		if(GET_STR("dnssec", dnssecname, api->request->query_string) > 0)
			add_querystr_string(api, querystr, "q.dnssec=", ":dnssec", &where);
	}

	// Get connection to in-memory database
	sqlite3 *db = get_memdb();

	// Finish preparing query string
	sqlite3_stmt *read_stmt = NULL;
	querystr_finish(querystr);

	// Attach disk database if necessary
	const char *message = "";
	if(disk && !attach_disk_database(&message))
	{
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, cannot attach disk database",
		                       message);
	}

	// Prepare SQLite3 statement
	int rc = sqlite3_prepare_v2(db, querystr, -1, &read_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, failed to prepare SQL query",
		                       sqlite3_errstr(rc));
	}

	// Bind items to prepared statement (if GET-filtering)
	if(api->request->query_string != NULL)
	{
		int idx;
		idx = sqlite3_bind_parameter_index(read_stmt, ":domain");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :domain = \"%s\" to query", domainname);
			if((rc = sqlite3_bind_text(read_stmt, idx, domainname, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind domain to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":cip");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :cip = \"%s\" to query", clientip);
			if((rc = sqlite3_bind_text(read_stmt, idx, clientip, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind cip to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":cname");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :cname = \"%s\" to query", clientname);
			if((rc = sqlite3_bind_text(read_stmt, idx, clientname, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind client to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":upstream");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :upstream = \"%s\" to query", upstreamname);
			if((rc = sqlite3_bind_text(read_stmt, idx, upstreamname, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind upstream to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":type");
		if(idx > 0)
		{
			enum query_type type;
			for(type = TYPE_A; type < TYPE_MAX; type++)
			{
				if(strcasecmp(typename, get_query_type_str(type, NULL, NULL)) == 0)
					break;
			}
			if(type < TYPE_MAX)
			{
				log_debug(DEBUG_API, "adding :type = %d to query", type);
				rc = sqlite3_bind_int(read_stmt, idx, type);
				if(rc != SQLITE_OK)
				{
					sqlite3_reset(read_stmt);
					sqlite3_finalize(read_stmt);
					return send_json_error(api, 500,
					                       "internal_error",
					                       "Internal server error, failed to bind type to SQL query",
					                       sqlite3_errstr(rc));
				}
			}
			else
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested type is invalid",
				                       typename);
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":status");
		if(idx > 0)
		{
			enum query_status status;
			for(status = QUERY_UNKNOWN; status < QUERY_STATUS_MAX; status++)
			{
				if(strcasecmp(statusname, get_query_status_str(status)) == 0)
					break;
			}
			if(status < QUERY_STATUS_MAX)
			{
				log_debug(DEBUG_API, "adding :status = %d to query", status);
				rc = sqlite3_bind_int(read_stmt, idx, status);
				if(rc != SQLITE_OK)
				{
					sqlite3_reset(read_stmt);
					sqlite3_finalize(read_stmt);
					return send_json_error(api, 500,
					                       "internal_error",
					                       "Internal server error, failed to bind status to SQL query",
					                       sqlite3_errstr(rc));
				}
			}
			else
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested status is invalid",
				                       statusname);
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":reply_type");
		if(idx > 0)
		{
			enum reply_type reply;
			for(reply = REPLY_UNKNOWN; reply < QUERY_REPLY_MAX; reply++)
			{
				if(strcasecmp(replyname, get_query_reply_str(reply)) == 0)
					break;
			}
			if(reply < QUERY_REPLY_MAX)
			{
				log_debug(DEBUG_API, "adding :reply_type = %d to query", reply);
				rc = sqlite3_bind_int(read_stmt, idx, reply);
				if(rc != SQLITE_OK)
				{
					sqlite3_reset(read_stmt);
					sqlite3_finalize(read_stmt);
					return send_json_error(api, 500,
					                       "internal_error",
					                       "Internal server error, failed to bind reply to SQL query",
					                       sqlite3_errstr(rc));
				}
			}
			else
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested reply is invalid",
				                       replyname);
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":dnssec");
		if(idx > 0)
		{
			enum dnssec_status dnssec;
			for(dnssec = DNSSEC_UNKNOWN; dnssec < DNSSEC_MAX; dnssec++)
			{
				if(strcasecmp(dnssecname, get_query_dnssec_str(dnssec)) == 0)
					break;
			}
			if(dnssec < DNSSEC_MAX)
			{
				log_debug(DEBUG_API, "adding :dnssec = %d to query", dnssec);
				rc = sqlite3_bind_int(read_stmt, idx, dnssec);
				if(rc != SQLITE_OK)
				{
					sqlite3_reset(read_stmt);
					sqlite3_finalize(read_stmt);
					return send_json_error(api, 500,
					                       "internal_error",
					                       "Internal server error, failed to bind dnssec to SQL query",
					                       sqlite3_errstr(rc));
				}
			}
			else
			{
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested dnssec is invalid",
				                       dnssecname);
			}
		}
	}

	// Debug logging
	log_debug(DEBUG_API, "SQL: %s", querystr);
	log_debug(DEBUG_API, "  with cursor: %lu, start: %u, length: %d", cursor, start, length);

	cJSON *queries = JSON_NEW_ARRAY();
	unsigned int added = 0, recordsCounted = 0;
	sqlite3_int64 firstID = -1, id = -1;
	bool skipTheRest = false;
	while((rc = sqlite3_step(read_stmt)) == SQLITE_ROW)
	{
		// Increase number of records from the database
		recordsCounted++;

		// Skip all records once we have enough (but still count them)
		if(skipTheRest)
			continue;

		// Check if we have reached the limit
		if(added >= (unsigned int)length)
		{
			if(api->request->query_string != NULL)
			{
				// We are filtering, so we have to continue to
				// step over the remaining rows to get the
				// correct number of total records
				skipTheRest = true;
				continue;
			}
			else
			{
				// We are not filtering, so we can stop here
				// The total number of records is the number
				// of records in the database
				break;
			}
		}

		// Get ID of query from database
		id = sqlite3_column_int64(read_stmt, 0); // q.id

		// Set firstID from the first returned value
		if(firstID == -1)
			firstID = id;

		// Server-side pagination
		if((unsigned long)id > cursor)
		{
			// Skip all results with id BEFORE cursor (static tip of table)
			continue;
		}
		else if(start > 0 && start >= recordsCounted)
		{
			// Skip all results BEFORE start (server-side pagination)
			continue;
		}
		else if(length > 0 && added >= (unsigned int)length)
		{
			// Length may be set to -1 to indicate we want
			// everything.
			// Skip everything AFTER we added the requested number
			// of queries if length is > 0.
			break;
		}

		// Build item object
		cJSON *item = JSON_NEW_OBJECT();
		queriesData query = { 0 };
		char buffer[20] = { 0 };
		JSON_ADD_NUMBER_TO_OBJECT(item, "id", id);
		JSON_ADD_NUMBER_TO_OBJECT(item, "time", sqlite3_column_double(read_stmt, 1)); // timestamp
		query.type = sqlite3_column_int(read_stmt, 2); // type
		query.status = sqlite3_column_int(read_stmt, 3); // status
		query.reply = sqlite3_column_int(read_stmt, 7); // reply_type
		query.dnssec = sqlite3_column_int(read_stmt, 9); // dnssec
		// We have to copy the string as TYPExxx string won't be static
		JSON_COPY_STR_TO_OBJECT(item, "type", get_query_type_str(query.type, &query, buffer));
		JSON_REF_STR_IN_OBJECT(item, "status", get_query_status_str(query.status));
		JSON_REF_STR_IN_OBJECT(item, "dnssec", get_query_dnssec_str(query.dnssec));
		JSON_COPY_STR_TO_OBJECT(item, "domain", sqlite3_column_text(read_stmt, 4)); // d.domain

		if(sqlite3_column_type(read_stmt, 5) == SQLITE_TEXT &&
		   sqlite3_column_bytes(read_stmt, 5) > 0)
			JSON_COPY_STR_TO_OBJECT(item, "upstream", sqlite3_column_text(read_stmt, 5)); // f.forward
		else
			JSON_ADD_NULL_TO_OBJECT(item, "upstream");

		cJSON *reply = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(reply, "type", get_query_reply_str(query.reply));
		JSON_ADD_NUMBER_TO_OBJECT(reply, "time", sqlite3_column_double(read_stmt, 8)); // reply_time
		JSON_ADD_ITEM_TO_OBJECT(item, "reply", reply);

		cJSON *client = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(client, "ip", sqlite3_column_text(read_stmt, 10)); // c.ip

		if(sqlite3_column_type(read_stmt, 11) == SQLITE_TEXT &&
		   sqlite3_column_bytes(read_stmt, 11) > 0)
			JSON_COPY_STR_TO_OBJECT(client, "name", sqlite3_column_text(read_stmt, 11)); // c.name
		else
			JSON_ADD_NULL_TO_OBJECT(client, "name");
		JSON_ADD_ITEM_TO_OBJECT(item, "client", client);

		JSON_ADD_NUMBER_TO_OBJECT(item, "ttl", 0); // sqlite3_column_int(read_stmt, 12));
		JSON_ADD_NUMBER_TO_OBJECT(item, "regex_id", 0); // sqlite3_column_int(read_stmt, 13));

		const unsigned char *cname = NULL;
		switch(query.status)
		{
			case QUERY_GRAVITY_CNAME:
			case QUERY_REGEX_CNAME:
			case QUERY_DENYLIST_CNAME:
			{
				cname = sqlite3_column_text(read_stmt, 12);
				break;
			}
			case QUERY_UNKNOWN:
			case QUERY_GRAVITY:
			case QUERY_FORWARDED:
			case QUERY_CACHE:
			case QUERY_REGEX:
			case QUERY_DENYLIST:
			case QUERY_EXTERNAL_BLOCKED_IP:
			case QUERY_EXTERNAL_BLOCKED_NULL:
			case QUERY_EXTERNAL_BLOCKED_NXRA:
			case QUERY_RETRIED:
			case QUERY_RETRIED_DNSSEC:
			case QUERY_IN_PROGRESS:
			case QUERY_DBBUSY:
			case QUERY_SPECIAL_DOMAIN:
			case QUERY_CACHE_STALE:
			case QUERY_STATUS_MAX:
				break;
		}
		if(cname != NULL)
			JSON_COPY_STR_TO_OBJECT(item, "cname", (const char*)cname);
		else
			JSON_ADD_NULL_TO_OBJECT(item, "cname");

		JSON_ADD_ITEM_TO_ARRAY(queries, item);

		added++;
	}
	log_debug(DEBUG_API, "Sending %u of %lu in memory and %lu on disk queries", added, mem_dbnum, disk_dbnum);
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);

	if(cursor_set)
	{
		// Repeat cursor received in the request. This ensures we get a
		// static result by skipping any newer queries.
		log_debug(DEBUG_API, "Sending cursor %lu", cursor);
		JSON_ADD_NUMBER_TO_OBJECT(json, "cursor", cursor);
	}
	else
	{
		// Send cursor pointing to the firstID of the data obtained in
		// this query. This ensures we get a static result by skipping
		// any newer queries.
		log_debug(DEBUG_API, "Sending cursor %lli (firstID)", (long long int)firstID);
		JSON_ADD_NUMBER_TO_OBJECT(json, "cursor", firstID);
	}

	// DataTables specific properties
	const unsigned long recordsTotal = disk ? disk_dbnum : mem_dbnum;
	JSON_ADD_NUMBER_TO_OBJECT(json, "recordsTotal", recordsTotal);
	JSON_ADD_NUMBER_TO_OBJECT(json, "recordsFiltered", api->request->query_string != NULL ? recordsCounted : recordsTotal);
	JSON_ADD_NUMBER_TO_OBJECT(json, "draw", draw);

	// Finalize statements
	sqlite3_finalize(read_stmt);

	if(disk && !detach_disk_database(&message))
	{
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, cannot detach disk database",
		                       message);
	}

	JSON_SEND_OBJECT(json);
}
