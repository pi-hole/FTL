/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "api.h"
#include "../shmem.h"
#include "../datastructure.h"
// config struct
#include "../config/config.h"
// read_setupVarsconf()
#include "../setupVars.h"
// get_aliasclient_list()
#include "../database/aliasclients.h"
// get_memdb()
#include "../database/query-table.h"

// dbopen(), dbclose()
#include "../database/common.h"

static int add_strings_to_array(struct ftl_conn *api, cJSON *array, const char *querystr)
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
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
		JSON_ARRAY_COPY_STR(array, (const char*)sqlite3_column_text(stmt, 0));

	if( rc != SQLITE_DONE )
	{
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
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// Get domains
	cJSON *domain = JSON_NEW_ARRAY();
	rc = add_strings_to_array(api, domain, "SELECT DISTINCT(domain) FROM queries");
	if(rc != 0)
	{
		cJSON_Delete(domain);
		return rc;
	}

	// Get clients
	cJSON *client = JSON_NEW_ARRAY();
	rc = add_strings_to_array(api, client, "SELECT DISTINCT(client) FROM queries");
	if(rc != 0)
	{
		cJSON_Delete(domain);
		cJSON_Delete(client);
		return rc;
	}

	// Get upstreams
	cJSON *upstream = JSON_NEW_ARRAY();
	rc = add_strings_to_array(api, upstream, "SELECT DISTINCT(forward) FROM queries WHERE forward IS NOT NULL");
	if(rc != 0)
	{
		cJSON_Delete(domain);
		cJSON_Delete(client);
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
		JSON_ARRAY_REF_STR(type, string);
	}

	// Get status
	cJSON *status = JSON_NEW_ARRAY();
	for(enum query_status s = STATUS_UNKNOWN; s < STATUS_MAX; s++)
	{
		query.status = s;
		const char *string = get_query_status_str(query.status);
		JSON_ARRAY_REF_STR(status, string);
	}

	// Get reply types
	cJSON *reply = JSON_NEW_ARRAY();
	for(enum reply_type r = REPLY_UNKNOWN; r < REPLY_MAX; r++)
	{
		query.reply = r;
		const char *string = get_query_reply_str(query.reply);
		JSON_ARRAY_REF_STR(reply, string);
	}

	// Get dnssec status
	cJSON *dnssec = JSON_NEW_ARRAY();
	for(enum dnssec_status d = DNSSEC_UNKNOWN; d < DNSSEC_MAX; d++)
	{
		query.dnssec = d;
		const char *string = get_query_dnssec_str(query.dnssec);
		JSON_ARRAY_REF_STR(dnssec, string);
	}

	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "domain", domain);
	JSON_OBJ_ADD_ITEM(json, "client", client);
	JSON_OBJ_ADD_ITEM(json, "upstream", upstream);
	JSON_OBJ_ADD_ITEM(json, "type", type);
	JSON_OBJ_ADD_ITEM(json, "status", status);
	JSON_OBJ_ADD_ITEM(json, "reply", reply);
	JSON_OBJ_ADD_ITEM(json, "dnssec", dnssec);

	JSON_SEND_OBJECT(json);
}

#define QUERYSTR "SELECT id,timestamp,type,status,domain,client,forward,additional_info,reply,dnssec,reply_time,client_name,ttl,regex_id"
#define QUERYSTRORDER "ORDER BY id DESC"
#define QUERYSTRLEN 4096
static void add_querystr_double(struct ftl_conn *api, char *querystr, const char *sql, const char *uripart, bool *where)
{
	double val;
	if(!get_double_var(api->request->query_string, uripart, &val))
		return;

	const size_t strpos = strlen(querystr);
	const char *glue = *where ? "AND" : "WHERE";
	*where = true;
	snprintf(querystr + strpos, QUERYSTRLEN - strpos, " %s %s%f", glue, sql, val);
}

static void add_querystr_string(struct ftl_conn *api, char *querystr, const char *sql, const char *val, bool *where)
{
	const size_t strpos = strlen(querystr);
	const char *glue = *where ? "AND" : "WHERE";
	*where = true;
	snprintf(querystr + strpos, QUERYSTRLEN - strpos, " %s %s%s", glue, sql, val);
}

static void querystr_finish(char *querystr)
{
	const size_t strpos = strlen(querystr);
	snprintf(querystr + strpos, QUERYSTRLEN - strpos, " %s", QUERYSTRORDER);
}

int api_queries(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	if(config.privacylevel >= PRIVACY_MAXIMUM)
	{
		// Minimum structure is
		// {"queries":[], "cursor": null}
		cJSON *json = JSON_NEW_OBJ();
		cJSON *queries = JSON_NEW_ARRAY();
		JSON_OBJ_ADD_ITEM(json, "queries", queries);
		// There are no more queries available, send NULL cursor
		JSON_OBJ_ADD_NULL(json, "cursor");
		JSON_SEND_OBJECT(json);
	}

	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	// On-disk database lookup requested?
	bool disk = false;
	if(api->request->query_string != NULL)
		get_bool_var(api->request->query_string, "disk", &disk);

	// Start building database query string
	char querystr[QUERYSTRLEN] = { 0 };
	sprintf(querystr, "%s FROM %s", QUERYSTR, disk ? "disk.queries" : "queries");
	int draw = 0;

	char domainname[512] = { 0 };
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
		char buffer[256] = { 0 };

		// Time filtering?
		add_querystr_double(api, querystr, "timestamp>=", "from", &where);
		add_querystr_double(api, querystr, "timestamp<", "until", &where);

		// Domain filtering?
		if(GET_VAR("domain", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%255s", domainname);
			add_querystr_string(api, querystr, "domain=", ":domain", &where);
		}

		// Upstream filtering?
		if(GET_VAR("upstream", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%255s", upstreamname);
			add_querystr_string(api, querystr, "forward=", ":upstream", &where);
		}

		// Client filtering?
		if(GET_VAR("client", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%255s", clientname);
			add_querystr_string(api, querystr, "client=", ":client", &where);
		}

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

		unsigned long unum = 0u;
		const char *msg = NULL;
		if(get_ulong_var_msg(api->request->query_string, "cursor", &unum, &msg) ||
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
		if(GET_VAR("type", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%31s", typename);
			add_querystr_string(api, querystr, "type=", ":type", &where);
		}

		// Query status filtering?
		if(GET_VAR("status", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%31s", statusname);
			add_querystr_string(api, querystr, "status=", ":status", &where);
		}

		// Reply type filtering?
		if(GET_VAR("reply", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%31s", replyname);
			add_querystr_string(api, querystr, "reply=", ":reply", &where);
		}

		// DNSSEC status filtering?
		if(GET_VAR("dnssec", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%31s", dnssecname);
			add_querystr_string(api, querystr, "dnssec=", ":dnssec", &where);
		}
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
		return false;
	}

	// Prepare SQLIte3 statement
	int rc = sqlite3_prepare_v2(db, querystr, -1, &read_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, failed to prepare SQL query",
		                       sqlite3_errstr(rc));
		return false;
	}

	// Bind items to prepared statement (if GET-filtering)
	if(api->request->query_string != NULL)
	{
		int idx;
		idx = sqlite3_bind_parameter_index(read_stmt, ":domain");
		if(idx > 0 && (rc = sqlite3_bind_text(read_stmt, idx, domainname, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			sqlite3_reset(read_stmt);
			sqlite3_finalize(read_stmt);
			return send_json_error(api, 500,
			                       "internal_error",
			                       "Internal server error, failed to bind domain to SQL query",
			                       sqlite3_errstr(rc));
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":client");
		if(idx > 0 && (rc = sqlite3_bind_text(read_stmt, idx, clientname, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			sqlite3_reset(read_stmt);
			sqlite3_finalize(read_stmt);
			return send_json_error(api, 500,
			                       "internal_error",
			                       "Internal server error, failed to bind client to SQL query",
			                       sqlite3_errstr(rc));
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":upstream");
		if(idx > 0 && (rc = sqlite3_bind_text(read_stmt, idx, upstreamname, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			sqlite3_reset(read_stmt);
			sqlite3_finalize(read_stmt);
			return send_json_error(api, 500,
			                       "internal_error",
			                       "Internal server error, failed to bind upstream to SQL query",
			                       sqlite3_errstr(rc));
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
			for(status = STATUS_UNKNOWN; status < STATUS_MAX; status++)
			{
				if(strcasecmp(statusname, get_query_status_str(status)) == 0)
					break;
			}
			if(status < STATUS_MAX)
			{
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
		idx = sqlite3_bind_parameter_index(read_stmt, ":reply");
		if(idx > 0)
		{
			enum reply_type reply;
			for(reply = REPLY_UNKNOWN; reply < REPLY_MAX; reply++)
			{
				if(strcasecmp(replyname, get_query_reply_str(reply)) == 0)
					break;
			}
			if(reply < REPLY_MAX)
			{
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
	unsigned int added = 0, records = 0;
	sqlite3_int64 firstID = -1, id = -1;
	while((rc = sqlite3_step(read_stmt)) == SQLITE_ROW)
	{
		// Get ID of query from database
		id = sqlite3_column_int64(read_stmt, 0);

		// Set firstID from the first returned value
		if(firstID == -1)
			firstID = id;

		// Increase number of records from the database
		records++;

		// Serve-side pagination
		if((unsigned long)id > cursor)
		{
			// Skip all results with id BEFORE cursor (static tip of table)
			continue;
		}
		else if(start > 0 && start >= records)
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
			continue;
		}

		// Build item object
		cJSON *item = JSON_NEW_OBJ();
		queriesData query = { 0 };
		char buffer[20] = { 0 };
		JSON_OBJ_ADD_NUMBER(item, "id", id);
		JSON_OBJ_ADD_NUMBER(item, "time", sqlite3_column_double(read_stmt, 1));
		query.type = sqlite3_column_int(read_stmt, 2);
		query.status = sqlite3_column_int(read_stmt, 3);
		query.reply = sqlite3_column_int(read_stmt, 8);
		query.dnssec = sqlite3_column_int(read_stmt, 9);
		// We have to copy the string as TYPExxx string won't be static
		JSON_OBJ_COPY_STR(item, "type", get_query_type_str(query.type, &query, buffer));
		JSON_OBJ_REF_STR(item, "status", get_query_status_str(query.status));
		JSON_OBJ_REF_STR(item, "dnssec", get_query_dnssec_str(query.dnssec));
		JSON_OBJ_COPY_STR(item, "domain", sqlite3_column_text(read_stmt, 4));
		if(sqlite3_column_type(read_stmt, 6) == SQLITE_NULL)
		{
			JSON_OBJ_ADD_NULL(item, "upstream");
		}
		else
		{
			JSON_OBJ_COPY_STR(item, "upstream", sqlite3_column_text(read_stmt, 6));
		}

		cJSON *reply = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(reply, "type", get_query_reply_str(query.reply));
		JSON_OBJ_ADD_NUMBER(reply, "time", sqlite3_column_double(read_stmt, 10));
		JSON_OBJ_ADD_ITEM(item, "reply", reply);

		cJSON *client = JSON_NEW_OBJ();
		JSON_OBJ_COPY_STR(client, "ip", sqlite3_column_text(read_stmt, 5));
		if(sqlite3_column_type(read_stmt, 11) == SQLITE_TEXT)
		{
			JSON_OBJ_COPY_STR(client, "name", sqlite3_column_text(read_stmt, 11));
		}
		else
		{
			JSON_OBJ_ADD_NULL(client, "name");
		}
		JSON_OBJ_ADD_ITEM(item, "client", client);

		JSON_OBJ_ADD_NUMBER(item, "ttl", sqlite3_column_int(read_stmt, 12));
		JSON_OBJ_ADD_NUMBER(item, "regex_id", sqlite3_column_int(read_stmt, 13));

		JSON_ARRAY_ADD_ITEM(queries, item);

		added++;
	}
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "queries", queries);

	if(cursor_set)
	{
		// Repeat cursor received in the request. This ensures we get a
		// static result by skipping any newer queries.
		JSON_OBJ_ADD_NUMBER(json, "cursor", cursor);
	}
	else
	{
		// Send cursor pointing to the firstID of the data obtained in
		// this query. This ensures we get a static result by skipping
		// any newer queries.
		JSON_OBJ_ADD_NUMBER(json, "cursor", firstID);
	}

	// DataTables specific properties
	JSON_OBJ_ADD_NUMBER(json, "recordsTotal", disk ? disk_dbnum : mem_dbnum);
	JSON_OBJ_ADD_NUMBER(json, "recordsFiltered", records);
	JSON_OBJ_ADD_NUMBER(json, "draw", draw);

	if(disk && !detach_disk_database(&message))
	{
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, cannot detach disk database",
		                       message);
		return false;
	}

	JSON_SEND_OBJECT(json);
}
