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

	sqlite3_stmt *stmt = NULL;
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

#define QUERYSTR "SELECT q.id,timestamp,q.type,status,d.domain,f.forward,additional_info,reply_type,reply_time,dnssec,c.ip,c.name,a.content,list_id"
// JOIN: Only return rows where there is a match in BOTH tables
// LEFT JOIN: Return all rows from the left table, and the matched rows from the right table
#define JOINSTR "JOIN client_by_id c ON q.client = c.id JOIN domain_by_id d ON q.domain = d.id LEFT JOIN forward_by_id f ON q.forward = f.id LEFT JOIN addinfo_by_id a ON a.id = q.additional_info"
#define QUERYSTRBUFFERLEN 4096

static void add_querystr_string(struct ftl_conn *api, char *querystr, const char *sql, const char *val, bool *where)
{
	const size_t strpos = strlen(querystr);
	const char *glue = *where ? "AND" : "WHERE";
	*where = true;
	snprintf(querystr + strpos, QUERYSTRBUFFERLEN - strpos, " %s (%s%s)", glue, sql, val);
}

static void querystr_finish(char *querystr, const char *sort_col, const char *sort_dir)
{
	const char *sort_col_sql = NULL;
	const char *sort_dir_sql = NULL;
	if(sort_col[0] != '\0' && sort_dir[0] != '\0')
	{
		// Try to parse the sort column ...
		if(strcasecmp(sort_col, "time") == 0)
			sort_col_sql = "timestamp";
		else if(strcasecmp(sort_col, "domain") == 0)
			sort_col_sql = "d.domain";
		else if(strcasecmp(sort_col, "client.ip") == 0)
			sort_col_sql = "c.ip";
		else if(strcasecmp(sort_col, "client.name") == 0)
			sort_col_sql = "c.name";
		else if(strcasecmp(sort_col, "upstream") == 0)
			sort_col_sql = "f.forward";
		else if(strcasecmp(sort_col, "type") == 0)
			sort_col_sql = "q.type";
		else if(strcasecmp(sort_col, "status") == 0)
			sort_col_sql = "q.status";
		else if(strcasecmp(sort_col, "reply") == 0)
			sort_col_sql = "q.reply_type";
		else if(strcasecmp(sort_col, "reply.time") == 0)
			sort_col_sql = "q.reply_time";
		else if(strcasecmp(sort_col, "dnssec") == 0)
			sort_col_sql = "q.dnssec";
		else if(strcasecmp(sort_col, "list_id") == 0)
			sort_col_sql = "list_id";

		// ... and the sort direction
		if(strcasecmp(sort_dir, "asc") == 0 || strcasecmp(sort_dir, "ascending") == 0)
			sort_dir_sql = "ASC";
		else if(strcasecmp(sort_dir, "desc") == 0 || strcasecmp(sort_dir, "descending") == 0)
			sort_dir_sql = "DESC";
	}

	const size_t strpos = strlen(querystr);
	if(sort_col_sql == NULL || sort_dir_sql == NULL)
	{
		// Default sorting: Most recent query first, sorting by ID (which is
		// the same as timestamp but faster)
		sort_col_sql = "q.id";
		sort_dir_sql = "DESC";
	}

	snprintf(querystr + strpos, QUERYSTRBUFFERLEN - strpos, " ORDER BY %s %s",
	         sort_col_sql, sort_dir_sql);
}

// This function modifies the passed string inline
static bool is_wildcard(char *string)
{
	// Check if wildcards are requested
	bool wildcard = false;
	const size_t stringlen = strlen(string);
	for(unsigned int i = 0u; i < stringlen; i++)
	{
		if(string[i] == '*')
		{
			// Replace "*" by SQLite3 wildcard character "%" and
			// memorize we actually want to do wildcard matching
			string[i] = '%';
			wildcard = true;
		}
	}
	return wildcard;
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
	snprintf(querystr, QUERYSTRBUFFERLEN, "%s FROM %s q %s", QUERYSTR, disk ? "disk.query_storage" : "query_storage", JOINSTR);
	int draw = 0;

	char domainname[512] = { 0 };
	char clientip[512] = { 0 };
	char clientname[512] = { 0 };
	char upstreamname[256] = { 0 };
	char typename[32] = { 0 };
	char statusname[32] = { 0 };
	char replyname[32] = { 0 };
	char dnssecname[32] = { 0 };

	char sort_dir[16] = { 0 };
	char sort_col[16] = { 0 };

	char search[2][512] = { { 0 }, { 0 } };

	// We start with the most recent query at the beginning (until the cursor is changed)
	unsigned long cursor, largest_db_index, mem_dbnum, disk_dbnum;
	db_counts(&largest_db_index, &mem_dbnum, &disk_dbnum);
	cursor = largest_db_index;

	// We send 100 queries (unless the API is asked for a different limit)
	int length = 100;
	unsigned int start = 0;
	bool cursor_set = false, where = false;
	double timestamp_from = 0.0, timestamp_until = 0.0;

	// Filter-/sorting based on GET parameters?
	if(api->request->query_string != NULL)
	{
		// Time filtering FROM (inclusive)
		if(get_double_var(api->request->query_string, "from", &timestamp_from))
			add_querystr_string(api, querystr, "timestamp>=", ":tsfrom", &where);

		// Time filtering UNTIL (exclusive)
		if(get_double_var(api->request->query_string, "until", &timestamp_until))
			add_querystr_string(api, querystr, "timestamp<", ":tsuntil", &where);

		// Domain filtering?
		if(GET_STR("domain", domainname, api->request->query_string) > 0)
		{
			if(is_wildcard(domainname))
				add_querystr_string(api, querystr, "d.domain LIKE", ":domain", &where);
			else
				add_querystr_string(api, querystr, "d.domain=", ":domain", &where);
		}

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
			{
				if(is_wildcard(upstreamname))
					add_querystr_string(api, querystr, "f.forward LIKE", ":upstream", &where);
				else
					add_querystr_string(api, querystr, "f.forward=", ":upstream", &where);
			}
		}

		// Client IP filtering?
		if(GET_STR("client_ip", clientip, api->request->query_string) > 0)
		{
			if(is_wildcard(clientip))
				add_querystr_string(api, querystr, "c.ip LIKE", ":cip", &where);
			else
				add_querystr_string(api, querystr, "c.ip=", ":cip", &where);
		}

		// Client filtering?
		if(GET_STR("client_name", clientname, api->request->query_string) > 0)
		{
			if(is_wildcard(clientname))
				add_querystr_string(api, querystr, "c.name LIKE", ":cname", &where);
			else
				add_querystr_string(api, querystr, "c.name=", ":cname", &where);
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

		uint64_t unum = 0u;
		const char *msg = NULL;
		if(get_uint64_var_msg(api->request->query_string, "cursor", &unum, &msg) ||
		   msg != NULL)
		{
			// Do not start at the most recent, but at an older
			// query (so new queries do not show up suddenly in the
			// log and shift pages)
			if(unum <= largest_db_index && msg == NULL)
			{
				cursor = unum;
				cursor_set = true;
				add_querystr_string(api, querystr, "q.id<=", ":cursor", &where);
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

		// Sorting?
		int sort_column = -1;
		// Encoded URI string: %5B = [ and %5D = ]
		if(get_int_var(api->request->query_string, "order%5B0%5D%5Bcolumn%5D", &sort_column) &&
		   GET_STR("order%5B0%5D%5Bdir%5D", sort_dir, api->request->query_string) > 0)
		{
			char sort_col_id[32] = { 0 };
			snprintf(sort_col_id, sizeof(sort_col_id), "columns%%5B%d%%5D%%5Bdata%%5D",
			         sort_column);

			// Encoded URI string: %5B = [ and %5D = ]
			if(GET_VAR(sort_col_id, sort_col, api->request->query_string) > 0)
				log_debug(DEBUG_API, "Sorting by column %s (%s)", sort_col, sort_dir);
			else
				log_warn("Sorting by column %d (%s) requested, but column name not found",
				         sort_column, sort_dir);
		}

		// Column searching?
		// ID 3 = domain, ID 4 = client, every other combination is requested
		for(unsigned int j = 0; j < 2; j++)
		{
			// Encoded URI string: %5B = [ and %5D = ]
			// columns[X][search][value] is the search string for column X
			char search_col[] = "columns%5BX%5D%5Bsearch%5D%5Bvalue%5D";
			search_col[10] = '3' + j;
			if(GET_STR(search_col, search[j], api->request->query_string) > 0)
			{
				// columns[X][data] is the name of column X
				char search_col_id[] = "columns%5BX%5D%5Bdata%5D";
				search_col_id[10] = '3' + j;

				// Encoded URI string: %5B = [ and %5D = ]
				char search_col_id_str[32] = { 0 };
				if(GET_VAR(search_col_id, search_col_id_str, api->request->query_string) > 0)
				{
					size_t searchlen = min(strlen(search[j]), sizeof(search[j]) - 2);

					// Replace "*" by SQLite3 wildcard character "%"
					for(unsigned int i = 0; i < searchlen; i++)
					{
						if(search[j][i] == '*')
							search[j][i] = '%';
					}

					// Add % at the end of the search string to
					// make it a wildcard if there is none
					if(search[j][searchlen - 1] != '%')
					{
						search[j][searchlen] = '%';
						search[j][searchlen + 1] = '\0';
						searchlen++;
					}

					// Add % at the beginning of the search
					// string to make it a wildcard if there
					// is none
					if(search[j][0] != '%')
					{
						memmove(search[j] + 1, search[j], searchlen + 1);
						search[j][0] = '%';
					}

					// Apply the search string to the query if this is an allowed column
					if(j == 0 && strcasecmp(search_col_id_str, "domain") == 0)
					{
						log_debug(DEBUG_API, "Searching column domain: \"%s\"", search[j]);
						add_querystr_string(api, querystr, "d.domain LIKE", ":domain_search", &where);
					}
					else if(j == 1 && (strcasecmp(search_col_id_str, "client.ip") == 0 || strcasecmp(search_col_id_str, "client") == 0))
					{
						log_debug(DEBUG_API, "Searching column client: \"%s\"", search[j]);
						// We search both client IP and name
						add_querystr_string(api, querystr, "c.ip LIKE :client_search OR c.name LIKE", ":client_search", &where);
					}
					else
						log_warn("Column %u with name \"%s\" is not searchable (allowed: 3 = domain, 4 = client)",
						         3 + j, search_col_id_str);
				}
				else
					log_warn("Column %u is not searchable (allowed: 3 = domain, 4 = client)", 3 + j);
			}
		}
	}

	// We use this boolean to memorize if we are filtering at all. It is used
	// later to decide if we can short-circuit the query counting for
	// performance reasons.
	bool filtering = false;

	// Regex filtering?
	regex_t *regex_domains = NULL;
	unsigned int N_regex_domains = 0;
	if(compile_filter_regex(api, "webserver.api.excludeDomains",
	                        config.webserver.api.excludeDomains.v.json,
	                        &regex_domains, &N_regex_domains))
		filtering = true;

	regex_t *regex_clients = NULL;
	unsigned int N_regex_clients = 0;
	if(compile_filter_regex(api, "webserver.api.excludeClients",
	                        config.webserver.api.excludeClients.v.json,
	                        &regex_clients, &N_regex_clients))
		filtering = true;

	// Finish preparing query string
	querystr_finish(querystr, sort_col, sort_dir);

	// Get connection to in-memory database
	sqlite3 *memdb = get_memdb();
	if(memdb == NULL)
	{
		return send_json_error(api, 500, // 500 Internal error
		                       "database_error",
		                       "Could not read from in-memory database",
		                       NULL);
	}

	// Prepare SQLite3 statement
	sqlite3_stmt *read_stmt = NULL;
	int rc = sqlite3_prepare_v2(memdb, querystr, -1, &read_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, failed to prepare read SQL query",
		                       sqlite3_errstr(rc));
	}

	// Bind items to prepared statement
	if(api->request->query_string != NULL)
	{
		int idx;
		idx = sqlite3_bind_parameter_index(read_stmt, ":tsfrom");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :tsfrom = %lf to query", timestamp_from);
			filtering = true;
			if((rc = sqlite3_bind_double(read_stmt, idx, timestamp_from)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind timestamp:from to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":tsuntil");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :tsuntil = %lf to query", timestamp_until);
			filtering = true;
			if((rc = sqlite3_bind_double(read_stmt, idx, timestamp_until)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind timestamp:until to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":domain");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :domain = \"%s\" to query", domainname);
			filtering = true;
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
			filtering = true;
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
			filtering = true;
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
			filtering = true;
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
				filtering = true;
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
				filtering = true;
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
				filtering = true;
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
				filtering = true;
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
		idx = sqlite3_bind_parameter_index(read_stmt, ":cursor");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :cursor = %lu to query", cursor);
			// Do not set filtering as the cursor is not a filter
			rc = sqlite3_bind_int64(read_stmt, idx, cursor);
			if(rc != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind count to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":domain_search");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :domain_search = \"%s\" to query", search[0]);
			filtering = true;
			if((rc = sqlite3_bind_text(read_stmt, idx, search[0], -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind domain_search to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
		idx = sqlite3_bind_parameter_index(read_stmt, ":client_search");
		if(idx > 0)
		{
			log_debug(DEBUG_API, "adding :client_search = \"%s\" to query", search[1]);
			filtering = true;
			if((rc = sqlite3_bind_text(read_stmt, idx, search[1], -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				sqlite3_reset(read_stmt);
				sqlite3_finalize(read_stmt);
				return send_json_error(api, 500,
				                       "internal_error",
				                       "Internal server error, failed to bind client_search to SQL query",
				                       sqlite3_errstr(rc));
			}
		}
	}

	// Debug logging
	log_debug(DEBUG_API, "SQL: %s", querystr);
	log_debug(DEBUG_API, "  with cursor: %lu, start: %u, length: %d", cursor, start, length);

	cJSON *queries = JSON_NEW_ARRAY();
	unsigned int added = 0, recordsCounted = 0, regex_skipped = 0;
	bool skipTheRest = false;
	while((rc = sqlite3_step(read_stmt)) == SQLITE_ROW)
	{
		// Increase number of records from the database
		recordsCounted++;

		// Apply possible domain regex filters to Query Log
		const char *domain = (const char*)sqlite3_column_text(read_stmt, 4); // d.domain
		if(N_regex_domains > 0)
		{
			bool match = false;
			// Iterate over all regex filters
			for(unsigned int i = 0; i < N_regex_domains; i++)
			{
				// Check if the domain matches the regex
				if(regexec(&regex_domains[i], domain, 0, NULL, 0) == 0)
				{
					// Domain matches
					match = true;
					break;
				}
			}
			if(match)
			{
				// Domain matches, we skip it and adjust the
				// counter
				recordsCounted--;
				regex_skipped++;
				continue;
			}
		}

		// Apply possible client regex filters to Query Log
		const char *client_ip = (const char*)sqlite3_column_text(read_stmt, 10); // c.ip
		const char *client_name = NULL;
		if(sqlite3_column_type(read_stmt, 11) == SQLITE_TEXT && sqlite3_column_bytes(read_stmt, 11) > 0)
			client_name = (const char*)sqlite3_column_text(read_stmt, 11); // c.name
		if(N_regex_clients > 0)
		{
			bool match = false;
			// Iterate over all regex filters
			for(unsigned int i = 0; i < N_regex_clients; i++)
			{
				// Check if the domain matches the regex
				if(regexec(&regex_clients[i], client_ip, 0, NULL, 0) == 0)
				{
					// Client IP matches
					match = true;
					break;
				}
				else if(client_name != NULL && regexec(&regex_clients[i], client_name, 0, NULL, 0) == 0)
				{
					// Client name matches
					match = true;
					break;
				}
			}
			if(match)
			{
				// Domain matches, we skip it and adjust the
				// counter
				recordsCounted--;
				regex_skipped++;
				continue;
			}
		}

		// Skip all records once we have enough (but still count them)
		if(skipTheRest)
			continue;

		// Check if we have reached the limit
		// Length may be set to -1 to indicate we want everything.
		if(length > 0 && added >= (unsigned int)length)
		{
			if(filtering)
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

		// Server-side pagination
		if(start > 0 && start >= recordsCounted)
		{
			// Skip all results BEFORE start (server-side pagination)
			continue;
		}
		else if(length > 0 && added >= (unsigned int)length)
		{
			// Skip everything AFTER we added the requested number
			// of queries if length is > 0.
			continue;
		}

		// Check if we have reached the limit
		if(added >= (unsigned int)length)
		{
			if(filtering)
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

		// Build item object
		cJSON *item = JSON_NEW_OBJECT();
		queriesData query = { 0 };
		char buffer[20] = { 0 };
		JSON_ADD_NUMBER_TO_OBJECT(item, "id", sqlite3_column_int64(read_stmt, 0)); // q.id);
		JSON_ADD_NUMBER_TO_OBJECT(item, "time", sqlite3_column_double(read_stmt, 1)); // timestamp
		query.type = sqlite3_column_int(read_stmt, 2); // type
		query.status = sqlite3_column_int(read_stmt, 3); // status
		query.reply = sqlite3_column_int(read_stmt, 7); // reply_type
		query.dnssec = sqlite3_column_int(read_stmt, 9); // dnssec
		// We have to copy the string as TYPExxx string won't be static
		JSON_COPY_STR_TO_OBJECT(item, "type", get_query_type_str(query.type, &query, buffer));
		JSON_REF_STR_IN_OBJECT(item, "status", get_query_status_str(query.status));
		JSON_REF_STR_IN_OBJECT(item, "dnssec", get_query_dnssec_str(query.dnssec));
		JSON_COPY_STR_TO_OBJECT(item, "domain", domain);

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
		JSON_COPY_STR_TO_OBJECT(client, "ip", client_ip);
		if(client_name != NULL)
			JSON_COPY_STR_TO_OBJECT(client, "name", client_name);
		else
			JSON_ADD_NULL_TO_OBJECT(client, "name");
		JSON_ADD_ITEM_TO_OBJECT(item, "client", client);

		// Add list_id if it exists
		if(sqlite3_column_type(read_stmt, 13) == SQLITE_INTEGER)
			JSON_ADD_NUMBER_TO_OBJECT(item, "list_id", sqlite3_column_int(read_stmt, 13)); // list_id
		else
			JSON_ADD_NULL_TO_OBJECT(item, "list_id");

		const unsigned char *cname = NULL;
		switch(query.status)
		{
			case QUERY_GRAVITY_CNAME:
			case QUERY_REGEX_CNAME:
			case QUERY_DENYLIST_CNAME:
			{
				cname = sqlite3_column_text(read_stmt, 12); // a.content
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
	log_debug(DEBUG_API, "Sending %u of %lu in memory and %lu on disk queries (counted %u, skipped %u)",
	          added, mem_dbnum, disk_dbnum, recordsCounted, regex_skipped);
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
		log_debug(DEBUG_API, "Sending cursor %lu (firstID)", get_max_db_idx());
		JSON_ADD_NUMBER_TO_OBJECT(json, "cursor", get_max_db_idx());
	}

	// DataTables specific properties
	const unsigned long recordsTotal = disk ? disk_dbnum : mem_dbnum;
	JSON_ADD_NUMBER_TO_OBJECT(json, "recordsTotal", recordsTotal);
	JSON_ADD_NUMBER_TO_OBJECT(json, "recordsFiltered", filtering ? recordsCounted : recordsTotal);
	JSON_ADD_NUMBER_TO_OBJECT(json, "draw", draw);

	// Finalize statements
	sqlite3_finalize(read_stmt);

	// Free regex memory if allocated
	if(N_regex_domains > 0)
	{
		// Free individual regexes
		for(unsigned int i = 0; i < N_regex_domains; i++)
			regfree(&regex_domains[i]);

		// Free array of regex pointers
		free(regex_domains);
	}
	if(N_regex_clients > 0)
	{
		// Free individual regexes
		for(unsigned int i = 0; i < N_regex_clients; i++)
			regfree(&regex_clients[i]);

		// Free array of regex po^inters
		free(regex_clients);
	}

	JSON_SEND_OBJECT(json);
}

bool compile_filter_regex(struct ftl_conn *api, const char *path, cJSON *json, regex_t **regex, unsigned int *N_regex)
{

	const int N = cJSON_GetArraySize(json);
	if(N < 1)
		return false;

	// Set number of regexes (positive = unsigned integer)
	*N_regex = N;

	// Allocate memory for regex array
	*regex = calloc(N, sizeof(regex_t));
	if(*regex == NULL)
	{
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, failed to allocate memory for regex array",
		                       NULL);
	}

	// Compile regexes
	unsigned int i = 0;
	cJSON *filter = NULL;
	cJSON_ArrayForEach(filter, json)
	{
		// Skip non-string, invalid and empty values
		if(!cJSON_IsString(filter) || filter->valuestring == NULL || strlen(filter->valuestring) == 0)
		{
			log_warn("Skipping invalid regex at %s.%u", path, i);
			continue;
		}

		// Compile regex
		int rc = regcomp(&(*regex)[i], filter->valuestring, REG_EXTENDED);
		if(rc != 0)
		{
			// Failed to compile regex
			char errbuf[1024] = { 0 };
			regerror(rc, &(*regex)[i], errbuf, sizeof(errbuf));
			log_err("Failed to compile regex \"%s\": %s",
			        filter->valuestring, errbuf);
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Failed to compile regex",
			                       filter->valuestring);
		}

		i++;
	}

	// We are filtering, so we have to continue to step over the
	// remaining rows to get the correct number of total records
	return true;
}
