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
// get_import_window(), get_db_info()
#include "database/query-table.h"
// dbopen(false, ), dbclose()
#include "database/common.h"
#include "api/queries.h"
// db_import_done
#include "gc.h"
// PRIu64
#include <inttypes.h>

int api_queries_suggestions(struct ftl_conn *api)
{
	// Does the user request a custom number of records to be included?
	int count = 30;
	get_int_var(api->request->query_string, "count", &count);

	// Get domains
	cJSON *domain = get_top_domains(api, count, false, true);
	cJSON *blocked = get_top_domains(api, count, true, true);
	// Add domains from both arrays, avoiding duplicates
	cJSON *entry = NULL;
	cJSON_ArrayForEach(entry, blocked)
	{
		// Check if the domain is already in the list
		bool found = false;
		cJSON *entry2 = NULL;
		cJSON_ArrayForEach(entry2, domain)
		{
			if(strcmp(cJSON_GetStringValue(entry), cJSON_GetStringValue(entry2)) == 0)
			{
				found = true;
				break;
			}
		}
		if(!found)
			JSON_ADD_ITEM_TO_ARRAY(domain, cJSON_Duplicate(entry, true));
	}
	// Free the blocked list
	cJSON_Delete(blocked);

	// Get clients, both by IP and names
	cJSON *client_ip = get_top_clients(api, count, false, true, false, false);
	cJSON *client_name = get_top_clients(api, count, false, true, true, false);

	// Delete duplicate entries from client_name
	cJSON_unique_array(client_name);

	// Get upstreams
	cJSON *upstream = get_top_upstreams(api, true);
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

	// Add special "permitted" upstream which is the sum of forwarded and
	// cached queries
	JSON_REF_STR_IN_ARRAY(upstream, "permitted");

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

#define QUERYSTR "SELECT q.id,timestamp,q.type,status,d.domain,f.forward,additional_info,reply_type,reply_time,dnssec,c.ip,c.name,a.content,list_id,ede"
// JOIN: Only return rows where there is a match in BOTH tables
// LEFT JOIN: Return all rows from the left table, and the matched rows from the right table
#define JOINSTR "JOIN client_by_id c ON q.client = c.id JOIN domain_by_id d ON q.domain = d.id LEFT JOIN forward_by_id f ON q.forward = f.id LEFT JOIN addinfo_by_id a ON a.id = q.additional_info"
#define QUERYSTRBUFFERLEN 4096

static void add_querystr_string(char *querystr, const char *sql, const char *val, bool *where)
{
	const size_t strpos = strlen(querystr);
	const char *glue = *where ? "AND" : "WHERE";
	*where = true;
	snprintf(querystr + strpos, QUERYSTRBUFFERLEN - strpos, " %s (%s%s)", glue, sql, val);
}

// The sort column and direction of a request. Anything unknown sorts by ID,
// newest first
static void parse_sort(const char *sort_col, const char *sort_dir, struct qlog_request *req)
{
	static const struct { const char *name; enum qlog_sort sort; } columns[] = {
		{ "time", QLOG_SORT_TIME },
		{ "domain", QLOG_SORT_DOMAIN },
		{ "client.ip", QLOG_SORT_CLIENT_IP },
		{ "client.name", QLOG_SORT_CLIENT_NAME },
		{ "upstream", QLOG_SORT_UPSTREAM },
		{ "type", QLOG_SORT_TYPE },
		{ "status", QLOG_SORT_STATUS },
		{ "reply", QLOG_SORT_REPLY },
		{ "reply.time", QLOG_SORT_REPLY_TIME },
		{ "dnssec", QLOG_SORT_DNSSEC },
		{ "list_id", QLOG_SORT_LIST_ID },
		{ "ede", QLOG_SORT_EDE },
	};

	req->sort = QLOG_SORT_ID;
	req->sort_desc = true;
	if(sort_col[0] == '\0' || sort_dir[0] == '\0')
		return;

	bool desc = false;
	if(strcasecmp(sort_dir, "asc") == 0 || strcasecmp(sort_dir, "ascending") == 0)
		desc = false;
	else if(strcasecmp(sort_dir, "desc") == 0 || strcasecmp(sort_dir, "descending") == 0)
		desc = true;
	else
		return;

	for(unsigned int i = 0; i < ArraySize(columns); i++)
	{
		if(strcasecmp(sort_col, columns[i].name) == 0)
		{
			req->sort = columns[i].sort;
			req->sort_desc = desc;
			return;
		}
	}
}

// The SQL expression of a sort column
static const char *sort_column_sql(const enum qlog_sort sort)
{
	switch(sort)
	{
		case QLOG_SORT_TIME:
			return "timestamp";
		case QLOG_SORT_DOMAIN:
			return "d.domain";
		case QLOG_SORT_CLIENT_IP:
			return "c.ip";
		case QLOG_SORT_CLIENT_NAME:
			return "c.name";
		case QLOG_SORT_UPSTREAM:
			return "f.forward";
		case QLOG_SORT_TYPE:
			return "q.type";
		case QLOG_SORT_STATUS:
			return "q.status";
		case QLOG_SORT_REPLY:
			return "q.reply_type";
		case QLOG_SORT_REPLY_TIME:
			return "q.reply_time";
		case QLOG_SORT_DNSSEC:
			return "q.dnssec";
		case QLOG_SORT_LIST_ID:
			return "list_id";
		case QLOG_SORT_EDE:
			return "ede";
		case QLOG_SORT_ID:
		default:
			// Most recent query first, sorting by ID (which is the same
			// as timestamp but faster)
			return "q.id";
	}
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

// Turn a column search into a LIKE pattern, modifying it inline: '*' becomes
// '%', and the pattern gets a leading and a trailing '%' unless it has one
static void search_pattern(char *search, const size_t size)
{
	// Leave room for a leading and a trailing wildcard plus the terminating
	// NUL that are added below
	size_t searchlen = min(strlen(search), size - 3);

	// Replace "*" by SQLite3 wildcard character "%"
	for(unsigned int i = 0; i < searchlen; i++)
	{
		if(search[i] == '*')
			search[i] = '%';
	}

	// Add % at the end of the search string to make it a wildcard if there
	// is none. Guard against searchlen == 0 (empty value), which would make
	// searchlen - 1 underflow into an out-of-bounds read.
	if(searchlen == 0 || search[searchlen - 1] != '%')
	{
		search[searchlen] = '%';
		search[searchlen + 1] = '\0';
		searchlen++;
	}

	// Add % at the beginning of the search string to make it a wildcard if
	// there is none
	if(search[0] != '%')
	{
		memmove(search + 1, search, searchlen + 1);
		search[0] = '%';
	}
}

// Read the string parameter var into dest of the given size, as
// get_string_var() does. Returns the length of its value, zero or less when it
// is absent or empty. A value that does not fit is answered with a 400 naming
// the parameter (as name) and the limit, the status of that reply goes to *ret
static int get_filter_var(struct ftl_conn *api, const char *qs, const char *var,
                          const char *name, char *dest, const size_t size, int *ret)
{
	const int len = get_string_var(qs, var, dest, size);
	if(len == -2)
	{
		char hint[64];
		snprintf(hint, sizeof(hint), "%s: at most %zu bytes", name, size - 1);
		*ret = send_json_error(api, 400,
		                       "bad_request",
		                       "Requested filter is too long",
		                       hint);
	}
	return len;
}

// Read the request into req. Returns 0, or the status of the error reply it
// sent. largest_id is the highest query ID a cursor may name
static int parse_queries_request(struct ftl_conn *api, struct qlog_request *req,
                                 const sqlite3_int64 largest_id)
{
	int ret = 0;

	// We start with the most recent query at the beginning (until the
	// cursor is changed). We send 100 queries (unless the API is asked for
	// a different limit)
	req->cursor = (uint64_t)largest_id;
	req->length = 100;

	char typename[32] = { 0 };
	char statusname[32] = { 0 };
	char replyname[32] = { 0 };
	char dnssecname[32] = { 0 };
	char sort_dir[16] = { 0 };
	char sort_col[16] = { 0 };

	const char *qs = api->request->query_string;
	if(qs != NULL)
	{
		// Time filtering FROM (inclusive) and UNTIL (exclusive)
		req->has_from = get_double_var(qs, "from", &req->from);
		req->has_until = get_double_var(qs, "until", &req->until);

		// Domain filtering?
		if(get_filter_var(api, qs, "domain", "domain", req->domain,
		                  sizeof(req->domain), &ret) > 0)
		{
			req->has_domain = true;
			req->domain_like = is_wildcard(req->domain);
		}
		if(ret != 0)
			return ret;

		// Upstream filtering?
		if(get_filter_var(api, qs, "upstream", "upstream", req->upstreamname,
		                  sizeof(req->upstreamname), &ret) > 0)
		{
			// If there is a space in the upstream name, truncate
			// the string to the first space. This is necessary as
			// upstreams may contains a hostname in parentheses,
			// after the IP address
			char *space = strchr(req->upstreamname, ' ');
			if(space != NULL)
				*space = '\0';

			// Pseudo-upstreams for blocked, cached and permitted queries
			if(strcmp(req->upstreamname, "blocklist") == 0)
				req->upstream = QLOG_UPSTREAM_BLOCKLIST;
			else if(strcmp(req->upstreamname, "cache") == 0)
				req->upstream = QLOG_UPSTREAM_CACHE;
			else if(strcmp(req->upstreamname, "permitted") == 0)
				req->upstream = QLOG_UPSTREAM_PERMITTED;
			else
			{
				req->upstream = QLOG_UPSTREAM_NAME;
				req->upstream_like = is_wildcard(req->upstreamname);
			}
		}
		if(ret != 0)
			return ret;

		// Client IP filtering?
		if(get_filter_var(api, qs, "client_ip", "client_ip", req->client_ip,
		                  sizeof(req->client_ip), &ret) > 0)
		{
			req->has_client_ip = true;
			req->client_ip_like = is_wildcard(req->client_ip);
		}
		if(ret != 0)
			return ret;

		// Client filtering?
		if(get_filter_var(api, qs, "client_name", "client_name", req->client_name,
		                  sizeof(req->client_name), &ret) > 0)
		{
			req->has_client_name = true;
			req->client_name_like = is_wildcard(req->client_name);
		}
		if(ret != 0)
			return ret;

		// DataTables server-side processing protocol
		// Draw counter: This is used by DataTables to ensure that the
		//               Ajax returns from server-side processing
		//               requests are drawn in sequence by DataTables
		//               (Ajax requests are asynchronous and thus can
		//               return out of sequence).
		get_int_var(qs, "draw", &req->draw);

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(qs, "length", &req->length);

		// Enforce a hard upper bound on the number of rows materialized into
		// the JSON response to prevent memory-exhaustion DoS. This cap applies
		// regardless of disk=true and regardless of the requested length.
		// Deliberate, documented behavior change: the length <= 0 ("all") case
		// is limited to the cap as well, so "all" now means "all up to
		// API_QUERIES_MAX_ROWS".
		if(req->length <= 0 || req->length > API_QUERIES_MAX_ROWS)
			req->length = API_QUERIES_MAX_ROWS;

		// Does the user request an offset from the cursor?
		get_uint_var(qs, "start", &req->start);

		uint64_t unum = 0u;
		const char *msg = NULL;
		if(get_uint64_var_msg(qs, "cursor", &unum, &msg) || msg != NULL)
		{
			// Do not start at the most recent, but at an older
			// query (so new queries do not show up suddenly in the
			// log and shift pages)
			if(unum <= (uint64_t)largest_id && msg == NULL)
			{
				req->cursor = unum;
				req->cursor_set = true;
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

		// Query type, status, reply type and DNSSEC status filtering?
		// Checked below, after the exclusion regexes
		if(get_filter_var(api, qs, "type", "type", typename, sizeof(typename), &ret) == -2 ||
		   get_filter_var(api, qs, "status", "status", statusname, sizeof(statusname), &ret) == -2 ||
		   get_filter_var(api, qs, "reply", "reply", replyname, sizeof(replyname), &ret) == -2 ||
		   get_filter_var(api, qs, "dnssec", "dnssec", dnssecname, sizeof(dnssecname), &ret) == -2)
			return ret;

		// Sorting?
		int sort_column = -1;
		// Encoded URI string: %5B = [ and %5D = ]
		if(get_int_var(qs, "order%5B0%5D%5Bcolumn%5D", &sort_column) &&
		   GET_STR("order%5B0%5D%5Bdir%5D", sort_dir, qs) > 0)
		{
			char sort_col_id[32] = { 0 };
			snprintf(sort_col_id, sizeof(sort_col_id), "columns%%5B%d%%5D%%5Bdata%%5D",
			         sort_column);

			// Encoded URI string: %5B = [ and %5D = ]
			if(GET_VAR(sort_col_id, sort_col, qs) > 0)
			{
				log_web_debug(DEBUG_API, "Sorting by column %s (%s)", sort_col, sort_dir);
			}
			else
			{
				log_web(LOG_WARNING, "Sorting by column %d (%s) requested, but column name not found",
				         sort_column, sort_dir);
			}
		}

		// Column searching?
		// ID 3 = domain, ID 4 = client, every other combination is requested
		for(unsigned int j = 0; j < 2; j++)
		{
			// Encoded URI string: %5B = [ and %5D = ]
			// columns[X][search][value] is the search string for column X
			char *search = j == 0 ? req->domain_search : req->client_search;
			char search_col[] = "columns%5BX%5D%5Bsearch%5D%5Bvalue%5D";
			search_col[10] = '3' + j;
			char search_name[] = "columns[X][search][value]";
			search_name[8] = '3' + j;
			// Leave room for the two wildcards search_pattern() may add
			if(get_filter_var(api, qs, search_col, search_name, search,
			                  QLOG_SEARCH_LEN - 2, &ret) <= 0)
			{
				if(ret != 0)
					return ret;
				continue;
			}

			// columns[X][data] is the name of column X
			char search_col_id[] = "columns%5BX%5D%5Bdata%5D";
			search_col_id[10] = '3' + j;

			// Encoded URI string: %5B = [ and %5D = ]
			char search_col_id_str[32] = { 0 };
			if(GET_VAR(search_col_id, search_col_id_str, qs) <= 0)
			{
				log_web(LOG_WARNING, "Column %u is not searchable (allowed: 3 = domain, 4 = client)", 3 + j);
				continue;
			}

			search_pattern(search, QLOG_SEARCH_LEN);

			// Apply the search string to the query if this is an allowed column
			if(j == 0 && strcasecmp(search_col_id_str, "domain") == 0)
			{
				log_web_debug(DEBUG_API, "Searching column domain: \"%s\"", search);
				req->has_domain_search = true;
			}
			else if(j == 1 && (strcasecmp(search_col_id_str, "client.ip") == 0 || strcasecmp(search_col_id_str, "client") == 0))
			{
				log_web_debug(DEBUG_API, "Searching column client: \"%s\"", search);
				req->has_client_search = true;
			}
			else
				log_web(LOG_WARNING, "Column %u with name \"%s\" is not searchable (allowed: 3 = domain, 4 = client)",
				         3 + j, search_col_id_str);
		}
	}
	parse_sort(sort_col, sort_dir, req);

	// We use this boolean to memorize if we are filtering at all. It is used
	// later to decide if we can short-circuit the query counting for
	// performance reasons. The cursor is no filter
	req->filtering = req->has_from || req->has_until || req->has_domain ||
	                 req->upstream != QLOG_UPSTREAM_NONE || req->has_client_ip ||
	                 req->has_client_name || req->has_domain_search || req->has_client_search;

	// Regex filtering?
	int regex_ret = 0;
	if(compile_filter_regex(api, "webserver.api.excludeDomains",
	                        config.webserver.api.excludeDomains.v.json,
	                        &req->regex_domains, &req->N_regex_domains, &regex_ret))
		req->filtering = true;
	if(regex_ret != 0)
		return regex_ret;

	if(compile_filter_regex(api, "webserver.api.excludeClients",
	                        config.webserver.api.excludeClients.v.json,
	                        &req->regex_clients, &req->N_regex_clients, &regex_ret))
		req->filtering = true;
	if(regex_ret != 0)
		return regex_ret;

	if(typename[0] != '\0')
	{
		enum query_type type;
		for(type = TYPE_A; type < TYPE_MAX; type++)
		{
			if(strcasecmp(typename, get_query_type_str(type, NULL, NULL)) == 0)
				break;
		}
		// Stored value to select: the enum value for a mapped type, 100
		// for OTHER (q.type>=100), 100 + nnn for TYPEnnn
		int type_val = -1;
		char *endptr = NULL;
		unsigned long nnn = 0;
		if(type == TYPE_OTHER)
			type_val = 100;
		else if(type < TYPE_MAX)
			type_val = type;
		else if(strncasecmp(typename, "TYPE", 4) == 0 && isdigit((unsigned char)typename[4]) &&
		        (nnn = strtoul(typename + 4, &endptr, 10)) <= UINT16_MAX &&
		        *endptr == '\0')
			type_val = 100 + nnn;
		if(type_val < 0)
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Requested type is invalid",
			                       typename);
		req->has_type = true;
		req->type_other = type == TYPE_OTHER;
		req->type = type_val;
		req->filtering = true;
	}

	if(statusname[0] != '\0')
	{
		enum query_status status;
		for(status = QUERY_UNKNOWN; status < QUERY_STATUS_MAX; status++)
		{
			if(strcasecmp(statusname, get_query_status_str(status)) == 0)
				break;
		}
		if(status >= QUERY_STATUS_MAX)
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Requested status is invalid",
			                       statusname);
		req->has_status = true;
		req->status = status;
		req->filtering = true;
	}

	if(replyname[0] != '\0')
	{
		enum reply_type reply;
		for(reply = REPLY_UNKNOWN; reply < QUERY_REPLY_MAX; reply++)
		{
			if(strcasecmp(replyname, get_query_reply_str(reply)) == 0)
				break;
		}
		if(reply >= QUERY_REPLY_MAX)
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Requested reply is invalid",
			                       replyname);
		req->has_reply = true;
		req->reply = reply;
		req->filtering = true;
	}

	if(dnssecname[0] != '\0')
	{
		enum dnssec_status dnssec;
		for(dnssec = DNSSEC_UNKNOWN; dnssec < DNSSEC_MAX; dnssec++)
		{
			if(strcasecmp(dnssecname, get_query_dnssec_str(dnssec)) == 0)
				break;
		}
		if(dnssec >= DNSSEC_MAX)
			return send_json_error(api, 400,
			                       "bad_request",
			                       "Requested dnssec is invalid",
			                       dnssecname);
		req->has_dnssec = true;
		req->dnssec = dnssec;
		req->filtering = true;
	}

	return 0;
}

// Does an exclusion regex hide this domain?
bool qlog_domain_excluded(const struct qlog_request *req, const char *domain)
{
	for(unsigned int i = 0; i < req->N_regex_domains; i++)
		if(regexec(&req->regex_domains[i], domain, 0, NULL, 0) == 0)
			return true;
	return false;
}

// Does an exclusion regex hide this client? The name is only matched when
// the client has one
bool qlog_client_excluded(const struct qlog_request *req, const char *client_ip, const char *client_name)
{
	for(unsigned int i = 0; i < req->N_regex_clients; i++)
	{
		if(regexec(&req->regex_clients[i], client_ip, 0, NULL, 0) == 0)
			return true;
		if(client_name != NULL && regexec(&req->regex_clients[i], client_name, 0, NULL, 0) == 0)
			return true;
	}
	return false;
}

// Add the JSON object of one query to the queries array. Returns 0, or the
// status of the error reply sent when memory runs out
int add_query_item(struct ftl_conn *api, cJSON *queries, const struct qlog_row *row)
{
	cJSON *item = JSON_NEW_OBJECT();
	if(item == NULL)
		return send_http_internal_error(api);

	// Unmapped query types are stored as 100 + the DNS type
	queriesData query = { 0 };
	if(row->type >= 100)
	{
		query.type = TYPE_OTHER;
		query.qtype = row->type - 100;
	}
	else
		query.type = row->type;
	char buffer[20] = { 0 };

	JSON_ADD_NUMBER_TO_OBJECT(item, "id", row->id);
	JSON_ADD_NUMBER_TO_OBJECT(item, "time", row->time);
	// We have to copy the string as TYPExxx string won't be static
	JSON_COPY_STR_TO_OBJECT(item, "type", get_query_type_str(query.type, &query, buffer));
	JSON_REF_STR_IN_OBJECT(item, "status", get_query_status_str(row->status));
	JSON_REF_STR_IN_OBJECT(item, "dnssec", get_query_dnssec_str(row->dnssec));
	JSON_COPY_STR_TO_OBJECT(item, "domain", row->domain);
	JSON_COPY_STR_TO_OBJECT(item, "upstream", row->upstream);

	// The nested objects are added to item before they are filled, so
	// deleting item on failure releases them as well. The JSON_* macros
	// cannot fill them, as they would delete only the nested object
	cJSON *reply = cJSON_AddObjectToObject(item, "reply");
	if(reply == NULL ||
	   !cJSON_AddItemToObject(reply, "type", cJSON_CreateStringReference(get_query_reply_str(row->reply))) ||
	   cJSON_AddNumberToObject(reply, "time", row->reply_time) == NULL)
		goto oom;

	cJSON *client = cJSON_AddObjectToObject(item, "client");
	if(client == NULL ||
	   cJSON_AddStringToObject(client, "ip", row->client_ip) == NULL ||
	   (row->client_name != NULL ? cJSON_AddStringToObject(client, "name", row->client_name) :
	                               cJSON_AddNullToObject(client, "name")) == NULL)
		goto oom;

	// Add list_id if it exists
	if(row->has_list_id)
		JSON_ADD_NUMBER_TO_OBJECT(item, "list_id", row->list_id);
	else
		JSON_ADD_NULL_TO_OBJECT(item, "list_id");

	// Add EDE code and text (if applicable)
	cJSON *ede = cJSON_AddObjectToObject(item, "ede");
	if(ede == NULL ||
	   cJSON_AddNumberToObject(ede, "code", row->ede) == NULL ||
	   !cJSON_AddItemToObject(ede, "text", row->ede > 0 ? cJSON_CreateStringReference(edestr(row->ede)) :
	                                                      cJSON_CreateNull()))
		goto oom;

	// Add CNAME information if it exists
	JSON_COPY_STR_TO_OBJECT(item, "cname", row->cname);

	JSON_ADD_ITEM_TO_ARRAY(queries, item);
	return 0;

oom:
	log_err("add_query_item(): Failed to allocate JSON object");
	cJSON_Delete(item);
	return send_http_internal_error(api);
}

// Read the query log from the on-disk database, with disk=true and while the
// queries of the history window are still being imported into shared memory,
// and count the matching queries. Returns 0, or the status of the error reply
// it sent
static int queries_from_sql(struct ftl_conn *api, const struct qlog_request *req, cJSON *queries,
                            unsigned int *records)
{
	// Start building database query string
	char querystr[QUERYSTRBUFFERLEN] = { 0 };
	snprintf(querystr, QUERYSTRBUFFERLEN, "%s FROM query_storage q %s", QUERYSTR, JOINSTR);

	bool where = false;
	// Until the import is done, the query log in memory is its window
	double window_from = 0.0, window_until = 0.0;
	if(!req->disk)
	{
		get_import_window(&window_from, &window_until);
		add_querystr_string(querystr, "timestamp BETWEEN :tswfrom AND ", ":tswuntil", &where);
	}
	if(req->has_from)
		add_querystr_string(querystr, "timestamp>=", ":tsfrom", &where);
	if(req->has_until)
		add_querystr_string(querystr, "timestamp<", ":tsuntil", &where);
	if(req->has_domain)
		add_querystr_string(querystr, req->domain_like ? "d.domain LIKE" : "d.domain=", ":domain", &where);
	if(req->upstream == QLOG_UPSTREAM_BLOCKLIST)
		add_querystr_string(querystr, "q.status IN ", get_blocked_statuslist(), &where);
	else if(req->upstream == QLOG_UPSTREAM_CACHE)
		add_querystr_string(querystr, "q.status IN ", get_cached_statuslist(), &where);
	else if(req->upstream == QLOG_UPSTREAM_PERMITTED)
		add_querystr_string(querystr, "q.status IN ", get_permitted_statuslist(), &where);
	else if(req->upstream == QLOG_UPSTREAM_NAME)
		add_querystr_string(querystr, req->upstream_like ? "f.forward LIKE" : "f.forward=", ":upstream", &where);
	if(req->has_client_ip)
		add_querystr_string(querystr, req->client_ip_like ? "c.ip LIKE" : "c.ip=", ":cip", &where);
	if(req->has_client_name)
		add_querystr_string(querystr, req->client_name_like ? "c.name LIKE" : "c.name=", ":cname", &where);
	if(req->cursor_set)
		add_querystr_string(querystr, "q.id<=", ":cursor", &where);
	// Unmapped query types are stored as 100 + the DNS type, so OTHER
	// matches everything at or above 100
	if(req->has_type)
		add_querystr_string(querystr, req->type_other ? "q.type>=" : "q.type=", ":type", &where);
	if(req->has_status)
		add_querystr_string(querystr, "q.status=", ":status", &where);
	if(req->has_reply)
		add_querystr_string(querystr, "q.reply_type=", ":reply_type", &where);
	if(req->has_dnssec)
		add_querystr_string(querystr, "q.dnssec=", ":dnssec", &where);
	if(req->has_domain_search)
		add_querystr_string(querystr, "d.domain LIKE", ":domain_search ESCAPE '\\'", &where);
	// We search both client IP and name
	if(req->has_client_search)
		add_querystr_string(querystr, "c.ip LIKE :client_search ESCAPE '\\' OR c.name LIKE", ":client_search ESCAPE '\\'", &where);

	// Finish preparing query string
	const size_t strpos = strlen(querystr);
	snprintf(querystr + strpos, QUERYSTRBUFFERLEN - strpos, " ORDER BY %s %s",
	         sort_column_sql(req->sort), req->sort_desc ? "DESC" : "ASC");

	// Each request reads on a connection of its own
	sqlite3 *db = dbopen(true, false);
	if(db == NULL)
	{
		return send_json_error(api, 500, // 500 Internal error
		                       "database_error",
		                       "Could not read from the long-term database",
		                       NULL);
	}

	// Prepare SQLite3 statement
	sqlite3_stmt *read_stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &read_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		dbclose(&db);
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, failed to prepare read SQL query",
		                       sqlite3_errstr(rc));
	}

	// Bind items to prepared statement
	struct {
		const char *name;
		bool text;
		const char *str;
		double num;
		const char *what;
	} binds[] = {
		{ ":tsfrom", false, NULL, req->from, "timestamp:from" },
		{ ":tsuntil", false, NULL, req->until, "timestamp:until" },
		{ ":tswfrom", false, NULL, window_from, "window:from" },
		{ ":tswuntil", false, NULL, window_until, "window:until" },
		{ ":domain", true, req->domain, 0.0, "domain" },
		{ ":cip", true, req->client_ip, 0.0, "cip" },
		{ ":cname", true, req->client_name, 0.0, "client" },
		{ ":upstream", true, req->upstreamname, 0.0, "upstream" },
		{ ":type", false, NULL, req->type, "type" },
		{ ":status", false, NULL, req->status, "status" },
		{ ":reply_type", false, NULL, req->reply, "reply" },
		{ ":dnssec", false, NULL, req->dnssec, "dnssec" },
		{ ":cursor", false, NULL, 0.0, "count" },
		{ ":domain_search", true, req->domain_search, 0.0, "domain_search" },
		{ ":client_search", true, req->client_search, 0.0, "client_search" },
	};
	for(unsigned int i = 0; i < ArraySize(binds); i++)
	{
		const int idx = sqlite3_bind_parameter_index(read_stmt, binds[i].name);
		if(idx <= 0)
			continue;
		if(binds[i].text)
		{
			log_web_debug(DEBUG_API, "adding %s = \"%s\" to query", binds[i].name, binds[i].str);
			rc = sqlite3_bind_text(read_stmt, idx, binds[i].str, -1, SQLITE_STATIC);
		}
		else if(strcmp(binds[i].name, ":cursor") == 0)
		{
			log_web_debug(DEBUG_API, "adding :cursor = %"PRIu64" to query", req->cursor);
			rc = sqlite3_bind_int64(read_stmt, idx, req->cursor);
		}
		else if(strncmp(binds[i].name, ":ts", 3) == 0)
		{
			log_web_debug(DEBUG_API, "adding %s = %lf to query", binds[i].name, binds[i].num);
			rc = sqlite3_bind_double(read_stmt, idx, binds[i].num);
		}
		else
		{
			log_web_debug(DEBUG_API, "adding %s = %d to query", binds[i].name, (int)binds[i].num);
			rc = sqlite3_bind_int(read_stmt, idx, (int)binds[i].num);
		}
		if(rc != SQLITE_OK)
		{
			char message[96] = { 0 };
			snprintf(message, sizeof(message), "Internal server error, failed to bind %s to SQL query",
			         binds[i].what);
			sqlite3_finalize(read_stmt);
			dbclose(&db);
			return send_json_error(api, 500,
			                       "internal_error",
			                       message,
			                       sqlite3_errstr(rc));
		}
	}

	// Debug logging
	log_web_debug(DEBUG_API, "SQL: %s", querystr);
	log_web_debug(DEBUG_API, "  with cursor: %"PRIu64", start: %u, length: %d",
	              req->cursor, req->start, req->length);

	unsigned int added = 0, counted = 0, regex_skipped = 0;
	while((rc = sqlite3_step(read_stmt)) == SQLITE_ROW)
	{
		struct qlog_row row = { 0 };
		row.id = sqlite3_column_int64(read_stmt, 0); // q.id
		row.time = sqlite3_column_double(read_stmt, 1); // timestamp
		row.type = sqlite3_column_int(read_stmt, 2); // type
		row.status = sqlite3_column_int(read_stmt, 3); // status
		// A broken row can carry a NULL domain. Substitute an empty string
		// so neither the regex filters nor the JSON output see a NULL
		row.domain = (const char*)sqlite3_column_text(read_stmt, 4); // d.domain
		if(row.domain == NULL)
			row.domain = "";
		if(sqlite3_column_type(read_stmt, 5) == SQLITE_TEXT &&
		   sqlite3_column_bytes(read_stmt, 5) > 0)
			row.upstream = (const char*)sqlite3_column_text(read_stmt, 5); // f.forward
		row.reply = sqlite3_column_int(read_stmt, 7); // reply_type
		row.reply_time = sqlite3_column_double(read_stmt, 8); // reply_time
		row.dnssec = sqlite3_column_int(read_stmt, 9); // dnssec
		row.client_ip = (const char*)sqlite3_column_text(read_stmt, 10); // c.ip
		if(row.client_ip == NULL)
			row.client_ip = "";
		if(sqlite3_column_type(read_stmt, 11) == SQLITE_TEXT && sqlite3_column_bytes(read_stmt, 11) > 0)
			row.client_name = (const char*)sqlite3_column_text(read_stmt, 11); // c.name

		// Apply possible domain and client regex filters to Query Log
		if(qlog_domain_excluded(req, row.domain) ||
		   qlog_client_excluded(req, row.client_ip, row.client_name))
		{
			regex_skipped++;
			continue;
		}

		// Server-side pagination: skip all records before start, take
		// length of them
		counted++;
		if(counted <= req->start)
			continue;
		if(added >= (unsigned int)req->length)
		{
			// We are filtering, so we have to continue to step over
			// the remaining rows to get the correct number of total
			// records. If not, the total number of records is the
			// number of records in the database
			if(req->filtering)
				continue;
			break;
		}

		// Add list_id if it exists
		row.has_list_id = sqlite3_column_type(read_stmt, 13) == SQLITE_INTEGER;
		row.list_id = sqlite3_column_int(read_stmt, 13); // list_id
		// Add EDE code, -1 for none as query_get_ede() reports it. Rows
		// stored before the column existed have NULL there
		row.ede = sqlite3_column_type(read_stmt, 14) == SQLITE_INTEGER ?
		          sqlite3_column_int(read_stmt, 14) : -1; // ede
		// CNAME information for the CNAME blocking statuses
		if(row.status == QUERY_GRAVITY_CNAME || row.status == QUERY_REGEX_CNAME ||
		   row.status == QUERY_DENYLIST_CNAME)
			row.cname = (const char*)sqlite3_column_text(read_stmt, 12); // a.content

		const int ret = add_query_item(api, queries, &row);
		if(ret != 0)
		{
			sqlite3_finalize(read_stmt);
			dbclose(&db);
			return ret;
		}
		added++;
	}
	log_web_debug(DEBUG_API, "Sending %u queries (counted %u, skipped %u)",
	              added, counted, regex_skipped);

	// Finalize statements
	sqlite3_finalize(read_stmt);
	dbclose(&db);

	*records = counted;
	return 0;
}

int api_queries(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	if(config.misc.privacylevel.v.privacy_level >= PRIVACY_MAXIMUM)
	{
		// Same keys as the regular reply below, with nothing to show:
		// there are no queries available, send NULL cursor and zero counts
		cJSON *json = JSON_NEW_OBJECT();
		cJSON *queries = JSON_NEW_ARRAY();
		JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);
		JSON_ADD_NULL_TO_OBJECT(json, "cursor");
		JSON_ADD_NUMBER_TO_OBJECT(json, "recordsTotal", 0);
		JSON_ADD_NUMBER_TO_OBJECT(json, "recordsFiltered", 0);
		int draw = 0;
		if(api->request->query_string != NULL)
			get_int_var(api->request->query_string, "draw", &draw);
		JSON_ADD_NUMBER_TO_OBJECT(json, "draw", draw);
		JSON_ADD_NUMBER_TO_OBJECT(json, "earliest_timestamp", 0.0);
		JSON_ADD_NUMBER_TO_OBJECT(json, "earliest_timestamp_disk", 0.0);
		JSON_SEND_OBJECT(json);
	}

	struct qlog_request req = { 0 };

	// On-disk database lookup requested?
	if(api->request->query_string != NULL)
		get_bool_var(api->request->query_string, "disk", &req.disk);

	// The newest query ID and the numbers of queries when the request
	// arrived. Once the import is done, the in-memory query log is read from
	// shared memory, which also has the queries that are not stored yet
	sqlite3_int64 largest_db_index = 0, mem_dbnum = 0;
	shm_query_log_counts(&largest_db_index, &mem_dbnum);
	uint64_t disk_dbnum = 0;
	get_db_info(true, &disk_dbnum, NULL);
	const bool from_shm = !req.disk && db_import_done;

	// Read the request, then the queries it selects
	unsigned int records = 0;
	cJSON *queries = NULL;
	int ret = parse_queries_request(api, &req, largest_db_index);
	if(ret == 0 && (queries = JSON_NEW_ARRAY()) == NULL)
		ret = send_http_internal_error(api);
	if(ret == 0 && from_shm)
		ret = queries_from_shm(api, &req, queries, &records);
	else if(ret == 0)
		ret = queries_from_sql(api, &req, queries, &records);

	// Release the compiled regexes
	free_filter_regex(req.regex_domains, req.N_regex_domains);
	free_filter_regex(req.regex_clients, req.N_regex_clients);
	if(ret != 0)
	{
		if(queries != NULL)
			cJSON_Delete(queries);
		return ret;
	}

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "queries", queries);

	if(from_shm && !req.cursor_set && largest_db_index < 0)
	{
		// No query yet, so there is nothing a cursor could point to
		JSON_ADD_NULL_TO_OBJECT(json, "cursor");
	}
	else if(req.cursor_set || from_shm)
	{
		// Repeat cursor received in the request, or the newest query
		// when it arrived. This ensures we get a static result by
		// skipping any newer queries.
		log_web_debug(DEBUG_API, "Sending cursor %"PRIu64, req.cursor);
		JSON_ADD_NUMBER_TO_OBJECT(json, "cursor", req.cursor);
	}
	else
	{
		// Send cursor pointing to the newest query when the request
		// arrived. This ensures we get a static result by skipping any
		// newer queries.
		log_web_debug(DEBUG_API, "Sending cursor %lld (newest)", largest_db_index);
		JSON_ADD_NUMBER_TO_OBJECT(json, "cursor", largest_db_index);
	}

	// DataTables specific properties
	const unsigned long recordsTotal = req.disk ? disk_dbnum : (uint64_t)mem_dbnum;
	JSON_ADD_NUMBER_TO_OBJECT(json, "recordsTotal", recordsTotal);
	JSON_ADD_NUMBER_TO_OBJECT(json, "recordsFiltered", req.filtering ? records : recordsTotal);
	JSON_ADD_NUMBER_TO_OBJECT(json, "draw", req.draw);

	// Add earliest timestamp in memory
	double earliest_timestamp_mem = 0.0;
	get_db_info(false, NULL, &earliest_timestamp_mem);
	JSON_ADD_NUMBER_TO_OBJECT(json, "earliest_timestamp", earliest_timestamp_mem);

	// Add number of queries and earliest timestamp in on-disk database
	double earliest_timestamp_disk = 0.0;
	get_db_info(true, NULL, &earliest_timestamp_disk);
	JSON_ADD_NUMBER_TO_OBJECT(json, "earliest_timestamp_disk", earliest_timestamp_disk);

	JSON_SEND_OBJECT(json);
}

// Release the regexes compiled by compile_filter_regex()
void free_filter_regex(regex_t *regex, const unsigned int N_regex)
{
	if(N_regex == 0)
		return;

	for(unsigned int i = 0; i < N_regex; i++)
		regfree(&regex[i]);

	free(regex);
}

// Returns whether any regex was compiled, i.e. whether filtering is in effect.
//
// A caller that can carry an HTTP status passes ret, and a failure then answers
// the request and reports the code it sent through it. Answering without that
// is not allowed: a caller which cannot propagate the code - get_top_domains()
// and get_top_clients() return a cJSON object, not a status - would go on to
// send a second body on the same connection. Those pass NULL, and a failure is
// logged and treated as "no filtering" instead.
bool compile_filter_regex(struct ftl_conn *api, const char *path, cJSON *json,
                          regex_t **regex, unsigned int *N_regex, int *ret)
{
	if(ret != NULL)
		*ret = 0;

	const int N = cJSON_GetArraySize(json);
	if(N < 1)
		return false;

	// Allocate memory for the regex array. N is the upper bound; empty or
	// invalid entries are skipped below, so the number actually compiled
	// (reported via *N_regex) may be smaller.
	*regex = calloc(N, sizeof(regex_t));
	if(*regex == NULL)
	{
		if(ret != NULL)
			*ret = send_json_error(api, 500,
			                       "internal_error",
			                       "Internal server error, failed to allocate memory for regex array",
			                       NULL);
		else
			log_web(LOG_ERR, "Cannot allocate regex array for %s", path);

		return false;
	}

	// Compile regexes
	unsigned int i = 0;
	cJSON *filter = NULL;
	cJSON_ArrayForEach(filter, json)
	{
		// Skip non-string, invalid and empty values
		if(!cJSON_IsString(filter) || filter->valuestring == NULL || strlen(filter->valuestring) == 0)
		{
			log_web(LOG_WARNING, "Skipping invalid regex at %s.%u", path, i);
			continue;
		}

		// Compile regex
		int rc = regcomp(&(*regex)[i], filter->valuestring, REG_EXTENDED | REG_ICASE | REG_NOSUB);
		if(rc != 0)
		{
			// Failed to compile regex
			char errbuf[1024] = { 0 };
			regerror(rc, &(*regex)[i], errbuf, sizeof(errbuf));
			log_web(LOG_ERR, "Failed to compile regex \"%s\": %s",
			        filter->valuestring, errbuf);

			// Release the regexes compiled so far and the array itself
			// before returning so the partially-built array does not leak
			for(unsigned int j = 0; j < i; j++)
				regfree(&(*regex)[j]);
			free(*regex);
			*regex = NULL;
			*N_regex = 0;

			if(ret != NULL)
				*ret = send_json_error(api, 400,
				                       "bad_request",
				                       "Failed to compile regex",
				                       filter->valuestring);

			return false;
		}

		i++;
	}

	// Only the first i slots were actually compiled; skipped (empty or
	// invalid) entries leave zero-initialized regex_t slots behind. Report
	// the real count so the caller never runs regexec()/regfree() over an
	// uncompiled slot, whose NULL program pointer would crash the daemon
	// (and, since one process serves DNS, take resolution down with it).
	*N_regex = i;

	// If no valid regex remained, drop the unused allocation and report that
	// no filtering is in effect for this list.
	if(i == 0)
	{
		free(*regex);
		*regex = NULL;
		return false;
	}

	// We are filtering, so we have to continue to step over the
	// remaining rows to get the correct number of total records
	return true;
}
