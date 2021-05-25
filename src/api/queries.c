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
#include "../config.h"
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
	for(enum query_types t = TYPE_A; t < TYPE_MAX; t++)
	{
		query.type = t;
		const char *string = get_query_type_str(&query, NULL);
		JSON_ARRAY_REF_STR(type, string);
	}

	// Get status
	cJSON *status = JSON_NEW_ARRAY();
	for(enum query_status s = STATUS_UNKNOWN; s < STATUS_MAX; s++)
	{
		query.status = s;
		const char *string = get_query_status_str(&query);
		JSON_ARRAY_REF_STR(status, string);
	}

	// Get reply types
	cJSON *reply = JSON_NEW_ARRAY();
	for(enum reply_type r = REPLY_UNKNOWN; r < REPLY_MAX; r++)
	{
		query.reply = r;
		const char *string = get_query_reply_str(&query);
		JSON_ARRAY_REF_STR(reply, string);
	}

	// Get dnssec status
	cJSON *dnssec = JSON_NEW_ARRAY();
	for(enum dnssec_status d = DNSSEC_UNKNOWN; d < DNSSEC_MAX; d++)
	{
		query.dnssec = d;
		const char *string = get_query_dnssec_str(&query);
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

#define QUERYSTR "SELECT id,timestamp,type,status,domain,client,forward,additional_info FROM queries"
#define QUERYSTRLEN 2048
static void add_querystr_double(struct ftl_conn *api, char *querystr, const char *sql, const char *uripart)
{
	double val;
	if(!get_double_var(api->request->query_string, "from", &val))
		return;

	const size_t strpos = strlen(querystr);
	const char *glue = (strpos < sizeof(QUERYSTR)) ? "WHERE" : "AND";
	snprintf(querystr + strpos, QUERYSTRLEN - strpos, " %s %s%f", glue, sql, val);
}

static void add_querystr_string(struct ftl_conn *api, char *querystr, const char *sql, const char *val)
{
	const size_t strpos = strlen(querystr);
	const char *glue = (strpos < sizeof(QUERYSTR)) ? "WHERE" : "AND";
	snprintf(querystr + strpos, QUERYSTRLEN - strpos, " %s %s%s", glue, sql, val);
}

int api_queries(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
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

	// Filtering requested?
	char querystr[QUERYSTRLEN] = { 0 };
	sprintf(querystr, QUERYSTR);
	int draw = 0;

	char domainname[512] = { 0 };
	char clientname[512] = { 0 };
	char upstreamname[256] = { 0 };

	// We start with the most recent query at the beginning (until the cursor is changed)
	unsigned int cursor = counters->queries;
	// We send 100 queries (unless the API is asked for a different limit)
	int length = 100;
	int start = 0;

	// Filtering based on GET parameters?
	if(api->request->query_string != NULL)
	{
		char buffer[256] = { 0 };

		// Time filtering?
		add_querystr_double(api, querystr, "timestamp>=", "from");
		add_querystr_double(api, querystr, "timestamp<", "until");

		// Domain filtering?
		if(GET_VAR("domain", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%255s", domainname);
			add_querystr_string(api, querystr, "domain=", ":domain");
		}

		// Upstream filtering?
		if(GET_VAR("upstream", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%255s", upstreamname);
			add_querystr_string(api, querystr, "forward=", ":upstream");
		}

		// Client filtering?
		if(GET_VAR("client", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%255s", clientname);
			add_querystr_string(api, querystr, "client=", ":client");
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
		get_int_var(api->request->query_string, "start", &start);

		unsigned int unum = 0u;
		const char *msg = NULL;
		if(get_uint_var_msg(api->request->query_string, "cursor", &unum, &msg) ||
		   msg != NULL)
		{
			// Do not start at the most recent, but at an older
			// query (so new queries do not show up suddenly in the
			// log and shift pages)
			if(unum <= (unsigned int)counters->queries && msg == NULL)
			{
				cursor = unum;
			}
			else
			{
				if(msg == NULL)
					msg = "Cursor larger than total number of queries";
				// Cursors larger than the current known number
				// of queries are invalid
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested cursor is invalid",
				                       msg);
			}
		}
	}

	// Get connection to in-memory database
	sqlite3 *db = get_memdb();

	// Prepare SQLite statement
	sqlite3_stmt *read_stmt = NULL;
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
	}

	if(config.debug & DEBUG_API)
		logg("SQL: %s, cursor: %u", querystr, cursor);

	cJSON *queries = JSON_NEW_ARRAY();
	int added = 0;
	while((rc = sqlite3_step(read_stmt)) == SQLITE_ROW)
	{
		logg("A");
		cJSON *item = JSON_NEW_OBJ();
		queriesData query = { 0 };
		char buffer[20] = { 0 };
		JSON_OBJ_ADD_NUMBER(item, "id", sqlite3_column_int(read_stmt, 0));
		JSON_OBJ_ADD_NUMBER(item, "time", sqlite3_column_double(read_stmt, 1));
		query.type = sqlite3_column_int(read_stmt, 2);
		query.status = sqlite3_column_int(read_stmt, 3);
		query.reply = REPLY_UNKNOWN;
		query.dnssec = DNSSEC_UNKNOWN;
		// We have to copy the string as TYPExxx string won't be static
		JSON_OBJ_COPY_STR(item, "type", get_query_type_str(&query, buffer));
		JSON_OBJ_REF_STR(item, "status", get_query_status_str(&query));
		JSON_OBJ_REF_STR(item, "dnssec", get_query_dnssec_str(&query));
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
		JSON_OBJ_REF_STR(reply, "type", get_query_reply_str(&query));
		JSON_OBJ_ADD_NUMBER(reply, "time", 0); // TODO: Needs to be added to the SQL database
		JSON_OBJ_ADD_ITEM(item, "reply", reply);

		cJSON *client = JSON_NEW_OBJ();
		// TODO: Add "client" field (may be NULL) with hostname stored in database
		JSON_OBJ_COPY_STR(client, "ip", sqlite3_column_text(read_stmt, 5));
		JSON_OBJ_REF_STR(client, "name", "localhost");
		JSON_OBJ_ADD_ITEM(item, "client", client);


		JSON_OBJ_ADD_NUMBER(item, "ttl", 0); // TODO: Needs to be added to the SQL database
		JSON_OBJ_ADD_NUMBER(item, "regex", 0); // TODO: Needs to be added to the SQL database

		JSON_ARRAY_ADD_ITEM(queries, item);

		if(length > -1 && ++added >= length)
		{
			break;
		}

//		lastID = queryID;
	}
		logg("B");
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "queries", queries);

	// if(lastID < 0)
		// There are no more queries available, send null cursor
	// else:
		// There are more queries available, send cursor pointing
		// onto the next older query so the API can request it if
		// needed
	// JSON_OBJ_ADD_NUMBER(json, "cursor", lastID);

	// DataTables specific properties
	JSON_OBJ_ADD_NUMBER(json, "recordsTotal", cursor);
	JSON_OBJ_ADD_NUMBER(json, "recordsFiltered", cursor); // Until we implement server-side filtering
	JSON_OBJ_ADD_NUMBER(json, "draw", draw);

		logg("C");
	JSON_SEND_OBJECT(json);
}
/*
int api_queries(struct ftl_conn *api)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
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

	// Do we want a more specific version of this command (domain/client/time interval filtered)?
	double from = 0.0, until = 0.0;

	char domainname[512] = { 0 };
	bool filterdomainname = false;
	int domainid = -1;

	char clientname[512] = { 0 };
	bool filterclientname = false;
	int clientid = -1;
	int *clientid_list = NULL;

	int querytype = 0;

	char forwarddest[256] = { 0 };
	bool filterforwarddest = false;
	int forwarddestid = 0;

	// We start with the most recent query at the beginning (until the cursor is changed)
	unsigned int cursor = counters->queries;
	// We send 100 queries (unless the API is asked for a different limit)
	int length = 100;
	int start = 0;
	int draw = 0;

	if(api->request->query_string != NULL)
	{
		// Time filtering?
		get_double_var(api->request->query_string, "from", &from);
		get_double_var(api->request->query_string, "until", &until);

		// DataTables server-side processing protocol
		// Draw counter: This is used by DataTables to ensure that the
		//               Ajax returns from server-side processing
		//               requests are drawn in sequence by DataTables
		//               (Ajax requests are asynchronous and thus can
		//               return out of sequence).
		get_int_var(api->request->query_string, "draw", &draw);

		// Query type filtering?
		int num;
		if(get_int_var(api->request->query_string, "type", &num) && num < TYPE_MAX)
			querytype = num;

		// Does the user request a non-default number of replies?
		// Note: We do not accept zero query requests here
		get_int_var(api->request->query_string, "length", &length);

		// Does the user request an offset from the cursor?
		get_int_var(api->request->query_string, "start", &start);

		// Upstream destination filtering?
		char buffer[256] = { 0 };
		if(GET_VAR("upstream", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%255s", forwarddest);
			filterforwarddest = true;

			if(strcmp(forwarddest, "cache") == 0)
			{
				forwarddestid = -1;
			}
			else if(strcmp(forwarddest, "blocklist") == 0)
			{
				forwarddestid = -2;
			}
			else
			{
				// Extract address/name and port
				char serv_addr[256] = { 0 };
				unsigned int serv_port = 53;
				// We limit the number of bytes written into the serv_addr buffer
				// to prevent buffer overflows. If there is no port available in
				// the database, we skip extracting them and use the default port
				sscanf(forwarddest, "%255[^#]#%u", serv_addr, &serv_port);
				serv_addr[INET6_ADDRSTRLEN-1] = '\0';

				// Iterate through all known forward destinations
				forwarddestid = -3;
				for(int i = 0; i < counters->upstreams; i++)
				{
					// Get forward pointer
					const upstreamsData* upstream = getUpstream(i, true);
					if(upstream == NULL)
					{
						continue;
					}

					// Try to match the requested string against their IP addresses and
					// (if available) their host names + port
					if((strcmp(getstr(upstream->ippos), serv_addr) == 0 ||
					   (upstream->namepos != 0 &&
					    strcmp(getstr(upstream->namepos), serv_addr) == 0)) &&
					   serv_port == upstream->port)
					{
						forwarddestid = i;
						break;
					}
				}
			}
		}

		// Domain filtering?
		if(GET_VAR("domain", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%511s", domainname);
			filterdomainname = true;
			// Iterate through all known domains
			for(int domainID = 0; domainID < counters->domains; domainID++)
			{
				// Get domain pointer
				const domainsData* domain = getDomain(domainID, true);
				if(domain == NULL)
				{
					continue;
				}

				// Try to match the requested string
				if(strcmp(getstr(domain->domainpos), domainname) == 0)
				{
					domainid = domainID;
					break;
				}
			}
		}

		// Client filtering?
		if(GET_VAR("client", buffer, api->request->query_string) > 0)
		{
			sscanf(buffer, "%511s", clientname);
			filterclientname = true;

			// Iterate through all known clients
			for(int i = 0; i < counters->clients; i++)
			{
				// Get client pointer
				const clientsData* client = getClient(i, true);

				// Skip invalid clients and also those managed by alias clients
				if(client == NULL || client->aliasclient_id >= 0)
					continue;

				// Try to match the requested string
				if(strcmp(getstr(client->ippos), clientname) == 0 ||
				   (client->namepos != 0 &&
				    strcmp(getstr(client->namepos), clientname) == 0))
				{
					clientid = i;

					// Is this an alias-client?
					if(client->flags.aliasclient)
						clientid_list = get_aliasclient_list(i);

					break;
				}
			}
		}

		unsigned int unum = 0u;
		const char *msg = NULL;
		if(get_uint_var_msg(api->request->query_string, "cursor", &unum, &msg) ||
		   msg != NULL)
		{
			// Do not start at the most recent, but at an older
			// query (so new queries do not show up suddenly in the
			// log and shift pages)
			if(unum <= (unsigned int)counters->queries && msg == NULL)
			{
				cursor = unum;
			}
			else
			{
				if(msg == NULL)
					msg = "Cursor larger than total number of queries";
				// Cursors larger than the current known number
				// of queries are invalid
				return send_json_error(api, 400,
				                       "bad_request",
				                       "Requested cursor is invalid",
				                       msg);
			}
		}
	}

	// Compute limits for the main for-loop
	// Default: Show the most recent 200 queries
	unsigned int ibeg = cursor - start;

	// Get potentially existing filtering flags
	char * filter = read_setupVarsconf("API_QUERY_LOG_SHOW");
	bool showpermitted = true, showblocked = true;
	if(filter != NULL)
	{
		if((strcmp(filter, "permittedonly")) == 0)
			showblocked = false;
		else if((strcmp(filter, "blockedonly")) == 0)
			showpermitted = false;
		else if((strcmp(filter, "nothing")) == 0)
		{
			showpermitted = false;
			showblocked = false;
		}
	}
	clearSetupVarsArray();

	cJSON *queries = JSON_NEW_ARRAY();
	int added = 0;
//	unsigned int lastID = 0u;
	for(unsigned int i = ibeg; i > 0u; i--)
	{
		const unsigned int queryID = i-1u;
		const queriesData* query = getQuery(queryID, true);
		// Check if this query has been create while in maximum privacy mode
		if(query == NULL || query->privacylevel >= PRIVACY_MAXIMUM)
			continue;

		// Verify query type
		if(query->type >= TYPE_MAX)
			continue;

		// Skip blocked queries when asked to
		if(query->flags.blocked && !showblocked)
			continue;

		// Skip permitted queries when asked to
		if(!query->flags.blocked && !showpermitted)
			continue;

		// Skip those entries which so not meet the requested timeframe
		if((from > query->timestamp && from > 0.0) || (query->timestamp > until && until > 0.0))
			continue;

		// Skip if domain is not identical with what the user wants to see
		if(filterdomainname && query->domainID != domainid)
			continue;
		if(filterdomainname)
		{
			// Check direct match
			if(query->domainID == domainid)
			{
				// Get this query
			}
			// If the domain of this query did not match, the CNAME
			// domain may still match - we have to check it in
			// addition if this query is of CNAME blocked type
			else if(query->CNAME_domainID > -1)
			{
				// Get this query
			}
			else
			{
				// Skip this query
				continue;
			}
		}

		// Skip if client name and IP are not identical with what the user wants to see
		if(filterclientname)
		{
			// Normal clients
			if(clientid_list == NULL && query->clientID != clientid)
				continue;
			// Alias-clients (we have to check for all clients managed by this alias-client)
			else if(clientid_list != NULL)
			{
				bool found = false;
				for(int j = 0; j < clientid_list[0]; j++)
					if(query->clientID == clientid_list[j + 1])
						found = true;
				if(!found)
					continue;
			}
		}

		// Skip if query type is not identical with what the user wants to see
		if(querytype != 0 && querytype != query->type)
			continue;

		if(filterforwarddest)
		{
			// Does the user want to see queries answered from blocking lists?
			if(forwarddestid == -2 && !query->flags.blocked)
				continue;
			// Does the user want to see queries answered from local cache?
			else if(forwarddestid == -1 && query->status != STATUS_CACHE)
				continue;
			// Does the user want to see queries answered by an upstream server?
			else if(forwarddestid >= 0 && forwarddestid != query->upstreamID)
				continue;
		}

		// Ask subroutine for domain. It may return "hidden" depending on
		// the privacy settings at the time the query was made
		const char *domain = getDomainString(query);

		// Similarly for the client
		const char *clientIPName = NULL;
		// Get client pointer
		const clientsData* client = getClient(query->clientID, true);
		if(domain == NULL || client == NULL)
			continue;

		if(strlen(getstr(client->namepos)) > 0)
			clientIPName = getClientNameString(query);
		else
			clientIPName = getClientIPString(query);

		double delay = 0.1*query->response;
		// Check if received (delay should be smaller than 30min)
		if(delay > 1.8e6 || query->reply == REPLY_UNKNOWN)
			delay = -1.0;

		// Get domain blocked during deep CNAME inspection, if applicable
		const char *CNAME_domain = NULL;
		if(query->CNAME_domainID > -1)
		{
			CNAME_domain = getCNAMEDomainString(query);
		}

		// Get ID of blocking regex, if applicable
		int regex_id = -1;
		if (query->status == STATUS_REGEX || query->status == STATUS_REGEX_CNAME)
		{
			unsigned int cacheID = findCacheID(query->domainID, query->clientID, query->type);
			DNSCacheData *dns_cache = getDNSCache(cacheID, true);
			if(dns_cache != NULL)
				regex_id = dns_cache->deny_regex_id;
		}

		// Get IP of upstream destination, if applicable
		char upstream[128] = { 0 };
		if(query->upstreamID > -1)
		{
			const upstreamsData *up = getUpstream(query->upstreamID, true);
			if(up != NULL)
			{
				in_port_t port = up->port;
				const char *name;
				if(up->namepos != 0)
					// Get upstream destination name if possible
					name = getstr(up->namepos);
				else
					// If we have no name, get the IP address
					name = getstr(up->ippos);

				snprintf(upstream, 127u, "%s#%d", name, port);
			}
		}

		// Get strings for various query status properties
		char buffer[12] = { 0 };
		const char *qtype = get_query_type_str(query, buffer);
		const char *qstatus = get_query_status_str(query);
		const char *qdnssec = get_query_dnssec_str(query);
		const char *qreply = get_query_reply_str(query);

		cJSON *item = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(item, "time", query->timestamp);
		// We have to copy the string as TYPExxx string won't be static
		JSON_OBJ_COPY_STR(item, "type", qtype);
		// Safe to reference the FTL-strings pointer here
		JSON_OBJ_REF_STR(item, "domain", domain);
		// Safe to reference the FTL-strings pointer here
		JSON_OBJ_REF_STR(item, "cname", CNAME_domain);
		// Safe to reference the static strings here
		JSON_OBJ_REF_STR(item, "status", qstatus);
		// Safe to reference the FTL-strings pointer here
		JSON_OBJ_REF_STR(item, "client", clientIPName);
		// Safe to reference the static strings here
		JSON_OBJ_REF_STR(item, "dnssec", qdnssec);

		cJSON *reply = JSON_NEW_OBJ();
		// Safe to reference the static strings here
		JSON_OBJ_REF_STR(reply, "type", qreply);
		JSON_OBJ_ADD_NUMBER(reply, "time", delay);
		JSON_OBJ_ADD_ITEM(item, "reply", reply);


		JSON_OBJ_ADD_NUMBER(item, "ttl", query->ttl);
		JSON_OBJ_ADD_NUMBER(item, "regex", regex_id);
		// We have to copy the string as the ip#port string isn't static
		if(upstream[0] != '\0')
		{
			JSON_OBJ_COPY_STR(item, "upstream", upstream);
		}
		else
		{
			JSON_OBJ_ADD_NULL(item, "upstream");
		}
		JSON_OBJ_ADD_NUMBER(item, "dbid", query->db);

		JSON_ARRAY_ADD_ITEM(queries, item);

		if(length > -1 && ++added >= length)
		{
			break;
		}

//		lastID = queryID;
	}

	// Free allocated memory
	if(clientid_list != NULL)
		free(clientid_list);

	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(json, "queries", queries);

	// if(lastID < 0)
		// There are no more queries available, send null cursor
	// else:
		// There are more queries available, send cursor pointing
		// onto the next older query so the API can request it if
		// needed
	// JSON_OBJ_ADD_NUMBER(json, "cursor", lastID);

	// DataTables specific properties
	JSON_OBJ_ADD_NUMBER(json, "recordsTotal", cursor);
	JSON_OBJ_ADD_NUMBER(json, "recordsFiltered", cursor); // Until we implement server-side filtering
	JSON_OBJ_ADD_NUMBER(json, "draw", draw);

	JSON_SEND_OBJECT(json);
}
*/
