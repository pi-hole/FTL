/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query log requests and rows
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef API_QUERIES_H
#define API_QUERIES_H

#include "webserver/http-common.h"
// regex_t
#include "regex_r.h"
// sqlite3_int64
#include "database/sqlite3.h"

// Hard upper bound on the number of query rows materialized into a single
// JSON response. This prevents /api/queries from exhausting memory by
// building the entire (in-memory or on-disk) query history as one document.
#define API_QUERIES_MAX_ROWS 10000

// Size of a column search's buffer
#define QLOG_SEARCH_LEN 512

// Columns the query log can be sorted by, QLOG_SORT_ID is the default
enum qlog_sort {
	QLOG_SORT_ID,
	QLOG_SORT_TIME,
	QLOG_SORT_DOMAIN,
	QLOG_SORT_CLIENT_IP,
	QLOG_SORT_CLIENT_NAME,
	QLOG_SORT_UPSTREAM,
	QLOG_SORT_TYPE,
	QLOG_SORT_STATUS,
	QLOG_SORT_REPLY,
	QLOG_SORT_REPLY_TIME,
	QLOG_SORT_DNSSEC,
	QLOG_SORT_LIST_ID,
	QLOG_SORT_EDE
};

// What the upstream parameter selects
enum qlog_upstream {
	QLOG_UPSTREAM_NONE,
	QLOG_UPSTREAM_NAME,      // forwarded to the given upstream
	QLOG_UPSTREAM_BLOCKLIST, // pseudo-upstreams selecting by status
	QLOG_UPSTREAM_CACHE,
	QLOG_UPSTREAM_PERMITTED
};

// A /api/queries request after parsing. A string filter with a '*' in it is
// a LIKE pattern ('*' replaced by '%'), the column searches are LIKE patterns
// with '\' as escape character
struct qlog_request {
	bool disk;
	int draw;
	int length;
	unsigned int start;
	// Highest query ID shown, the request's cursor or the newest query
	bool cursor_set;
	uint64_t cursor;
	// Any filter, search or exclusion regex: recordsFiltered is counted
	bool filtering;
	bool has_from, has_until;
	double from, until;
	bool has_domain, domain_like;
	char domain[512];
	enum qlog_upstream upstream;
	bool upstream_like;
	char upstreamname[256];
	bool has_client_ip, client_ip_like;
	char client_ip[512];
	bool has_client_name, client_name_like;
	char client_name[512];
	// The type is the stored value: the enum value of a mapped type, 100 +
	// the DNS type of any other. OTHER selects every value from 100 on
	bool has_type, type_other;
	int type;
	bool has_status, has_reply, has_dnssec;
	int status, reply, dnssec;
	bool has_domain_search, has_client_search;
	char domain_search[QLOG_SEARCH_LEN], client_search[QLOG_SEARCH_LEN];
	enum qlog_sort sort;
	bool sort_desc;
	// webserver.api.excludeDomains and webserver.api.excludeClients
	regex_t *regex_domains, *regex_clients;
	unsigned int N_regex_domains, N_regex_clients;
};

// What the reply shows of one query. The type is stored as in the request
// above, a client without a name has NULL there
struct qlog_row {
	int64_t id;
	double time;
	int type;
	int status;
	int reply;
	double reply_time;
	int dnssec;
	bool has_list_id;
	int list_id;
	int ede;
	const char *domain, *upstream, *client_ip, *client_name, *cname;
};

int add_query_item(struct ftl_conn *api, cJSON *queries, const struct qlog_row *row);
bool qlog_domain_excluded(const struct qlog_request *req, const char *domain);
bool qlog_client_excluded(const struct qlog_request *req, const char *client_ip, const char *client_name);

// The query log from shared memory, see queries-shm.c
void shm_query_log_counts(sqlite3_int64 *newest_id, sqlite3_int64 *total);
int queries_from_shm(struct ftl_conn *api, const struct qlog_request *req, cJSON *queries,
                     unsigned int *records);

#endif // API_QUERIES_H
