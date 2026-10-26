/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query log read from the queries in shared memory
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api/queries.h"
#include "datastructure.h"
#include "shmem.h"
// get_queries_removed()
#include "gc.h"
// sqlite3_strlike()
#include "database/sqlite3.h"
// client_name_at()
#include "name-history.h"

/*
 * The query log from shared memory gives the answers of the SQL query in
 * queries_from_sql(): the filters behave like its WHERE clause, the order is
 * SQLite's (NULL first, text bytewise) and rows with equal keys come in ID
 * order in the direction of the sort. The SHM lock is taken per chunk of
 * rows, so positions are absolute (index plus the queries the garbage
 * collector has removed), no pointer into shared memory is kept across an
 * unlock, and a heap row is only taken if the query at its position still
 * has its ID.
 */

// Rows per hold of the SHM lock. Measured with 2M queries in memory on amd64
// (FTL pinned to its own cores): FTL's own time, and the p99 of 1000 DNS
// queries/s while one client pages through the middle of a sort by domain
//
//   rows   status sort, first page   domain search "co"   DNS p99
//     16          28 ms                     44 ms           0.36 ms
//     32          24 ms                     42 ms           0.54 ms
//     64          23 ms                     40 ms           0.86 ms
//    128          21 ms                     38 ms           2.7 ms
//    256          20 ms                     38 ms           63 ms
//   1024          20 ms                     38 ms           233 ms
//
// Larger chunks make full scans a little faster. But once a deep page keeps a
// large heap, every chunk holds the lock long enough for DNS queries to queue
// behind it. 64 rows is the largest size that keeps the p99 below 1 ms with
// 100k, 500k and 2M queries alike
#define QLOG_CHUNK 64

// Rows per hold once the heap holds QLOG_DEEP_HEAP rows. A DNS query takes
// the lock about ten times, waiting for a chunk each time, so at higher rates
// a deep page needs shorter holds. Middle page of the domain sort, 2M queries,
// same machine, DNS p99 with 64 and with 8 rows:
//
//   queries/s     64 rows               8 rows
//      6000       57 ms, 9 % lost       0.21 ms, none lost
//     10000       65 ms, 24 % lost      0.56 ms, none lost
#define QLOG_CHUNK_DEEP 8
// First pages stay below it, the middle page with 100k queries (a heap of
// 50000 rows) needs it: with 65536 its DNS p99 stayed at 7 to 10 ms
#define QLOG_DEEP_HEAP 4096u

// A sorted request whose heap would hold more rows than this is counted
// first, to see whether its page is in the back half of the result
#define QLOG_FLIP_MIN 10000u

// Size of the first block of string copies, each further one is twice as
// large, up to the second size
#define QLOG_BLOCK_MIN (64u*1024u)
#define QLOG_BLOCK_MAX (1024u*1024u)

// One query log scan at a time: each holds its heap and its string copies.
// This serializes all query log requests read from shared memory, so one that
// takes a second (a deep page of a sort over millions of queries) makes the
// query log of every other client wait for it
static pthread_mutex_t qlog_gate = PTHREAD_MUTEX_INITIALIZER;

// Sort key, ID and absolute position of a matching query
struct qlog_key {
	union {
		double num;
		const char *str; // NULL = SQL NULL
	} k;
	int64_t id;
	unsigned int pos;
	bool null; // numeric key is SQL NULL
};

// Result of the domain, client or upstream part of the filters per ID: 0 =
// not evaluated, 1 = no match, 2 = match. The string pool positions it was
// evaluated for detect recycled IDs and renamed clients
struct qlog_cache {
	unsigned char *state;
	size_t *pos1, *pos2;
	unsigned int n;
};

// Private copy of a string of the shared string pool, by pool position (the
// pool only grows, positions are stable)
struct qlog_str {
	size_t pos;
	const char *str;
};

// Block of string copies. Blocks are allocated between two chunks and never
// move, so the heap and the rows can point into them
struct qlog_block {
	struct qlog_block *prev;
	size_t used, size;
	char buf[];
};

struct qlog_scan {
	const struct qlog_request *req;
	bool heap_mode;  // keep the first rows in a heap instead of reading in order
	bool count_only; // only count the matching queries
	bool flip;       // in the opposite order, see queries_from_shm()
	bool desc;       // read the array newest first
	double disorder; // see track_query_time()
	struct qlog_cache domains, clients, upstreams;
	// Results for queries hiding their domain or client, -1 = not evaluated
	signed char hidden_domain, hidden_client;
	// "ip#port" of each upstream that exists when the request arrives
	const char **upstream_str;
	unsigned int n_upstream_str;
	// Open addressing, power of two, at most half full
	struct qlog_str *strs;
	unsigned int n_strs, cap_strs;
	// The string copies, newest block first. A pool string takes at most
	// str_max bytes with its terminator, the strings of one position at most
	// room bytes
	struct qlog_block *block;
	size_t str_max, room;
	// Max-heap of the first k rows in the requested order, last on top. The
	// page is [ws, we) of them
	struct qlog_key *heap;
	unsigned int n_heap, cap_heap;
	uint64_t k, ws, we;
	// The rows of the reply
	struct qlog_row *page;
	unsigned int n_page;
	// Filter evaluations in the current chunk that ran exclusion regexes
	unsigned int evals;
	// Matching queries
	unsigned int counted;
	bool done, oom;
};

/* ---------------------------------------------------------------------------
 * Strings
 * ------------------------------------------------------------------------- */

static bool str_table_resize(struct qlog_scan *s, const unsigned int cap)
{
	struct qlog_str *table = calloc(cap, sizeof(*table));
	if(table == NULL)
		return false;

	for(unsigned int i = 0; i < s->cap_strs; i++)
	{
		if(s->strs[i].str == NULL)
			continue;
		unsigned int j = (unsigned int)(s->strs[i].pos * 2654435761u) & (cap - 1);
		while(table[j].str != NULL)
			j = (j + 1) & (cap - 1);
		table[j] = s->strs[i];
	}
	if(s->strs != NULL)
		free(s->strs);
	s->strs = table;
	s->cap_strs = cap;
	return true;
}

// Room for n more strings, so pool_str() never grows the table while the
// SHM lock is held
static bool str_table_reserve(struct qlog_scan *s, const unsigned int n)
{
	unsigned int cap = s->cap_strs > 0 ? s->cap_strs : 1024;
	while(2 * (s->n_strs + n) > cap)
		cap *= 2;
	return cap == s->cap_strs || str_table_resize(s, cap);
}

// Free bytes in the newest string block
static size_t block_free(const struct qlog_scan *s)
{
	return s->block != NULL ? s->block->size - s->block->used : 0;
}

// A new string block unless the newest one has room for the strings of one
// more position
static bool block_reserve(struct qlog_scan *s)
{
	if(block_free(s) >= s->room)
		return true;
	size_t size = s->block != NULL ? 2 * s->block->size : QLOG_BLOCK_MIN;
	if(size > QLOG_BLOCK_MAX)
		size = QLOG_BLOCK_MAX;
	if(size < 2 * s->room)
		size = 2 * s->room;
	struct qlog_block *block = malloc(sizeof(*block) + size);
	if(block == NULL)
		return false;
	block->prev = s->block;
	block->used = 0;
	block->size = size;
	s->block = block;
	return true;
}

// size bytes in the newest string block for a copy, which the caller adds to
// used. Fails only if a reservation was too small. Called with the SHM lock
// held
static char *block_space(struct qlog_scan *s, const size_t size)
{
	if(block_free(s) < size)
	{
		s->oom = true;
		return NULL;
	}
	return s->block->buf + s->block->used;
}

// Private copy of the pool string at pos. Called with the SHM lock held, the
// table and the block have room for it (see scan_reserve())
static const char *pool_str(struct qlog_scan *s, const size_t pos)
{
	// The empty string is at position 0
	if(pos == 0)
		return "";
	// Full only if a reservation was too small
	if(2 * s->n_strs >= s->cap_strs)
	{
		s->oom = true;
		return "";
	}

	unsigned int j = (unsigned int)(pos * 2654435761u) & (s->cap_strs - 1);
	while(s->strs[j].str != NULL)
	{
		if(s->strs[j].pos == pos)
			return s->strs[j].str;
		j = (j + 1) & (s->cap_strs - 1);
	}

	// addstr() stores no string longer than str_max - 1 bytes
	const char *str = getstr(pos);
	const size_t len = strnlen(str, s->str_max - 1);
	char *copy = block_space(s, len + 1);
	if(copy == NULL)
		return "";
	memcpy(copy, str, len);
	copy[len] = '\0';
	s->block->used += len + 1;

	s->strs[j].pos = pos;
	s->strs[j].str = copy;
	s->n_strs++;
	return copy;
}

// The strings of a query as the in-memory database has them, privacy levels
// included. pos is 0 for the strings that are not taken from the pool
static const char *query_domain(const queriesData *query, size_t *pos)
{
	*pos = 0;
	if(query->privacylevel >= PRIVACY_HIDE_DOMAINS)
		return HIDDEN_DOMAIN;
	const domainsData *domain = getDomain(query->domainID, true);
	if(domain == NULL)
		return "";
	*pos = domain->domainpos;
	return *pos > 0 ? getstr(*pos) : "";
}

static const char *query_client_ip(const queriesData *query, size_t *pos)
{
	*pos = 0;
	if(query->privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		return HIDDEN_CLIENT;
	const clientsData *client = getClient(query->clientID, true);
	if(client == NULL)
		return "";
	*pos = client->ippos;
	return *pos > 0 ? getstr(*pos) : "";
}

static const char *query_client_name(const queriesData *query, size_t *pos)
{
	*pos = 0;
	if(query->privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		return HIDDEN_CLIENT;
	const clientsData *client = getClient(query->clientID, true);
	if(client == NULL)
		return "";
	// The name the client had when the query was made
	*pos = client_name_at(query->clientID, client->namepos, query->db);
	return *pos > 0 ? getstr(*pos) : "";
}

// "ip#port" of the upstream a query was forwarded to, NULL if none, in the
// newest string block. Built once per upstream that exists when the request
// arrives, each time for a newer one. Called with the SHM lock held
static const char *query_upstream(struct qlog_scan *s, const queriesData *query)
{
	if(query->upstreamID < 0)
		return NULL;
	const upstreamsData *upstream = getUpstream(query->upstreamID, true);
	if(upstream == NULL)
		return NULL;

	const unsigned int id = (unsigned int)query->upstreamID;
	if(id < s->n_upstream_str && s->upstream_str[id] != NULL)
		return s->upstream_str[id];

	// The IP, '#', up to five digits of the port and the terminator
	const char *ip = getstr(upstream->ippos);
	const size_t len = strnlen(ip, s->str_max - 1);
	char *str = block_space(s, len + 7);
	if(str == NULL)
		return NULL;
	const int n = snprintf(str, len + 7, "%.*s#%u", (int)len, ip, (unsigned int)upstream->port);
	s->block->used += (n > 0 ? (size_t)n : 0) + 1;
	if(id < s->n_upstream_str)
		s->upstream_str[id] = str;
	return str;
}

// The list ID of a query's row once it is stored, before that the one its
// DNS cache entry has, which is what the next export stores
static bool query_list_id(const queriesData *query, int *list_id)
{
	*list_id = query->list_id;
	if(!query->flags.database.stored)
	{
		const int cacheID = query->cacheID > -1 ? query->cacheID :
		                    findCacheID(query->domainID, query->clientID, query->type, false);
		const DNSCacheData *cache = getDNSCache(cacheID, true);
		*list_id = cache != NULL ? cache->list_id : -1;
	}
	return *list_id != -1;
}

// Stored query type: the enum value of a mapped type, 100 + the DNS type of
// any other
static int query_type(const queriesData *query)
{
	return query->type != TYPE_OTHER ? query->type : 100 + query->qtype;
}

/* ---------------------------------------------------------------------------
 * Filters
 * ------------------------------------------------------------------------- */

// The = or LIKE of a filter parameter (LIKE without ESCAPE)
static bool filter_matches(const char *pattern, const bool like, const char *str)
{
	return like ? sqlite3_strlike(pattern, str, 0) == 0 : strcmp(pattern, str) == 0;
}

// A column search, LIKE with '\' as escape character
static bool search_matches(const char *pattern, const char *str)
{
	return sqlite3_strlike(pattern, str, '\\') == 0;
}

static bool cache_init(struct qlog_cache *c, const unsigned int n, const bool two)
{
	c->n = n;
	c->state = calloc(n, 1);
	c->pos1 = calloc(n, sizeof(size_t));
	c->pos2 = two ? calloc(n, sizeof(size_t)) : NULL;
	return c->state != NULL && c->pos1 != NULL && (!two || c->pos2 != NULL);
}

static void cache_free(struct qlog_cache *c)
{
	if(c->state != NULL)
		free(c->state);
	if(c->pos1 != NULL)
		free(c->pos1);
	if(c->pos2 != NULL)
		free(c->pos2);
}

// Cached result for an ID: -1 if not evaluated for these pool positions
static int cache_get(const struct qlog_cache *c, const unsigned int id, const size_t pos1, const size_t pos2)
{
	if(id >= c->n || c->state[id] == 0 || c->pos1[id] != pos1 ||
	   (c->pos2 != NULL && c->pos2[id] != pos2))
		return -1;
	return c->state[id] == 2;
}

static void cache_set(struct qlog_cache *c, const unsigned int id, const size_t pos1, const size_t pos2,
                      const bool match)
{
	// IDs above the size the cache got at the start are evaluated each time
	if(id >= c->n)
		return;
	c->state[id] = match ? 2 : 1;
	c->pos1[id] = pos1;
	if(c->pos2 != NULL)
		c->pos2[id] = pos2;
}

// Domain filter, domain search and domain exclusion regexes
static bool domain_passes(const struct qlog_request *req, const char *domain)
{
	if(req->has_domain && !filter_matches(req->domain, req->domain_like, domain))
		return false;
	if(req->has_domain_search && !search_matches(req->domain_search, domain))
		return false;
	return !qlog_domain_excluded(req, domain);
}

// Client filters, client search and client exclusion regexes. A client
// without a name has an empty one
static bool client_passes(const struct qlog_request *req, const char *ip, const char *name)
{
	if(req->has_client_ip && !filter_matches(req->client_ip, req->client_ip_like, ip))
		return false;
	if(req->has_client_name && !filter_matches(req->client_name, req->client_name_like, name))
		return false;
	if(req->has_client_search && !search_matches(req->client_search, ip) &&
	   !search_matches(req->client_search, name))
		return false;
	return !qlog_client_excluded(req, ip, name[0] != '\0' ? name : NULL);
}

// Does a query match the request? Called with the SHM lock held
static bool query_matches(struct qlog_scan *s, const queriesData *query)
{
	const struct qlog_request *req = s->req;

	// Neither queries after the cursor nor those recorded at the maximum
	// privacy level are shown
	if(query->db > (int64_t)req->cursor || query->privacylevel >= PRIVACY_MAXIMUM)
		return false;
	if(req->has_from && !(query->timestamp >= req->from))
		return false;
	if(req->has_until && !(query->timestamp < req->until))
		return false;
	if(req->has_type && (req->type_other ? query_type(query) < 100 : query_type(query) != req->type))
		return false;
	if(req->has_status && (int)query->status != req->status)
		return false;
	if(req->has_reply && (int)query->reply != req->reply)
		return false;
	if(req->has_dnssec && (int)query->dnssec != req->dnssec)
		return false;
	switch(req->upstream)
	{
		case QLOG_UPSTREAM_BLOCKLIST:
			if(!is_blocked(query->status))
				return false;
			break;
		case QLOG_UPSTREAM_CACHE:
			if(!is_cached(query->status))
				return false;
			break;
		case QLOG_UPSTREAM_PERMITTED:
			if(is_blocked(query->status))
				return false;
			break;
		case QLOG_UPSTREAM_NAME:
		{
			// A query that was not forwarded matches no upstream
			if(query->upstreamID < 0)
				return false;
			const unsigned int id = (unsigned int)query->upstreamID;
			int match = cache_get(&s->upstreams, id, 0, 0);
			if(match < 0)
			{
				const char *upstream = query_upstream(s, query);
				match = upstream != NULL && filter_matches(req->upstreamname, req->upstream_like, upstream);
				cache_set(&s->upstreams, id, 0, 0, match);
			}
			if(!match)
				return false;
			break;
		}
		case QLOG_UPSTREAM_NONE:
			break;
	}

	// Domain part, evaluated once per domain
	if(req->has_domain || req->has_domain_search || req->N_regex_domains > 0)
	{
		int match;
		if(query->privacylevel >= PRIVACY_HIDE_DOMAINS)
		{
			if(s->hidden_domain < 0)
				s->hidden_domain = domain_passes(req, HIDDEN_DOMAIN);
			match = s->hidden_domain;
		}
		else
		{
			size_t pos = 0;
			const char *domain = query_domain(query, &pos);
			if((match = cache_get(&s->domains, query->domainID, pos, 0)) < 0)
			{
				match = domain_passes(req, domain);
				if(req->N_regex_domains > 0)
					s->evals++;
				cache_set(&s->domains, query->domainID, pos, 0, match);
			}
		}
		if(!match)
			return false;
	}

	// Client part, evaluated once per client and name
	if(req->has_client_ip || req->has_client_name || req->has_client_search || req->N_regex_clients > 0)
	{
		int match;
		if(query->privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		{
			if(s->hidden_client < 0)
				s->hidden_client = client_passes(req, HIDDEN_CLIENT, HIDDEN_CLIENT);
			match = s->hidden_client;
		}
		else
		{
			size_t ippos = 0, namepos = 0;
			const char *ip = query_client_ip(query, &ippos);
			// Finding the name is a search in the name history, done only for
			// the filters that look at it
			const char *name = "";
			if(req->has_client_name || req->has_client_search || req->N_regex_clients > 0)
				name = query_client_name(query, &namepos);
			if((match = cache_get(&s->clients, query->clientID, ippos, namepos)) < 0)
			{
				match = client_passes(req, ip, name);
				if(req->N_regex_clients > 0)
					s->evals++;
				cache_set(&s->clients, query->clientID, ippos, namepos, match);
			}
		}
		if(!match)
			return false;
	}

	return true;
}

/* ---------------------------------------------------------------------------
 * Order
 * ------------------------------------------------------------------------- */

// SQLite's order of two values of the sort column: NULL first, numbers by
// value, text bytewise (BINARY)
static int cmp_keys(const struct qlog_scan *s, const struct qlog_key *a, const struct qlog_key *b)
{
	switch(s->req->sort)
	{
		case QLOG_SORT_DOMAIN:
		case QLOG_SORT_CLIENT_IP:
		case QLOG_SORT_CLIENT_NAME:
		case QLOG_SORT_UPSTREAM:
			if(a->k.str == NULL || b->k.str == NULL)
				return (a->k.str != NULL) - (b->k.str != NULL);
			return strcmp(a->k.str, b->k.str);
		case QLOG_SORT_ID:
		case QLOG_SORT_TIME:
		case QLOG_SORT_TYPE:
		case QLOG_SORT_STATUS:
		case QLOG_SORT_REPLY:
		case QLOG_SORT_REPLY_TIME:
		case QLOG_SORT_DNSSEC:
		case QLOG_SORT_LIST_ID:
		case QLOG_SORT_EDE:
		default:
			if(a->null || b->null)
				return (!a->null) - (!b->null);
			return (a->k.num > b->k.num) - (a->k.num < b->k.num);
	}
}

// < 0 if row a comes before row b in the reply. Rows with equal keys in ID
// order, both in the direction of the sort
static int cmp_rows(const struct qlog_scan *s, const struct qlog_key *a, const struct qlog_key *b)
{
	int c = cmp_keys(s, a, b);
	if(c == 0)
		c = (a->id > b->id) - (a->id < b->id);
	return s->req->sort_desc != s->flip ? -c : c;
}

// Sort key of a query. Text from the string pool points into shared memory,
// its pool position is returned in strpos. Called with the SHM lock held
static void query_key(struct qlog_scan *s, const queriesData *query, const unsigned int pos,
                      struct qlog_key *key, size_t *strpos)
{
	*strpos = 0;
	memset(key, 0, sizeof(*key));
	key->id = query->db;
	key->pos = pos;

	switch(s->req->sort)
	{
		case QLOG_SORT_DOMAIN:
			key->k.str = query_domain(query, strpos);
			break;
		case QLOG_SORT_CLIENT_IP:
			key->k.str = query_client_ip(query, strpos);
			break;
		case QLOG_SORT_CLIENT_NAME:
			key->k.str = query_client_name(query, strpos);
			break;
		case QLOG_SORT_UPSTREAM:
			key->k.str = query_upstream(s, query);
			break;
		case QLOG_SORT_TIME:
			key->k.num = query->timestamp;
			break;
		case QLOG_SORT_TYPE:
			key->k.num = query_type(query);
			break;
		case QLOG_SORT_STATUS:
			key->k.num = query->status;
			break;
		case QLOG_SORT_REPLY:
			key->k.num = query->reply;
			break;
		case QLOG_SORT_REPLY_TIME:
			key->null = !query->flags.response_calculated;
			key->k.num = query->response;
			break;
		case QLOG_SORT_DNSSEC:
			key->k.num = query->dnssec;
			break;
		case QLOG_SORT_LIST_ID:
		{
			int list_id = -1;
			key->null = !query_list_id(query, &list_id);
			key->k.num = list_id;
			break;
		}
		case QLOG_SORT_EDE:
			key->k.num = query_get_ede(query);
			break;
		case QLOG_SORT_ID:
		default:
			key->k.num = (double)query->db;
			break;
	}
}

static void heap_swap(struct qlog_key *a, struct qlog_key *b)
{
	const struct qlog_key t = *a;
	*a = *b;
	*b = t;
}

// Restore the max-heap property below entry i of the first n entries
static void heap_sift_down(const struct qlog_scan *s, unsigned int i, const unsigned int n)
{
	for(;;)
	{
		const unsigned int l = 2 * i + 1, r = l + 1;
		unsigned int m = i;
		if(l < n && cmp_rows(s, &s->heap[l], &s->heap[m]) > 0)
			m = l;
		if(r < n && cmp_rows(s, &s->heap[r], &s->heap[m]) > 0)
			m = r;
		if(m == i)
			return;
		heap_swap(&s->heap[i], &s->heap[m]);
		i = m;
	}
}

// Keep the first k rows in a max-heap. Called with the SHM lock held, the
// heap has room for one more row (see scan())
static void heap_offer(struct qlog_scan *s, const queriesData *query, const unsigned int pos)
{
	struct qlog_key key;
	size_t strpos = 0;
	query_key(s, query, pos, &key, &strpos);
	if(s->n_heap >= s->k && cmp_rows(s, &key, &s->heap[0]) >= 0)
		return;

	// A key that goes into the heap outlives the lock
	if(strpos > 0)
		key.k.str = pool_str(s, strpos);

	if(s->n_heap < s->k)
	{
		unsigned int i = s->n_heap++;
		s->heap[i] = key;
		while(i > 0 && cmp_rows(s, &s->heap[(i - 1) / 2], &s->heap[i]) < 0)
		{
			heap_swap(&s->heap[(i - 1) / 2], &s->heap[i]);
			i = (i - 1) / 2;
		}
	}
	else
	{
		s->heap[0] = key;
		heap_sift_down(s, 0, s->n_heap);
	}
}

// Sort the heap into the order of the reply
static void heap_sort(struct qlog_scan *s)
{
	for(unsigned int n = s->n_heap; n > 1; n--)
	{
		heap_swap(&s->heap[0], &s->heap[n - 1]);
		heap_sift_down(s, 0, n - 1);
	}
}

/* ---------------------------------------------------------------------------
 * The scan
 * ------------------------------------------------------------------------- */

// What the reply shows of a query, with private copies of the strings.
// Called with the SHM lock held
static void query_row(struct qlog_scan *s, const queriesData *query, struct qlog_row *row)
{
	size_t pos = 0;
	memset(row, 0, sizeof(*row));
	row->id = query->db;
	row->time = query->timestamp;
	row->type = query_type(query);
	row->status = query->status;
	row->reply = query->reply;
	row->reply_time = query->flags.response_calculated ? query->response : 0.0;
	row->dnssec = query->dnssec;
	row->has_list_id = query_list_id(query, &row->list_id);
	row->ede = query_get_ede(query);

	const char *str = query_domain(query, &pos);
	row->domain = pos > 0 ? pool_str(s, pos) : str;
	row->upstream = query_upstream(s, query);
	str = query_client_ip(query, &pos);
	row->client_ip = pos > 0 ? pool_str(s, pos) : str;
	str = query_client_name(query, &pos);
	row->client_name = pos > 0 ? pool_str(s, pos) : str;
	// A client without a name has none in the database
	if(row->client_name[0] == '\0')
		row->client_name = NULL;

	// The domain that was blocked inside the CNAME chain
	if((query->status == QUERY_GRAVITY_CNAME || query->status == QUERY_REGEX_CNAME ||
	    query->status == QUERY_DENYLIST_CNAME) && query->CNAME_domainID > -1)
	{
		const domainsData *cname = getDomain(query->CNAME_domainID, true);
		if(query->privacylevel >= PRIVACY_HIDE_DOMAINS)
			row->cname = HIDDEN_DOMAIN;
		else if(cname != NULL)
			row->cname = pool_str(s, cname->domainpos);
	}
}

// The positions [lo, hi) that can hold queries of the request: up to the
// cursor and, with a time range, near it. Called with the SHM lock held,
// returns indices
static void scan_bounds(const struct qlog_request *req, unsigned int *lo, unsigned int *hi)
{
	const double disorder = counters->query_time_disorder;
	*lo = 0;
	*hi = counters->queries;

	// IDs grow with the position: the first one after the cursor
	unsigned int a = *lo, b = *hi;
	while(a < b)
	{
		const unsigned int mid = a + (b - a) / 2;
		const queriesData *query = getQuery(mid, true);
		if(query != NULL && query->db > (int64_t)req->cursor)
			b = mid;
		else
			a = mid + 1;
	}
	*hi = a;

	// No query in front of one older than (from - disorder) is in range
	if(req->has_from)
	{
		a = *lo;
		b = *hi;
		while(a < b)
		{
			const unsigned int mid = a + (b - a) / 2;
			const queriesData *query = getQuery(mid, true);
			if(query == NULL || query->timestamp < req->from - disorder)
				a = mid + 1;
			else
				b = mid;
		}
		*lo = a;
	}

	// No query after one at (until + disorder) or newer is in range
	if(req->has_until)
	{
		a = *lo;
		b = *hi;
		while(a < b)
		{
			const unsigned int mid = a + (b - a) / 2;
			const queriesData *query = getQuery(mid, true);
			if(query != NULL && query->timestamp >= req->until + disorder)
				b = mid;
			else
				a = mid + 1;
		}
		*hi = a;
	}
}

// One position of the scan. Called with the SHM lock held
static void scan_query(struct qlog_scan *s, const unsigned int idx, const unsigned int pos)
{
	const queriesData *query = getQuery(idx, true);
	if(query == NULL || !query_matches(s, query))
		return;
	s->counted++;

	if(s->count_only)
		return;
	if(s->heap_mode)
	{
		heap_offer(s, query, pos);
		// In time order, no query further on can enter a full heap once
		// one is more than the disorder bound past its last row
		if(s->req->sort == QLOG_SORT_TIME && !s->req->filtering && s->n_heap == s->k &&
		   (s->desc ? query->timestamp + s->disorder < s->heap[0].k.num :
		              query->timestamp - s->disorder > s->heap[0].k.num))
			s->done = true;
		return;
	}

	// In order: skip start rows, take length. Without a filter there is
	// nothing to count after that
	if(s->counted <= s->req->start)
		return;
	if(s->n_page < (unsigned int)s->req->length)
		query_row(s, query, &s->page[s->n_page++]);
	else if(!s->req->filtering)
		s->done = true;
}

// Room for the rows and strings of one more chunk: the heap, the string
// table and a string block, so the scan allocates none of them while the SHM
// lock is held. The block has room for the strings of one more position, a
// chunk ends early once it has less
static bool scan_reserve(struct qlog_scan *s)
{
	if(s->heap_mode && !s->count_only && s->cap_heap < s->k && s->cap_heap < s->n_heap + QLOG_CHUNK)
	{
		uint64_t cap = s->cap_heap > 0 ? 2 * (uint64_t)s->cap_heap : 4096;
		if(cap > s->k)
			cap = s->k;
		struct qlog_key *heap = realloc(s->heap, cap * sizeof(*heap));
		if(heap == NULL)
			return false;
		s->heap = heap;
		s->cap_heap = (unsigned int)cap;
	}
	// A row interns up to four strings, a heap key one
	return str_table_reserve(s, (s->heap_mode ? 1 : 4) * QLOG_CHUNK) && block_reserve(s);
}

// Read the positions [lo, hi) of the array in the scan's direction, the SHM
// lock taken per chunk of them. Called and returns with the SHM lock held
static void scan(struct qlog_scan *s, const unsigned int lo, const unsigned int hi)
{
	unsigned int next = s->desc ? hi : lo;
	unsigned int chunk = QLOG_CHUNK;
	for(unsigned int n = QLOG_CHUNK; !s->done && !s->oom; n++)
	{
		// A chunk also ends after each filter evaluation that ran exclusion
		// regexes, as one runs all of them (20 take ~6 us)
		if(n >= chunk || block_free(s) < s->room || s->evals > 0)
		{
			chunk = s->n_heap >= QLOG_DEEP_HEAP ? QLOG_CHUNK_DEEP : QLOG_CHUNK;
			s->evals = 0;
			// Let DNS in between two chunks, make room for the next
			unlock_shm();
			const bool ok = scan_reserve(s);
			lock_shm_reader();
			if(!ok)
			{
				s->oom = true;
				break;
			}
			n = 0;
		}

		// Queries the garbage collector removed meanwhile are gone.
		// Positions are compared by their difference, they wrap around
		const unsigned int removed = get_queries_removed();
		if(s->desc)
		{
			if(next == lo || (int)(next - removed) <= 0)
				break;
			next--;
		}
		else
		{
			if((int)(next - removed) < 0)
				next = removed;
			if((int)(hi - next) <= 0)
				break;
		}
		scan_query(s, next - removed, next);
		if(!s->desc)
			next++;
	}
}

// Read the rows [ws, we) of the sorted heap. A query the garbage collector
// removed in the meantime is left out, never replaced by another. Called and
// returns with the SHM lock held
static void read_page(struct qlog_scan *s)
{
	unsigned int n = QLOG_CHUNK;
	for(uint64_t i = s->ws; i < s->we && i < s->n_heap && !s->oom; i++, n++)
	{
		// Chunks as in scan()
		if(n == QLOG_CHUNK || block_free(s) < s->room)
		{
			unlock_shm();
			const bool ok = str_table_reserve(s, 4 * QLOG_CHUNK) && block_reserve(s);
			lock_shm_reader();
			if(!ok)
			{
				s->oom = true;
				break;
			}
			n = 0;
		}
		const struct qlog_key *key = &s->heap[i];
		const unsigned int removed = get_queries_removed();
		const queriesData *query = (int)(key->pos - removed) >= 0 ? getQuery(key->pos - removed, true) : NULL;
		if(query != NULL && query->db == key->id)
			query_row(s, query, &s->page[s->n_page++]);
	}
}

// The newest query ID and the number of queries in the query log when a
// request arrives
void shm_query_log_counts(sqlite3_int64 *newest_id, sqlite3_int64 *total)
{
	lock_shm();
	*newest_id = counters->next_query_id - 1;
	*total = counters->queries - counters->queries_maxprivacy;
	unlock_shm();
}

// Fill the queries array from shared memory and count the matching queries.
// Returns 0, or the status of the error reply it sent
int queries_from_shm(struct ftl_conn *api, const struct qlog_request *req, cJSON *queries,
                     unsigned int *records)
{
	struct qlog_scan s = { 0 };
	s.req = req;
	s.hidden_domain = s.hidden_client = -1;
	s.heap_mode = req->sort != QLOG_SORT_ID;
	s.k = (uint64_t)req->start + (uint64_t)req->length;
	// addstr() stores strings of up to a page. A position copies at most
	// six: the domain and its CNAME, the client's IP and name, and the
	// upstream with "#port", twice if it is newer than the request (for the
	// filter and the row)
	s.str_max = (size_t)getpagesize();
	s.room = 6 * (s.str_max + 6);

	pthread_mutex_lock(&qlog_gate);
	lock_shm_reader();

	// The time order is the array order while no timestamp is out of it
	s.disorder = counters->query_time_disorder;
	if(req->sort == QLOG_SORT_TIME && s.disorder <= 0.0)
		s.heap_mode = false;
	// The heap fills fastest with the rows that win among equal keys
	s.desc = (s.heap_mode || req->sort == QLOG_SORT_TIME) ? req->sort_desc : true;
	unsigned int lo = 0, hi = 0;
	scan_bounds(req, &lo, &hi);
	const unsigned int removed = get_queries_removed();
	lo += removed;
	hi += removed;
	const unsigned int n_domains = counters->domains, n_clients = counters->clients,
	                   n_upstreams = counters->upstreams;
	unlock_shm();

	// Caches for the IDs that exist now, newer ones are evaluated each time
	if(!cache_init(&s.domains, n_domains, false) || !cache_init(&s.clients, n_clients, true) ||
	   !cache_init(&s.upstreams, n_upstreams, false) ||
	   (s.upstream_str = calloc(n_upstreams, sizeof(*s.upstream_str))) == NULL ||
	   (s.page = calloc(req->length, sizeof(*s.page))) == NULL)
		s.oom = true;
	else
		s.n_upstream_str = n_upstreams;

	lock_shm_reader();

	// A page in the back half of a sorted result is the mirrored page of the
	// opposite order, read backwards. With the ID as the last key, the order
	// is total, so this is exact and needs a smaller heap. Without a filter,
	// and while no query of the maximum privacy level is in memory, every
	// query up to the cursor is in the result. Otherwise count first
	s.ws = req->start;
	s.we = s.k;
	if(s.heap_mode && s.k > QLOG_FLIP_MIN && !s.oom)
	{
		const int left = (int)(hi - get_queries_removed());
		uint64_t total = left > 0 ? (uint64_t)left : 0;
		if(req->filtering || counters->queries_maxprivacy > 0)
		{
			s.count_only = true;
			scan(&s, lo, hi);
			s.count_only = false;
			total = s.counted;
		}
		if(s.ws >= total)
			s.done = true;
		else if(total - s.ws < s.we)
		{
			const uint64_t end = s.we < total ? s.we : total;
			s.flip = true;
			s.desc = !s.desc;
			s.ws = total - end;
			s.we = s.k = total - req->start;
		}
		if(!s.done)
			s.counted = 0;
	}
	if(!s.oom)
		scan(&s, lo, hi);

	// The page is part of the heap, sorted without the lock
	if(s.heap_mode && !s.oom)
	{
		unlock_shm();
		heap_sort(&s);
		lock_shm_reader();
		read_page(&s);
		for(unsigned int i = 0; s.flip && i < s.n_page / 2; i++)
		{
			const struct qlog_row row = s.page[i];
			s.page[i] = s.page[s.n_page - 1 - i];
			s.page[s.n_page - 1 - i] = row;
		}
	}
	unlock_shm();
	pthread_mutex_unlock(&qlog_gate);

	// Build the reply without the lock
	int ret = 0;
	for(unsigned int i = 0; i < s.n_page && !s.oom && ret == 0; i++)
		ret = add_query_item(api, queries, &s.page[i]);
	*records = s.counted;

	// Release everything the scan owns
	while(s.block != NULL)
	{
		struct qlog_block *prev = s.block->prev;
		free(s.block);
		s.block = prev;
	}
	if(s.strs != NULL)
		free(s.strs);
	if(s.upstream_str != NULL)
		free(s.upstream_str);
	if(s.heap != NULL)
		free(s.heap);
	if(s.page != NULL)
		free(s.page);
	cache_free(&s.domains);
	cache_free(&s.clients);
	cache_free(&s.upstreams);

	if(ret != 0)
		return ret;
	if(s.oom)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Internal server error, out of memory while reading the query log",
		                       NULL);
	return 0;
}
