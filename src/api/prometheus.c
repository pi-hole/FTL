/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/metrics (Prometheus text format)
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "api/api.h"
#include "config/config.h"
// sha256_hex()
#include "config/password.h"
#include "log.h"
// counters, lock_shm(), unlock_shm(), get_qps()
#include "shmem.h"
// get_blocked_count(), get_forwarded_count(), get_cached_count(),
// get_query_type_str(), get_query_status_str(), get_query_reply_str()
#include "datastructure.h"
// struct metrics, get_dnsmasq_metrics(), rrtype_name()
#include "metrics.h"
// gravity_last_updated()
#include "database/gravity-db.h"
// get_queries_removed()
#include "gc.h"
// get_imported_queries()
#include "database/query-table.h"
#include "webserver/cJSON/cJSON.h"
// constant-time comparison memeql_sec()
#include <nettle/memops.h>
// SHA256_DIGEST_SIZE
#include <nettle/sha2.h>

#define PROMETHEUS_BEARER_MAX_LEN 512u

// Prometheus text exposition format, version 0.0.4. This is the most widely
// compatible content type and is accepted by "promtool check metrics".
#define PROM_CONTENT_TYPE "text/plain; version=0.0.4; charset=utf-8"

// Length of the well-formed UTF-8 sequence starting at in, 0 if there is none
static size_t utf8_sequence_length(const unsigned char *in)
{
	size_t len;
	unsigned int cp;
	if(in[0] < 0x80)
		return 1;
	else if((in[0] & 0xE0) == 0xC0)
		len = 2, cp = in[0] & 0x1F;
	else if((in[0] & 0xF0) == 0xE0)
		len = 3, cp = in[0] & 0x0F;
	else if((in[0] & 0xF8) == 0xF0)
		len = 4, cp = in[0] & 0x07;
	else
		return 0;

	for(size_t i = 1; i < len; i++)
	{
		if((in[i] & 0xC0) != 0x80)
			return 0;
		cp = (cp << 6) | (in[i] & 0x3F);
	}

	// Reject overlong forms, surrogates and code points beyond U+10FFFF
	static const unsigned int min_cp[] = { 0, 0, 0x80, 0x800, 0x10000 };
	if(cp < min_cp[len] || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)
		return 0;

	return len;
}

// Escape a Prometheus label *value*. Domain and client names are
// attacker-influenceable (anyone on the network can query a crafted name that
// lands in the top lists) and reach FTL byte for byte, so every byte that is
// not printable, valid UTF-8 is written as visible \xHH text. This includes
// the backslash itself, which keeps the encoding reversible: two different
// names can never map to the same label, which would make Prometheus reject
// the whole scrape as a duplicate series. The double quote is the only byte
// left that needs the format's own escaping. Returns a newly allocated string
// (caller frees) or NULL on allocation failure.
static char * __attribute__((malloc)) escape_label(const char *in)
{
	if(in == NULL)
		in = "";

	const unsigned char *u = (const unsigned char *)in;
	const size_t len = strlen(in);

	// Worst case every byte becomes the five characters of \\xHH
	char *out = calloc(5 * len + 1, sizeof(char));
	if(out == NULL)
		return NULL;

	char *p = out;
	for(size_t i = 0; i < len;)
	{
		const size_t seq = utf8_sequence_length(&u[i]);
		if(seq > 1)
		{
			memcpy(p, &u[i], seq);
			p += seq;
			i += seq;
		}
		else if(seq == 1 && u[i] >= 0x20 && u[i] != 0x7F && u[i] != '\\')
		{
			if(u[i] == '"')
				*p++ = '\\';
			*p++ = (char)u[i++];
		}
		else
		{
			p += sprintf(p, "\\\\x%02X", u[i++]);
		}
	}
	*p = '\0';

	return out;
}

// Extract the bearer token from the "Authorization: Bearer <token>" header.
// The token is intentionally only accepted via this header - never via a query
// string (which would leak into access logs and proxies) or a cookie (which
// would reintroduce the CSRF attack surface). Returns a newly allocated copy of
// the token that the caller must free(), or NULL if no bearer token is present.
static char * __attribute__((malloc)) get_bearer_token(struct ftl_conn *api)
{
	const char *auth = mg_get_header(api->conn, "Authorization");
	if(auth == NULL)
		return NULL;

	const char *prefix = "Bearer ";
	const size_t prefix_len = strlen(prefix);
	if(strncasecmp(auth, prefix, prefix_len) != 0)
		return NULL;

	// Skip the prefix and any additional leading spaces
	const char *token = auth + prefix_len;
	while(*token == ' ')
		token++;

	if(*token == '\0')
		return NULL;

	// Trim trailing spaces/tabs and reject multi-part token values.
	const char *end = token + strlen(token);
	while(end > token && (end[-1] == ' ' || end[-1] == '\t'))
		end--;

	if(end <= token)
		return NULL;

	const size_t len = (size_t)(end - token);
	if(len > PROMETHEUS_BEARER_MAX_LEN)
		return NULL;

	for(size_t i = 0; i < len; i++)
	{
		if(token[i] == ' ' || token[i] == '\t')
			return NULL;
	}

	char *presented = calloc(len + 1, sizeof(char));
	if(presented == NULL)
		return NULL;

	strncpy(presented, token, len);
	presented[len] = '\0';

	return presented;
}

// Verify the presented bearer token against the stored SHA-256 hash (passed in
// by the caller, which copied it under lock_shm()). The comparison is done in
// constant time (length pre-check gating memeql_sec()) on the hashes so neither
// the token nor its length leaks through a timing side-channel.
static bool prometheus_authenticated(struct ftl_conn *api, const char *stored)
{
	char *presented = get_bearer_token(api);
	if(presented == NULL)
		return false;

	char *presented_hash = sha256_hex(presented);
	free(presented);
	if(presented_hash == NULL)
		return false;

	const size_t a = strlen(presented_hash);
	const size_t b = strlen(stored);
	const bool match = (a == b) && memeql_sec(presented_hash, stored, a);

	free(presented_hash);
	return match;
}

// Append the top-N domains and clients as labeled gauge series. This is only
// reached when webserver.api.prometheus.perEntityMetrics is enabled. The heavy
// lifting (privacy-level enforcement, excludeDomains/excludeClients filtering,
// bounded top-K selection and shared-memory locking) is reused verbatim from
// get_top_domains()/get_top_clients() so the Prometheus view can never expose
// anything the JSON API would hide.
static void add_per_entity_metrics(struct ftl_conn *api, FILE *fp)
{
	unsigned int topN = config.webserver.api.prometheus.topN.v.ui;
	if(topN > PROMETHEUS_TOPN_MAX)
		topN = PROMETHEUS_TOPN_MAX;

	if(topN == 0)
		return;

	// topN is bounded by PROMETHEUS_TOPN_MAX (clamped above), so it always
	// fits into the int the reused helpers expect.
	const int count = (int)topN;

	// Top domains (by permitted queries)
	cJSON *td = get_top_domains(api, count, false, false);
	if(td != NULL)
	{
		fputs("# HELP pihole_top_domain_queries Permitted DNS queries for the most active domains\n", fp);
		fputs("# TYPE pihole_top_domain_queries gauge\n", fp);

		const cJSON *domains = cJSON_GetObjectItem(td, "domains");
		const cJSON *item = NULL;
		cJSON_ArrayForEach(item, domains)
		{
			const char *domain = cJSON_GetStringValue(cJSON_GetObjectItem(item, "domain"));
			const cJSON *cnt = cJSON_GetObjectItem(item, "count");
			if(domain == NULL || cnt == NULL)
				continue;

			char *esc = escape_label(domain);
			if(esc == NULL)
				continue;
			fprintf(fp, "pihole_top_domain_queries{domain=\"%s\"} %d\n", esc, (int)cnt->valuedouble);
			free(esc);
		}
		cJSON_Delete(td);
	}

	// Top clients (by total queries), identified by their IP alone. Names
	// change (the first scrape often comes before the PTR lookup finished)
	// and would start a new series each time, so they come as a separate
	// info metric to join on
	cJSON *tc = get_top_clients(api, count, false, false, false, false);
	if(tc == NULL)
		return;

	const cJSON *clients = cJSON_GetObjectItem(tc, "clients");
	const cJSON *item = NULL;
	fputs("# HELP pihole_top_client_queries DNS queries for the most active clients\n", fp);
	fputs("# TYPE pihole_top_client_queries gauge\n", fp);
	cJSON_ArrayForEach(item, clients)
	{
		const char *ip = cJSON_GetStringValue(cJSON_GetObjectItem(item, "ip"));
		const cJSON *cnt = cJSON_GetObjectItem(item, "count");
		char *esc_ip = ip != NULL && cnt != NULL ? escape_label(ip) : NULL;
		if(esc_ip == NULL)
			continue;
		fprintf(fp, "pihole_top_client_queries{ip=\"%s\"} %d\n", esc_ip, (int)cnt->valuedouble);
		free(esc_ip);
	}

	fputs("# HELP pihole_client_info Names of the most active clients, always 1\n", fp);
	fputs("# TYPE pihole_client_info gauge\n", fp);
	cJSON_ArrayForEach(item, clients)
	{
		const char *ip = cJSON_GetStringValue(cJSON_GetObjectItem(item, "ip"));
		const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(item, "name"));
		if(ip == NULL || name == NULL || name[0] == '\0')
			continue;
		char *esc_ip = escape_label(ip);
		char *esc_name = escape_label(name);
		if(esc_ip != NULL && esc_name != NULL)
			fprintf(fp, "pihole_client_info{ip=\"%s\",name=\"%s\"} 1\n", esc_ip, esc_name);
		free(esc_ip);
		free(esc_name);
	}
	cJSON_Delete(tc);
}

int api_metrics(struct ftl_conn *api)
{
	// Copy the configured token hash under the shared-memory lock: the config
	// string can be free()d and reassigned by a concurrent token (re)generation
	// (generatePrometheusToken) or config PATCH on another worker thread, so
	// reading it lock-free would risk a use-after-free. The buffer holds one
	// character more than a valid 64-character hash: the TOML reader does not
	// run the config validators, so a hand-edited over-long value reaches here;
	// copying up to 65 characters keeps it longer than 64 so valid_sha256_hex()
	// rejects it below (fail closed) instead of silently accepting a truncation.
	char stored[2 * SHA256_DIGEST_SIZE + 2] = { 0 };
	lock_shm();
	if(config.webserver.api.prometheus.token.v.s != NULL)
		strncpy(stored, config.webserver.api.prometheus.token.v.s, sizeof(stored) - 1);
	unlock_shm();

	// Fail closed: while no token is configured the endpoint does not exist.
	// Returning 404 (rather than 401/403) avoids advertising the endpoint on
	// installs that have never enabled it and keeps it strictly opt-in.
	if(stored[0] == '\0')
	{
		send_http_code(api, "text/plain; charset=utf-8", 404, "Not Found\n");
		return 404;
	}

	// Invalid hashes are treated as disabled to fail closed.
	if(!valid_sha256_hex(stored))
	{
		send_http_code(api, "text/plain; charset=utf-8", 404, "Not Found\n");
		return 404;
	}

	// Constant-time bearer-token check. A uniform 401 is returned whether the
	// token was absent or wrong. No rate limiting is applied because the token
	// is a 256-bit random value, making brute force infeasible.
	if(!prometheus_authenticated(api, stored))
	{
		send_http_code(api, "text/plain; charset=utf-8", 401, "Unauthorized\n");
		return 401;
	}

	// ---- Snapshot all aggregate counters under a single short lock ----
	// We only copy scalars here and format the (potentially large) text buffer
	// afterwards, so the shared-memory lock is held for as little time as
	// possible.
	lock_shm();
	// counters->{queries,clients,domains,upstreams} and the querytype/status/
	// reply arrays are unsigned int; keep them unsigned so a count above
	// INT_MAX is not printed as a negative (invalid) Prometheus counter.
	const unsigned int total = counters->queries;
	// Leave out the history imported at startup so the counter starts at zero
	const unsigned int total_since_start = counters->queries + get_queries_removed() - get_imported_queries();
	const unsigned int blocked = get_blocked_count();
	const unsigned int forwarded = get_forwarded_count();
	const unsigned int cached = get_cached_count();
	const int num_gravity = counters->database.gravity;
	const unsigned int num_clients = counters->clients_total;
	const unsigned int num_domains = counters->domains_total;
	const unsigned int num_upstreams = counters->upstreams;
	const unsigned int activeclients = get_active_clients();

	unsigned int querytypes[TYPE_MAX] = { 0 };
	for(enum query_type t = TYPE_A; t < TYPE_MAX; t++)
		querytypes[t] = counters->querytype[t];

	unsigned int statuses[QUERY_STATUS_MAX] = { 0 };
	for(enum query_status s = 0; s < QUERY_STATUS_MAX; s++)
		statuses[s] = counters->status[s];

	unsigned int replies[QUERY_REPLY_MAX] = { 0 };
	for(enum reply_type r = 0; r < QUERY_REPLY_MAX; r++)
		replies[r] = counters->reply[r];
	unlock_shm();

	// Values that do not need the shared-memory lock
	const double qps = get_qps();
	const time_t gravity_updated = gravity_last_updated();

	// dnsmasq metrics have their own synchronization
	struct metrics m = { 0 };
	get_dnsmasq_metrics(&m);

	// ---- Build the exposition text without holding any lock ----
	char *buf = NULL;
	size_t buflen = 0;
	FILE *fp = open_memstream(&buf, &buflen);
	if(fp == NULL)
	{
		log_err("Cannot open memory stream for Prometheus metrics: %s", strerror(errno));
		return send_http_internal_error(api);
	}

	// Query totals. All of them but the first are gauges: they reflect the
	// queries in FTL's in-memory history (the last webserver.api.maxHistory
	// window, 24h by default) and go down when garbage collection removes
	// queries that aged out. Use pihole_dns_queries_total for rate()
	fputs("# HELP pihole_dns_queries_total DNS queries received since FTL started, not counting the history imported from the database\n", fp);
	fputs("# TYPE pihole_dns_queries_total counter\n", fp);
	fprintf(fp, "pihole_dns_queries_total %u\n", total_since_start);

	fputs("# HELP pihole_queries Number of DNS queries in FTL's history window (webserver.api.maxHistory)\n", fp);
	fputs("# TYPE pihole_queries gauge\n", fp);
	fprintf(fp, "pihole_queries %u\n", total);

	fputs("# HELP pihole_queries_blocked Number of blocked DNS queries in FTL's history window\n", fp);
	fputs("# TYPE pihole_queries_blocked gauge\n", fp);
	fprintf(fp, "pihole_queries_blocked %u\n", blocked);

	fputs("# HELP pihole_queries_forwarded Number of forwarded DNS queries in FTL's history window\n", fp);
	fputs("# TYPE pihole_queries_forwarded gauge\n", fp);
	fprintf(fp, "pihole_queries_forwarded %u\n", forwarded);

	fputs("# HELP pihole_queries_cached Number of cached DNS queries in FTL's history window\n", fp);
	fputs("# TYPE pihole_queries_cached gauge\n", fp);
	fprintf(fp, "pihole_queries_cached %u\n", cached);

	fprintf(fp, "# HELP pihole_query_frequency DNS queries per second, averaged over the last %d seconds\n", QPS_AVGLEN);
	fputs("# TYPE pihole_query_frequency gauge\n", fp);
	fprintf(fp, "pihole_query_frequency %f\n", qps);

	// Query types (gauge - see note on the query totals above)
	fputs("# HELP pihole_queries_by_type DNS queries by record type in FTL's history window\n", fp);
	fputs("# TYPE pihole_queries_by_type gauge\n", fp);
	for(enum query_type t = TYPE_A; t < TYPE_MAX; t++)
	{
		char *esc = escape_label(get_query_type_str(t, NULL, NULL));
		if(esc == NULL)
			continue;
		fprintf(fp, "pihole_queries_by_type{type=\"%s\"} %u\n", esc, querytypes[t]);
		free(esc);
	}

	// Query statuses (gauge - see note on the query totals above)
	fputs("# HELP pihole_queries_by_status DNS queries by processing status in FTL's history window\n", fp);
	fputs("# TYPE pihole_queries_by_status gauge\n", fp);
	for(enum query_status s = 0; s < QUERY_STATUS_MAX; s++)
	{
		char *esc = escape_label(get_query_status_str(s));
		if(esc == NULL)
			continue;
		fprintf(fp, "pihole_queries_by_status{status=\"%s\"} %u\n", esc, statuses[s]);
		free(esc);
	}

	// Query replies (gauge - see note on the query totals above)
	fputs("# HELP pihole_queries_by_reply DNS queries by reply type in FTL's history window\n", fp);
	fputs("# TYPE pihole_queries_by_reply gauge\n", fp);
	for(enum reply_type r = 0; r < QUERY_REPLY_MAX; r++)
	{
		char *esc = escape_label(get_query_reply_str(r));
		if(esc == NULL)
			continue;
		fprintf(fp, "pihole_queries_by_reply{reply=\"%s\"} %u\n", esc, replies[r]);
		free(esc);
	}

	// Clients / domains / upstreams, the same numbers as in /api/stats/summary
	fputs("# HELP pihole_clients Number of clients added since FTL started, including those recycled since\n", fp);
	fputs("# TYPE pihole_clients gauge\n", fp);
	fprintf(fp, "pihole_clients %u\n", num_clients);

	fputs("# HELP pihole_clients_active Number of clients with queries in FTL's history window\n", fp);
	fputs("# TYPE pihole_clients_active gauge\n", fp);
	fprintf(fp, "pihole_clients_active %u\n", activeclients);

	fputs("# HELP pihole_domains Number of domains added since FTL started, including those recycled since\n", fp);
	fputs("# TYPE pihole_domains gauge\n", fp);
	fprintf(fp, "pihole_domains %u\n", num_domains);

	fputs("# HELP pihole_upstreams Number of upstream destinations held in memory\n", fp);
	fputs("# TYPE pihole_upstreams gauge\n", fp);
	fprintf(fp, "pihole_upstreams %u\n", num_upstreams);

	// Without a readable gravity database, the count is a negative error
	// code and the timestamp 0, neither of which must plot as a value
	if(num_gravity >= 0)
	{
		fputs("# HELP pihole_gravity_domains Number of domains on the gravity (block) list\n", fp);
		fputs("# TYPE pihole_gravity_domains gauge\n", fp);
		fprintf(fp, "pihole_gravity_domains %d\n", num_gravity);
	}

	if(gravity_updated > 0)
	{
		fputs("# HELP pihole_gravity_last_update_timestamp_seconds Unix time of the last gravity update\n", fp);
		fputs("# TYPE pihole_gravity_last_update_timestamp_seconds gauge\n", fp);
		fprintf(fp, "pihole_gravity_last_update_timestamp_seconds %ld\n", (long)gravity_updated);
	}

	// dnsmasq keeps its counters as unsigned 32 bit values, struct metrics
	// stores them as int, so they are printed unsigned again. dnsmasq zeroes
	// the cache counters on every cache flush (e.g., when blocking is turned
	// on or off), Prometheus treats that like a restart
	fputs("# HELP pihole_dns_cache_size Configured capacity of the DNS cache\n", fp);
	fputs("# TYPE pihole_dns_cache_size gauge\n", fp);
	fprintf(fp, "pihole_dns_cache_size %u\n", (unsigned int)m.dns.cache.size);

	fputs("# HELP pihole_dns_cache_inserted_total Number of entries inserted into the DNS cache, reset on every cache flush\n", fp);
	fputs("# TYPE pihole_dns_cache_inserted_total counter\n", fp);
	fprintf(fp, "pihole_dns_cache_inserted_total %u\n", (unsigned int)m.dns.cache.inserted);

	fputs("# HELP pihole_dns_cache_evicted_total Number of live cache entries evicted before their TTL, reset on every cache flush\n", fp);
	fputs("# TYPE pihole_dns_cache_evicted_total counter\n", fp);
	fprintf(fp, "pihole_dns_cache_evicted_total %u\n", (unsigned int)m.dns.cache.live_freed);

	fputs("# HELP pihole_dns_cache_expired Number of expired entries currently in the DNS cache\n", fp);
	fputs("# TYPE pihole_dns_cache_expired gauge\n", fp);
	fprintf(fp, "pihole_dns_cache_expired %u\n", (unsigned int)m.dns.cache.expired);

	fputs("# HELP pihole_dns_cache_immortal Number of immortal DNS cache entries\n", fp);
	fputs("# TYPE pihole_dns_cache_immortal gauge\n", fp);
	fprintf(fp, "pihole_dns_cache_immortal %u\n", (unsigned int)m.dns.cache.immortal);

	// dnsmasq counts these on its UDP path only. TCP queries, which includes
	// everything FTL's own DoT, DoQ and DoH servers hand over, are missing
	fputs("# HELP pihole_dns_replies_total DNS replies over UDP by source as counted by dnsmasq (optimized: stale answers served from the cache)\n", fp);
	fputs("# TYPE pihole_dns_replies_total counter\n", fp);
	fprintf(fp, "pihole_dns_replies_total{source=\"local\"} %u\n", (unsigned int)m.dns.local_answered);
	fprintf(fp, "pihole_dns_replies_total{source=\"optimized\"} %u\n", (unsigned int)m.dns.stale_answered);
	fprintf(fp, "pihole_dns_replies_total{source=\"auth\"} %u\n", (unsigned int)m.dns.auth_answered);

	fputs("# HELP pihole_dns_upstream_sent_total DNS queries over UDP sent to upstream servers, retransmissions included\n", fp);
	fputs("# TYPE pihole_dns_upstream_sent_total counter\n", fp);
	fprintf(fp, "pihole_dns_upstream_sent_total %u\n", (unsigned int)m.dns.forwarded_queries);

	fputs("# HELP pihole_dns_upstream_unanswered_total DNS queries over UDP given up without an upstream answer, counted when their slot is reused\n", fp);
	fputs("# TYPE pihole_dns_upstream_unanswered_total counter\n", fp);
	fprintf(fp, "pihole_dns_upstream_unanswered_total %u\n", (unsigned int)m.dns.unanswered_queries);

	// DHCP message counters
	fputs("# HELP pihole_dhcp_messages_total DHCPv4 messages by type\n", fp);
	fputs("# TYPE pihole_dhcp_messages_total counter\n", fp);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"ack\"} %u\n", (unsigned int)m.dhcp.ack);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"decline\"} %u\n", (unsigned int)m.dhcp.decline);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"discover\"} %u\n", (unsigned int)m.dhcp.discover);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"inform\"} %u\n", (unsigned int)m.dhcp.inform);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"nak\"} %u\n", (unsigned int)m.dhcp.nak);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"offer\"} %u\n", (unsigned int)m.dhcp.offer);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"release\"} %u\n", (unsigned int)m.dhcp.release);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"request\"} %u\n", (unsigned int)m.dhcp.request);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"noanswer\"} %u\n", (unsigned int)m.dhcp.noanswer);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"bootp\"} %u\n", (unsigned int)m.dhcp.bootp);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"pxe\"} %u\n", (unsigned int)m.dhcp.pxe);

	// DHCP leases. Leases read from the lease file at startup count as
	// allocated, allocated minus pruned is the number of active leases
	fputs("# HELP pihole_dhcp_leases_allocated_total DHCP leases allocated since FTL started, by IP family\n", fp);
	fputs("# TYPE pihole_dhcp_leases_allocated_total counter\n", fp);
	fprintf(fp, "pihole_dhcp_leases_allocated_total{family=\"ipv4\"} %u\n", (unsigned int)m.dhcp.leases.allocated_4);
	fprintf(fp, "pihole_dhcp_leases_allocated_total{family=\"ipv6\"} %u\n", (unsigned int)m.dhcp.leases.allocated_6);

	fputs("# HELP pihole_dhcp_leases_pruned_total DHCP leases removed since FTL started, by IP family\n", fp);
	fputs("# TYPE pihole_dhcp_leases_pruned_total counter\n", fp);
	fprintf(fp, "pihole_dhcp_leases_pruned_total{family=\"ipv4\"} %u\n", (unsigned int)m.dhcp.leases.pruned_4);
	fprintf(fp, "pihole_dhcp_leases_pruned_total{family=\"ipv6\"} %u\n", (unsigned int)m.dhcp.leases.pruned_6);

	// Optional per-domain/per-client series (privacy-sensitive, opt-in)
	if(config.webserver.api.prometheus.perEntityMetrics.v.b)
		add_per_entity_metrics(api, fp);

	fclose(fp);

	if(buf == NULL)
		return send_http_internal_error(api);

	// Send the response with an explicit no-store cache directive. Unlike
	// mg_send_http_ok(), mg_response_header_send() does NOT emit a
	// Content-Length itself, so we must set it here - otherwise keep-alive
	// scrapers cannot find the end of the body and stall until the keep-alive
	// timeout on every scrape.
	char content_length[32] = { 0 };
	snprintf(content_length, sizeof(content_length), "%zu", buflen);
	mg_response_header_start(api->conn, 200);
	mg_response_header_add(api->conn, "Content-Type", PROM_CONTENT_TYPE, -1);
	mg_response_header_add(api->conn, "Content-Length", content_length, -1);
	mg_response_header_add(api->conn, "Cache-Control", "no-store", -1);
	mg_response_header_send(api->conn);
	mg_write(api->conn, buf, buflen);

	free(buf);

	// Return the HTTP status code (handler convention, see JSON_SEND_OBJECT).
	// Returning the mg_write() byte count instead would both mislog the status
	// and, on a 0 (client disconnected mid-write), make api_handler() emit a
	// second 404 response.
	return 200;
}
