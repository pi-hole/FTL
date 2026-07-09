/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/metrics (Prometheus/OpenMetrics)
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
#include "webserver/cJSON/cJSON.h"
// constant-time comparison memeql_sec()
#include <nettle/memops.h>
// SHA256_DIGEST_SIZE
#include <nettle/sha2.h>

#define PROMETHEUS_BEARER_MAX_LEN 512u

// Prometheus text exposition format, version 0.0.4. This is the most widely
// compatible content type and is accepted by "promtool check metrics".
#define PROM_CONTENT_TYPE "text/plain; version=0.0.4; charset=utf-8"

// Escape a Prometheus label *value* according to the text exposition format:
// backslash, double-quote and newline have to be escaped. Domain, client and
// similar names end up as label values and are attacker-influenceable (anyone
// on the network can query a crafted name that lands in the top lists), so this
// escaping is mandatory to prevent them from corrupting the output or injecting
// forged samples. Returns a newly allocated string (caller frees) or NULL on
// allocation failure.
static char * __attribute__((malloc)) escape_label(const char *in)
{
	if(in == NULL)
		in = "";

	const size_t len = strlen(in);

	// Worst case every character has to be escaped into two characters
	char *out = calloc(2 * len + 1, sizeof(char));
	if(out == NULL)
		return NULL;

	char *p = out;
	for(size_t i = 0; i < len; i++)
	{
		switch(in[i])
		{
			case '\\':
				*p++ = '\\';
				*p++ = '\\';
				break;
			case '"':
				*p++ = '\\';
				*p++ = '"';
				break;
			case '\n':
				*p++ = '\\';
				*p++ = 'n';
				break;
			case '\r':
				*p++ = '\\';
				*p++ = 'r';
				break;
			default:
				*p++ = in[i];
				break;
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

// Append the top-N domains and clients as labelled gauge series. This is only
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

	// Top clients (by total queries). Prefer the client name, fall back to IP.
	cJSON *tc = get_top_clients(api, count, false, false, false, false);
	if(tc != NULL)
	{
		fputs("# HELP pihole_top_client_queries DNS queries for the most active clients\n", fp);
		fputs("# TYPE pihole_top_client_queries gauge\n", fp);

		const cJSON *clients = cJSON_GetObjectItem(tc, "clients");
		const cJSON *item = NULL;
		cJSON_ArrayForEach(item, clients)
		{
			const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(item, "name"));
			const char *ip = cJSON_GetStringValue(cJSON_GetObjectItem(item, "ip"));
			const cJSON *cnt = cJSON_GetObjectItem(item, "count");
			if(cnt == NULL)
				continue;

			// The IP uniquely identifies a client, so it is the primary label -
			// this avoids duplicate time series (which make Prometheus reject
			// the whole scrape) when two clients share a hostname. The name is
			// added as a secondary label for readability.
			char *esc_ip = escape_label(ip != NULL ? ip : "");
			char *esc_name = escape_label(name != NULL ? name : "");
			if(esc_ip != NULL && esc_name != NULL)
				fprintf(fp, "pihole_top_client_queries{ip=\"%s\",name=\"%s\"} %d\n",
				        esc_ip, esc_name, (int)cnt->valuedouble);
			free(esc_ip);
			free(esc_name);
		}
		cJSON_Delete(tc);
	}
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
	const unsigned int blocked = get_blocked_count();
	const unsigned int forwarded = get_forwarded_count();
	const unsigned int cached = get_cached_count();
	const int num_gravity = counters->database.gravity;
	const unsigned int num_clients = counters->clients;
	const unsigned int num_domains = counters->domains;
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

	// Query totals.
	// Note: these are gauges, not counters - they reflect the queries in FTL's
	// in-memory history (the last misc.maxHistory window, 24h by default) and
	// are decremented by garbage collection as queries age out, so they can go
	// down as well as up. Use the monotonic pihole_dns_replies_total /
	// pihole_dns_cache_* counters below for rate() calculations.
	fputs("# HELP pihole_queries Number of DNS queries in FTL's history window (misc.maxHistory)\n", fp);
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

	fputs("# HELP pihole_query_frequency Queries per second (rolling average)\n", fp);
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

	// Clients / domains / gravity
	fputs("# HELP pihole_clients_total Number of known clients\n", fp);
	fputs("# TYPE pihole_clients_total gauge\n", fp);
	fprintf(fp, "pihole_clients_total %u\n", num_clients);

	fputs("# HELP pihole_clients_active Number of clients active within the last 24 hours\n", fp);
	fputs("# TYPE pihole_clients_active gauge\n", fp);
	fprintf(fp, "pihole_clients_active %u\n", activeclients);

	fputs("# HELP pihole_domains_total Number of unique domains seen\n", fp);
	fputs("# TYPE pihole_domains_total gauge\n", fp);
	fprintf(fp, "pihole_domains_total %u\n", num_domains);

	fputs("# HELP pihole_upstreams_total Number of known upstream destinations\n", fp);
	fputs("# TYPE pihole_upstreams_total gauge\n", fp);
	fprintf(fp, "pihole_upstreams_total %u\n", num_upstreams);

	fputs("# HELP pihole_gravity_domains Number of domains on the gravity (block) list\n", fp);
	fputs("# TYPE pihole_gravity_domains gauge\n", fp);
	fprintf(fp, "pihole_gravity_domains %d\n", num_gravity);

	fputs("# HELP pihole_gravity_last_update_timestamp_seconds Unix time of the last gravity update\n", fp);
	fputs("# TYPE pihole_gravity_last_update_timestamp_seconds gauge\n", fp);
	fprintf(fp, "pihole_gravity_last_update_timestamp_seconds %ld\n", (long)gravity_updated);

	// dnsmasq cache metrics
	fputs("# HELP pihole_dns_cache_size Number of entries in the DNS cache\n", fp);
	fputs("# TYPE pihole_dns_cache_size gauge\n", fp);
	fprintf(fp, "pihole_dns_cache_size %d\n", m.dns.cache.size);

	fputs("# HELP pihole_dns_cache_inserted_total Number of entries inserted into the DNS cache\n", fp);
	fputs("# TYPE pihole_dns_cache_inserted_total counter\n", fp);
	fprintf(fp, "pihole_dns_cache_inserted_total %d\n", m.dns.cache.inserted);

	fputs("# HELP pihole_dns_cache_evicted_total Number of live cache entries evicted before their TTL\n", fp);
	fputs("# TYPE pihole_dns_cache_evicted_total counter\n", fp);
	fprintf(fp, "pihole_dns_cache_evicted_total %d\n", m.dns.cache.live_freed);

	fputs("# HELP pihole_dns_cache_expired_total Number of expired DNS cache entries\n", fp);
	fputs("# TYPE pihole_dns_cache_expired_total counter\n", fp);
	fprintf(fp, "pihole_dns_cache_expired_total %d\n", m.dns.cache.expired);

	fputs("# HELP pihole_dns_cache_immortal Number of immortal DNS cache entries\n", fp);
	fputs("# TYPE pihole_dns_cache_immortal gauge\n", fp);
	fprintf(fp, "pihole_dns_cache_immortal %d\n", m.dns.cache.immortal);

	// dnsmasq reply breakdown
	fputs("# HELP pihole_dns_replies_total DNS replies by source\n", fp);
	fputs("# TYPE pihole_dns_replies_total counter\n", fp);
	fprintf(fp, "pihole_dns_replies_total{source=\"local\"} %d\n", m.dns.local_answered);
	fprintf(fp, "pihole_dns_replies_total{source=\"forwarded\"} %d\n", m.dns.forwarded_queries);
	fprintf(fp, "pihole_dns_replies_total{source=\"optimized\"} %d\n", m.dns.stale_answered);
	fprintf(fp, "pihole_dns_replies_total{source=\"unanswered\"} %d\n", m.dns.unanswered_queries);
	fprintf(fp, "pihole_dns_replies_total{source=\"auth\"} %d\n", m.dns.auth_answered);

	// DHCP message counters
	fputs("# HELP pihole_dhcp_messages_total DHCP messages by type\n", fp);
	fputs("# TYPE pihole_dhcp_messages_total counter\n", fp);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"ack\"} %d\n", m.dhcp.ack);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"decline\"} %d\n", m.dhcp.decline);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"discover\"} %d\n", m.dhcp.discover);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"inform\"} %d\n", m.dhcp.inform);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"nak\"} %d\n", m.dhcp.nak);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"offer\"} %d\n", m.dhcp.offer);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"release\"} %d\n", m.dhcp.release);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"request\"} %d\n", m.dhcp.request);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"noanswer\"} %d\n", m.dhcp.noanswer);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"bootp\"} %d\n", m.dhcp.bootp);
	fprintf(fp, "pihole_dhcp_messages_total{type=\"pxe\"} %d\n", m.dhcp.pxe);

	// DHCP leases
	fputs("# HELP pihole_dhcp_leases DHCP leases by IP family and operation\n", fp);
	fputs("# TYPE pihole_dhcp_leases gauge\n", fp);
	fprintf(fp, "pihole_dhcp_leases{family=\"ipv4\",operation=\"allocated\"} %d\n", m.dhcp.leases.allocated_4);
	fprintf(fp, "pihole_dhcp_leases{family=\"ipv4\",operation=\"pruned\"} %d\n", m.dhcp.leases.pruned_4);
	fprintf(fp, "pihole_dhcp_leases{family=\"ipv6\",operation=\"allocated\"} %d\n", m.dhcp.leases.allocated_6);
	fprintf(fp, "pihole_dhcp_leases{family=\"ipv6\",operation=\"pruned\"} %d\n", m.dhcp.leases.pruned_6);

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
