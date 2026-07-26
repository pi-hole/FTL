/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound TLS client for encrypted upstreams (DoT/DoH)
*
*  Public interface of the strict, fail-closed OpenSSL client that talks to the
*  real upstream resolver and never falls back to plaintext. Each upstream owns a
*  connection pool that serves many concurrent exchanges over a bounded set of
*  keep-alive connections, with TLS 1.3 session resumption.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_TLS_CLIENT_H
#define DOTDOH_TLS_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "upstream_uri.h"

// Per-upstream connection pool. Opaque: all the connection, session and
// concurrency state lives inside the implementation.
struct tls_pool; // opaque

// Diagnostic counters, one set per upstream pool. Snapshotted under debug.dotdoh
// to assess keep-alive effectiveness and how often the session-resumption edge
// case (a full handshake despite an available ticket) actually happens.
struct dotdoh_stats {
	unsigned long long queries_total;             // exchanges that succeeded
	unsigned long long sessions_closed;           // connections torn down
	unsigned long long queries_per_session_sum;   // sum of per-conn served counts
	unsigned long long queries_per_session_max;   // deepest single-conn reuse
	unsigned long long handshakes_resumed;         // SSL_session_reused() == 1
	unsigned long long handshakes_fresh_cold;      // full, no ticket to try (expected)
	unsigned long long handshakes_full_fallback;   // full despite a ticket (edge case)
	unsigned long long conns_opened;               // fresh connections established
	unsigned long long conns_reaped_idle;          // closed as (likely) idle-dead
	unsigned long long conns_dead_on_reuse;        // reuse hit a dead connection
};

// Build the shared, read-only-after-init SSL_CTX: trust store (ca_file NULL
// selects the system bundle), fail-closed verification and the client session
// cache used for resumption. Returns true on success. Idempotent.
bool tls_client_global_init(const char *ca_file);
void tls_client_global_free(void);

// Create / destroy a per-upstream pool. max_conns bounds the concurrent
// connections to this upstream. The pool copies *u.
struct tls_pool *tls_pool_new(const struct upstream_uri *u, int max_conns) __attribute__((malloc));
void tls_pool_free(struct tls_pool *p);

// Perform one DNS exchange for this pool's upstream, borrowing (or establishing)
// a connection. query/qlen is the DNS wire message; the answer is written into
// answer[answer_sz]. Returns the answer length, or -1 on any failure (the caller
// drops the query so dnsmasq fails over). Thread-safe: many workers may call this
// on the same pool concurrently. Fail-closed.
ssize_t tls_pool_exchange(struct tls_pool *p, const uint8_t *query, size_t qlen,
                          uint8_t *answer, size_t answer_sz);

// Snapshot this pool's diagnostic counters into *out.
void tls_pool_get_stats(struct tls_pool *p, struct dotdoh_stats *out);

#endif // DOTDOH_TLS_CLIENT_H
