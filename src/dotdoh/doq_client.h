/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound DoQ client (DNS-over-QUIC, RFC 9250)
*
*  Public interface of the DoQ client. It mirrors the tls_client/quic_client pool
*  API so the proxy routes a doq:// upstream exactly as it routes DoT/DoH/DoH3.
*  The transport is OpenSSL QUIC with ALPN "doq" and the DNS message framed
*  exactly as in DoT (2-byte length prefix), one query per bidirectional stream.
*  The handshake is fail-closed (chain + hostname verification) and a failed
*  exchange returns -1 so the query is dropped and FTL fails over rather than
*  downgrading.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_DOQ_CLIENT_H
#define DOTDOH_DOQ_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "upstream_uri.h"
// struct dotdoh_stats is shared with the TCP client (one summary path).
#include "tls_client.h"

// Per-upstream DoQ connection pool; all state lives in the implementation.
struct doq_pool; // opaque

// The shared QUIC client context (quic_client_global_init(), quic_common.h) must
// be up before a pool is created; without it doq_pool_new() returns NULL.

// Create / destroy a per-upstream DoQ pool. The pool copies *u; max_conns is the
// proxy's per-upstream connection budget, kept for symmetry with the TCP pool and
// the stats - each exchange opens its own connection, so nothing is pooled here.
// Returns NULL on failure (e.g. no QUIC build).
struct doq_pool *doq_pool_new(const struct upstream_uri *u, int max_conns) __attribute__((malloc));
void doq_pool_free(struct doq_pool *p);

// Perform one DNS exchange over QUIC. query/qlen is the DNS wire message; the
// answer is written into answer[answer_sz]. Returns the answer length, or -1 on
// failure (caller drops the query, dnsmasq fails over). Thread-safe, fail-closed.
ssize_t doq_pool_exchange(struct doq_pool *p, const uint8_t *query, size_t qlen,
                          uint8_t *answer, size_t answer_sz);

// Snapshot this pool's diagnostic counters into *out.
void doq_pool_get_stats(struct doq_pool *p, struct dotdoh_stats *out);

#endif // DOTDOH_DOQ_CLIENT_H
