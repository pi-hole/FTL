/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound QUIC client for DoH3 upstreams (HTTP/3 over QUIC)
*
*  Public interface of the DoH3 client: it mirrors the tls_client pool API so the
*  proxy can route an h3:// upstream through it exactly as it routes DoT/DoH
*  through the TCP pool. The transport underneath is OpenSSL QUIC + nghttp3; the
*  handshake is fail-closed (chain + hostname verification) just like the TCP
*  path, and a failed exchange returns -1 so the query is dropped and FTL fails
*  over rather than downgrading.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_QUIC_CLIENT_H
#define DOTDOH_QUIC_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "upstream_uri.h"
// struct dotdoh_stats is shared with the TCP client so the proxy can report both
// transports through one summary path.
#include "tls_client.h"

// Per-upstream QUIC connection pool. Opaque: all connection and concurrency
// state lives inside the implementation.
struct quic_pool; // opaque

// Create / destroy a per-upstream DoH3 pool. max_conns bounds the concurrent
// QUIC connections to this upstream. The pool copies *u. Returns NULL on failure
// (e.g. this build has no QUIC/nghttp3 support).
struct quic_pool *quic_pool_new(const struct upstream_uri *u, int max_conns) __attribute__((malloc));
void quic_pool_free(struct quic_pool *p);

// Perform one DNS exchange over HTTP/3. query/qlen is the DNS wire message; the
// answer is written into answer[answer_sz]. Returns the answer length, or -1 on
// any failure (the caller drops the query so dnsmasq fails over). Thread-safe.
// Fail-closed.
ssize_t quic_pool_exchange(struct quic_pool *p, const uint8_t *query, size_t qlen,
                           uint8_t *answer, size_t answer_sz);

// Snapshot this pool's diagnostic counters into *out.
void quic_pool_get_stats(struct quic_pool *p, struct dotdoh_stats *out);

#endif // DOTDOH_QUIC_CLIENT_H
