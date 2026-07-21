/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound QUIC client for DoH3 upstreams (HTTP/3 over QUIC)
*
*  Talks HTTP/3 over QUIC to the real upstream resolver. Like the TCP client it
*  is strict and fail-closed: a failed handshake or exchange returns -1 and the
*  query is dropped, so FTL fails over to the next server rather than downgrading
*  to plaintext. Each upstream owns a bounded QUIC connection pool that many
*  worker threads borrow concurrently, mirroring the tls_client pool model.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "quic_client.h"

// DoH3 fundamentally needs OpenSSL QUIC plus nghttp3; both are gated by the same
// flags the webserver HTTP/3 terminator uses. Without them there is no QUIC
// transport, so the pool cannot be created and every exchange fails closed.
#if defined(HAVE_TLS) && defined(HAVE_HTTP3)

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// Per-upstream QUIC pool. For now it only carries the immutable upstream
// descriptor, the connection cap and the diagnostic counters; the actual QUIC
// connection state (OpenSSL QUIC SSL objects, nghttp3 connections, the UDP BIO)
// is added when the exchange is implemented. The lock guards the stats.
struct quic_pool {
	struct upstream_uri u;      // upstream descriptor (immutable)
	int max;                    // connection cap (immutable)
	pthread_mutex_t lock;       // guards stats
	struct dotdoh_stats stats;
};

struct quic_pool *quic_pool_new(const struct upstream_uri *u, int max_conns)
{
	if(u == NULL || max_conns < 1)
		return NULL;
	struct quic_pool *p = calloc(1, sizeof(*p));
	if(p == NULL)
		return NULL;
	p->u = *u;
	p->max = max_conns;
	pthread_mutex_init(&p->lock, NULL);
	return p;
}

void quic_pool_free(struct quic_pool *p)
{
	if(p == NULL)
		return;
	pthread_mutex_destroy(&p->lock);
	free(p);
}

// The QUIC/nghttp3 exchange is not implemented yet: the pool is armed so an
// h3:// upstream gets its loopback listener and routing, but until the transport
// is wired up every exchange fails closed. The trivial body is a const-folding
// candidate, so silence -Wsuggest-attribute here (the attribute cannot be
// applied - the real implementation has side effects). clang lacks the warning.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
#endif
ssize_t quic_pool_exchange(struct quic_pool *p, const uint8_t *query, size_t qlen,
                           uint8_t *answer, size_t answer_sz)
{
	(void)p; (void)query; (void)qlen; (void)answer; (void)answer_sz;
	return -1;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

void quic_pool_get_stats(struct quic_pool *p, struct dotdoh_stats *out)
{
	if(p == NULL || out == NULL)
		return;
	pthread_mutex_lock(&p->lock);
	*out = p->stats;
	pthread_mutex_unlock(&p->lock);
}

#else // no QUIC / HTTP3 support in this build

// Without OpenSSL QUIC + nghttp3 there is no DoH3 transport. The pool cannot be
// created and every exchange fails closed; the config layer refuses to arm an
// h3:// upstream when quic_pool_new() returns NULL. These trivial stubs are
// const-folding candidates, so silence the GCC-only attribute suggestion (the
// malloc attribute on quic_pool_new() also conflicts with -Wsuggest-attribute).
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
#endif
struct quic_pool *quic_pool_new(const struct upstream_uri *u, int max_conns)
{
	(void)u; (void)max_conns;
	return NULL;
}
void quic_pool_free(struct quic_pool *p) { (void)p; }
ssize_t quic_pool_exchange(struct quic_pool *p, const uint8_t *query, size_t qlen,
                           uint8_t *answer, size_t answer_sz)
{
	(void)p; (void)query; (void)qlen; (void)answer; (void)answer_sz;
	return -1;
}
void quic_pool_get_stats(struct quic_pool *p, struct dotdoh_stats *out) { (void)p; (void)out; }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif // HAVE_TLS && HAVE_HTTP3
