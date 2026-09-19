/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound DoQ client (DNS-over-QUIC, RFC 9250)
*
*  DoQ is the cheapest of the encrypted transports to speak: the DNS message goes
*  on a QUIC stream with the same 2-byte length prefix DoT uses, so there is no
*  HTTP layer at all. Like the other clients it is strict and fail-closed - a bad
*  chain, a stream reset or a timeout returns -1 and the query is dropped, so FTL
*  fails over to the next server instead of downgrading to plaintext.
*
*  Each exchange runs on its own short-lived QUIC connection, mirroring the DoH3
*  client: many workers then run concurrently without sharing a connection
*  object, at the cost of one 1-RTT handshake per query. Reusing connections
*  across queries would need a shared, locked connection object; that is a
*  follow-up, not a correctness matter.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "doq_client.h"

// DoQ needs OpenSSL QUIC, but - unlike DoH3 - no HTTP/3 library.
#if defined(HAVE_TLS) && defined(HAVE_QUIC)

// dot_frame/dot_deframe (RFC 9250 reuses the DoT framing), DNS_MSG_MAX
#include "framing.h"
// edns_remove_option()
#include "edns_pad.h"
// shared QUIC socket/handshake/timer plumbing
#include "quic_common.h"

#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

// Overall budget (ms) for one DoQ exchange (connect + handshake + query +
// answer), so a bad upstream cannot pin a worker; on expiry, dnsmasq fails over.
#define DOQ_EXCHANGE_TIMEOUT_MS 10000

// ALPN token for DNS-over-QUIC (RFC 9250 Sec. 4.1.2). QUIC mandates ALPN, so an
// upstream that does not speak DoQ fails the handshake instead of half-working.
static const unsigned char DOQ_ALPN[] = { 3, 'd', 'o', 'q' };

// EDNS(0) TCP Keepalive (RFC 7828). RFC 9250 Sec. 5.5.2 forbids it on a DoQ
// connection in either direction, and a conformant server aborts the connection
// with DOQ_PROTOCOL_ERROR when it sees one - as our own inbound listener does.
// It is a hop-by-hop option, so stripping it here is also what RFC 7828 wants of
// a forwarder.
#define EDNS_OPT_TCP_KEEPALIVE 11

// Per-upstream DoQ pool. In the connection-per-exchange model it holds only the
// immutable upstream descriptor and the stats (lock-guarded); the QUIC
// connection is short-lived on the worker stack for one exchange.
struct doq_pool {
	struct upstream_uri u;      // upstream descriptor (immutable)
	int max;                    // connection cap (immutable; informational here)
	pthread_mutex_t lock;       // guards stats
	struct dotdoh_stats stats;
};

struct doq_pool *doq_pool_new(const struct upstream_uri *u, int max_conns)
{
	if(quic_client_ctx() == NULL || u == NULL || max_conns < 1)
		return NULL;
	struct doq_pool *p = calloc(1, sizeof(*p));
	if(p == NULL)
		return NULL;
	p->u = *u;
	p->max = max_conns;
	pthread_mutex_init(&p->lock, NULL);
	return p;
}

void doq_pool_free(struct doq_pool *p)
{
	if(p == NULL)
		return;
	pthread_mutex_destroy(&p->lock);
	free(p);
}

// Write the whole framed query to the request stream and close our sending side
// with a FIN, which is how DoQ delimits the query (RFC 9250 Sec. 4.2). Returns
// false on a fatal stream/connection error or on running out of time.
static bool doq_send_query(SSL *conn, SSL *stream, int fd,
                           const uint8_t *buf, size_t len, uint64_t deadline)
{
	size_t off = 0;
	while(off < len)
	{
		size_t written = 0;
		const int r = SSL_write_ex(stream, buf + off, len - off, &written);
		if(r == 1 && written > 0)
		{
			off += written;
			continue;
		}
		if(r != 1)
		{
			const int err = SSL_get_error(stream, r);
			if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
				return false;
		}
		// Blocked (or a zero-byte accept): wait for progress rather than spin.
		if(quic_now_ms() >= deadline)
			return false;
		quic_wait(conn, fd, deadline);
		SSL_handle_events(conn);
	}
	// FIN: no more data on this stream. The peer needs it to start resolving.
	return SSL_stream_conclude(stream, 0) == 1;
}

// Read the length-prefixed answer from the request stream into buf. Returns the
// DNS message length and sets *msg_off, or -1 on a protocol error, a reset, a
// premature FIN or the deadline expiring.
static ssize_t doq_read_answer(SSL *conn, SSL *stream, int fd, uint8_t *buf,
                               size_t bufsz, size_t *msg_off, uint64_t deadline)
{
	size_t have = 0;
	for(;;)
	{
		const ssize_t alen = dot_deframe(buf, have, msg_off);
		if(alen < 0)
			return -1;  // zero-length frame: protocol error
		if(alen > 0)
			return alen; // complete answer buffered

		if(have >= bufsz)
			return -1; // no room left and still incomplete

		size_t nread = 0;
		const int r = SSL_read_ex(stream, buf + have, bufsz - have, &nread);
		if(r == 1 && nread > 0)
		{
			have += nread;
			continue;
		}
		if(r != 1)
		{
			const int err = SSL_get_error(stream, r);
			if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
				// ZERO_RETURN (FIN before a full answer), a reset or a
				// connection error - none of them can ever complete.
				return -1;
		}
		if(quic_now_ms() >= deadline)
			return -1;
		quic_wait(conn, fd, deadline);
		SSL_handle_events(conn);
	}
}

// One exchange over a freshly handshaked connection. Returns the answer length
// written into answer[], or -1.
static ssize_t doq_exchange_on_conn(SSL *conn, int fd, const uint8_t *query, size_t qlen,
                                    uint8_t *answer, size_t answer_sz, uint64_t deadline)
{
	// Framing and receive buffers: 64 KiB each is too much for a worker's thread
	// stack, so keep one set per worker thread (as the proxy does).
	static _Thread_local uint8_t sendbuf[2 + DNS_MSG_MAX];
	static _Thread_local uint8_t recvbuf[2 + DNS_MSG_MAX];

	ssize_t flen = dot_frame(query, qlen, sendbuf, sizeof(sendbuf));
	if(flen < 0)
		return -1;

	// A downstream client's edns-tcp-keepalive rides through dnsmasq untouched; it
	// must not reach a DoQ upstream. Strip it from our framed copy (the helper
	// keeps the padded length intact by absorbing the freed bytes into the
	// padding, so this is usually length-neutral) and correct the prefix if not.
	const size_t stripped = edns_remove_option(sendbuf + 2, qlen, EDNS_OPT_TCP_KEEPALIVE);
	if(stripped != qlen)
	{
		sendbuf[0] = (uint8_t)((stripped >> 8) & 0xff);
		sendbuf[1] = (uint8_t)(stripped & 0xff);
		flen = (ssize_t)(2 + stripped);
	}

	// RFC 9250 Sec. 4.2.1: the DNS Message ID MUST be 0 on a QUIC stream (the
	// stream itself correlates query and answer). Remember the ID dnsmasq chose
	// and restore it on the answer, which comes back with the zeroed ID.
	const uint8_t qid[2] = { sendbuf[2], sendbuf[3] };
	sendbuf[2] = sendbuf[3] = 0;

	// One query per client-initiated bidirectional stream.
	SSL *stream = SSL_new_stream(conn, 0);
	if(stream == NULL)
		return -1;

	ssize_t rv = -1;
	size_t off = 0;
	if(doq_send_query(conn, stream, fd, sendbuf, (size_t)flen, deadline))
	{
		const ssize_t alen = doq_read_answer(conn, stream, fd, recvbuf,
		                                     sizeof(recvbuf), &off, deadline);
		// A DNS message shorter than the 12-byte header cannot carry the ID we
		// have to restore, so it is malformed by definition.
		if(alen >= 12 && (size_t)alen <= answer_sz)
		{
			memcpy(answer, recvbuf + off, (size_t)alen);
			answer[0] = qid[0];
			answer[1] = qid[1];
			rv = alen;
		}
	}

	SSL_free(stream);
	return rv;
}

ssize_t doq_pool_exchange(struct doq_pool *p, const uint8_t *query, size_t qlen,
                          uint8_t *answer, size_t answer_sz)
{
	SSL_CTX *qctx = quic_client_ctx();
	if(qctx == NULL || p == NULL || query == NULL || answer == NULL)
		return -1;
	// A query shorter than the DNS header has no Message ID to zero and restore
	// (RFC 9250 Sec. 4.2.1), and is malformed anyway.
	if(qlen < 12 || qlen > DNS_MSG_MAX)
		return -1;

	const struct upstream_uri *u = &p->u;
	const uint64_t deadline = quic_now_ms() + DOQ_EXCHANGE_TIMEOUT_MS;

	// 1. Connected, non-blocking UDP socket to the upstream.
	int fd = -1;
	BIO_ADDR *peer = NULL;
	if(!quic_udp_connect(u->connect_host, u->port, deadline, &fd, &peer))
	{
		log_warn("dotdoh: DoQ connect to %s#%d failed", u->connect_host, u->port);
		return -1;
	}

	// 2. QUIC connection object over that socket.
	SSL *conn = SSL_new(qctx);
	BIO *bio = conn != NULL ? BIO_new_dgram(fd, BIO_CLOSE) : NULL;
	if(conn == NULL || bio == NULL)
	{
		// SSL_set_bio() has not run, so the SSL does not own the fd: a BIO
		// (BIO_CLOSE) closes it on BIO_free(), else close it directly;
		// SSL_free() alone would leak it.
		if(bio != NULL)
			BIO_free(bio);
		else
			close(fd);
		if(conn != NULL)
			SSL_free(conn);
		BIO_ADDR_free(peer);
		return -1;
	}
	SSL_set_bio(conn, bio, bio); // SSL owns the BIO (and the fd via BIO_CLOSE)

	// ALPN "doq", the initial peer address, non-blocking mode and manual stream
	// control - we open and drive the request stream by hand.
	SSL_set_alpn_protos(conn, DOQ_ALPN, sizeof(DOQ_ALPN));
	SSL_set1_initial_peer_addr(conn, peer);
	BIO_ADDR_free(peer);
	SSL_set_blocking_mode(conn, 0);
	SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE);

	ssize_t rv = -1;
	bool connected = false;

	// 3. Handshake (fail-closed: a bad chain or hostname aborts here), then the
	// single query/answer stream.
	if(quic_bind_verify_name(conn, u->verify_name) &&
	   quic_do_handshake(conn, fd, deadline))
	{
		connected = true;
		rv = doq_exchange_on_conn(conn, fd, query, qlen, answer, answer_sz, deadline);
	}

	// 4. Accounting + teardown.
	pthread_mutex_lock(&p->lock);
	if(connected)
	{
		p->stats.conns_opened++;
		p->stats.handshakes_fresh_cold++; // DoQ exchange = one fresh connection
		p->stats.sessions_closed++;
		p->stats.queries_per_session_sum += (rv >= 0) ? 1u : 0u;
		if(rv >= 0 && p->stats.queries_per_session_max < 1)
			p->stats.queries_per_session_max = 1;
	}
	if(rv >= 0)
		p->stats.queries_total++;
	pthread_mutex_unlock(&p->lock);

	// Best-effort immediate close so the upstream does not wait on us; do not
	// block the worker flushing it. No args means the default application error
	// code 0, which is DOQ_NO_ERROR.
	SSL_shutdown_ex(conn, SSL_SHUTDOWN_FLAG_RAPID | SSL_SHUTDOWN_FLAG_NO_BLOCK,
	                NULL, 0);
	SSL_free(conn); // frees the datagram BIO and closes the UDP fd
	return rv;
}

void doq_pool_get_stats(struct doq_pool *p, struct dotdoh_stats *out)
{
	if(p == NULL || out == NULL)
		return;
	pthread_mutex_lock(&p->lock);
	*out = p->stats;
	pthread_mutex_unlock(&p->lock);
}

#else // no QUIC support in this build

// Without OpenSSL QUIC there is no DoQ transport: the pool cannot be created and
// every exchange fails closed (the proxy leaves a doq:// upstream un-armed when
// doq_pool_new() returns NULL). These trivial stubs are const-folding
// candidates, so silence the GCC-only -Wsuggest-attribute suggestions.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
#endif
struct doq_pool *doq_pool_new(const struct upstream_uri *u, int max_conns)
{
	(void)u; (void)max_conns;
	return NULL;
}
void doq_pool_free(struct doq_pool *p) { (void)p; }
ssize_t doq_pool_exchange(struct doq_pool *p, const uint8_t *query, size_t qlen,
                          uint8_t *answer, size_t answer_sz)
{
	(void)p; (void)query; (void)qlen; (void)answer; (void)answer_sz;
	return -1;
}
void doq_pool_get_stats(struct doq_pool *p, struct dotdoh_stats *out) { (void)p; (void)out; }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif // HAVE_TLS && HAVE_QUIC
