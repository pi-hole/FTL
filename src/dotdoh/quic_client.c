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
*  to plaintext. Each upstream owns a QUIC pool; a worker performs one exchange
*  over its own short-lived QUIC connection, so many workers run concurrently
*  without sharing a (non-thread-safe) OpenSSL QUIC connection object.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "quic_client.h"

// DoH3 needs OpenSSL QUIC plus nghttp3 (same flags as the webserver HTTP/3
// terminator). Without them the pool cannot be created and exchanges fail closed.
#if defined(HAVE_TLS) && defined(HAVE_HTTP3)

#include "framing.h" // DNS_MSG_MAX
// shared QUIC socket/handshake/timer plumbing
#include "quic_common.h"

#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <nghttp3/nghttp3.h>

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

// Overall budget (ms) for one QUIC exchange (connect + handshake + request +
// response), so a bad upstream cannot pin a worker; on expiry, dnsmasq fails over.
#define QUIC_EXCHANGE_TIMEOUT_MS 10000

// Per-upstream QUIC pool. In the connection-per-exchange model it holds only the
// immutable upstream descriptor and the stats (lock-guarded); the QUIC connection
// is short-lived on the worker stack for one exchange.
struct quic_pool {
	struct upstream_uri u;      // upstream descriptor (immutable)
	int max;                    // connection cap (immutable; informational here)
	pthread_mutex_t lock;       // guards stats
	struct dotdoh_stats stats;
};

// Monotonic timestamp in nanoseconds for nghttp3's bookkeeping.
static nghttp3_tstamp h3_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (nghttp3_tstamp)ts.tv_sec * 1000000000ull + (nghttp3_tstamp)ts.tv_nsec;
}

struct quic_pool *quic_pool_new(const struct upstream_uri *u, int max_conns)
{
	if(quic_client_ctx() == NULL || u == NULL || max_conns < 1)
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

// ---------------------------------------------------------------------------
// One QUIC/HTTP3 exchange
// ---------------------------------------------------------------------------

// Streams we track: the request bidi stream, our three local uni streams (control
// + QPACK encoder/decoder), and the three the server opens back. Cap covers all.
#define QUIC_MAX_STREAMS 16

struct qstream {
	int64_t id;
	SSL *ssl;         // OpenSSL QUIC child stream object
	bool local_uni;   // a control/QPACK stream we created (write-only)
	bool read_done;   // FIN or reset seen, no more reads
};

// Per-exchange transfer state, reached from the nghttp3 callbacks via the
// connection user data.
struct quic_xfer {
	int64_t req_sid;        // the request stream id
	const uint8_t *query;   // request body (the padded DNS query)
	size_t qlen;            // request body length
	size_t qoff;            // bytes already handed to nghttp3
	uint8_t *answer;        // caller's answer buffer
	size_t answer_sz;       // its capacity
	size_t answer_len;      // response body bytes collected so far
	int status;             // parsed :status (0 until seen)
	bool overflow;          // response body exceeded answer_sz
	bool done;              // request stream closed
	bool failed;            // request stream closed with an error
};

// One QUIC connection plus its HTTP/3 session and stream table, for one exchange.
struct quic_client_conn {
	SSL *ssl;                              // QUIC connection object
	nghttp3_conn *h3;
	struct qstream streams[QUIC_MAX_STREAMS];
	int nstreams;
	struct quic_xfer x;
};

static struct qstream *find_stream(struct quic_client_conn *c, int64_t id)
{
	for(int i = 0; i < c->nstreams; i++)
		if(c->streams[i].id == id)
			return &c->streams[i];
	return NULL;
}

// Register a QUIC stream object in the connection's table. Returns false (and does
// not take ownership) when the table is full.
static bool add_stream(struct quic_client_conn *c, SSL *ssl, bool local_uni)
{
	if(c->nstreams >= QUIC_MAX_STREAMS)
		return false;
	struct qstream *s = &c->streams[c->nstreams++];
	s->ssl = ssl;
	s->local_uni = local_uni;
	s->read_done = false;
	s->id = (int64_t)SSL_get_stream_id(ssl);
	return true;
}

// nghttp3 data reader: hand the whole padded DNS query to nghttp3 as the POST body
// in one vec. The caller's query buffer is stable for the exchange (safe to retain).
static nghttp3_ssize quic_req_read(nghttp3_conn *h3, int64_t stream_id,
                                   nghttp3_vec *vec, size_t veccnt,
                                   uint32_t *pflags, void *conn_user_data,
                                   void *stream_user_data)
{
	(void)h3; (void)stream_id; (void)stream_user_data;
	struct quic_client_conn *c = conn_user_data;
	if(veccnt < 1)
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	vec[0].base = (uint8_t *)(uintptr_t)(c->x.query + c->x.qoff);
	vec[0].len = c->x.qlen - c->x.qoff;
	c->x.qoff = c->x.qlen;
	*pflags = NGHTTP3_DATA_FLAG_EOF;
	return 1;
}

// Capture the :status pseudo-header of the response.
static int quic_cb_recv_header(nghttp3_conn *h3, int64_t stream_id, int32_t token,
                               nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                               uint8_t flags, void *conn_user_data,
                               void *stream_user_data)
{
	(void)h3; (void)token; (void)flags; (void)stream_user_data;
	struct quic_client_conn *c = conn_user_data;
	if(stream_id != c->x.req_sid)
		return 0;
	const nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
	const nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
	if(n.len == 7 && memcmp(n.base, ":status", 7) == 0)
	{
		int s = 0;
		// A :status is exactly three digits; cap the loop so a hostile upstream's
		// long digit run cannot overflow the int accumulator (undefined behaviour).
		for(size_t i = 0; i < v.len && i < 3 && v.base[i] >= '0' && v.base[i] <= '9'; i++)
			s = s * 10 + (v.base[i] - '0');
		c->x.status = s;
	}
	return 0;
}

// Collect response DATA into the answer buffer. Overrunning the bounded buffer is
// a hard failure (fail closed): flag it and abort the read so the exchange -1s.
static int quic_cb_recv_data(nghttp3_conn *h3, int64_t stream_id,
                             const uint8_t *data, size_t datalen,
                             void *conn_user_data, void *stream_user_data)
{
	(void)h3; (void)stream_user_data;
	struct quic_client_conn *c = conn_user_data;
	if(stream_id != c->x.req_sid)
		return 0;
	if(datalen > c->x.answer_sz - c->x.answer_len)
	{
		c->x.overflow = true;
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}
	memcpy(c->x.answer + c->x.answer_len, data, datalen);
	c->x.answer_len += datalen;
	return 0;
}

// The request stream closed: a non-zero application error code means it was reset
// rather than completed cleanly.
static int quic_cb_stream_close(nghttp3_conn *h3, int64_t stream_id,
                                uint64_t app_error_code, void *conn_user_data,
                                void *stream_user_data)
{
	(void)h3; (void)stream_user_data;
	struct quic_client_conn *c = conn_user_data;
	if(stream_id != c->x.req_sid)
		return 0;
	c->x.done = true;
	if(app_error_code != 0)
		c->x.failed = true;
	return 0;
}

static const nghttp3_callbacks quic_callbacks = {
	.stream_close = quic_cb_stream_close,
	.recv_data    = quic_cb_recv_data,
	.recv_header  = quic_cb_recv_header,
};

// Fill one nghttp3_nv from NUL-terminated name/value strings.
static nghttp3_nv quic_nv(const char *name, const char *value)
{
	nghttp3_nv nv;
	nv.name = (const uint8_t *)name;
	nv.value = (const uint8_t *)value;
	nv.namelen = strlen(name);
	nv.valuelen = strlen(value);
	nv.flags = NGHTTP3_NV_FLAG_NONE;
	return nv;
}

// Read all currently available bytes from a readable stream and feed them to
// nghttp3. Returns 0 normally, -1 on a fatal nghttp3 error.
static int stream_pump_read(struct quic_client_conn *c, struct qstream *s)
{
	uint8_t buf[16384];
	for(;;)
	{
		size_t nread = 0;
		const int r = SSL_read_ex(s->ssl, buf, sizeof(buf), &nread);
		if(r == 1 && nread > 0)
		{
			if(nghttp3_conn_read_stream2(c->h3, s->id, buf, nread, 0, h3_now()) < 0)
				return -1;
			continue;
		}
		const int err = SSL_get_error(s->ssl, r);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0;
		if(err == SSL_ERROR_ZERO_RETURN)
		{
			// Clean end of the receiving side: feed FIN to nghttp3 only for a
			// graceful finish; a reset just stops reads.
			s->read_done = true;
			if(SSL_get_stream_read_state(s->ssl) == SSL_STREAM_STATE_FINISHED)
			{
				if(nghttp3_conn_read_stream2(c->h3, s->id, NULL, 0, 1, h3_now()) < 0)
					return -1;
				// Tell nghttp3 the QUIC stream has closed so it runs the
				// stream_close callback - which is what completes the exchange.
				// nghttp3 does not derive that from the FIN alone, so without this
				// a fully received response never finishes and the exchange times
				// out. Our bidi request stream's send side is already concluded.
				if(nghttp3_conn_close_stream(c->h3, s->id, 0) < 0)
					return -1;
			}
			else if(s->id == c->x.req_sid)
				// Receive side ended without a clean FIN: fail the exchange now
				// instead of spinning to the deadline.
				c->x.done = c->x.failed = true;
			return 0;
		}
		// Reset or connection-level error: stop reading this stream. If it is the
		// request stream, fail the exchange promptly rather than waiting out the
		// deadline (a hostile/buggy upstream reset would otherwise pin the worker).
		s->read_done = true;
		if(s->id == c->x.req_sid)
			c->x.done = c->x.failed = true;
		return 0;
	}
}

// Drain nghttp3's pending stream writes to the QUIC streams. Returns 0 or -1.
static int conn_pump_write(struct quic_client_conn *c)
{
	for(;;)
	{
		nghttp3_vec vec[16];
		int64_t sid = -1;
		int fin = 0;
		const nghttp3_ssize n = nghttp3_conn_writev_stream(c->h3, &sid, &fin, vec, 16);
		if(n < 0)
			return -1;
		if(n == 0 && sid == -1)
			break; // nothing more to write right now

		struct qstream *s = find_stream(c, sid);
		if(s == NULL)
		{
			// Unknown stream: acknowledge zero progress and stop for now.
			nghttp3_conn_add_write_offset(c->h3, sid, 0);
			break;
		}

		size_t total = 0;
		bool blocked = false;
		for(nghttp3_ssize i = 0; i < n && !blocked; i++)
		{
			size_t off = 0;
			while(off < vec[i].len)
			{
				size_t written = 0;
				const int r = SSL_write_ex(s->ssl, vec[i].base + off,
				                           vec[i].len - off, &written);
				if(r == 1)
				{
					off += written;
					total += written;
				}
				else
				{
					const int err = SSL_get_error(s->ssl, r);
					if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
						return -1; // fatal (e.g. STOP_SENDING / conn error): fail fast
					// Stream send buffer full / not yet writable: retry later.
					blocked = true;
					break;
				}
			}
		}

		if(nghttp3_conn_add_write_offset(c->h3, sid, total) != 0)
			return -1;
		// OpenSSL owns retransmission once bytes are accepted, so nghttp3 may
		// release its copy immediately.
		if(total > 0 && nghttp3_conn_add_ack_offset(c->h3, sid, total) != 0)
			return -1;

		if(fin && !blocked)
			SSL_stream_conclude(s->ssl, 0); // send FIN once all data is flushed
		if(blocked)
			break;
	}
	return 0;
}

// Accept any server-initiated streams (its control + QPACK streams) into the
// table so their bytes can be fed to nghttp3.
static void conn_accept_streams(struct quic_client_conn *c)
{
	for(;;)
	{
		SSL *st = SSL_accept_stream(c->ssl, SSL_ACCEPT_STREAM_NO_BLOCK);
		if(st == NULL)
			break;
		if(!add_stream(c, st, false))
		{
			SSL_free(st);
			break;
		}
	}
}

// Tear down the HTTP/3 session, every stream object and the QUIC connection.
static void conn_teardown(struct quic_client_conn *c)
{
	if(c->ssl != NULL)
		// Best-effort immediate close so the server does not wait on us; do not
		// block the worker flushing it.
		SSL_shutdown_ex(c->ssl, SSL_SHUTDOWN_FLAG_RAPID | SSL_SHUTDOWN_FLAG_NO_BLOCK,
		                NULL, 0);
	if(c->h3 != NULL)
		nghttp3_conn_del(c->h3);
	for(int i = 0; i < c->nstreams; i++)
		if(c->streams[i].ssl != NULL)
			SSL_free(c->streams[i].ssl);
	if(c->ssl != NULL)
		SSL_free(c->ssl); // frees the datagram BIO and closes the UDP fd
}

// Set up nghttp3 and the mandatory local control / QPACK streams on a freshly
// handshaked QUIC connection. Returns true on success.
static bool conn_setup_h3(struct quic_client_conn *c)
{
	nghttp3_settings settings;
	nghttp3_settings_default(&settings);
	if(nghttp3_conn_client_new(&c->h3, &quic_callbacks, &settings, NULL, c) != 0)
		return false;

	SSL *ctrl = SSL_new_stream(c->ssl, SSL_STREAM_FLAG_UNI);
	SSL *qenc = SSL_new_stream(c->ssl, SSL_STREAM_FLAG_UNI);
	SSL *qdec = SSL_new_stream(c->ssl, SSL_STREAM_FLAG_UNI);
	if(ctrl == NULL || qenc == NULL || qdec == NULL)
	{
		if(ctrl != NULL) SSL_free(ctrl);
		if(qenc != NULL) SSL_free(qenc);
		if(qdec != NULL) SSL_free(qdec);
		return false;
	}
	if(!add_stream(c, ctrl, true) || !add_stream(c, qenc, true) || !add_stream(c, qdec, true))
		return false; // objects are now owned by the table, freed in teardown

	const int64_t cid = c->streams[0].id, eid = c->streams[1].id, did = c->streams[2].id;
	if(nghttp3_conn_bind_control_stream(c->h3, cid) != 0 ||
	   nghttp3_conn_bind_qpack_streams(c->h3, eid, did) != 0)
		return false;
	return true;
}

// Open the request stream and submit the DoH POST. Returns true on success.
static bool conn_submit_request(struct quic_client_conn *c, const struct upstream_uri *u,
                                const uint8_t *query, size_t qlen,
                                uint8_t *answer, size_t answer_sz)
{
	SSL *req = SSL_new_stream(c->ssl, 0); // client-initiated bidirectional
	if(req == NULL)
		return false;
	if(!add_stream(c, req, false))
	{
		SSL_free(req);
		return false;
	}
	const int64_t sid = (int64_t)SSL_get_stream_id(req);

	c->x.req_sid = sid;
	c->x.query = query;
	c->x.qlen = qlen;
	c->x.answer = answer;
	c->x.answer_sz = answer_sz;

	// An IPv6-literal authority must be bracketed; a hostname never contains ':'.
	char authority[UURI_HOST_MAX + 2];
	if(strchr(u->verify_name, ':') != NULL)
		snprintf(authority, sizeof(authority), "[%s]", u->verify_name);
	else
		snprintf(authority, sizeof(authority), "%s", u->verify_name);

	char clen[16];
	snprintf(clen, sizeof(clen), "%zu", qlen);

	// RFC 8484: POST the DNS wire message with media type application/dns-message.
	const nghttp3_nv nva[] = {
		quic_nv(":method", "POST"),
		quic_nv(":scheme", "https"),
		quic_nv(":authority", authority),
		quic_nv(":path", u->doh_path),
		quic_nv("content-type", "application/dns-message"),
		quic_nv("accept", "application/dns-message"),
		quic_nv("content-length", clen),
	};
	const nghttp3_data_reader dr = { quic_req_read };
	return nghttp3_conn_submit_request(c->h3, sid, nva, sizeof(nva) / sizeof(nva[0]),
	                                   &dr, c) == 0;
}

ssize_t quic_pool_exchange(struct quic_pool *p, const uint8_t *query, size_t qlen,
                           uint8_t *answer, size_t answer_sz)
{
	SSL_CTX *qctx = quic_client_ctx();
	if(qctx == NULL || p == NULL || query == NULL || answer == NULL)
		return -1;
	if(qlen == 0 || qlen > DNS_MSG_MAX)
		return -1;

	const struct upstream_uri *u = &p->u;
	const uint64_t deadline = quic_now_ms() + QUIC_EXCHANGE_TIMEOUT_MS;

	// 1. Connected, non-blocking UDP socket to the upstream.
	int fd = -1;
	BIO_ADDR *peer = NULL;
	if(!quic_udp_connect(u->connect_host, u->port, deadline, &fd, &peer))
	{
		log_warn("dotdoh: DoH3 connect to %s#%d failed", u->connect_host, u->port);
		return -1;
	}

	// 2. QUIC connection object over that socket.
	struct quic_client_conn c;
	memset(&c, 0, sizeof(c));
	c.ssl = SSL_new(qctx);
	BIO *bio = c.ssl != NULL ? BIO_new_dgram(fd, BIO_CLOSE) : NULL;
	if(c.ssl == NULL || bio == NULL)
	{
		// SSL_set_bio() has not run, so the SSL does not own the fd: a BIO (BIO_CLOSE)
		// closes it on BIO_free(), else close it directly; SSL_free() alone leaks it.
		if(bio != NULL)
			BIO_free(bio);
		else
			close(fd);
		if(c.ssl != NULL)
			SSL_free(c.ssl);
		BIO_ADDR_free(peer);
		return -1;
	}
	SSL_set_bio(c.ssl, bio, bio); // SSL owns the BIO (and the fd via BIO_CLOSE)

	// ALPN "h3" (opts into HTTP/3), the initial peer address, non-blocking mode
	// and manual stream control - we accept and drive every stream by hand.
	static const unsigned char alpn_h3[] = { 2, 'h', '3' };
	SSL_set_alpn_protos(c.ssl, alpn_h3, sizeof(alpn_h3));
	SSL_set1_initial_peer_addr(c.ssl, peer);
	BIO_ADDR_free(peer);
	SSL_set_blocking_mode(c.ssl, 0);
	SSL_set_default_stream_mode(c.ssl, SSL_DEFAULT_STREAM_MODE_NONE);

	// Bind the certificate verification name; a failed set is fatal (fail-closed).
	const bool vok = quic_bind_verify_name(c.ssl, u->verify_name);

	ssize_t rv = -1;
	bool connected = false;

	// 3. Handshake (fail-closed: bad chain/hostname aborts here).
	if(vok && quic_do_handshake(c.ssl, fd, deadline))
	{
		connected = true;
		// 4. HTTP/3 session + control/QPACK streams, then submit the request.
		if(conn_setup_h3(&c) &&
		   conn_submit_request(&c, u, query, qlen, answer, answer_sz))
		{
			// 5. Drive the exchange until the request stream closes or we run out
			// of time.
			for(;;)
			{
				if(conn_pump_write(&c) < 0)
					break;
				SSL_handle_events(c.ssl);
				conn_accept_streams(&c);
				bool read_err = false;
				for(int i = 0; i < c.nstreams; i++)
				{
					struct qstream *s = &c.streams[i];
					if(s->local_uni || s->read_done)
						continue;
					if(stream_pump_read(&c, s) < 0)
					{
						read_err = true;
						break;
					}
				}
				if(read_err)
					break;
				// Reading may have produced control/QPACK output (and acks); flush.
				if(conn_pump_write(&c) < 0)
					break;
				SSL_handle_events(c.ssl);
				if(c.x.done)
					break;
				if(quic_now_ms() >= deadline)
					break;
				quic_wait(c.ssl, fd, deadline);
			}

			// A cleanly closed request stream carrying a 200 with a non-empty body
			// is the only success; anything else fails closed.
			if(c.x.done && !c.x.failed && !c.x.overflow &&
			   c.x.status == 200 && c.x.answer_len > 0)
				rv = (ssize_t)c.x.answer_len;
		}
	}

	// 6. Accounting + teardown.
	pthread_mutex_lock(&p->lock);
	if(connected)
	{
		p->stats.conns_opened++;
		p->stats.handshakes_fresh_cold++; // QUIC exchange = one fresh connection
		p->stats.sessions_closed++;
		p->stats.queries_per_session_sum += (rv >= 0) ? 1u : 0u;
		if(rv >= 0 && p->stats.queries_per_session_max < 1)
			p->stats.queries_per_session_max = 1;
	}
	if(rv >= 0)
		p->stats.queries_total++;
	pthread_mutex_unlock(&p->lock);

	conn_teardown(&c);
	return rv;
}

void quic_pool_get_stats(struct quic_pool *p, struct dotdoh_stats *out)
{
	if(p == NULL || out == NULL)
		return;
	pthread_mutex_lock(&p->lock);
	*out = p->stats;
	pthread_mutex_unlock(&p->lock);
}

#else // no QUIC / HTTP3 support in this build

// Without OpenSSL QUIC + nghttp3 there is no DoH3 transport: the pool cannot be
// created and every exchange fails closed (the config layer refuses an h3://
// upstream when quic_pool_new() returns NULL). These trivial stubs are const-
// folding candidates, so silence the GCC-only -Wsuggest-attribute suggestions.
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
