/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound TLS client for encrypted upstreams (DoT/DoH)
*
*  Talks TLS to the real upstream resolver. Verification is REQUIRED (chain +
*  hostname): a failed check aborts the handshake, so the path is fail-closed by
*  construction. The caller then gets -1 and drops the query, and FTL fails over
*  to the next server - we never downgrade to plaintext.
*
*  Each upstream owns a connection pool: a bounded, thread-safe set of keep-alive
*  connections that many worker threads borrow concurrently, with TLS 1.3 session
*  resumption so a rebuilt connection skips the full handshake. There is no
*  proactive refresh - a DoT server closes idle connections on its own schedule
*  and we simply resume-on-demand, skipping connections we can tell are already
*  dead (idle longer than the learned per-upstream idle window).
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "tls_client.h"

#ifdef HAVE_TLS

#include "framing.h"
#ifdef HAVE_HTTP2
// DoH: an https:// upstream that negotiates "h2" via ALPN is driven by nghttp2.
#include <nghttp2/nghttp2.h>
#endif
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
// For the bounded, non-blocking connect and the socket-level send timeout below.
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

// Timeout (ms) for the TCP connect, plus an overall wall-clock budget for the
// whole exchange. The per-op read timeout above only bounds an idle peer; these
// hard deadlines also bound a black-holed connect, a full receive window, or a
// peer trickling one byte per idle window, so one bad upstream cannot pin a worker.
#define TLS_CONNECT_TIMEOUT_MS 5000
#define TLS_EXCHANGE_TIMEOUT_MS 10000

// Learned per-upstream idle window (ms): how long a pooled connection may sit
// idle before we assume the server closed it and rebuild via resumption. Seeded
// from measured values (see seed_idle_ms), adapted at runtime, clamped to
// [MIN, MAX] with a slack band for hysteresis.
#define IDLE_SEED_DOT_MS   10000
#define IDLE_SEED_DOH_MS   30000
#define IDLE_MIN_MS         2000
#define IDLE_MAX_MS       120000
#define IDLE_SLACK_MS       1000

// Where to look for trust anchors when no explicit CA path is set. Distributions
// place the bundle differently, so try the common single-file locations then the
// hashed directory. FTL's musl binary runs on any of these, so not Debian-only.
static const char *const TLS_DEFAULT_CA_FILES[] = {
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine, Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL, Fedora, CentOS
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // Alpine, *BSD, macOS
};
#define TLS_DEFAULT_CA_DIR  "/etc/ssl/certs"

// Shared, read-only-after-init crypto state: one SSL_CTX carries the trust store,
// fail-closed verify mode and client session cache for all upstreams; each
// connection draws its own SSL from it. OpenSSL seeds its own RNG, no DRBG here.
static bool g_ready = false;
static SSL_CTX *g_ctx = NULL;
// ex_data slot carrying the owning pool pointer on each SSL, so the new-session
// callback can file a fresh ticket back into the right pool.
static int g_pool_ex_idx = -1;

// One pooled connection. The scratch buffers live here (not on the stack and not
// shared) so that concurrent exchanges on different connections never clobber
// each other. Borrowed exclusively by one worker between borrow and return, so
// nothing here needs its own lock.
struct tls_conn {
	bool connected;
	bool in_use;
	int fd;                                         // connected TCP socket
	SSL *ssl;
	uint64_t last_used_ms;                          // when last returned to the pool
	uint64_t borrowed_idle_ms;                      // idle age at the current borrow
	unsigned queries_served;                        // exchanges on this connection
	uint8_t req[DNS_MSG_MAX + 512];                 // framed request we send
	uint8_t rbuf[DNS_MSG_MAX + DOH_HEADER_MAX];     // response accumulation buffer
#ifdef HAVE_HTTP2
	bool is_h2;                                     // ALPN negotiated "h2" (DoH only)
	nghttp2_session *h2;                            // persistent client session, lazy
#endif
};

// Per-upstream pool: a bounded set of connections plus the shared resumption
// ticket, the learned idle window and the diagnostic counters. The lock guards
// every field except u/max (immutable after creation).
struct tls_pool {
	struct upstream_uri u;         // upstream descriptor (immutable)
	int max;                       // connection cap (immutable)
	pthread_mutex_t lock;
	pthread_cond_t cond;           // signalled when a slot frees
	struct tls_conn **slots;       // max entries; NULL = empty slot
	int nconns;                    // non-NULL slots (open or connecting)
	SSL_SESSION *sess;             // newest resumption ticket, or NULL
	uint64_t idle_est_ms;          // learned idle window
	struct dotdoh_stats stats;
};

enum hs_outcome { HS_RESUMED, HS_FRESH_COLD, HS_FULL_FALLBACK };

// Monotonic clock in milliseconds, for deadlines and idle ages.
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// Milliseconds left until deadline, clamped to [0, cap].
static int ms_left(uint64_t deadline, int cap)
{
	const uint64_t n = now_ms();
	if(n >= deadline)
		return 0;
	const uint64_t left = deadline - n;
	return left < (uint64_t)cap ? (int)left : cap;
}

// Capture a fresh TLS 1.3 ticket into the owning pool so the next (re)connect can
// resume. Returns 1 to take ownership of sess (OpenSSL keeps our stored ref).
static int new_session_cb(SSL *ssl, SSL_SESSION *sess)
{
	struct tls_pool *p = SSL_get_ex_data(ssl, g_pool_ex_idx);
	if(p == NULL)
		return 0; // not ours to keep; let OpenSSL free it
	pthread_mutex_lock(&p->lock);
	if(p->sess != NULL)
		SSL_SESSION_free(p->sess);
	p->sess = sess;
	pthread_mutex_unlock(&p->lock);
	return 1;
}

bool tls_client_global_init(const char *ca_file)
{
	// Idempotent: the proxy may be (re)started, but the context only needs to
	// be built once.
	if(g_ready)
		return true;

	g_ctx = SSL_CTX_new(TLS_client_method());
	if(g_ctx == NULL)
	{
		log_err("dotdoh: SSL_CTX_new() failed");
		return false;
	}

	// Require at least TLS 1.2 for encrypted DNS upstreams.
	SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);

	// Enforce forward secrecy on the TLS 1.2 leg: OpenSSL's default list still
	// offers static-RSA suites with no PFS, so a passive recorder who later obtains
	// the key could decrypt a captured session. Restrict TLS 1.2 to ECDHE; TLS 1.3
	// (the primary path) is forward-secret by definition and unaffected.
	if(SSL_CTX_set_cipher_list(g_ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES") != 1)
	{
		log_err("dotdoh: SSL_CTX_set_cipher_list() failed");
		SSL_CTX_free(g_ctx);
		g_ctx = NULL;
		return false;
	}

	// This is the fail-closed heart of the client: SSL_VERIFY_PEER makes a bad
	// chain abort the handshake instead of merely being reported after the
	// fact. The hostname is checked per-connection via SSL_set1_host() below.
	SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, NULL);

	// Client-side session cache for TLS 1.3 resumption: we file tickets into the
	// owning pool from new_session_cb and re-apply them per (re)connect, so no
	// internal store is needed.
	SSL_CTX_set_session_cache_mode(g_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(g_ctx, new_session_cb);
	if(g_pool_ex_idx < 0)
		g_pool_ex_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	// Load the trust anchors. An explicit path (dns.upstreamCA, or the test CA
	// during E2E) always wins. Otherwise try each well-known system bundle and
	// finally the hashed directory.
	int loaded = 0;
	if(ca_file != NULL && ca_file[0] != '\0')
		loaded = SSL_CTX_load_verify_file(g_ctx, ca_file) == 1;
	else
	{
		for(size_t i = 0; !loaded && i < sizeof(TLS_DEFAULT_CA_FILES) / sizeof(*TLS_DEFAULT_CA_FILES); i++)
			loaded = SSL_CTX_load_verify_file(g_ctx, TLS_DEFAULT_CA_FILES[i]) == 1;
		if(!loaded)
			loaded = SSL_CTX_load_verify_dir(g_ctx, TLS_DEFAULT_CA_DIR) == 1;
	}
	if(!loaded)
	{
		log_err("dotdoh: could not load a CA trust store "
		        "(set dns.upstreamCA or install a system CA bundle)");
		SSL_CTX_free(g_ctx);
		g_ctx = NULL;
		return false;
	}

	g_ready = true;
	return true;
}

void tls_client_global_free(void)
{
	if(!g_ready)
		return;
	SSL_CTX_free(g_ctx);
	g_ctx = NULL;
	g_ready = false;
}

// Bounded, non-blocking TCP connect returning a connected socket in *out_fd. A
// blocking connect() has no timeout, so a black-holed upstream would pin the
// worker for the kernel's full SYN timeout (~2 min); connect non-blocking and
// poll() for the deadline. The socket stays non-blocking for the OpenSSL I/O.
static int net_connect_timeout(int *out_fd, const char *host,
                               const char *port, int timeout_ms)
{
	struct addrinfo hints = { 0 };
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *res = NULL;
	if(getaddrinfo(host, port, &hints, &res) != 0)
		return -1;

	// timeout_ms is the budget for the whole connect, not per address: share
	// the remaining time across every A/AAAA record rather than restarting the
	// full timeout for each, so a multi-homed host cannot blow the deadline.
	const uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

	int ret = -1;
	for(struct addrinfo *cur = res; cur != NULL; cur = cur->ai_next)
	{
		// SOCK_CLOEXEC so a connected upstream socket is not inherited across
		// FTL's execvp() self-restart.
		const int fd = socket(cur->ai_family, cur->ai_socktype | SOCK_CLOEXEC, cur->ai_protocol);
		if(fd < 0)
			continue;

		// Non-blocking connect, then wait for writability within the deadline.
		const int flags = fcntl(fd, F_GETFL, 0);
		if(flags < 0)
		{
			close(fd);
			continue;
		}
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);

		struct pollfd pfd = { .fd = fd, .events = POLLOUT };
		int soerr = 0;
		socklen_t sl = sizeof(soerr);
		if((connect(fd, cur->ai_addr, cur->ai_addrlen) == 0 || errno == EINPROGRESS) &&
		   poll(&pfd, 1, ms_left(deadline, timeout_ms)) == 1 && (pfd.revents & POLLOUT) &&
		   getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0)
		{
			// Leave the socket non-blocking: the handshake and exchange are driven
			// by poll() against a deadline (ssl_io_wait), which a fixed SO_RCVTIMEO
			// cannot bound against a peer that trickles bytes below the timeout.
			*out_fd = fd;
			ret = 0;
			break;
		}
		close(fd);
	}

	freeaddrinfo(res);
	return ret;
}

// Wait, bounded by the deadline, for the fd to be ready for the I/O OpenSSL asked
// for. On a non-blocking socket SSL_* returns WANT_READ/WANT_WRITE as soon as it
// would block, so polling here is what actually caps total handshake/exchange
// wall-clock - a fixed SO_RCVTIMEO only bounds one idle read(), not a slow drip.
// Returns false on timeout, deadline reached, or poll error (all fail-closed).
static bool ssl_io_wait(int fd, int ssl_err, uint64_t deadline)
{
	const uint64_t now = now_ms();
	if(now >= deadline)
		return false;
	struct pollfd pfd = { .fd = fd,
	                      .events = (ssl_err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN };
	return poll(&pfd, 1, (int)(deadline - now)) == 1;
}

// Free the OpenSSL/socket objects of a connection that is being discarded. Does
// not touch pool bookkeeping.
static void conn_teardown(struct tls_conn *c)
{
#ifdef HAVE_HTTP2
	if(c->h2 != NULL)
	{
		nghttp2_session_del(c->h2);
		c->h2 = NULL;
	}
#endif
	if(c->ssl != NULL)
	{
		if(c->connected)
		{
			// Runs under the pool lock, so a blocking close_notify to a stalled
			// upstream would freeze the pool - and it buys nothing on a connection
			// we are discarding. Shut down quietly (no I/O); the TCP close signals
			// the end.
			SSL_set_quiet_shutdown(c->ssl, 1);
			SSL_shutdown(c->ssl);
		}
		SSL_free(c->ssl);
		c->ssl = NULL;
	}
	if(c->fd >= 0)
	{
		close(c->fd);
		c->fd = -1;
	}
	c->connected = false;
}

// Open a TCP connection and drive the TLS handshake to the pool's upstream,
// applying any stored resumption ticket. Returns true once verified and ready
// and reports the handshake outcome in *outcome. deadline bounds connect +
// handshake so a stalled peer cannot pin the worker.
static bool conn_connect(struct tls_pool *p, struct tls_conn *c,
                         uint64_t deadline, enum hs_outcome *outcome)
{
	const struct upstream_uri *u = &p->u;
	c->fd = -1;
	c->ssl = NULL;
	*outcome = HS_FRESH_COLD;

	char portstr[8];
	snprintf(portstr, sizeof(portstr), "%d", u->port);

	if(net_connect_timeout(&c->fd, u->connect_host, portstr,
	                       ms_left(deadline, TLS_CONNECT_TIMEOUT_MS)) != 0)
	{
		log_warn("dotdoh: connect to %s#%d failed", u->connect_host, u->port);
		goto fail;
	}

	c->ssl = SSL_new(g_ctx);
	if(c->ssl == NULL)
		goto fail;

	// Tie the SSL to its pool so new_session_cb can file tickets back.
	SSL_set_ex_data(c->ssl, g_pool_ex_idx, p);

	// Apply the newest stored ticket for this upstream, if any. SSL_set_session
	// takes its own ref, so we drop ours right after.
	bool tried_resume = false;
	pthread_mutex_lock(&p->lock);
	SSL_SESSION *s = p->sess;
	if(s != NULL)
		SSL_SESSION_up_ref(s);
	pthread_mutex_unlock(&p->lock);
	if(s != NULL)
	{
		SSL_set_session(c->ssl, s);
		SSL_SESSION_free(s);
		tried_resume = true;
	}

	// verify_name is what the cert is checked against and, for a hostname, the SNI.
	// A bare-IP upstream is verified against iPAddress SANs instead (host matching
	// only covers dNSName/CN) and RFC 6066 forbids an IP literal as SNI. Both bind
	// the check to the SSL's verify param (SSL_set1_host() is deprecated in 4.0).
	struct in_addr v4;
	struct in6_addr v6;
	if(inet_pton(AF_INET, u->verify_name, &v4) == 1 ||
	   inet_pton(AF_INET6, u->verify_name, &v6) == 1)
	{
		if(X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(c->ssl), u->verify_name) != 1)
			goto fail;
	}
	else
	{
		if(X509_VERIFY_PARAM_set1_host(SSL_get0_param(c->ssl), u->verify_name, 0) != 1)
			goto fail;
		SSL_set_tlsext_host_name(c->ssl, u->verify_name);
	}

	if(SSL_set_fd(c->ssl, c->fd) != 1)
		goto fail;

#ifdef HAVE_HTTP2
	// DoH offers "h2" then "http/1.1" and lets the server choose; if h2 is not
	// selected we fall back to HTTP/1.1 framing. DoT does not use ALPN.
	if(u->type == UST_DOH)
	{
		static const unsigned char alpn[] =
			{ 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
		SSL_set_alpn_protos(c->ssl, alpn, sizeof(alpn));
	}
#endif

	// Non-blocking handshake: SSL_connect yields WANT_READ/WANT_WRITE and we poll
	// with the remaining budget, so a slow-drip peer cannot outlast the deadline.
	// A verification failure returns a hard error here - fail-closed.
	int rc;
	while((rc = SSL_connect(c->ssl)) != 1)
	{
		const int err = SSL_get_error(c->ssl, rc);
		if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
		{
			log_warn("dotdoh: TLS handshake with %s (%s#%d) failed",
			         u->verify_name, u->connect_host, u->port);
			goto fail;
		}
		if(!ssl_io_wait(c->fd, err, deadline))
		{
			log_warn("dotdoh: TLS handshake with %s (%s#%d) timed out",
			         u->verify_name, u->connect_host, u->port);
			goto fail;
		}
	}

#ifdef HAVE_HTTP2
	// Record the negotiated protocol; the nghttp2 session is created lazily in conn_do_h2().
	c->is_h2 = false;
	if(u->type == UST_DOH)
	{
		const unsigned char *proto = NULL;
		unsigned int plen = 0;
		SSL_get0_alpn_selected(c->ssl, &proto, &plen);
		if(proto != NULL && plen == 2 && memcmp(proto, "h2", 2) == 0)
			c->is_h2 = true;
	}
#endif

	*outcome = SSL_session_reused(c->ssl) ? HS_RESUMED
	         : (tried_resume ? HS_FULL_FALLBACK : HS_FRESH_COLD);
	c->connected = true;
	return true;

fail:
	conn_teardown(c);
	return false;
}

// Write the whole buffer, tolerating short writes and transient
// WANT_READ/WANT_WRITE conditions. Returns true once everything is sent.
static bool ssl_write_all(struct tls_conn *c, const uint8_t *buf, size_t len, uint64_t deadline)
{
	size_t off = 0;
	while(off < len)
	{
		const int w = SSL_write(c->ssl, buf + off, (int)(len - off));
		if(w > 0)
		{
			off += (size_t)w;
			continue;
		}
		const int err = SSL_get_error(c->ssl, w);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		{
			if(!ssl_io_wait(c->fd, err, deadline))
				return false;
			continue;
		}
		return false;
	}
	return true;
}

#ifdef HAVE_HTTP2
// --- DoH over HTTP/2 (nghttp2) ---------------------------------------------
//
// Driven when an https:// upstream selected "h2" via ALPN. The pool serialises
// exchanges, so one request stream is in flight at a time; the nghttp2 session
// persists across exchanges (preface sent once). Any error maps to -1 so the
// caller tears down the connection and fails over.

// Per-exchange state, on the worker stack for the duration of conn_do_h2().
// Reached from the nghttp2 callbacks via the stream user data.
struct h2_xfer {
	const uint8_t *query;   // request body (the padded DNS query)
	size_t qlen;            // request body length
	size_t qoff;            // bytes already pulled by the data provider
	uint8_t *answer;        // caller's answer buffer
	size_t answer_sz;       // its capacity
	size_t answer_len;      // response body bytes collected so far
	int status;             // parsed :status (0 until seen)
	bool overflow;          // response body exceeded answer_sz
	bool closed;            // stream has closed
	bool failed;            // stream closed with an error (RST/GOAWAY)
};

// nghttp2 data provider: hand the padded DNS query to nghttp2 as the POST body.
static nghttp2_ssize h2_req_read(nghttp2_session *session, int32_t stream_id,
                                 uint8_t *buf, size_t length, uint32_t *data_flags,
                                 nghttp2_data_source *source, void *user_data)
{
	(void)session; (void)stream_id; (void)user_data;
	struct h2_xfer *x = source->ptr;
	const size_t avail = x->qlen - x->qoff;
	const size_t n = avail < length ? avail : length;
	if(n > 0)
	{
		memcpy(buf, x->query + x->qoff, n);
		x->qoff += n;
	}
	if(x->qoff >= x->qlen)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	return (nghttp2_ssize)n;
}

// Capture the :status pseudo-header of the response.
static int h2_on_header(nghttp2_session *session, const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen,
                        uint8_t flags, void *user_data)
{
	(void)flags; (void)user_data;
	if(frame->hd.type != NGHTTP2_HEADERS)
		return 0;
	struct h2_xfer *x = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
	if(x == NULL)
		return 0;
	if(namelen == 7 && memcmp(name, ":status", 7) == 0)
	{
		int s = 0;
		// A :status is exactly three digits; cap the loop so a hostile upstream's
		// long digit run cannot overflow the int accumulator (undefined behaviour).
		for(size_t i = 0; i < valuelen && i < 3 && value[i] >= '0' && value[i] <= '9'; i++)
			s = s * 10 + (value[i] - '0');
		x->status = s;
	}
	return 0;
}

// Collect response DATA into the answer buffer. Overrunning the bounded buffer
// is a hard failure (fail closed): abort the session so the exchange returns -1.
static int h2_on_data_chunk(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                            const uint8_t *data, size_t len, void *user_data)
{
	(void)flags; (void)user_data;
	struct h2_xfer *x = nghttp2_session_get_stream_user_data(session, stream_id);
	if(x == NULL)
		return 0;
	if(len > x->answer_sz - x->answer_len)
	{
		x->overflow = true;
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	memcpy(x->answer + x->answer_len, data, len);
	x->answer_len += len;
	return 0;
}

// Mark the stream done; a non-zero error code means it was reset, not completed.
static int h2_on_stream_close(nghttp2_session *session, int32_t stream_id,
                              uint32_t error_code, void *user_data)
{
	(void)user_data;
	struct h2_xfer *x = nghttp2_session_get_stream_user_data(session, stream_id);
	if(x == NULL)
		return 0;
	x->closed = true;
	if(error_code != NGHTTP2_NO_ERROR)
		x->failed = true;
	return 0;
}

// Create the persistent nghttp2 client session on first use and queue the
// connection preface (SETTINGS). Returns true once c->h2 is ready.
static bool h2_session_init(struct tls_conn *c)
{
	if(c->h2 != NULL)
		return true;

	nghttp2_session_callbacks *cbs = NULL;
	if(nghttp2_session_callbacks_new(&cbs) != 0)
		return false;
	nghttp2_session_callbacks_set_on_header_callback(cbs, h2_on_header);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, h2_on_data_chunk);
	nghttp2_session_callbacks_set_on_stream_close_callback(cbs, h2_on_stream_close);
	const int rv = nghttp2_session_client_new(&c->h2, cbs, c);
	nghttp2_session_callbacks_del(cbs);
	if(rv != 0)
	{
		c->h2 = NULL;
		return false;
	}
	// The connection preface is the 24-byte magic (auto-emitted) plus a SETTINGS
	// frame we submit; an empty SETTINGS is valid. Flushed with the first request.
	if(nghttp2_submit_settings(c->h2, NGHTTP2_FLAG_NONE, NULL, 0) != 0)
	{
		nghttp2_session_del(c->h2);
		c->h2 = NULL;
		return false;
	}
	return true;
}

// Flush all frames nghttp2 has queued to the TLS connection.
static bool h2_send(struct tls_conn *c, uint64_t deadline)
{
	for(;;)
	{
		const uint8_t *data = NULL;
		const nghttp2_ssize n = nghttp2_session_mem_send2(c->h2, &data);
		if(n < 0)
			return false;
		if(n == 0)
			return true;
		if(!ssl_write_all(c, data, (size_t)n, deadline))
			return false;
	}
}

// Fill one nghttp2_nv from NUL-terminated name/value strings.
static nghttp2_nv h2_nv(const char *name, const char *value)
{
	nghttp2_nv nv;
	nv.name = (uint8_t *)name;
	nv.namelen = strlen(name);
	nv.value = (uint8_t *)value;
	nv.valuelen = strlen(value);
	nv.flags = NGHTTP2_NV_FLAG_NONE;
	return nv;
}

// Perform one DoH exchange over HTTP/2 on an established, h2-negotiated
// connection. Returns the answer length, or -1 on any error.
static ssize_t conn_do_h2(struct tls_conn *c, const struct upstream_uri *u,
                          const uint8_t *query, size_t qlen,
                          uint8_t *answer, size_t answer_sz, uint64_t deadline)
{
	if(qlen == 0 || qlen > DNS_MSG_MAX)
		return -1;
	if(!h2_session_init(c))
		return -1;

	struct h2_xfer x = { .query = query, .qlen = qlen,
	                     .answer = answer, .answer_sz = answer_sz };

	// An IPv6-literal authority must be bracketed; a hostname never contains ':'.
	char authority[UURI_HOST_MAX + 2];
	if(strchr(u->verify_name, ':') != NULL)
		snprintf(authority, sizeof(authority), "[%s]", u->verify_name);
	else
		snprintf(authority, sizeof(authority), "%s", u->verify_name);

	char clen[16];
	snprintf(clen, sizeof(clen), "%zu", qlen);

	// RFC 8484: POST the DNS wire message with media type application/dns-message.
	const nghttp2_nv nva[] = {
		h2_nv(":method", "POST"),
		h2_nv(":scheme", "https"),
		h2_nv(":authority", authority),
		h2_nv(":path", u->doh_path),
		h2_nv("content-type", "application/dns-message"),
		h2_nv("accept", "application/dns-message"),
		h2_nv("content-length", clen),
	};

	nghttp2_data_provider2 prd = { .source.ptr = &x, .read_callback = h2_req_read };
	const int32_t sid = nghttp2_submit_request2(c->h2, NULL, nva,
	                                            sizeof(nva) / sizeof(nva[0]), &prd, &x);
	if(sid < 0)
		return -1;

	// Drive the single in-flight request until the stream closes or the deadline
	// passes. The read scratch reuses c->rbuf (unused on the h2 path).
	while(!x.closed)
	{
		if(!h2_send(c, deadline))
			return -1;
		if(x.closed)
			break;
		if(!nghttp2_session_want_read(c->h2) && !nghttp2_session_want_write(c->h2))
			break;
		if(now_ms() >= deadline)
			return -1;
		const int r = SSL_read(c->ssl, c->rbuf, (int)sizeof(c->rbuf));
		if(r <= 0)
		{
			const int err = SSL_get_error(c->ssl, r);
			// Block in poll() until readable/writable or the deadline passes,
			// instead of spinning the CPU re-reading the non-blocking socket
			// (mirrors conn_do()); the deadline is still enforced at the top.
			if((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
			   ssl_io_wait(c->fd, err, deadline))
				continue;
			return -1;
		}
		if(nghttp2_session_mem_recv2(c->h2, c->rbuf, (size_t)r) < 0)
			return -1;
	}

	// Flush frames the final recv queued (SETTINGS ACK, WINDOW_UPDATE) to leave a
	// reused keep-alive connection clean. Best-effort - the answer is in hand.
	(void)h2_send(c, deadline);

	// A cleanly closed stream carrying a 200 with a non-empty body is the only
	// success; anything else fails closed.
	if(x.failed || x.overflow || x.status != 200 || x.answer_len == 0)
		return -1;
	return (ssize_t)x.answer_len;
}
#endif // HAVE_HTTP2

// Send one query and read back the framed answer over an established connection.
// Returns the answer length, or -1 on any protocol/transport error.
static ssize_t conn_do(struct tls_conn *c, const struct upstream_uri *u,
                       const uint8_t *query, size_t qlen,
                       uint8_t *answer, size_t answer_sz, uint64_t deadline)
{
#ifdef HAVE_HTTP2
	// A DoH upstream that negotiated "h2" uses the nghttp2 path; DoT and the
	// HTTP/1.1 DoH fallback continue below unchanged.
	if(u->type == UST_DOH && c->is_h2)
		return conn_do_h2(c, u, query, qlen, answer, answer_sz, deadline);
#endif

	// Frame the request: DoT prepends a 2-byte length, DoH wraps it in a POST.
	ssize_t reqlen;
	if(u->type == UST_DOT)
		reqlen = dot_frame(query, qlen, c->req, sizeof(c->req));
	else
		reqlen = doh_build_request(u->verify_name, u->doh_path, query, qlen, c->req, sizeof(c->req));
	if(reqlen < 0)
		return -1;

	if(!ssl_write_all(c, c->req, (size_t)reqlen, deadline))
		return -1;

	// Accumulate the response until the framer says a full message is present.
	// The buffer is bounded, so a misbehaving upstream cannot make us grow it.
	uint8_t *buf = c->rbuf;
	const size_t bufcap = sizeof(c->rbuf);
	size_t have = 0;
	for(;;)
	{
		// A bounded buffer stops a peer padding the response indefinitely.
		if(have >= bufcap || now_ms() >= deadline)
			return -1;
		const int r = SSL_read(c->ssl, buf + have, (int)(bufcap - have));
		if(r <= 0)
		{
			// TLS 1.3 delivers post-handshake messages (e.g., a
			// NewSessionTicket sent right after the handshake) to SSL_read() as
			// WANT_READ once consumed without app data. Not an error - poll within
			// the deadline and read again for the actual response.
			const int err = SSL_get_error(c->ssl, r);
			if((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
			   ssl_io_wait(c->fd, err, deadline))
				continue;
			return -1; // timeout, close_notify or hard error
		}
		have += (size_t)r;

		size_t off = 0, blen = 0;
		if(u->type == UST_DOT)
		{
			const ssize_t m = dot_deframe(buf, have, &off);
			if(m < 0)
				return -1;
			if(m > 0)
			{
				if((size_t)m > answer_sz)
					return -1;
				memcpy(answer, buf + off, (size_t)m);
				return m;
			}
		}
		else
		{
			const ssize_t consumed = doh_parse_response(buf, have, &off, &blen);
			if(consumed < 0)
				return -1;
			if(consumed > 0)
			{
				if(blen > answer_sz)
					return -1;
				memcpy(answer, buf + off, blen);
				return (ssize_t)blen;
			}
		}
		// Otherwise we need more bytes; loop and read again.
	}
}

// Seed the learned idle window from measured resolver behaviour: DoT closes idle
// connections quickly (~10 s), DoH keeps them far longer, and a couple of known
// DoT providers hold on longer. Everything adapts from here at runtime.
static uint64_t seed_idle_ms(const struct upstream_uri *u)
{
	if(u->type == UST_DOT)
	{
		if(strstr(u->verify_name, "dns.google") != NULL)
			return 60000; // measured ~60 s
		return IDLE_SEED_DOT_MS;
	}
	// DoH
	if(strstr(u->verify_name, "cloudflare-dns.com") != NULL ||
	   strstr(u->verify_name, "dns.google") != NULL)
		return IDLE_MAX_MS; // measured effectively unbounded within the probe cap
	return IDLE_SEED_DOH_MS;
}

// --- pool bookkeeping (all callers hold p->lock) ---------------------------

// Record a connection's reuse depth as it is retired, then tear it down and
// clear its slot.
static void retire_slot(struct tls_pool *p, int i)
{
	struct tls_conn *c = p->slots[i];
	if(c == NULL)
		return;
	p->stats.sessions_closed++;
	p->stats.queries_per_session_sum += c->queries_served;
	if(c->queries_served > p->stats.queries_per_session_max)
		p->stats.queries_per_session_max = c->queries_served;
	conn_teardown(c);
	free(c);
	p->slots[i] = NULL;
	p->nconns--;
}

// Nudge the learned idle window: a reuse that succeeded after idle_age proves
// the server keeps connections at least that long (grow); a reuse that died
// proves it closes by then (shrink). Clamped, with a slack band to damp it.
static void adapt_idle(struct tls_pool *p, uint64_t idle_age, bool alive)
{
	if(idle_age == 0)
		return;
	if(alive)
	{
		const uint64_t want = idle_age + IDLE_SLACK_MS;
		if(want > p->idle_est_ms)
			p->idle_est_ms = want > IDLE_MAX_MS ? IDLE_MAX_MS : want;
	}
	else
	{
		const uint64_t want = idle_age > IDLE_SLACK_MS ? idle_age - IDLE_SLACK_MS : IDLE_MIN_MS;
		if(want < p->idle_est_ms)
			p->idle_est_ms = want < IDLE_MIN_MS ? IDLE_MIN_MS : want;
	}
}

struct tls_pool *tls_pool_new(const struct upstream_uri *u, int max_conns)
{
	if(!g_ready || u == NULL || max_conns < 1)
		return NULL;
	struct tls_pool *p = calloc(1, sizeof(*p));
	if(p == NULL)
		return NULL;
	p->slots = calloc((size_t)max_conns, sizeof(*p->slots));
	if(p->slots == NULL)
	{
		free(p);
		return NULL;
	}
	p->u = *u;
	p->max = max_conns;
	p->idle_est_ms = seed_idle_ms(u);
	pthread_mutex_init(&p->lock, NULL);
	pthread_cond_init(&p->cond, NULL);
	return p;
}

void tls_pool_free(struct tls_pool *p)
{
	if(p == NULL)
		return;
	pthread_mutex_lock(&p->lock);
	for(int i = 0; i < p->max; i++)
		retire_slot(p, i);
	if(p->sess != NULL)
	{
		SSL_SESSION_free(p->sess);
		p->sess = NULL;
	}
	pthread_mutex_unlock(&p->lock);
	pthread_mutex_destroy(&p->lock);
	pthread_cond_destroy(&p->cond);
	free(p->slots);
	free(p);
}

// Borrow a ready connection: reuse a warm one, reap ones we can tell are dead,
// open a fresh one while under the cap, or wait for a slot to free. On success
// returns a connected, exclusively-owned connection and sets *reused. Returns
// NULL if it could not obtain one before the deadline.
static struct tls_conn *borrow(struct tls_pool *p, uint64_t deadline, bool *reused)
{
	pthread_mutex_lock(&p->lock);
	for(;;)
	{
		int free_slot = -1;
		const uint64_t now = now_ms();
		for(int i = 0; i < p->max; i++)
		{
			struct tls_conn *c = p->slots[i];
			if(c == NULL)
			{
				if(free_slot < 0)
					free_slot = i;
				continue;
			}
			if(c->in_use || !c->connected)
				continue;
			const uint64_t idle_age = now > c->last_used_ms ? now - c->last_used_ms : 0;
			if(idle_age > p->idle_est_ms)
			{
				// Almost certainly closed by the server - reap and resume.
				p->stats.conns_reaped_idle++;
				retire_slot(p, i);
				if(free_slot < 0)
					free_slot = i;
				continue;
			}
			// Reuse this warm connection.
			c->in_use = true;
			c->borrowed_idle_ms = idle_age;
			pthread_mutex_unlock(&p->lock);
			*reused = true;
			return c;
		}

		// Nothing warm; open a fresh connection if we are under the cap.
		if(free_slot >= 0 && p->nconns < p->max)
		{
			struct tls_conn *c = calloc(1, sizeof(*c));
			if(c == NULL)
			{
				pthread_mutex_unlock(&p->lock);
				return NULL;
			}
			c->fd = -1;
			c->in_use = true;
			p->slots[free_slot] = c;
			p->nconns++;
			pthread_mutex_unlock(&p->lock);

			enum hs_outcome outcome;
			const bool ok = conn_connect(p, c, deadline, &outcome);

			pthread_mutex_lock(&p->lock);
			if(!ok)
			{
				// Never became a session; drop the slot without reuse stats.
				free(c);
				p->slots[free_slot] = NULL;
				p->nconns--;
				pthread_cond_signal(&p->cond);
				pthread_mutex_unlock(&p->lock);
				return NULL;
			}
			p->stats.conns_opened++;
			if(outcome == HS_RESUMED)
				p->stats.handshakes_resumed++;
			else if(outcome == HS_FULL_FALLBACK)
				p->stats.handshakes_full_fallback++;
			else
				p->stats.handshakes_fresh_cold++;
			c->borrowed_idle_ms = 0;
			pthread_mutex_unlock(&p->lock);
			*reused = false;
			return c;
		}

		// Saturated: wait for a slot to free, bounded by the deadline.
		const uint64_t now2 = now_ms();
		if(now2 >= deadline)
		{
			pthread_mutex_unlock(&p->lock);
			return NULL;
		}
		const uint64_t left = deadline - now2;
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += (time_t)(left / 1000u);
		ts.tv_nsec += (long)((left % 1000u) * 1000000u);
		if(ts.tv_nsec >= 1000000000L)
		{
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000L;
		}
		if(pthread_cond_timedwait(&p->cond, &p->lock, &ts) == ETIMEDOUT)
		{
			pthread_mutex_unlock(&p->lock);
			return NULL;
		}
		// Woken (or spurious): re-scan.
	}
}

// Return a connection after a successful exchange: keep it warm and account the
// query. Grows the learned idle window if the reuse survived a long gap.
static void return_ok(struct tls_pool *p, struct tls_conn *c)
{
	pthread_mutex_lock(&p->lock);
	c->in_use = false;
	c->last_used_ms = now_ms();
	c->queries_served++;
	p->stats.queries_total++;
	if(c->borrowed_idle_ms > 0)
		adapt_idle(p, c->borrowed_idle_ms, true);
	pthread_cond_signal(&p->cond);
	pthread_mutex_unlock(&p->lock);
}

// Discard a connection after a failed exchange: tear it down and free its slot.
// If a reused connection died, that informs the learned idle window.
static void return_dead(struct tls_pool *p, struct tls_conn *c, bool reused)
{
	pthread_mutex_lock(&p->lock);
	if(reused)
	{
		p->stats.conns_dead_on_reuse++;
		adapt_idle(p, c->borrowed_idle_ms, false);
	}
	for(int i = 0; i < p->max; i++)
	{
		if(p->slots[i] == c)
		{
			retire_slot(p, i);
			break;
		}
	}
	pthread_cond_signal(&p->cond);
	pthread_mutex_unlock(&p->lock);
}

ssize_t tls_pool_exchange(struct tls_pool *p, const uint8_t *query, size_t qlen,
                          uint8_t *answer, size_t answer_sz)
{
	if(!g_ready || p == NULL)
		return -1;

	// One budget for the whole exchange (both attempts share it) so a stalled
	// connect, handshake, read or write cannot pin a worker. A pooled connection
	// the upstream closed while idle is rebuilt once; a second failure fails closed.
	const uint64_t deadline = now_ms() + TLS_EXCHANGE_TIMEOUT_MS;

	for(int attempt = 0; attempt < 2; attempt++)
	{
		bool reused = false;
		struct tls_conn *c = borrow(p, deadline, &reused);
		if(c == NULL)
			continue; // could not connect/obtain one; retry once

		const ssize_t r = conn_do(c, &p->u, query, qlen, answer, answer_sz, deadline);
		if(r >= 0)
		{
			return_ok(p, c);
			return r;
		}
		return_dead(p, c, reused);
	}
	return -1;
}

void tls_pool_get_stats(struct tls_pool *p, struct dotdoh_stats *out)
{
	if(p == NULL || out == NULL)
		return;
	pthread_mutex_lock(&p->lock);
	*out = p->stats;
	pthread_mutex_unlock(&p->lock);
}

#else // !HAVE_TLS

// Without TLS there is no client; encrypted upstreams are unavailable and every
// exchange fails closed (the config layer refuses to enable them). These stubs
// are const-folding candidates, so GCC raises -Wsuggest-attribute=const, which
// cannot be applied (conflicts with tls_pool_new()'s malloc attribute) - silence
// it (GCC-only; clang lacks the warning).
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#endif
bool tls_client_global_init(const char *ca_file) { (void)ca_file; return false; }
void tls_client_global_free(void) { }
struct tls_pool *tls_pool_new(const struct upstream_uri *u, int max_conns)
{
	(void)u; (void)max_conns;
	return NULL;
}
void tls_pool_free(struct tls_pool *p) { (void)p; }
ssize_t tls_pool_exchange(struct tls_pool *p, const uint8_t *query, size_t qlen,
                          uint8_t *answer, size_t answer_sz)
{
	(void)p; (void)query; (void)qlen; (void)answer; (void)answer_sz;
	return -1;
}
void tls_pool_get_stats(struct tls_pool *p, struct dotdoh_stats *out) { (void)p; (void)out; }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif // HAVE_TLS
