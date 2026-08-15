/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Inbound DoT (DNS-over-TLS) listener - event-driven
*
*  DoT is raw TLS carrying length-prefixed DNS (RFC 7858), not HTTP, so - unlike
*  DoH, which the front terminator serves over HTTP - it needs its own OpenSSL
*  server listener. This is a single-threaded event loop: every connection is a
*  non-blocking state machine (TLS handshake -> read query -> resolve over a
*  non-blocking loopback socket -> write answer -> keep-alive), multiplexed with
*  poll(). One thread serves all connections, so a flood costs a small state
*  record each rather than a thread stack, and a slow resolve never blocks other
*  connections. This is also the model DoQ (DNS-over-QUIC) will need, so the TLS
*  I/O is kept behind a few small helpers that a QUIC transport can replace.
*
*  The decrypted query is resolved through the shared loopback handoff to dnsmasq
*  (the same private-EDNS attribution as the DoH path) and the answer is padded
*  per RFC 8467 when the downstream client asked for it. Here "client" is always
*  that downstream device, never our own TLS-client role (the outbound side).
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "server.h"
// dot_frame/dot_deframe, DNS_MSG_MAX
#include "framing.h"
// edns_pad_response(), edns_has_padding_option()
#include "edns_pad.h"
// global config (webserver.tls.cert, dns.port)
#include "config/config.h"
// killed, thread_names
#include "signals.h"

#ifdef HAVE_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <time.h>

#define DOT_PORT 853
// Cap concurrent DoT connections so a flood cannot exhaust memory. Each slot
// holds a small state record plus ~192 KiB of I/O buffers, allocated once and
// then pooled across connections (freed only at thread shutdown), so the cap
// bounds the worst-case footprint while a connection flood costs no per-
// connection allocation. The event loop itself scales far higher.
#define DOT_MAX_CONNS 32
// Cap concurrent connections from a single source IP so one client cannot hold
// every slot (a drip of one query per connection re-arms the per-query deadline,
// so the slow-loris sweep never fires; this is what bounds a single source).
#define DOT_MAX_CONNS_PER_IP 16
// Most queries a single connection may serve before we close it (keep-alive bound).
#define DOT_MAX_QUERIES 64
// Max wall-clock time for one query cycle (handshake, or read+resolve+write),
// swept each poll wake-up. Bounds a single cycle - a stalled handshake, a
// slow-drip reader or a hung resolve - defeating slow-loris on any one phase.
#define DOT_QUERY_TIMEOUT_S 10
// Absolute cap on a whole connection's lifetime, independent of keep-alive
// activity. Without it a client that sends one cheap query just under the
// per-cycle deadline could hold a slot for DOT_MAX_QUERIES * DOT_QUERY_TIMEOUT_S;
// this bounds it so a handful of drip clients cannot lock out the DoT slots.
#define DOT_CONN_MAX_LIFETIME_S 120

// Per-connection buffers. rbuf accumulates the length-prefixed client query;
// abuf holds the raw answer; wbuf holds the framed bytes currently being written
// (the attributed query upstream, then the answer downstream - the two never
// overlap in time). The client-attributed query is assembled straight into wbuf
// (dotdoh_prepare_query), so it needs no buffer of its own.
#define RBUF_SZ (2 + DNS_MSG_MAX)
#define ABUF_SZ (DNS_MSG_MAX)
#define WBUF_SZ (2 + DNS_MSG_MAX)

// A single server context, rebuilt in place when the certificate on disk
// changes. The loop is single-threaded (SSL_new happens on this thread too), so
// swapping g_ctx needs no lock. g_cert_mtime tracks the loaded certificate's
// modification time to detect a renewal.
static SSL_CTX *g_ctx = NULL;
static bool g_ready = false;
static time_t g_cert_mtime = 0;

// Human-readable text for the most recent OpenSSL error (init path only, which
// is single-threaded, so the static buffer inside ERR_error_string is fine).
static const char *ossl_err(void)
{
	const unsigned long e = ERR_get_error();
	return e ? ERR_error_string(e, NULL) : "no error";
}

// Build a server-side TLS context from the webserver's PEM (it holds both the
// certificate chain and the private key). Returns a new SSL_CTX, or NULL on
// failure (logged). No client certificate is requested (SSL_VERIFY_NONE default).
static SSL_CTX *dot_build_ctx(const char *cert)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if(ctx == NULL)
	{
		log_err("dotdoh: could not create DoT SSL_CTX: %s", ossl_err());
		return NULL;
	}

	// Harden TLS: minimum TLS 1.2 (no SSL 3.0 / TLS 1.0 / 1.1).
	if(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
	{
		log_err("dotdoh: could not set DoT minimum TLS version: %s", ossl_err());
		goto fail;
	}
	if(SSL_CTX_use_certificate_chain_file(ctx, cert) != 1)
	{
		log_err("dotdoh: could not load DoT certificate from %s: %s", cert, ossl_err());
		goto fail;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, cert, SSL_FILETYPE_PEM) != 1)
	{
		log_err("dotdoh: could not load DoT private key from %s: %s", cert, ossl_err());
		goto fail;
	}
	if(SSL_CTX_check_private_key(ctx) != 1)
	{
		log_err("dotdoh: DoT private key does not match the certificate in %s: %s",
		        cert, ossl_err());
		goto fail;
	}
	return ctx;

fail:
	SSL_CTX_free(ctx);
	return NULL;
}

// Build the initial TLS context. Returns false - quietly - while the certificate
// is not yet readable, so the DoT thread can wait for the webserver to generate
// it on a fresh install rather than giving up permanently.
static bool dot_server_init(void)
{
	if(g_ready)
		return true;

	const char *cert = config.webserver.tls.cert.v.s;
	if(cert == NULL || cert[0] == '\0' || access(cert, R_OK) != 0)
		return false; // not written yet; the caller retries

	g_ctx = dot_build_ctx(cert);
	if(g_ctx == NULL)
		return false;

	struct stat st;
	g_cert_mtime = stat(cert, &st) == 0 ? st.st_mtime : 0;
	g_ready = true;
	return true;
}

// Rebuild the context when the certificate file changes (the webserver renews
// the Pi-hole self-signed certificate before it expires). Single-threaded with
// SSL_new(), so the swap needs no lock; in-flight SSL objects hold their own
// reference to the old context and release it when they close.
static void dot_reload_cert_if_changed(void)
{
	const char *cert = config.webserver.tls.cert.v.s;
	if(cert == NULL || cert[0] == '\0')
		return;
	struct stat st;
	if(stat(cert, &st) != 0 || st.st_mtime == g_cert_mtime)
		return;

	SSL_CTX *nctx = dot_build_ctx(cert);
	if(nctx == NULL)
		return; // keep serving the current context; retry on the next change

	SSL_CTX_free(g_ctx);
	g_ctx = nctx;
	g_cert_mtime = st.st_mtime;
	log_info("dotdoh: reloaded DoT certificate from %s", cert);
}

// Monotonic seconds for connection deadlines: immune to wall-clock steps
// (NTP/admin changes), which time() is not.
static time_t dot_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

// Connection state machine. The order is the lifecycle of one query cycle; a
// keep-alive connection loops WRITE -> READ.
enum dot_state {
	DS_HANDSHAKE,  // SSL_accept
	DS_READ,       // read a length-prefixed query over TLS
	DS_UP_CONNECT, // connect() to the loopback DNS listener (non-blocking)
	DS_UP_WRITE,   // write the framed query to the loopback listener
	DS_UP_READ,    // read the framed answer from the loopback listener
	DS_WRITE       // write the framed answer back over TLS
};

struct dot_conn {
	bool used;
	int cfd;                 // client TLS socket (non-blocking)
	SSL *ssl;
	int upfd;                // loopback resolve socket, kept open across keep-alive
	                         // queries for reuse; -1 when none is open
	bool up_reused;          // upfd carried over from a previous query this conn
	bool up_idle;            // upfd is at a clean message boundary (no exchange
	                         // in flight), so it may go back into the pool
	bool up_retried;         // already reconnected once for the current query
	enum dot_state st;
	int active_fd;           // fd this connection is currently waiting on
	short active_ev;         // POLLIN or POLLOUT
	time_t deadline;         // absolute monotonic deadline for the current cycle
	time_t hard_deadline;    // absolute cap on the whole connection's lifetime
	int served;              // queries answered so far (keep-alive cap)
	bool client_padded;      // the current query carried an EDNS Padding option
	char client[INET6_ADDRSTRLEN]; // downstream client IP (attribution + logging)
	char dest[INET6_ADDRSTRLEN];   // local IP the client connected to (pi.hole answer)

	uint8_t *rbuf; size_t have;              // client read accumulation
	uint8_t *abuf; size_t alen, agot;        // answer from dnsmasq
	size_t qsave;                            // bytes of the query kept in abuf, so a
	                                         // refusal can still be answered
	uint8_t  lenbuf[2]; size_t up_lengot;    // answer length prefix
	uint8_t *wbuf; size_t wlen, woff;        // framed bytes being written
};

static struct dot_conn g_conns[DOT_MAX_CONNS];
static int g_nconns = 0;

// Free a connection's resources and its slot.
static void conn_free(struct dot_conn *c)
{
	if(c->ssl != NULL)
	{
		// Best-effort close_notify. On a non-blocking socket this may not
		// complete; a DoT client tolerates a bare close, so we do not spin.
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl); // does not close cfd
	}
	if(c->cfd >= 0)
		close(c->cfd);
	// Hand the loopback socket back only when no exchange is in flight on it.
	// conn_free() is also the deadline-sweep and shutdown path, which can fire
	// with a query half-written or an answer not yet read; pooling such a socket
	// would leave it out of step and serve the pending answer to whoever takes
	// it next. Anything mid-exchange is closed instead.
	if(c->upfd >= 0)
	{
		if(c->up_idle)
			dotdoh_loopback_give(c->upfd);
		else
			dotdoh_loopback_drop(c->upfd);
	}
	// Keep the I/O buffers attached to the slot for the next connection to reuse
	// (they are freed once, at thread shutdown); reset only the bookkeeping.
	uint8_t *rbuf = c->rbuf, *abuf = c->abuf, *wbuf = c->wbuf;
	memset(c, 0, sizeof(*c));
	c->rbuf = rbuf; c->abuf = abuf; c->wbuf = wbuf;
	g_nconns--;
}

// Allocate a connection slot for an accepted socket. Returns NULL (and closes
// cfd) if the cap is reached, no slot is free, or allocation fails.
static struct dot_conn *conn_new(int cfd, const char *client, const char *dest)
{
	if(g_nconns >= DOT_MAX_CONNS)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoT connection limit (%d) reached, dropping %s",
		          DOT_MAX_CONNS, client);
		close(cfd);
		return NULL;
	}
	int same_src = 0;
	for(int i = 0; i < DOT_MAX_CONNS; i++)
		if(g_conns[i].used && strcmp(g_conns[i].client, client) == 0)
			same_src++;
	if(same_src >= DOT_MAX_CONNS_PER_IP)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoT per-source limit (%d) reached for %s, dropping",
		          DOT_MAX_CONNS_PER_IP, client);
		close(cfd);
		return NULL;
	}
	struct dot_conn *c = NULL;
	for(int i = 0; i < DOT_MAX_CONNS; i++)
		if(!g_conns[i].used) { c = &g_conns[i]; break; }
	if(c == NULL) { close(cfd); return NULL; }

	// Preserve any pooled buffers across the reset (conn_free left them attached),
	// and allocate them only the first time this slot is used.
	uint8_t *rbuf = c->rbuf, *abuf = c->abuf, *wbuf = c->wbuf;
	memset(c, 0, sizeof(*c));
	c->rbuf = rbuf != NULL ? rbuf : malloc(RBUF_SZ);
	c->abuf = abuf != NULL ? abuf : malloc(ABUF_SZ);
	c->wbuf = wbuf != NULL ? wbuf : malloc(WBUF_SZ);
	c->ssl = SSL_new(g_ctx);
	if(c->rbuf == NULL || c->abuf == NULL || c->wbuf == NULL || c->ssl == NULL)
	{
		if(c->ssl != NULL) SSL_free(c->ssl);
		c->ssl = NULL;
		// Leave any successfully-allocated buffers attached for a later retry;
		// they are released at thread shutdown.
		close(cfd);
		return NULL;
	}
	SSL_set_fd(c->ssl, cfd); // does not take ownership of the fd

	c->used = true;
	c->cfd = cfd;
	c->upfd = -1;
	c->st = DS_HANDSHAKE;
	c->active_fd = cfd;
	c->active_ev = POLLIN;
	c->deadline = dot_now() + DOT_QUERY_TIMEOUT_S;
	c->hard_deadline = dot_now() + DOT_CONN_MAX_LIFETIME_S;
	snprintf(c->client, sizeof(c->client), "%s", client);
	snprintf(c->dest, sizeof(c->dest), "%s", dest != NULL ? dest : "");
	g_nconns++;
	return c;
}

// Build a SERVFAIL reply to the query `q` in `out`. The question is echoed when
// it parses, else the reply carries an empty question section. Returns its
// length, or -1 if it does not fit.
static ssize_t dot_servfail(const uint8_t *q, size_t qlen, uint8_t *out, size_t outcap)
{
	if(qlen < 12 || outcap < 12)
		return -1;

	// Walk the QNAME. A compression pointer cannot legitimately appear in a
	// question, so anything that is not a plain label ends the attempt.
	size_t n = 12;
	while(n < qlen && q[n] != 0)
	{
		if(q[n] > 63)
			break;
		n += 1u + q[n];
	}
	// RFC 1035 Sec. 4.1.2: the response's question mirrors the request's. Trust
	// QDCOUNT for that, not the byte layout - a QDCOUNT=0 message (an EDNS-only
	// probe, or a DSO request whose OPCODE we now preserve) would otherwise have
	// bytes from its OPT echoed back as a fabricated question.
	const bool has_qd = ((q[4] << 8) | q[5]) == 1;
	// RFC 1035 Sec. 2.3.4 caps a name at 255 octets. Mirroring a longer one would
	// emit an illegal question, and make each refusal copy up to 64 KiB about
	// while we are already shedding load.
	const bool have_q = has_qd && n < qlen && q[n] == 0 && n + 5 <= qlen &&
	                    n - 11 <= 255;
	const size_t len = have_q ? n + 5 : 12;
	if(len > outcap)
		return -1;

	memmove(out, q, len); // may be called in place (out == q)
	// RFC 1035 Sec. 4.1.1: OPCODE is copied into the response; RFC 4035 Sec. 3.2.2
	// does the same for CD. AA and TC are ours to clear.
	out[2] = 0x80 | (q[2] & 0x79);          // QR=1, OPCODE and RD from the query
	out[3] = 0x80 | (q[3] & 0x10) | 0x02;   // RA=1, CD from the query, RCODE=SERVFAIL
	out[4] = 0; out[5] = have_q ? 1 : 0;
	out[6] = 0; out[7] = 0;         // ANCOUNT
	out[8] = 0; out[9] = 0;         // NSCOUNT
	out[10] = 0; out[11] = 0;       // ARCOUNT
	return (ssize_t)len;
}

// Answer the query kept in c->abuf with SERVFAIL and arm the write, leaving the
// connection up. Returns 1 to keep driving, or -1 if the reply cannot be built.
static int conn_answer_servfail(struct dot_conn *c)
{
	c->upfd = -1; // clear the sentinel dotdoh_loopback_take() left behind
	// Sample the query's EDNS state before dot_servfail() overwrites the buffer
	// it sits in.
	bool query_do = false;
	const bool query_edns = edns_query_opt(c->abuf, c->qsave, &query_do);

	ssize_t slen = dot_servfail(c->abuf, c->qsave, c->abuf, ABUF_SZ);
	if(slen < 0)
		return -1;
	// RFC 6891 Sec. 6.1.1: answer an EDNS query with an OPT, whether or not it
	// padded - replying without one marks us EDNS-lame. RFC 8467 Sec. 4: only
	// pad when it asked, as the resolved answer does, or the refusal leaks the
	// query length the client paid to hide. The synthesised OPT copies the
	// query's DO bit (RFC 3225 Sec. 3).
	if(query_edns)
		slen = (ssize_t)edns_pad_response_synth(c->abuf, (size_t)slen, ABUF_SZ,
		                                        query_do, c->client_padded);
	const ssize_t flen = dot_frame(c->abuf, (size_t)slen, c->wbuf, WBUF_SZ);
	if(flen < 0)
		return -1;
	c->wlen = (size_t)flen;
	c->woff = 0;
	c->alen = 0; c->agot = 0; c->up_lengot = 0;
	c->up_reused = false;
	c->up_idle = false;
	c->st = DS_WRITE;
	return 1;
}

// Open a non-blocking loopback socket to dnsmasq's own DNS listener and begin
// connecting. Returns 0 and sets c->upfd + the wait state; -2 when the shared
// concurrency limit refuses the query, which the caller answers with SERVFAIL
// rather than dropping the connection; -1 on failure.
static int conn_start_resolve(struct dot_conn *c)
{
	// Prefer a pooled loopback socket: a client that opens a fresh DoT
	// connection per query would otherwise fork a dnsmasq child per query, and a
	// burst of those exhausts dnsmasq's child slots - after which queries are
	// read but never answered.
	c->upfd = dotdoh_loopback_take();
	if(c->upfd >= 0)
	{
		c->up_reused = true;
		c->st = DS_UP_WRITE;
		return 0;
	}
	if(c->upfd == -2)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoT query from %s refused, concurrency limit reached",
		          c->client);
		return -2; // distinct from -1: answer this query, keep the connection
	}
	c->upfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if(c->upfd < 0)
	{
		dotdoh_loopback_drop(-1);
		return -1;
	}
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(config.dns.port.v.u16);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	const int r = connect(c->upfd, (struct sockaddr *)&sa, sizeof(sa));
	if(r == 0)
	{
		c->st = DS_UP_WRITE; // connected immediately (loopback often is)
		return 0;
	}
	if(errno == EINPROGRESS)
	{
		c->st = DS_UP_CONNECT;
		c->active_fd = c->upfd;
		c->active_ev = POLLOUT;
		return 0;
	}
	return -1;
}

// Reconnect the loopback socket once when a REUSED (possibly stale) connection
// failed before any answer byte arrived - dnsmasq's TCP child may have closed it
// after its own keep-alive limit or an idle period. The framed query is still in
// wbuf, so resend it on a fresh connection. Returns the drive contract below: 1
// (advanced, keep driving), 0 (reconnect in flight, yield), -1 (give up).
static int conn_retry_upstream(struct dot_conn *c)
{
	dotdoh_loopback_drop(c->upfd);
	c->upfd = -1;
	c->up_reused = false;
	c->up_retried = true;
	c->woff = 0;                     // resend the framed query from the start
	c->alen = 0; c->agot = 0; c->up_lengot = 0;
	const int rs = conn_start_resolve(c);   // sets DS_UP_WRITE or DS_UP_CONNECT
	if(rs == -2)
		return conn_answer_servfail(c); // the slot went elsewhere while we retried
	if(rs != 0)
		return -1;
	return c->st == DS_UP_CONNECT ? 0 : 1;
}

// State-handler return contract (shared by the helpers below and drive_conn's
// switch): 1 = keep driving (state advanced, loop again), 0 = yield until the next
// poll (active_fd/active_ev set for the wait), -1 = close and free the connection.

// DS_READ: buffer and deframe one client query. On a complete query, attribute it
// to the real downstream client and kick off the loopback resolve.
static int drive_read(struct dot_conn *c)
{
	size_t off = 0;
	const ssize_t qlen = dot_deframe(c->rbuf, c->have, &off);
	if(qlen < 0)
		return -1; // protocol error (zero-length frame)
	if(qlen == 0)
	{
		if(c->have >= RBUF_SZ)
			return -1; // a frame larger than we will ever accept
		const int r = SSL_read(c->ssl, c->rbuf + c->have, (int)(RBUF_SZ - c->have));
		if(r > 0) { c->have += (size_t)r; return 1; } // try to deframe again
		const int e = SSL_get_error(c->ssl, r);
		if(e == SSL_ERROR_WANT_READ)  { c->active_fd = c->cfd; c->active_ev = POLLIN;  return 0; }
		if(e == SSL_ERROR_WANT_WRITE) { c->active_fd = c->cfd; c->active_ev = POLLOUT; return 0; }
		return -1; // clean close_notify (ZERO_RETURN) or a hard error
	}

	// A full query is buffered at rbuf[off .. off+qlen). Give it a fresh
	// per-cycle deadline: on a keep-alive connection the idle wait for this
	// query must not eat into its resolve+write budget. The absolute
	// hard_deadline still bounds the whole connection against slow-loris.
	c->deadline = dot_now() + DOT_QUERY_TIMEOUT_S;

	// Remember whether it asked for padding (before we attribute it), then build
	// the client-attributed, framed query straight into wbuf. rbuf is read before
	// the memmove below drops the consumed bytes, and stays intact for any
	// pipelined query queued behind this one.
	c->client_padded = edns_has_padding_option(c->rbuf + off, (size_t)qlen);

	// Keep the query itself before anything can fail: whenever we cannot resolve
	// it - refused below, or unattributable here - we answer it rather than
	// dropping the connection, and the deframe further down discards it.
	c->qsave = (size_t)qlen < ABUF_SZ ? (size_t)qlen : ABUF_SZ;
	memcpy(c->abuf, c->rbuf + off, c->qsave);

	const ssize_t flen = dotdoh_prepare_query(c->rbuf + off, (size_t)qlen, c->client,
	                                          c->dest[0] != '\0' ? c->dest : NULL,
	                                          c->wbuf, WBUF_SZ);
	if(flen < 0)
	{
		// Attribution failed - an OPT we cannot safely rewrite, or no room for the
		// client option. That is this one query's problem, not the session's.
		log_debug(DEBUG_TLS, "dotdoh: DoT query from %s could not be attributed, answering SERVFAIL",
		          c->client);
		const size_t consumed_bad = off + (size_t)qlen;
		memmove(c->rbuf, c->rbuf + consumed_bad, c->have - consumed_bad);
		c->have -= consumed_bad;
		return conn_answer_servfail(c);
	}
	c->wlen = (size_t)flen;
	c->woff = 0;

	const size_t consumed = off + (size_t)qlen;
	memmove(c->rbuf, c->rbuf + consumed, c->have - consumed);
	c->have -= consumed;

	// Reuse an open loopback connection across this connection's keep-alive
	// queries: dnsmasq serves up to TCP_MAX_QUERIES per TCP connection, so we do
	// not fork a fresh child per query. If dnsmasq has since closed it, the resend
	// path in drive_up_write/drive_up_read reconnects once.
	c->up_retried = false;
	if(c->upfd >= 0)
	{
		c->up_reused = true;
		c->st = DS_UP_WRITE;
		return 1;
	}
	c->up_reused = false;
	const int rs = conn_start_resolve(c);
	if(rs == -2)
	{
		// At the concurrency limit. Answer SERVFAIL so the client backs off and
		// keeps its session; tearing the connection down would cost it a fresh
		// TLS handshake exactly when we are already overloaded.
		return conn_answer_servfail(c);
	}
	if(rs != 0)
		return -1;
	// If the non-blocking connect is still in flight it set DS_UP_CONNECT and a
	// POLLOUT wait; yield so the SO_ERROR check runs only once the socket is
	// actually connected. A loopback connect usually completes immediately
	// (DS_UP_WRITE), in which case we keep driving.
	if(c->st == DS_UP_CONNECT)
		return 0;
	return 1;
}

// DS_UP_WRITE: write the framed query to the loopback upstream. A hard error on a
// reused connection means dnsmasq closed a kept-alive child; reconnect once.
static int drive_up_write(struct dot_conn *c)
{
	// The socket stops being poolable the moment we start writing, not once the
	// write finishes: a short write yields with the frame half sent, and a
	// teardown in that window (either deadline sweep, or shutdown) would
	// otherwise pool a socket carrying a partial query. dnsmasq is then blocked
	// waiting for the rest, so nothing is readable and the checkout probe cannot
	// tell the socket is unusable.
	c->up_idle = false;

	while(c->woff < c->wlen)
	{
		const ssize_t w = write(c->upfd, c->wbuf + c->woff, c->wlen - c->woff);
		if(w > 0) { c->woff += (size_t)w; continue; }
		if(w < 0 && errno == EINTR) continue;
		if(w < 0 && errno == EAGAIN)
		{ c->active_fd = c->upfd; c->active_ev = POLLOUT; return 0; }
		if(c->up_reused && !c->up_retried)
			return conn_retry_upstream(c);
		return -1;
	}
	// Query sent; prepare to read the framed answer.
	c->alen = 0; c->agot = 0; c->up_lengot = 0;
	c->st = DS_UP_READ;
	return 1;
}

// DS_UP_READ: read the framed answer from the loopback upstream, optionally pad it
// (RFC 8467), and frame it for the TLS write back to the client.
static int drive_up_read(struct dot_conn *c)
{
	// Read the 2-byte length prefix first.
	while(c->up_lengot < 2)
	{
		const ssize_t r = read(c->upfd, c->lenbuf + c->up_lengot, 2 - c->up_lengot);
		if(r > 0) { c->up_lengot += (size_t)r; continue; }
		if(r < 0 && errno == EINTR) continue;
		if(r < 0 && errno == EAGAIN)
		{ c->active_fd = c->upfd; c->active_ev = POLLIN; return 0; }
		// EOF (r==0) or hard error. If nothing has arrived yet on a reused
		// connection, dnsmasq closed a stale child: reconnect and resend once.
		if(c->up_reused && !c->up_retried && c->up_lengot == 0 && c->agot == 0)
			return conn_retry_upstream(c);
		return -1; // closed early or error
	}
	if(c->alen == 0)
	{
		c->alen = ((size_t)c->lenbuf[0] << 8) | (size_t)c->lenbuf[1];
		if(c->alen == 0 || c->alen > ABUF_SZ)
			return -1;
	}
	// Read exactly alen answer bytes.
	while(c->agot < c->alen)
	{
		const ssize_t r = read(c->upfd, c->abuf + c->agot, c->alen - c->agot);
		if(r > 0) { c->agot += (size_t)r; continue; }
		if(r < 0 && errno == EINTR) continue;
		if(r < 0 && errno == EAGAIN)
		{ c->active_fd = c->upfd; c->active_ev = POLLIN; return 0; }
		return -1;
	}
	// Answer complete. Keep the loopback socket open so the next keep-alive query
	// reuses it instead of forking a fresh dnsmasq child - and it is now back at
	// a message boundary, so conn_free() may return it to the shared pool.
	c->up_idle = true;

	// Hand the loopback socket back now that the exchange is complete, rather
	// than holding it until the connection closes. It stays warm in the pool for
	// whoever needs it next - including this connection's next query - but an
	// idle keep-alive client no longer occupies one of the shared admission
	// slots, which would otherwise let a handful of idle DoT connections starve
	// DoQ and DoH.
	if(c->upfd >= 0)
	{
		dotdoh_loopback_give(c->upfd);
		c->upfd = -1;
		// Clear the boundary flag with the fd it described: the next query takes a
		// fresh socket, and leaving it set would let conn_free() pool that one
		// while it is still connecting.
		c->up_idle = false;
		c->up_reused = false;
		c->up_retried = false;
	}

	// RFC 8467 Sec. 4: pad the answer only if the query asked for it.
	if(c->client_padded)
		c->alen = edns_pad_response(c->abuf, c->alen, ABUF_SZ);

	// Frame the answer into wbuf for the TLS write.
	const ssize_t flen = dot_frame(c->abuf, c->alen, c->wbuf, WBUF_SZ);
	if(flen < 0)
		return -1;
	c->wlen = (size_t)flen;
	c->woff = 0;
	c->st = DS_WRITE;
	return 1;
}

// Drive a connection's state machine as far as it can go without blocking.
// Returns 0 if the connection is still alive (its active_fd/active_ev are set for
// the next poll), or -1 if it finished or errored and must be freed. All TLS and
// socket calls are non-blocking; a would-block sets the wait state and returns 0.
static int drive_conn(struct dot_conn *c)
{
	for(;;)
	{
		switch(c->st)
		{
		case DS_HANDSHAKE:
		{
			const int r = SSL_accept(c->ssl);
			if(r == 1)
			{
				c->st = DS_READ;
				c->deadline = dot_now() + DOT_QUERY_TIMEOUT_S;
				continue;
			}
			const int e = SSL_get_error(c->ssl, r);
			if(e == SSL_ERROR_WANT_READ)  { c->active_fd = c->cfd; c->active_ev = POLLIN;  return 0; }
			if(e == SSL_ERROR_WANT_WRITE) { c->active_fd = c->cfd; c->active_ev = POLLOUT; return 0; }
			return -1; // handshake failed
		}

		case DS_READ:
		{
			const int r = drive_read(c);
			if(r <= 0) return r; // 0 = yield (wait armed), -1 = close
			continue;            // 1 = state advanced, keep driving
		}

		case DS_UP_CONNECT:
		{
			int err = 0;
			socklen_t l = sizeof(err);
			if(getsockopt(c->upfd, SOL_SOCKET, SO_ERROR, &err, &l) != 0 || err != 0)
				return -1;
			c->st = DS_UP_WRITE;
			continue;
		}

		case DS_UP_WRITE:
		{
			const int r = drive_up_write(c);
			if(r <= 0) return r; // 0 = yield (wait armed), -1 = close
			continue;            // 1 = query sent, proceed to DS_UP_READ
		}

		case DS_UP_READ:
		{
			const int r = drive_up_read(c);
			if(r <= 0) return r; // 0 = yield (wait armed), -1 = close
			continue;            // 1 = answer framed, proceed to DS_WRITE
		}

		case DS_WRITE:
		{
			while(c->woff < c->wlen)
			{
				const int w = SSL_write(c->ssl, c->wbuf + c->woff, (int)(c->wlen - c->woff));
				if(w > 0) { c->woff += (size_t)w; continue; }
				const int e = SSL_get_error(c->ssl, w);
				if(e == SSL_ERROR_WANT_READ)  { c->active_fd = c->cfd; c->active_ev = POLLIN;  return 0; }
				if(e == SSL_ERROR_WANT_WRITE) { c->active_fd = c->cfd; c->active_ev = POLLOUT; return 0; }
				return -1;
			}
			// Answer sent. Enforce the keep-alive cap, then wait for the next query
			// on the same connection (any pipelined bytes are already in rbuf).
			if(++c->served >= DOT_MAX_QUERIES)
				return -1;
			c->st = DS_READ;
			c->active_fd = c->cfd;
			c->active_ev = POLLIN;
			c->deadline = dot_now() + DOT_QUERY_TIMEOUT_S;
			continue;
		}
		}
	}
}

// Create a bound, listening, non-blocking DoT socket for the given family, or -1.
// The v6 socket is v6-only so v4 and v6 can share port 853 (and v4 clients arrive
// as AF_INET, not v4-mapped).
static int dot_listen_socket(int family)
{
	const int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if(fd < 0)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoT %s socket() failed: %s",
		          family == AF_INET ? "IPv4" : "IPv6", strerror(errno));
		return -1;
	}
	const int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if(family == AF_INET6)
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));

	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t slen;
	if(family == AF_INET)
	{
		struct sockaddr_in *sa = (struct sockaddr_in *)(void *)&ss;
		sa->sin_family = AF_INET;
		sa->sin_addr.s_addr = htonl(INADDR_ANY);
		sa->sin_port = htons(DOT_PORT);
		slen = sizeof(*sa);
	}
	else
	{
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(void *)&ss;
		sa->sin6_family = AF_INET6;
		sa->sin6_addr = in6addr_any;
		sa->sin6_port = htons(DOT_PORT);
		slen = sizeof(*sa);
	}
	if(bind(fd, (struct sockaddr *)&ss, slen) != 0 || listen(fd, SOMAXCONN) != 0)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoT %s bind/listen on port %d failed: %s",
		          family == AF_INET ? "IPv4" : "IPv6", DOT_PORT, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

// Accept every pending connection on a ready listener, applying the source filter
// and the concurrency cap, and kick each accepted connection's handshake.
static void dot_accept_all(int lfd)
{
	for(;;)
	{
		struct sockaddr_storage peer;
		socklen_t plen = sizeof(peer);
		const int cfd = accept4(lfd, (struct sockaddr *)&peer, &plen,
		                        SOCK_CLOEXEC | SOCK_NONBLOCK);
		if(cfd < 0)
		{
			if(errno == EINTR)
				continue; // interrupted before a connection was accepted; retry
			if(errno == EAGAIN)
				return;   // listen queue drained
			// Per-connection errors that accept(2) says to treat like EAGAIN: retry
			// the next pending connection, so a client that aborts before we accept
			// (ECONNABORTED and friends) cannot stall the single-threaded reactor.
			if(errno == ECONNABORTED || errno == EPROTO || errno == EHOSTUNREACH ||
			   errno == ENETUNREACH || errno == ENETDOWN || errno == EOPNOTSUPP)
				continue;
			// Genuine resource exhaustion (EMFILE/ENFILE/ENOBUFS/ENOMEM): the pending
			// connection stays on the listener, so back off before returning rather
			// than spin until an fd frees.
			log_debug(DEBUG_TLS, "dotdoh: DoT accept4() error: %s", strerror(errno));
			const struct timespec backoff = { .tv_sec = 0, .tv_nsec = 100000000 };
			nanosleep(&backoff, NULL);
			return;
		}

		char client[INET6_ADDRSTRLEN];
		if(peer.ss_family == AF_INET6)
		{
			struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(void *)&peer;
			inet_ntop(AF_INET6, &sa->sin6_addr, client, sizeof(client));
		}
		else
		{
			struct sockaddr_in *sa = (struct sockaddr_in *)(void *)&peer;
			inet_ntop(AF_INET, &sa->sin_addr, client, sizeof(client));
		}

		// The local address the client connected to, so pi.hole/<hostname> can be
		// answered with the reachable IP instead of the loopback forward address.
		char dest[INET6_ADDRSTRLEN] = "";
		struct sockaddr_storage local;
		socklen_t llen = sizeof(local);
		if(getsockname(cfd, (struct sockaddr *)&local, &llen) == 0)
		{
			if(local.ss_family == AF_INET6)
			{
				struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(void *)&local;
				inet_ntop(AF_INET6, &sa->sin6_addr, dest, sizeof(dest));
			}
			else
			{
				struct sockaddr_in *sa = (struct sockaddr_in *)(void *)&local;
				inet_ntop(AF_INET, &sa->sin_addr, dest, sizeof(dest));
			}
		}

		// Honour dns.listeningMode: drop non-local clients unless LISTEN_ALL.
		if(!dotdoh_source_allowed(client))
		{
			log_debug(DEBUG_TLS, "dotdoh: refused DoT connection from non-local client %s", client);
			close(cfd);
			continue;
		}

		struct dot_conn *c = conn_new(cfd, client, dest); // closes cfd on failure
		if(c != NULL && drive_conn(c) < 0)
			conn_free(c);
	}
}

void *dotdoh_dot_thread(void *val)
{
	(void)val;
	prctl(PR_SET_NAME, thread_names[DOTDOH_DOT], 0, 0, 0);

	// The main thread handles termination signals; this loop only checks `killed`.
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	// Wait for the webserver thread to write the TLS certificate before loading
	// it. On a fresh install it does not exist yet; retrying (instead of exiting)
	// avoids leaving DoT down until the next restart. `killed` breaks us out.
	bool waited = false;
	while(!dot_server_init())
	{
		if(killed)
			return NULL;
		if(!waited)
		{
			log_info("dotdoh: DoT waiting for the webserver TLS certificate");
			waited = true;
		}
		const struct timespec wait = { .tv_sec = 1, .tv_nsec = 0 };
		nanosleep(&wait, NULL);
	}

	int lfds[2];
	int nlisten = 0;
	const int f4 = dot_listen_socket(AF_INET);
	if(f4 >= 0) lfds[nlisten++] = f4;
	const int f6 = dot_listen_socket(AF_INET6);
	if(f6 >= 0) lfds[nlisten++] = f6;
	if(nlisten == 0)
	{
		log_err("dotdoh: DoT listener could not bind any socket on port %d", DOT_PORT);
		return NULL;
	}
	log_info("dotdoh: DoT server listening on port %d", DOT_PORT);

	time_t last_cert_check = dot_now();
	while(!killed)
	{
		// Pick up a renewed certificate (checked at a coarse interval; renewal is
		// on a multi-day timescale, so a minute of detection latency is fine).
		const time_t tnow = dot_now();
		if(tnow - last_cert_check >= 60)
		{
			last_cert_check = tnow;
			dot_reload_cert_if_changed();
		}
		// Build the poll set: the listeners plus one active fd per live connection.
		struct pollfd pfd[2 + DOT_MAX_CONNS];
		struct dot_conn *pc[2 + DOT_MAX_CONNS];
		nfds_t n = 0;
		for(int i = 0; i < nlisten; i++)
		{
			pfd[n].fd = lfds[i]; pfd[n].events = POLLIN; pfd[n].revents = 0;
			pc[n] = NULL; n++;
		}
		const time_t now = dot_now();
		int timeout_ms = 1000; // also bounds how quickly we notice `killed`
		for(int i = 0; i < DOT_MAX_CONNS; i++)
		{
			struct dot_conn *c = &g_conns[i];
			if(!c->used)
				continue;
			pfd[n].fd = c->active_fd; pfd[n].events = c->active_ev; pfd[n].revents = 0;
			pc[n] = c; n++;
			const long ms = (long)(c->deadline - now) * 1000;
			if(ms < timeout_ms)
				timeout_ms = ms < 0 ? 0 : (int)ms;
		}

		const int pr = poll(pfd, n, timeout_ms);
		if(pr < 0)
		{
			if(errno != EINTR)
			{
				const struct timespec backoff = { .tv_sec = 0, .tv_nsec = 100000000 };
				nanosleep(&backoff, NULL);
			}
			continue;
		}

		if(pr > 0)
		{
			// Service ready connections first, then accept new ones.
			for(nfds_t i = 0; i < n; i++)
			{
				if(pc[i] == NULL || pfd[i].revents == 0)
					continue;
				if(drive_conn(pc[i]) < 0)
					conn_free(pc[i]);
			}
			for(nfds_t i = 0; i < n; i++)
				if(pc[i] == NULL && (pfd[i].revents & POLLIN))
					dot_accept_all(pfd[i].fd);
		}

		// Sweep connections that overran their deadline (slow-loris / stalled).
		const time_t swept = dot_now();
		for(int i = 0; i < DOT_MAX_CONNS; i++)
			if(g_conns[i].used &&
			   (swept >= g_conns[i].deadline || swept >= g_conns[i].hard_deadline))
			{
				log_debug(DEBUG_TLS, "dotdoh: DoT connection from %s timed out", g_conns[i].client);
				conn_free(&g_conns[i]);
			}
	}

	for(int i = 0; i < DOT_MAX_CONNS; i++)
		if(g_conns[i].used)
			conn_free(&g_conns[i]);
	// Release the pooled per-connection buffers (kept attached across reuse). Only
	// slots that actually served a connection have them; guard against NULL as
	// FTL's free() wrapper warns on a NULL argument.
	for(int i = 0; i < DOT_MAX_CONNS; i++)
	{
		if(g_conns[i].rbuf != NULL) free(g_conns[i].rbuf);
		if(g_conns[i].abuf != NULL) free(g_conns[i].abuf);
		if(g_conns[i].wbuf != NULL) free(g_conns[i].wbuf);
		g_conns[i].rbuf = g_conns[i].abuf = g_conns[i].wbuf = NULL;
	}
	for(int i = 0; i < nlisten; i++)
		close(lfds[i]);
	return NULL;
}

#else // !HAVE_TLS

// Without TLS there is no DoT listener. dns.dot still starts this thread, which
// returns immediately, so the setting is inert rather than fatal. The stub is a
// const-folding candidate, so silence the GCC-only -Wsuggest-attribute
// suggestion that -Werror would otherwise turn into a build failure.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#endif
void *dotdoh_dot_thread(void *val)
{
	(void)val;
	return NULL;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif // HAVE_TLS
