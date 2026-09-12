/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Inbound DoQ (DNS-over-QUIC, RFC 9250) listener - event-driven
*
*  DoQ carries DNS on QUIC streams with the same 2-byte length prefix DoT uses,
*  one query per client-initiated bidirectional stream. It is neither HTTP nor
*  TCP, so it gets its own listener on UDP/853 next to the DoT listener on
*  TCP/853 (different transports may share a port number).
*
*  Like the DoT listener this is a single-threaded event loop: OpenSSL owns the
*  QUIC transport (handshake, loss recovery, flow control, address validation)
*  while every in-flight query is a small non-blocking state machine (read query
*  -> resolve over a non-blocking loopback socket -> write answer -> FIN),
*  multiplexed with poll(). A slow resolve therefore never stalls another
*  connection, and a flood costs a bounded state record rather than a thread.
*
*  The decrypted query is resolved through the shared loopback handoff to dnsmasq
*  (the same private-EDNS attribution as the DoT and DoH paths) and the answer is
*  padded per RFC 8467 when the downstream client asked for it. Here "client" is
*  always that downstream device, never our own QUIC-client role (the outbound
*  side in doq_client.c).
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "server.h"
// dot_frame/dot_deframe (RFC 9250 reuses the DoT framing), DNS_MSG_MAX
#include "framing.h"
// edns_pad_response(), edns_has_padding_option(), edns_has_option()
#include "edns_pad.h"
// global config (webserver.tls.cert, dns.port)
#include "config/config.h"
// killed, thread_names
#include "signals.h"

#if defined(HAVE_TLS) && defined(HAVE_QUIC)

#include <openssl/quic.h>
#include <openssl/bio.h>
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

// RFC 9250 Sec. 4.1.1: DoQ uses UDP port 853 by default - the same number DoT
// uses on TCP, which does not collide.
#define DOQ_PORT 853
// ALPN token for DNS-over-QUIC (RFC 9250 Sec. 4.1.2). QUIC mandates ALPN, so a
// client that does not offer it is rejected during the handshake.
#define DOQ_ALPN_STR "doq"

// Application error codes (RFC 9250 Sec. 4.3).
#define DOQ_NO_ERROR         0x0
#define DOQ_INTERNAL_ERROR   0x1
#define DOQ_PROTOCOL_ERROR   0x2
#define DOQ_EXCESSIVE_LOAD   0x4

// Cap concurrent QUIC connections so a flood cannot exhaust memory.
#define DOQ_MAX_CONNS 64
// Cap concurrent connections from a single source IP so one client cannot hold
// every slot.
#define DOQ_MAX_CONNS_PER_IP 16
// Cap in-flight queries across all connections. Each holds ~192 KiB of pooled
// I/O buffers plus one loopback socket to dnsmasq, so this - not the connection
// count - is what bounds the listener's footprint and its load on dnsmasq.
#define DOQ_MAX_STREAMS 32
// Most concurrent streams a single connection may hold. Together with
// DOQ_MAX_CONNS_PER_IP this bounds what one connection costs; the global
// DOQ_MAX_STREAMS above is what actually caps total in-flight queries.
#define DOQ_MAX_STREAMS_PER_CONN 16
// Most queries a single connection may serve before we close it.
#define DOQ_MAX_QUERIES 64
// Wall-clock budget for one query, re-armed once the query has been read, and
// swept on each poll wake-up: it bounds first the read phase and then the
// resolve+write phase, so neither a slow-drip stream nor a hung resolve can pin
// a slot.
#define DOQ_QUERY_TIMEOUT_S 10
// Absolute cap on a whole connection's lifetime, independent of activity.
#define DOQ_CONN_MAX_LIFETIME_S 120
// Idle cap: a connection without an in-flight query is closed after this long,
// so parked connections do not hold slots.
#define DOQ_CONN_IDLE_TIMEOUT_S 30

// Per-stream buffers, same layout as the DoT listener: rbuf accumulates the
// length-prefixed client query, abuf holds the raw answer, wbuf holds the framed
// bytes being written (the attributed query upstream, then the answer
// downstream - the two never overlap in time).
#define RBUF_SZ (2 + DNS_MSG_MAX)
#define ABUF_SZ (DNS_MSG_MAX)
#define WBUF_SZ (2 + DNS_MSG_MAX)

// EDNS(0) TCP Keepalive (RFC 7828). RFC 9250 Sec. 5.5.2 forbids it on DoQ and
// requires the connection be closed with DOQ_PROTOCOL_ERROR if one arrives.
#define EDNS_OPT_TCP_KEEPALIVE 11

// One QUIC listener: a bound UDP socket plus the OpenSSL listener SSL over it.
struct doq_listener {
	int fd;
	SSL *ssl;
};
static struct doq_listener g_listeners[2]; // IPv4 and IPv6
static int g_nlisten = 0;

// The server context, rebuilt when the certificate on disk changes. The loop is
// single-threaded, so swapping it needs no lock.
static SSL_CTX *g_ctx = NULL;
static time_t g_cert_mtime = 0;

// Stream state machine. The order is the lifecycle of one query.
enum doq_state {
	DQ_READ,       // read the length-prefixed query off the QUIC stream
	DQ_UP_CONNECT, // connect() to the loopback DNS listener (non-blocking)
	DQ_UP_WRITE,   // write the framed query to the loopback listener
	DQ_UP_READ,    // read the framed answer from the loopback listener
	DQ_WRITE       // write the framed answer back on the QUIC stream
};

struct doq_conn;

struct doq_stream {
	bool used;
	struct doq_conn *conn;
	SSL *ssl;                // OpenSSL QUIC child stream object
	int64_t id;
	enum doq_state st;
	int upfd;                // loopback resolve socket (-1 when none is open)
	bool up_pooled;          // upfd came from the shared pool (may be stale)
	bool up_retried;         // already re-connected once for this query
	short up_ev;             // POLLIN or POLLOUT while waiting on upfd
	time_t deadline;         // absolute monotonic deadline for this query
	bool client_padded;      // the query carried an EDNS Padding option

	uint8_t *rbuf; size_t have;           // client read accumulation
	uint8_t *abuf; size_t alen, agot;     // answer from dnsmasq
	uint8_t  lenbuf[2]; size_t up_lengot; // answer length prefix
	uint8_t *wbuf; size_t wlen, woff;     // framed bytes being written
};

struct doq_conn {
	bool used;
	SSL *ssl;                      // OpenSSL QUIC connection object
	int nstreams;                  // streams currently attached to this conn
	int served;                    // queries answered so far (keep-alive cap)
	bool dead;                     // tear down at the end of the iteration
	time_t hard_deadline;          // absolute cap on the connection's lifetime
	time_t idle_deadline;          // closed when it expires with no live stream
	char client[INET6_ADDRSTRLEN]; // downstream client IP (attribution + logging)
	char dest[INET6_ADDRSTRLEN];   // local IP the client reached us on (pi.hole answer)
};

static struct doq_conn g_conns[DOQ_MAX_CONNS];
static struct doq_stream g_streams[DOQ_MAX_STREAMS];
static int g_nconns = 0;
static int g_nstreams = 0;

// Human-readable text for the most recent OpenSSL error. The certificate reload
// path calls this from the DoQ thread while other threads use OpenSSL too, so it
// renders into thread-local storage rather than ERR_error_string()'s process-wide
// buffer. Reads the most recent entry, not the oldest still queued, and drains
// the queue afterwards so a later message cannot report a stale error.
static const char *ossl_err(void)
{
	static _Thread_local char buf[256];
	const unsigned long e = ERR_peek_last_error();
	if(e == 0)
		return "no error";
	ERR_error_string_n(e, buf, sizeof(buf));
	ERR_clear_error();
	return buf;
}

// Monotonic seconds for deadlines: immune to wall-clock steps (NTP/admin
// changes), which time() is not.
static time_t doq_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

// Abort one stream with a DoQ application error code (RFC 9250 Sec. 4.3).
static void doq_reset_stream(SSL *ssl, uint64_t code)
{
	SSL_STREAM_RESET_ARGS args = { .quic_error_code = code };
	SSL_stream_reset(ssl, &args, sizeof(args));
}

// Close a connection immediately with a DoQ application error code, without
// blocking the loop on the flush.
static void doq_close_conn(SSL *ssl, uint64_t code)
{
	SSL_SHUTDOWN_EX_ARGS args;
	memset(&args, 0, sizeof(args));
	args.quic_error_code = code;
	SSL_shutdown_ex(ssl, SSL_SHUTDOWN_FLAG_RAPID | SSL_SHUTDOWN_FLAG_NO_BLOCK,
	                &args, sizeof(args));
}

// ALPN selection: accept only "doq". QUIC mandates ALPN, so a client offering
// anything else is rejected outright rather than served over a guessed protocol.
static int alpn_select_doq(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen, void *arg)
{
	(void)ssl;
	(void)arg;
	const unsigned int want = (unsigned int)strlen(DOQ_ALPN_STR);
	for(unsigned int i = 0; i + 1 <= inlen; )
	{
		const unsigned int l = in[i];
		if(i + 1 + l > inlen)
			break;
		if(l == want && memcmp(&in[i + 1], DOQ_ALPN_STR, want) == 0)
		{
			*out = &in[i + 1];
			*outlen = (unsigned char)want;
			return SSL_TLSEXT_ERR_OK;
		}
		i += 1 + l;
	}
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// Build the QUIC server context from the webserver's PEM (it holds both the
// certificate chain and the private key). Returns NULL on failure (logged).
static SSL_CTX *doq_build_ctx(const char *cert)
{
	SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
	if(ctx == NULL)
	{
		log_err("dotdoh: could not create DoQ SSL_CTX: %s", ossl_err());
		return NULL;
	}
	if(SSL_CTX_use_certificate_chain_file(ctx, cert) != 1)
	{
		log_err("dotdoh: could not load DoQ certificate from %s: %s", cert, ossl_err());
		goto fail;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, cert, SSL_FILETYPE_PEM) != 1)
	{
		log_err("dotdoh: could not load DoQ private key from %s: %s", cert, ossl_err());
		goto fail;
	}
	if(SSL_CTX_check_private_key(ctx) != 1)
	{
		log_err("dotdoh: DoQ private key does not match the certificate in %s: %s",
		        cert, ossl_err());
		goto fail;
	}
	SSL_CTX_set_alpn_select_cb(ctx, alpn_select_doq, NULL);
	// No 0-RTT: early data is replayable, and a replayed DNS query would be
	// answered (and logged) again. This is the OpenSSL default; set it so the
	// intent is explicit and survives a default change.
	SSL_CTX_set_max_early_data(ctx, 0);
	return ctx;

fail:
	SSL_CTX_free(ctx);
	return NULL;
}

// Create a bound, non-blocking UDP socket for the given family, or -1. The v6
// socket is v6-only so v4 and v6 can share port 853 and v4 clients arrive as
// AF_INET rather than v4-mapped.
static int doq_bind_socket(int family)
{
	const int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if(fd < 0)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ %s socket() failed: %s",
		          family == AF_INET ? "IPv4" : "IPv6", strerror(errno));
		return -1;
	}
	// No SO_REUSEADDR here: UDP has no TIME_WAIT to work around, and with the flag
	// a second daemon binds the same port successfully while the kernel delivers
	// the datagrams to only one of us. Without it the clash surfaces as EADDRINUSE.
	const int one = 1;
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
		sa->sin_port = htons(DOQ_PORT);
		slen = sizeof(*sa);
	}
	else
	{
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(void *)&ss;
		sa->sin6_family = AF_INET6;
		sa->sin6_addr = in6addr_any;
		sa->sin6_port = htons(DOQ_PORT);
		slen = sizeof(*sa);
	}
	if(bind(fd, (struct sockaddr *)&ss, slen) != 0)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ %s bind on UDP port %d failed: %s",
		          family == AF_INET ? "IPv4" : "IPv6", DOQ_PORT, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

// Wrap a bound socket in an OpenSSL QUIC listener. Address validation (Retry) is
// on - SSL_LISTENER_FLAG_NO_VALIDATE is deliberately not passed - so an
// off-path spoofer cannot make us amplify traffic towards a forged source.
static SSL *doq_make_listener(int fd)
{
	SSL *l = SSL_new_listener(g_ctx, 0);
	if(l == NULL)
	{
		log_err("dotdoh: DoQ SSL_new_listener() failed: %s", ossl_err());
		return NULL;
	}
	BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
	if(bio == NULL)
	{
		log_err("dotdoh: DoQ BIO_new_dgram() failed: %s", ossl_err());
		SSL_free(l);
		return NULL;
	}
	SSL_set_bio(l, bio, bio); // the listener owns the BIO, not the fd
	SSL_set_blocking_mode(l, 0);
	if(SSL_listen(l) <= 0)
	{
		log_err("dotdoh: DoQ SSL_listen() failed: %s", ossl_err());
		SSL_free(l);
		return NULL;
	}
	return l;
}

static void stream_free(struct doq_stream *s);
static void conn_free(struct doq_conn *c);

// Drop every listener (and its socket). Connections are torn down separately.
static void listeners_close(void)
{
	for(int i = 0; i < g_nlisten; i++)
	{
		if(g_listeners[i].ssl != NULL)
			SSL_free(g_listeners[i].ssl);
		if(g_listeners[i].fd >= 0)
			close(g_listeners[i].fd);
		g_listeners[i].ssl = NULL;
		g_listeners[i].fd = -1;
	}
	g_nlisten = 0;
}

// Bind IPv4 and IPv6 listeners. Returns the number that came up.
static int listeners_open(void)
{
	const int families[2] = { AF_INET, AF_INET6 };
	for(int i = 0; i < 2; i++)
	{
		const int fd = doq_bind_socket(families[i]);
		if(fd < 0)
			continue;
		SSL *l = doq_make_listener(fd);
		if(l == NULL)
		{
			close(fd);
			continue;
		}
		g_listeners[g_nlisten].fd = fd;
		g_listeners[g_nlisten].ssl = l;
		g_nlisten++;
	}
	return g_nlisten;
}

// Rebuild the context and the listeners when the certificate file changes (the
// webserver renews the Pi-hole self-signed certificate before it expires). An
// OpenSSL listener binds the context it was created with, so the listeners - and
// with them the live connections - are recreated; clients reconnect. Renewal is
// a multi-day event, so this is rare.
static void doq_reload_cert_if_changed(void)
{
	const char *cert = config.webserver.tls.cert.v.s;
	if(cert == NULL || cert[0] == '\0')
		return;
	struct stat st;
	if(stat(cert, &st) != 0 || st.st_mtime == g_cert_mtime)
		return;

	SSL_CTX *nctx = doq_build_ctx(cert);
	if(nctx == NULL)
		return; // keep serving the current context; retry on the next change

	SSL_CTX *octx = g_ctx;
	g_ctx = nctx;
	g_cert_mtime = st.st_mtime;

	for(int i = 0; i < DOQ_MAX_STREAMS; i++)
		if(g_streams[i].used)
			stream_free(&g_streams[i]);
	for(int i = 0; i < DOQ_MAX_CONNS; i++)
		if(g_conns[i].used)
			conn_free(&g_conns[i]);
	listeners_close();

	// The old context is released only after everything that referenced it is
	// gone (OpenSSL refcounts it, so this is belt and braces).
	if(octx != NULL)
		SSL_CTX_free(octx);

	if(listeners_open() == 0)
		log_err("dotdoh: DoQ could not rebind after a certificate change");
	else
		log_info("dotdoh: reloaded DoQ certificate from %s", cert);
}

// Release a stream slot. The QUIC stream object is freed even when our FIN is
// still queued: OpenSSL keeps flushing concluded send data after the object
// goes away.
static void stream_free(struct doq_stream *s)
{
	if(!s->used)
		return;
	if(s->ssl != NULL)
		SSL_free(s->ssl);
	if(s->upfd >= 0)
		dotdoh_loopback_drop(s->upfd);
	if(s->conn != NULL)
		s->conn->nstreams--;
	// Keep the pooled I/O buffers attached to the slot for the next stream (they
	// are freed once, at thread shutdown); reset only the bookkeeping.
	uint8_t *rbuf = s->rbuf, *abuf = s->abuf, *wbuf = s->wbuf;
	memset(s, 0, sizeof(*s));
	s->rbuf = rbuf; s->abuf = abuf; s->wbuf = wbuf;
	s->upfd = -1;
	g_nstreams--;
}

// Take a stream slot for an accepted QUIC stream. Returns NULL (having freed the
// stream object) when a cap is reached or an allocation fails.
static struct doq_stream *stream_new(struct doq_conn *c, SSL *ssl)
{
	if(g_nstreams >= DOQ_MAX_STREAMS || c->nstreams >= DOQ_MAX_STREAMS_PER_CONN)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ stream limit reached, resetting a stream from %s",
		          c->client);
		// Tell the client we are overloaded rather than dropping it silently.
		doq_reset_stream(ssl, DOQ_EXCESSIVE_LOAD);
		SSL_free(ssl);
		return NULL;
	}
	struct doq_stream *s = NULL;
	for(int i = 0; i < DOQ_MAX_STREAMS; i++)
		if(!g_streams[i].used) { s = &g_streams[i]; break; }
	if(s == NULL)
	{
		SSL_free(ssl);
		return NULL;
	}

	uint8_t *rbuf = s->rbuf, *abuf = s->abuf, *wbuf = s->wbuf;
	memset(s, 0, sizeof(*s));
	s->upfd = -1; // hold the "no loopback socket open" invariant from the start
	s->rbuf = rbuf != NULL ? rbuf : malloc(RBUF_SZ);
	s->abuf = abuf != NULL ? abuf : malloc(ABUF_SZ);
	s->wbuf = wbuf != NULL ? wbuf : malloc(WBUF_SZ);
	if(s->rbuf == NULL || s->abuf == NULL || s->wbuf == NULL)
	{
		// Leave any successfully-allocated buffers attached for a later retry;
		// they are released at thread shutdown.
		doq_reset_stream(ssl, DOQ_INTERNAL_ERROR);
		SSL_free(ssl);
		return NULL;
	}

	s->used = true;
	s->conn = c;
	s->ssl = ssl;
	s->id = (int64_t)SSL_get_stream_id(ssl);
	s->st = DQ_READ;
	s->deadline = doq_now() + DOQ_QUERY_TIMEOUT_S;
	c->nstreams++;
	g_nstreams++;
	return s;
}

// Release a connection slot together with every stream still attached to it.
static void conn_free(struct doq_conn *c)
{
	if(!c->used)
		return;
	for(int i = 0; i < DOQ_MAX_STREAMS; i++)
		if(g_streams[i].used && g_streams[i].conn == c)
			stream_free(&g_streams[i]);
	if(c->ssl != NULL)
	{
		// Best-effort immediate close; do not block the loop flushing it.
		doq_close_conn(c->ssl, DOQ_NO_ERROR);
		SSL_free(c->ssl);
	}
	memset(c, 0, sizeof(*c));
	g_nconns--;
}

// Format the QUIC peer address of a freshly accepted connection into out.
// Returns false when OpenSSL has no usable peer address, which fails the
// connection closed rather than attributing it to an unknown client.
static bool conn_peer_ip(SSL *ssl, char *out, size_t outlen)
{
	BIO_ADDR *ba = BIO_ADDR_new();
	if(ba == NULL)
		return false;
	bool ok = false;
	if(SSL_get_peer_addr(ssl, ba) == 1)
	{
		const int fam = BIO_ADDR_family(ba);
		if(fam == AF_INET)
		{
			struct in_addr a4;
			size_t al = sizeof(a4);
			if(BIO_ADDR_rawaddress(ba, &a4, &al) == 1)
				ok = inet_ntop(AF_INET, &a4, out, (socklen_t)outlen) != NULL;
		}
		else if(fam == AF_INET6)
		{
			struct in6_addr a6;
			size_t al = sizeof(a6);
			if(BIO_ADDR_rawaddress(ba, &a6, &al) == 1)
				ok = inet_ntop(AF_INET6, &a6, out, (socklen_t)outlen) != NULL;
		}
	}
	BIO_ADDR_free(ba);
	return ok;
}

// The local address this peer reached us on. OpenSSL's QUIC API exposes the peer
// address but no per-connection local address, and the listener is bound to the
// wildcard, so ask the kernel which source address it would use to reach that
// peer - the very address it would put on a reply datagram, and therefore the one
// a plain-DNS answer would be built from. Without it pi.hole/<hostname> would be
// answered from the loopback forward (127.0.0.1), which is useless to a LAN
// client. Leaves out[0] = '\0' when it cannot be determined, exactly like the DoT
// listener does when getsockname() fails.
static void conn_local_ip(const char *peer, char *out, size_t outlen)
{
	out[0] = '\0';
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t slen;
	int family;
	if(inet_pton(AF_INET, peer, &((struct sockaddr_in *)(void *)&ss)->sin_addr) == 1)
	{
		struct sockaddr_in *sa = (struct sockaddr_in *)(void *)&ss;
		sa->sin_family = family = AF_INET;
		sa->sin_port = htons(DOQ_PORT);
		slen = sizeof(*sa);
	}
	else if(inet_pton(AF_INET6, peer, &((struct sockaddr_in6 *)(void *)&ss)->sin6_addr) == 1)
	{
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(void *)&ss;
		sa->sin6_family = family = AF_INET6;
		sa->sin6_port = htons(DOQ_PORT);
		slen = sizeof(*sa);
	}
	else
		return;

	// connect() on a UDP socket only fixes the route, it sends nothing.
	const int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(fd < 0)
		return;
	struct sockaddr_storage local;
	socklen_t llen = sizeof(local);
	if(connect(fd, (struct sockaddr *)&ss, slen) == 0 &&
	   getsockname(fd, (struct sockaddr *)&local, &llen) == 0)
	{
		if(local.ss_family == AF_INET6)
		{
			struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(void *)&local;
			if(!IN6_IS_ADDR_UNSPECIFIED(&sa->sin6_addr))
				inet_ntop(AF_INET6, &sa->sin6_addr, out, (socklen_t)outlen);
		}
		else if(local.ss_family == AF_INET)
		{
			struct sockaddr_in *sa = (struct sockaddr_in *)(void *)&local;
			// The unspecified address is FTL's internal-traffic marker, never a
			// reachable answer for pi.hole - convey nothing rather than 0.0.0.0.
			if(sa->sin_addr.s_addr != htonl(INADDR_ANY))
				inet_ntop(AF_INET, &sa->sin_addr, out, (socklen_t)outlen);
		}
	}
	close(fd);
}

// Take a connection slot for an accepted QUIC connection. Returns NULL (having
// freed the connection object) when a cap is hit or the peer is not allowed.
static struct doq_conn *conn_new(SSL *ssl)
{
	char client[INET6_ADDRSTRLEN];
	if(!conn_peer_ip(ssl, client, sizeof(client)))
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ connection without a usable peer address, dropping");
		SSL_free(ssl);
		return NULL;
	}

	// Apply dns.listeningMode: drop non-local clients unless LISTEN_ALL.
	if(!dotdoh_source_allowed(client))
	{
		log_debug(DEBUG_TLS, "dotdoh: refused DoQ connection from non-local client %s", client);
		SSL_free(ssl);
		return NULL;
	}
	if(g_nconns >= DOQ_MAX_CONNS)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ connection limit (%d) reached, dropping %s",
		          DOQ_MAX_CONNS, client);
		SSL_free(ssl);
		return NULL;
	}
	int same_src = 0;
	for(int i = 0; i < DOQ_MAX_CONNS; i++)
		if(g_conns[i].used && strcmp(g_conns[i].client, client) == 0)
			same_src++;
	if(same_src >= DOQ_MAX_CONNS_PER_IP)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ per-source limit (%d) reached for %s, dropping",
		          DOQ_MAX_CONNS_PER_IP, client);
		SSL_free(ssl);
		return NULL;
	}
	struct doq_conn *c = NULL;
	for(int i = 0; i < DOQ_MAX_CONNS; i++)
		if(!g_conns[i].used) { c = &g_conns[i]; break; }
	if(c == NULL)
	{
		SSL_free(ssl);
		return NULL;
	}

	memset(c, 0, sizeof(*c));
	c->used = true;
	c->ssl = ssl;
	c->hard_deadline = doq_now() + DOQ_CONN_MAX_LIFETIME_S;
	c->idle_deadline = doq_now() + DOQ_CONN_IDLE_TIMEOUT_S;
	snprintf(c->client, sizeof(c->client), "%s", client);
	conn_local_ip(client, c->dest, sizeof(c->dest));

	SSL_set_blocking_mode(ssl, 0);
	// We accept and drive streams by hand; do not auto-create a default stream.
	SSL_set_default_stream_mode(ssl, SSL_DEFAULT_STREAM_MODE_NONE);
	SSL_set_incoming_stream_policy(ssl, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

	g_nconns++;
	return c;
}

// Open a non-blocking loopback socket to dnsmasq's own DNS listener and begin
// connecting. Returns 0 and sets s->upfd + the wait state, or -1 on failure.
//
// One socket per stream, not per connection as the DoT listener does: DoQ streams
// on one connection are concurrent, so a shared socket would serialize them
// behind each other. The concurrent-stream cap is what bounds how many of these
// exist at once.
static int stream_start_resolve(struct doq_stream *s)
{
	// Reuse a pooled loopback socket when one is available: dnsmasq forks a
	// child per TCP connection, so creating one per stream would fork per query.
	s->upfd = dotdoh_loopback_take();
	if(s->upfd >= 0)
	{
		s->up_pooled = true;
		s->st = DQ_UP_WRITE;
		s->up_ev = POLLOUT;
		return 0;
	}
	if(s->upfd == -2)
	{
		// At the concurrency limit; server.c has already logged the summary. Tell
		// the client why, as the stream-cap path does - a bare teardown reads as
		// DOQ_NO_ERROR and gives it no reason to back off.
		log_debug(DEBUG_TLS, "dotdoh: DoQ query from %s refused, concurrency limit reached",
		          s->conn->client);
		doq_reset_stream(s->ssl, DOQ_EXCESSIVE_LOAD);
		return -1;
	}
	s->up_pooled = false;
	s->upfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if(s->upfd < 0)
	{
		// take() reserved an in-flight slot even though the pool was empty; give
		// it back or the count never recovers.
		dotdoh_loopback_drop(-1);
		return -1;
	}
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(config.dns.port.v.u16);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	const int r = connect(s->upfd, (struct sockaddr *)&sa, sizeof(sa));
	if(r == 0)
	{
		s->st = DQ_UP_WRITE; // connected immediately (loopback often is)
		s->up_ev = POLLOUT;
		return 0;
	}
	if(errno == EINPROGRESS)
	{
		s->st = DQ_UP_CONNECT;
		s->up_ev = POLLOUT;
		return 0;
	}
	return -1;
}

// Re-run the resolve on a fresh loopback socket after a pooled one turned out to
// be stale. The framed query is still in wbuf, so it is simply resent. Returns
// the drive contract: 1 keep driving, 0 yield, -1 give up.
static int stream_retry_upstream(struct doq_stream *s)
{
	dotdoh_loopback_drop(s->upfd);
	s->upfd = -1;
	s->up_pooled = false;
	s->up_retried = true;
	s->woff = 0;                       // resend the framed query from the start
	s->alen = 0; s->agot = 0; s->up_lengot = 0;
	if(stream_start_resolve(s) != 0)
		return -1;
	return s->st == DQ_UP_CONNECT ? 0 : 1;
}

// State-handler return contract (shared by the helpers below and drive_stream's
// switch): 1 = keep driving (state advanced, loop again), 0 = yield until the
// next poll, -1 = the stream is finished or broken and must be torn down.

// DQ_READ: buffer and deframe the client query. On a complete query, attribute
// it to the real downstream client and kick off the loopback resolve.
static int drive_read(struct doq_stream *s)
{
	size_t off = 0;
	const ssize_t qlen = dot_deframe(s->rbuf, s->have, &off);
	if(qlen < 0)
		return -1; // protocol error (zero-length frame)
	if(qlen == 0)
	{
		if(s->have >= RBUF_SZ)
			return -1; // a frame larger than we will ever accept
		size_t nread = 0;
		const int r = SSL_read_ex(s->ssl, s->rbuf + s->have, RBUF_SZ - s->have, &nread);
		if(r == 1 && nread > 0)
		{
			s->have += nread;
			return 1; // try to deframe again
		}
		if(r == 1)
			return 0; // read nothing: wait for more datagrams rather than fail
		const int e = SSL_get_error(s->ssl, r);
		if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			return 0; // more datagrams needed; the loop re-drives us
		return -1;    // FIN before a full query, a reset, or a hard error
	}

	// RFC 9250 Sec. 5.5.2: edns-tcp-keepalive is a protocol error on DoQ.
	if(edns_has_option(s->rbuf + off, (size_t)qlen, EDNS_OPT_TCP_KEEPALIVE))
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ query from %s carried edns-tcp-keepalive, "
		          "closing the connection", s->conn->client);
		doq_close_conn(s->conn->ssl, DOQ_PROTOCOL_ERROR);
		s->conn->dead = true;
		return -1;
	}

	// A full query is buffered at rbuf[off .. off+qlen). Give it a fresh
	// deadline now that the read phase is over.
	s->deadline = doq_now() + DOQ_QUERY_TIMEOUT_S;

	// Remember whether it asked for padding (before we attribute it), then build
	// the client-attributed, framed query straight into wbuf, conveying the local
	// address the client reached us on (conn_local_ip) so pi.hole/<hostname> is
	// answered with that address rather than the loopback forward's.
	s->client_padded = edns_has_padding_option(s->rbuf + off, (size_t)qlen);
	const ssize_t flen = dotdoh_prepare_query(s->rbuf + off, (size_t)qlen,
	                                          s->conn->client,
	                                          s->conn->dest[0] != '\0' ? s->conn->dest : NULL,
	                                          s->wbuf, WBUF_SZ);
	if(flen < 0)
		return -1;
	s->wlen = (size_t)flen;
	s->woff = 0;

	// One query per stream (RFC 9250 Sec. 4.2). Bytes beyond that one message are
	// a protocol violation, so fail the stream instead of silently dropping them:
	// quietly ignoring them would let a non-conformant client smuggle a second
	// message past us.
	if(s->have > off + (size_t)qlen)
	{
		log_debug(DEBUG_TLS, "dotdoh: DoQ stream from %s carried %zu trailing bytes, "
		          "resetting it", s->conn->client, s->have - off - (size_t)qlen);
		doq_reset_stream(s->ssl, DOQ_PROTOCOL_ERROR);
		return -1;
	}
	s->have = 0;

	if(stream_start_resolve(s) != 0)
		return -1;
	// A loopback connect usually completes immediately (DQ_UP_WRITE); if it is
	// still in flight, yield so the SO_ERROR check runs once it is connected.
	return s->st == DQ_UP_CONNECT ? 0 : 1;
}

// DQ_UP_WRITE: write the framed, attributed query to the loopback upstream.
static int drive_up_write(struct doq_stream *s)
{
	while(s->woff < s->wlen)
	{
		const ssize_t w = write(s->upfd, s->wbuf + s->woff, s->wlen - s->woff);
		if(w > 0) { s->woff += (size_t)w; continue; }
		if(w < 0 && errno == EINTR) continue;
		if(w < 0 && errno == EAGAIN) { s->up_ev = POLLOUT; return 0; }
		// A pooled socket the peer closed between the checkout probe and this
		// write fails here; resend once on a fresh one, as the DoT path does.
		if(s->up_pooled && !s->up_retried)
			return stream_retry_upstream(s);
		return -1;
	}
	s->alen = 0; s->agot = 0; s->up_lengot = 0;
	s->st = DQ_UP_READ;
	s->up_ev = POLLIN;
	return 1;
}

// DQ_UP_READ: read the framed answer from the loopback upstream, optionally pad
// it (RFC 8467), and frame it for the write back to the client.
static int drive_up_read(struct doq_stream *s)
{
	while(s->up_lengot < 2)
	{
		const ssize_t r = read(s->upfd, s->lenbuf + s->up_lengot, 2 - s->up_lengot);
		if(r > 0) { s->up_lengot += (size_t)r; continue; }
		if(r < 0 && errno == EINTR) continue;
		if(r < 0 && errno == EAGAIN) { s->up_ev = POLLIN; return 0; }
		// A pooled socket dnsmasq closed after its own keep-alive limit fails
		// here before a single answer byte: reconnect once and resend.
		if(s->up_pooled && !s->up_retried && s->up_lengot == 0)
			return stream_retry_upstream(s);
		return -1; // closed early or error
	}
	if(s->alen == 0)
	{
		s->alen = ((size_t)s->lenbuf[0] << 8) | (size_t)s->lenbuf[1];
		if(s->alen == 0 || s->alen > ABUF_SZ)
			return -1;
	}
	while(s->agot < s->alen)
	{
		const ssize_t r = read(s->upfd, s->abuf + s->agot, s->alen - s->agot);
		if(r > 0) { s->agot += (size_t)r; continue; }
		if(r < 0 && errno == EINTR) continue;
		if(r < 0 && errno == EAGAIN) { s->up_ev = POLLIN; return 0; }
		return -1;
	}

	// Answer complete: hand the socket back so the next query reuses it rather
	// than forking another dnsmasq child.
	dotdoh_loopback_give(s->upfd);
	s->upfd = -1;
	s->up_pooled = false;
	s->up_ev = 0;

	// RFC 8467 Sec. 4: pad the answer only if the query asked for it.
	if(s->client_padded)
		s->alen = edns_pad_response(s->abuf, s->alen, ABUF_SZ);

	const ssize_t flen = dot_frame(s->abuf, s->alen, s->wbuf, WBUF_SZ);
	if(flen < 0)
		return -1;
	s->wlen = (size_t)flen;
	s->woff = 0;
	s->st = DQ_WRITE;
	return 1;
}

// DQ_WRITE: write the framed answer back on the QUIC stream and FIN it, which is
// how DoQ delimits a response (RFC 9250 Sec. 4.2).
static int drive_write(struct doq_stream *s)
{
	while(s->woff < s->wlen)
	{
		size_t written = 0;
		const int w = SSL_write_ex(s->ssl, s->wbuf + s->woff, s->wlen - s->woff, &written);
		if(w == 1 && written > 0) { s->woff += written; continue; }
		if(w == 1)
			return 0; // accepted nothing: yield rather than spin on it
		const int e = SSL_get_error(s->ssl, w);
		if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			return 0; // flow-controlled; the loop re-drives us
		return -1;
	}
	// FIN the response. Either way the stream is done and gets reaped; OpenSSL
	// keeps flushing concluded send data after the stream object is freed.
	SSL_stream_conclude(s->ssl, 0);
	s->conn->served++;
	return -1; // finished: the caller reaps the slot
}

// Drive one stream as far as it can go without blocking. Returns 0 if it is
// still alive, or -1 if it finished or errored and must be torn down.
static int drive_stream(struct doq_stream *s)
{
	for(;;)
	{
		int r;
		switch(s->st)
		{
		case DQ_READ:
			r = drive_read(s);
			break;

		case DQ_UP_CONNECT:
		{
			int err = 0;
			socklen_t l = sizeof(err);
			if(getsockopt(s->upfd, SOL_SOCKET, SO_ERROR, &err, &l) != 0 || err != 0)
				return -1;
			s->st = DQ_UP_WRITE;
			r = 1;
			break;
		}

		case DQ_UP_WRITE:
			r = drive_up_write(s);
			break;

		case DQ_UP_READ:
			r = drive_up_read(s);
			break;

		case DQ_WRITE:
			r = drive_write(s);
			break;

		default:
			return -1;
		}
		if(r <= 0)
			return r;
	}
}

// Accept every QUIC stream the client has opened on this connection. Only
// client-initiated bidirectional streams carry queries; a unidirectional stream
// is not part of DoQ, so it is reset rather than served.
static void conn_accept_streams(struct doq_conn *c)
{
	for(;;)
	{
		SSL *st = SSL_accept_stream(c->ssl, SSL_ACCEPT_STREAM_NO_BLOCK);
		if(st == NULL)
			break;
		if(c->served >= DOQ_MAX_QUERIES)
		{
			// Keep-alive budget exhausted: stop serving and let the connection go.
			doq_reset_stream(st, DOQ_EXCESSIVE_LOAD);
			SSL_free(st);
			c->dead = true;
			continue;
		}
		if((SSL_get_stream_type(st) & SSL_STREAM_TYPE_WRITE) == 0)
		{
			// A receive-only (unidirectional) stream cannot carry a response.
			doq_reset_stream(st, DOQ_PROTOCOL_ERROR);
			SSL_free(st);
			continue;
		}
		struct doq_stream *s = stream_new(c, st); // frees st on failure
		if(s == NULL)
			continue;
		c->idle_deadline = doq_now() + DOQ_CONN_IDLE_TIMEOUT_S;
		if(drive_stream(s) < 0)
			stream_free(s);
	}
}

// Accept every connection whose handshake completed on this listener.
static void listener_accept_all(SSL *listener)
{
	for(;;)
	{
		SSL *cs = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
		if(cs == NULL)
			break;
		struct doq_conn *c = conn_new(cs); // frees cs on failure
		if(c != NULL)
			conn_accept_streams(c);
	}
}

// How long poll() may sleep before an OpenSSL QUIC timer needs service, capped
// so a stopping thread is noticed promptly and the deadline sweep still runs.
static int doq_event_timeout_ms(void)
{
	int best = 1000;
	struct timeval tv;
	int inf = 0;
	for(int i = 0; i < g_nlisten; i++)
		if(SSL_get_event_timeout(g_listeners[i].ssl, &tv, &inf) == 1 && !inf)
		{
			const long ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
			if(ms < best)
				best = ms < 0 ? 0 : (int)ms;
		}
	for(int i = 0; i < DOQ_MAX_CONNS; i++)
		if(g_conns[i].used &&
		   SSL_get_event_timeout(g_conns[i].ssl, &tv, &inf) == 1 && !inf)
		{
			const long ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
			if(ms < best)
				best = ms < 0 ? 0 : (int)ms;
		}
	return best;
}

// Tear down connections that are dead, closed by the peer, or over a deadline.
static void doq_reap(void)
{
	const time_t now = doq_now();

	// Streams first: a stream over its deadline is a stalled query, not
	// necessarily a bad connection, so only the stream goes.
	for(int i = 0; i < DOQ_MAX_STREAMS; i++)
	{
		struct doq_stream *s = &g_streams[i];
		if(!s->used)
			continue;
		if(now >= s->deadline)
		{
			log_debug(DEBUG_TLS, "dotdoh: DoQ query from %s timed out", s->conn->client);
			doq_reset_stream(s->ssl, DOQ_INTERNAL_ERROR);
			stream_free(s);
		}
	}

	for(int i = 0; i < DOQ_MAX_CONNS; i++)
	{
		struct doq_conn *c = &g_conns[i];
		if(!c->used)
			continue;
		SSL_CONN_CLOSE_INFO info;
		const bool closed = SSL_get_conn_close_info(c->ssl, &info, sizeof(info)) == 1;
		const bool idle = c->nstreams == 0 && now >= c->idle_deadline;
		if(c->dead || closed || idle || now >= c->hard_deadline)
			conn_free(c);
	}
}

void *dotdoh_doq_thread(void *val)
{
	(void)val;
	prctl(PR_SET_NAME, thread_names[DOTDOH_DOQ], 0, 0, 0);

	// The main thread handles termination signals; this loop only checks `killed`.
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	for(int i = 0; i < DOQ_MAX_STREAMS; i++)
		g_streams[i].upfd = -1;

	// Wait for the webserver thread to write the TLS certificate before loading
	// it. On a fresh install it does not exist yet; retrying (instead of exiting)
	// avoids leaving DoQ down until the next restart. `killed` breaks us out.
	bool waited = false;
	for(;;)
	{
		const char *cert = config.webserver.tls.cert.v.s;
		if(cert != NULL && cert[0] != '\0' && access(cert, R_OK) == 0)
		{
			g_ctx = doq_build_ctx(cert);
			if(g_ctx != NULL)
			{
				struct stat st;
				g_cert_mtime = stat(cert, &st) == 0 ? st.st_mtime : 0;
				break;
			}
		}
		if(killed)
			return NULL;
		if(!waited)
		{
			log_info("dotdoh: DoQ waiting for the webserver TLS certificate");
			waited = true;
		}
		const struct timespec wait = { .tv_sec = 1, .tv_nsec = 0 };
		nanosleep(&wait, NULL);
	}

	if(listeners_open() == 0)
	{
		log_err("dotdoh: DoQ listener could not bind any socket on UDP port %d", DOQ_PORT);
		SSL_CTX_free(g_ctx);
		g_ctx = NULL;
		return NULL;
	}
	log_info("dotdoh: DoQ server listening on UDP port %d", DOQ_PORT);

	time_t last_cert_check = doq_now();
	while(!killed)
	{
		// Pick up a renewed certificate (checked at a coarse interval; renewal is
		// on a multi-day timescale, so a minute of detection latency is fine).
		const time_t tnow = doq_now();
		if(tnow - last_cert_check >= 60)
		{
			last_cert_check = tnow;
			doq_reload_cert_if_changed();
		}
		if(g_nlisten == 0)
		{
			// A rebind after a certificate change failed: back off and retry,
			// rather than sitting idle until the certificate changes again.
			const struct timespec wait = { .tv_sec = 1, .tv_nsec = 0 };
			nanosleep(&wait, NULL);
			listeners_open();
			continue;
		}

		// Poll set: every listener socket plus the loopback socket of each stream
		// currently waiting on one.
		struct pollfd pfd[2 + DOQ_MAX_STREAMS];
		struct doq_stream *pstream[2 + DOQ_MAX_STREAMS];
		nfds_t n = 0;
		for(int i = 0; i < g_nlisten; i++)
		{
			pfd[n].fd = g_listeners[i].fd;
			pfd[n].events = POLLIN;
			if(SSL_net_write_desired(g_listeners[i].ssl))
				pfd[n].events |= POLLOUT;
			pfd[n].revents = 0;
			pstream[n] = NULL;
			n++;
		}
		// A connection may also need to write; its datagrams leave through a
		// listener socket, so arm POLLOUT on all of them.
		bool conn_wants_write = false;
		for(int i = 0; i < DOQ_MAX_CONNS && !conn_wants_write; i++)
			if(g_conns[i].used && SSL_net_write_desired(g_conns[i].ssl))
				conn_wants_write = true;
		if(conn_wants_write)
			for(nfds_t k = 0; k < n; k++)
				pfd[k].events |= POLLOUT;
		for(int i = 0; i < DOQ_MAX_STREAMS; i++)
		{
			struct doq_stream *s = &g_streams[i];
			if(!s->used || s->upfd < 0 || s->up_ev == 0)
				continue;
			pfd[n].fd = s->upfd;
			pfd[n].events = s->up_ev;
			pfd[n].revents = 0;
			pstream[n] = s;
			n++;
		}

		const int pr = poll(pfd, n, doq_event_timeout_ms());
		if(pr < 0 && errno != EINTR)
		{
			const struct timespec backoff = { .tv_sec = 0, .tv_nsec = 100000000 };
			nanosleep(&backoff, NULL);
			continue;
		}

		// Let OpenSSL process incoming datagrams and fire its timers.
		for(int i = 0; i < g_nlisten; i++)
			SSL_handle_events(g_listeners[i].ssl);
		for(int i = 0; i < DOQ_MAX_CONNS; i++)
			if(g_conns[i].used)
				SSL_handle_events(g_conns[i].ssl);

		// New connections, then new streams on existing connections.
		for(int i = 0; i < g_nlisten; i++)
			listener_accept_all(g_listeners[i].ssl);
		for(int i = 0; i < DOQ_MAX_CONNS; i++)
			if(g_conns[i].used && !g_conns[i].dead)
				conn_accept_streams(&g_conns[i]);

		// Drive every live stream. QUIC readiness is not an fd condition, so the
		// stream states that read or write on the connection are simply retried
		// each wake-up; the loopback states only run when their fd is ready.
		for(nfds_t i = 0; i < n; i++)
			if(pstream[i] != NULL && pstream[i]->used && pfd[i].revents != 0 &&
			   drive_stream(pstream[i]) < 0)
				stream_free(pstream[i]);
		for(int i = 0; i < DOQ_MAX_STREAMS; i++)
		{
			struct doq_stream *s = &g_streams[i];
			if(!s->used || s->upfd >= 0)
				continue; // loopback states are driven by their fd above
			if(drive_stream(s) < 0)
				stream_free(s);
		}

		doq_reap();
	}

	for(int i = 0; i < DOQ_MAX_STREAMS; i++)
		if(g_streams[i].used)
			stream_free(&g_streams[i]);
	for(int i = 0; i < DOQ_MAX_CONNS; i++)
		if(g_conns[i].used)
			conn_free(&g_conns[i]);
	// Release the pooled per-stream buffers (kept attached across reuse). Only
	// slots that actually served a stream have them; guard against NULL as FTL's
	// free() wrapper warns on a NULL argument.
	for(int i = 0; i < DOQ_MAX_STREAMS; i++)
	{
		if(g_streams[i].rbuf != NULL) free(g_streams[i].rbuf);
		if(g_streams[i].abuf != NULL) free(g_streams[i].abuf);
		if(g_streams[i].wbuf != NULL) free(g_streams[i].wbuf);
		g_streams[i].rbuf = g_streams[i].abuf = g_streams[i].wbuf = NULL;
	}
	listeners_close();
	if(g_ctx != NULL)
	{
		SSL_CTX_free(g_ctx);
		g_ctx = NULL;
	}
	return NULL;
}

#else // !HAVE_TLS || !HAVE_QUIC

// Without OpenSSL QUIC there is no DoQ listener. dns.doq still starts this
// thread, which returns immediately, so the setting is inert rather than fatal.
// The stub is a const-folding candidate, so silence the GCC-only
// -Wsuggest-attribute suggestion that -Werror would otherwise turn into a build
// failure on any OpenSSL older than 4.0.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#endif
void *dotdoh_doq_thread(void *val)
{
	(void)val;
	return NULL;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif // HAVE_TLS && HAVE_QUIC
