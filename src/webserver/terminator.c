/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  In-process TLS front terminator (HTTP/1.1)
*
*  Milestone M1: bind the public TLS port, terminate TLS, and forward the plain
*  HTTP/1.1 byte stream to the CivetWeb backend on the loopback interface. TLS is
*  the only thing this layer understands; everything above it (HTTP framing,
*  keep-alive, routing, Lua, auth) stays in CivetWeb, which now speaks plain
*  HTTP/1.1 on loopback. HTTP/2 (nghttp2) and HTTP/3 (nghttp3/QUIC) are added on
*  top of this in later milestones.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/terminator.h"
// log_err(), log_info(), log_warn()
#include "log.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef HAVE_HTTP2
#include <nghttp2/nghttp2.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

// Bidirectional relay buffer size (per direction, per iteration).
#define RELAY_BUF 16384u
// Socket send/receive timeout so a stuck peer cannot pin a handler thread.
#define IO_TIMEOUT_SEC 30

// Terminator state. There is a single terminator instance for the whole
// process, mirroring the single CivetWeb context in webserver.c.
static SSL_CTX *ssl_ctx = NULL;
static int listen_fd = -1;
static int backend_port = 0;
static volatile bool running = false;
static pthread_t accept_tid;
static bool accept_tid_valid = false;

// Log the pending OpenSSL error queue at error level, prefixed with context.
static void log_ssl_errors(const char *context)
{
	unsigned long e;
	while((e = ERR_get_error()) != 0)
	{
		char buf[256];
		ERR_error_string_n(e, buf, sizeof(buf));
		log_err("Terminator: %s: %s", context, buf);
	}
}

// ALPN selection: pick our most-preferred protocol that the client offers.
// "h2" is preferred when HTTP/2 support is compiled in, otherwise (and as the
// fallback) "http/1.1". Selection is done by hand to avoid the confusing
// server/client argument order of SSL_select_next_proto().
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
	static const char *const prefs[] = {
#ifdef HAVE_HTTP2
		"h2",
#endif
		"http/1.1"
	};
	(void)ssl;
	(void)arg;
	for(size_t p = 0; p < sizeof(prefs) / sizeof(prefs[0]); p++)
	{
		const size_t plen = strlen(prefs[p]);
		// The client's ALPN list is a sequence of (1-byte length, bytes) entries
		for(unsigned int i = 0; i + 1 <= inlen; )
		{
			const unsigned int l = in[i];
			if(i + 1 + l > inlen)
				break;
			if(l == plen && memcmp(&in[i + 1], prefs[p], plen) == 0)
			{
				*out = &in[i + 1];
				*outlen = (unsigned char)l;
				return SSL_TLSEXT_ERR_OK;
			}
			i += 1 + l;
		}
	}
	// No overlap: decline ALPN, the client falls back to HTTP/1.1
	return SSL_TLSEXT_ERR_NOACK;
}

// Build the server-side SSL_CTX from the combined PEM (certificate + key).
static SSL_CTX *create_server_ctx(const char *cert_path)
{
	SSL_CTX *c = SSL_CTX_new(TLS_server_method());
	if(c == NULL)
	{
		log_ssl_errors("SSL_CTX_new() failed");
		return NULL;
	}
	SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
	// The PEM carries both the certificate (chain) and the private key.
	if(SSL_CTX_use_certificate_chain_file(c, cert_path) != 1 ||
	   SSL_CTX_use_PrivateKey_file(c, cert_path, SSL_FILETYPE_PEM) != 1 ||
	   SSL_CTX_check_private_key(c) != 1)
	{
		log_ssl_errors("loading TLS certificate/key failed");
		SSL_CTX_free(c);
		return NULL;
	}
	SSL_CTX_set_alpn_select_cb(c, alpn_select_cb, NULL);
	return c;
}

// Bind a dual-stack (IPv4 + IPv6) TCP listener on the given port, all
// interfaces. Returns the fd or -1.
static int bind_listener(int port)
{
	// SOCK_CLOEXEC so the fd is not inherited across FTL's execvp() self-restart,
	// where it would keep the port busy and make the new process fail to re-bind.
	const int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if(fd < 0)
	{
		log_err("Terminator: socket() failed: %s", strerror(errno));
		return -1;
	}

	const int on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	// Accept both IPv4 (as v4-mapped) and IPv6 on this single socket.
	const int off = 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_addr = in6addr_any;
	sa.sin6_port = htons((uint16_t)port);
	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		log_err("Terminator: bind() to port %d failed: %s", port, strerror(errno));
		close(fd);
		return -1;
	}
	if(listen(fd, SOMAXCONN) != 0)
	{
		log_err("Terminator: listen() on port %d failed: %s", port, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

// Connect a fresh plaintext TCP socket to the CivetWeb backend on loopback.
// Returns the fd or -1.
static int connect_backend(void)
{
	const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if(fd < 0)
		return -1;

	const struct timeval tv = { .tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)backend_port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		log_err("Terminator: connect to backend 127.0.0.1:%d failed: %s",
		        backend_port, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

// Write the full buffer to a plain fd (blocking socket). Returns 0 or -1.
static int write_all_fd(int fd, const char *buf, size_t len)
{
	while(len > 0)
	{
		const ssize_t n = write(fd, buf, len);
		if(n > 0)
		{
			buf += n;
			len -= (size_t)n;
		}
		else if(n < 0 && errno == EINTR)
			continue;
		else
			return -1;
	}
	return 0;
}

// Write the full buffer to the TLS connection (blocking socket). Returns 0 or -1.
static int write_all_ssl(SSL *ssl, const char *buf, size_t len)
{
	while(len > 0)
	{
		const int n = SSL_write(ssl, buf, (int)len);
		if(n > 0)
		{
			buf += n;
			len -= (size_t)n;
		}
		else
		{
			const int err = SSL_get_error(ssl, n);
			if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
				continue;
			return -1;
		}
	}
	return 0;
}

// Fill a PROXY protocol v2 header describing the real client (source) and the
// local accepting socket (destination) into hdr, which must hold at least 52
// bytes. Returns 0 and the header length in *out_len, or -1 for an unsupported
// address family. CivetWeb parses this header and attributes the request to the
// actual client instead of the loopback terminator, so client-IP-based logging
// and auth stay correct.
static int build_proxy_v2(int client_fd, unsigned char *hdr, size_t *out_len)
{
	struct sockaddr_storage src, dst;
	socklen_t sl = sizeof(src), dl = sizeof(dst);
	if(getpeername(client_fd, (struct sockaddr *)&src, &sl) != 0 ||
	   getsockname(client_fd, (struct sockaddr *)&dst, &dl) != 0)
		return -1;

	static const unsigned char sig[12] =
		{ 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
	memcpy(hdr, sig, sizeof(sig));
	hdr[12] = 0x21; // version 2, PROXY command
	size_t len = 0;

	if(src.ss_family == AF_INET)
	{
		const struct sockaddr_in *s = (const struct sockaddr_in *)&src;
		const struct sockaddr_in *d = (const struct sockaddr_in *)&dst;
		hdr[13] = 0x11; // TCP over IPv4
		hdr[14] = 0; hdr[15] = 12;
		memcpy(hdr + 16, &s->sin_addr, 4);
		memcpy(hdr + 20, &d->sin_addr, 4);
		memcpy(hdr + 24, &s->sin_port, 2);
		memcpy(hdr + 26, &d->sin_port, 2);
		len = 16 + 12;
	}
	else if(src.ss_family == AF_INET6)
	{
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)&src;
		const struct sockaddr_in6 *d = (const struct sockaddr_in6 *)&dst;
		// The listener is dual-stack, so IPv4 clients arrive as v4-mapped IPv6;
		// emit them as IPv4 for a faithful, compact header.
		if(IN6_IS_ADDR_V4MAPPED(&s->sin6_addr))
		{
			hdr[13] = 0x11;
			hdr[14] = 0; hdr[15] = 12;
			memcpy(hdr + 16, s->sin6_addr.s6_addr + 12, 4);
			if(IN6_IS_ADDR_V4MAPPED(&d->sin6_addr))
				memcpy(hdr + 20, d->sin6_addr.s6_addr + 12, 4);
			memcpy(hdr + 24, &s->sin6_port, 2);
			memcpy(hdr + 26, &d->sin6_port, 2);
			len = 16 + 12;
		}
		else
		{
			hdr[13] = 0x21; // TCP over IPv6
			hdr[14] = 0; hdr[15] = 36;
			memcpy(hdr + 16, &s->sin6_addr, 16);
			memcpy(hdr + 32, &d->sin6_addr, 16);
			memcpy(hdr + 48, &s->sin6_port, 2);
			memcpy(hdr + 50, &d->sin6_port, 2);
			len = 16 + 36;
		}
	}
	else
		return -1;

	*out_len = len;
	return 0;
}

// Announce the real client to the backend by writing a PROXY protocol v2 header
// once at the very start of the backend connection, before any request bytes.
// Returns 0 on success, -1 on error.
static int send_proxy_v2(int be_fd, int client_fd)
{
	unsigned char hdr[16 + 36];
	size_t len = 0;
	if(build_proxy_v2(client_fd, hdr, &len) != 0)
		return -1;
	return write_all_fd(be_fd, (const char *)hdr, len);
}

// Relay bytes both ways between the TLS'd client and the plaintext backend until
// either side closes. TLS is transparent here: CivetWeb sees a normal HTTP/1.1
// stream, so keep-alive, chunked bodies, ranges, etc. all work unchanged. The
// real client address was already announced to the backend via send_proxy_v2().
static void relay(SSL *ssl, int client_fd, int be_fd)
{
	char buf[RELAY_BUF];
	for(;;)
	{
		struct pollfd fds[2];
		fds[0].fd = client_fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = be_fd;
		fds[1].events = POLLIN;
		fds[1].revents = 0;

		// If OpenSSL has buffered, already-decrypted data, drain it without
		// waiting in poll() (the socket may not be readable in that case).
		const int timeout = SSL_pending(ssl) > 0 ? 0 : (IO_TIMEOUT_SEC * 1000);
		const int pr = poll(fds, 2, timeout);
		if(pr < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		if(pr == 0)
			break; // idle timeout

		// client -> backend
		if(SSL_pending(ssl) > 0 || (fds[0].revents & (POLLIN | POLLHUP | POLLERR)))
		{
			const int n = SSL_read(ssl, buf, sizeof(buf));
			if(n > 0)
			{
				if(write_all_fd(be_fd, buf, (size_t)n) != 0)
					break;
			}
			else
			{
				const int err = SSL_get_error(ssl, n);
				if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
					break; // clean close or fatal error
			}
		}

		// backend -> client
		if(fds[1].revents & (POLLIN | POLLHUP | POLLERR))
		{
			const ssize_t n = read(be_fd, buf, sizeof(buf));
			if(n > 0)
			{
				if(write_all_ssl(ssl, buf, (size_t)n) != 0)
					break;
			}
			else if(n == 0)
				break; // backend closed
			else if(errno != EINTR)
				break;
		}
	}
}

#ifdef HAVE_HTTP2
// ---------------------------------------------------------------------------
// HTTP/2 gateway (ALPN "h2")
//
// Runs an nghttp2 server session on the TLS connection and bridges every request
// stream to a plain HTTP/1.1 request against the CivetWeb backend, translating
// the response back to HTTP/2. CivetWeb keeps speaking HTTP/1.1 and never sees
// HTTP/2.
//
// The gateway streams and multiplexes: each request stream gets its own
// non-blocking backend connection, the request body is streamed to the backend
// as it arrives (respecting HTTP/2 flow control), and the HTTP/1.1 response is
// parsed incrementally and pulled back into HTTP/2 DATA frames on demand via an
// nghttp2 data provider. A single poll() loop drives the client TLS socket and
// every active backend socket, so many streams make progress concurrently and
// no single stream blocks the whole session.
// ---------------------------------------------------------------------------

#define H2_REQHDR_MAX 8192u
#define H2_MAX_HDRS 64u
// Response header block size cap before we give up parsing.
#define H2_RESP_HDR_MAX 65536u
// Per-stream decoded response body high-water mark: once this much undelivered
// body is buffered we stop reading the backend, applying backpressure toward the
// (slower) client.
#define H2_BODY_HIGH_WATER (256u * 1024u)
// Soft cap on the outbound TLS buffer; we stop pulling more frames out of
// nghttp2 once this much is queued for SSL_write().
#define H2_WBUF_SOFT_CAP (512u * 1024u)
// Maximum PROXY protocol v2 header size (16 fixed + 36 for IPv6).
#define H2_PROXY_MAX 52u

// EAGAIN and EWOULDBLOCK are the same value on Linux; test both only where they
// actually differ so -Wlogical-op stays quiet.
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
#define WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
#define WOULDBLOCK(e) ((e) == EAGAIN)
#endif

// Request body framing towards the HTTP/1.1 backend.
enum { REQ_NONE, REQ_RAW, REQ_CHUNKED };
// Response body framing from the HTTP/1.1 backend.
enum { BODY_NONE, BODY_LENGTH, BODY_CHUNKED, BODY_CLOSE };
// Incremental Transfer-Encoding: chunked decoder states.
enum { CH_SIZE, CH_EXT, CH_SIZE_LF, CH_DATA, CH_DATA_CR, CH_DATA_LF, CH_TRAILER, CH_DONE };

struct h2_conn;

struct h2_stream {
	struct h2_stream *next;
	struct h2_conn *conn;
	int32_t stream_id;

	// Request pseudo-headers and the reconstructed HTTP/1.1 header block
	char method[16];
	char authority[256];
	char path[2048];
	char reqhdr[H2_REQHDR_MAX];
	size_t reqhdr_len;
	bool content_length_seen;

	// Backend connection (non-blocking)
	int be_fd;
	bool be_connecting;

	// Outbound request buffer (PROXY header + HTTP/1.1 head + body), drained to
	// the backend from [req_out_off, req_out_len)
	char *req_out;
	size_t req_out_len, req_out_off, req_out_cap;
	int req_mode;
	bool req_started;
	// Client DATA bytes appended but not yet acknowledged to nghttp2's flow
	// control; credited once they have been flushed to the backend.
	size_t body_uncredited;

	// Response header accumulation and parse state
	bool resp_headers_parsed;
	bool resp_headers_sent;
	char *resp_hdr;
	size_t resp_hdr_len, resp_hdr_cap;

	// Response body framing / decoder state
	int body_mode;
	size_t body_remaining;   // BODY_LENGTH: bytes still expected
	int chunk_state;
	size_t chunk_size;       // chunked: size being accumulated
	size_t chunk_remaining;  // chunked: bytes left in the current chunk
	size_t trailer_line_len; // chunked: length of the current trailer line

	// Decoded response body ready for the nghttp2 data provider, served from
	// [body_off, body_len)
	char *body_buf;
	size_t body_len, body_off, body_cap;
	bool resp_complete;      // full response body has been decoded
	bool resp_deferred;      // data provider is parked on NGHTTP2_ERR_DEFERRED
	bool error;              // gateway error: backend torn down, stream ending
};

struct h2_conn {
	SSL *ssl;
	int client_fd;
	nghttp2_session *session;
	struct h2_stream *streams; // singly linked list of active streams

	// Outbound TLS buffer: serialized nghttp2 frames awaiting SSL_write(),
	// pending in [woff, wlen)
	char *wbuf;
	size_t wlen, woff, wcap;
	bool ssl_want_write;       // last SSL_write() returned WANT_WRITE

	// Reused poll() scratch buffers (pfds[0] is always the client fd)
	struct pollfd *pfds;
	struct h2_stream **pmap;
	size_t pcap;
};

// Put fd into non-blocking mode. Returns 0 or -1.
static int set_nonblocking(int fd)
{
	const int fl = fcntl(fd, F_GETFL, 0);
	if(fl < 0)
		return -1;
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

// Open a non-blocking plaintext TCP socket to the CivetWeb backend on loopback.
// Sets *connected to true if the connection completed immediately (the common
// case on loopback), false if it is still in progress (EINPROGRESS). Returns the
// fd or -1.
static int connect_backend_nb(bool *connected)
{
	const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if(fd < 0)
		return -1;

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)backend_port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	const int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if(r == 0)
	{
		*connected = true;
		return fd;
	}
	if(errno == EINPROGRESS)
	{
		*connected = false;
		return fd;
	}
	close(fd);
	return -1;
}

// Append n bytes to a growing heap buffer. Returns 0 or -1.
static int buf_append(char **buf, size_t *len, size_t *cap, const char *data, size_t n)
{
	if(*len + n > *cap)
	{
		size_t newcap = (*cap == 0) ? 8192 : *cap;
		while(newcap < *len + n)
			newcap *= 2;
		char *nb = realloc(*buf, newcap);
		if(nb == NULL)
			return -1;
		*buf = nb;
		*cap = newcap;
	}
	memcpy(*buf + *len, data, n);
	*len += n;
	return 0;
}

// Hop-by-hop / pseudo-reconstructed headers that must not be forwarded.
static bool h2_skip_header(const char *name, size_t len)
{
	static const char *const skip[] = {
		"connection", "keep-alive", "proxy-connection", "transfer-encoding",
		"upgrade", "te", "host", "http2-settings"
	};
	for(size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++)
		if(len == strlen(skip[i]) && strncasecmp(name, skip[i], len) == 0)
			return true;
	return false;
}

// Queue bytes to send to the backend, compacting already-sent data first so the
// buffer does not grow without bound. Returns 0 or -1.
static int h2_req_push(struct h2_stream *s, const char *data, size_t n)
{
	if(s->req_out_off > 0)
	{
		memmove(s->req_out, s->req_out + s->req_out_off, s->req_out_len - s->req_out_off);
		s->req_out_len -= s->req_out_off;
		s->req_out_off = 0;
	}
	return buf_append(&s->req_out, &s->req_out_len, &s->req_out_cap, data, n);
}

// Queue decoded response body bytes for the data provider, compacting already-
// delivered data first. Returns 0 or -1.
static int h2_body_push(struct h2_stream *s, const char *data, size_t n)
{
	if(s->body_off > 0)
	{
		memmove(s->body_buf, s->body_buf + s->body_off, s->body_len - s->body_off);
		s->body_len -= s->body_off;
		s->body_off = 0;
	}
	return buf_append(&s->body_buf, &s->body_len, &s->body_cap, data, n);
}

static void h2_stream_link(struct h2_conn *c, struct h2_stream *s)
{
	s->next = c->streams;
	c->streams = s;
}

static void h2_stream_unlink(struct h2_conn *c, struct h2_stream *s)
{
	struct h2_stream **pp = &c->streams;
	while(*pp != NULL)
	{
		if(*pp == s)
		{
			*pp = s->next;
			return;
		}
		pp = &(*pp)->next;
	}
}

static void h2_stream_free(struct h2_stream *s)
{
	if(s == NULL)
		return;
	if(s->be_fd >= 0)
		close(s->be_fd);
	free(s->req_out);
	free(s->resp_hdr);
	free(s->body_buf);
	free(s);
}

// Close the backend socket and return any request-body bytes that were charged
// against the flow-control window but never forwarded to the connection window.
// With manual window management nghttp2 does not reclaim these on stream close,
// so failing to do this would slowly shrink the shared connection window.
static void h2_be_close(struct h2_stream *s)
{
	if(s->be_fd >= 0)
	{
		close(s->be_fd);
		s->be_fd = -1;
	}
	s->be_connecting = false;
	if(s->body_uncredited > 0)
	{
		nghttp2_session_consume_connection(s->conn->session, s->body_uncredited);
		s->body_uncredited = 0;
	}
}

// Fail a stream at the gateway: tear down its backend socket and either submit a
// status-only response (if nothing has been sent yet) or reset the stream (if
// the response head is already on the wire).
static void h2_gateway_error(struct h2_stream *s, const char *status3)
{
	h2_be_close(s);
	s->error = true;
	s->resp_complete = true;
	if(s->resp_headers_sent)
	{
		nghttp2_submit_rst_stream(s->conn->session, NGHTTP2_FLAG_NONE,
		                          s->stream_id, NGHTTP2_INTERNAL_ERROR);
	}
	else
	{
		const nghttp2_nv nva[] = {
			{ (uint8_t *)":status", (uint8_t *)status3, 7, 3, NGHTTP2_NV_FLAG_NONE }
		};
		nghttp2_submit_response2(s->conn->session, s->stream_id, nva, 1, NULL);
		s->resp_headers_sent = true;
	}
}

// Once the request headers are complete, decide the request body framing, open
// the backend connection, and queue the PROXY header and HTTP/1.1 request head.
static void h2_start_backend(struct h2_stream *s, bool has_body)
{
	if(!has_body)
		s->req_mode = REQ_NONE;
	else if(s->content_length_seen)
		s->req_mode = REQ_RAW;      // length known: forward the body verbatim
	else
		s->req_mode = REQ_CHUNKED;  // unknown length: chunk it to the backend

	bool connected = false;
	s->be_fd = connect_backend_nb(&connected);
	if(s->be_fd < 0)
	{
		h2_gateway_error(s, "502");
		return;
	}
	s->be_connecting = !connected;

	unsigned char ph[H2_PROXY_MAX];
	size_t phlen = 0;
	if(build_proxy_v2(s->conn->client_fd, ph, &phlen) != 0 ||
	   h2_req_push(s, (const char *)ph, phlen) != 0)
	{
		h2_gateway_error(s, "502");
		return;
	}

	char head[H2_REQHDR_MAX + 4096];
	const int hl = snprintf(head, sizeof(head),
	                        "%s %s HTTP/1.1\r\nHost: %s\r\n%.*s%sConnection: close\r\n\r\n",
	                        s->method[0] ? s->method : "GET",
	                        s->path[0] ? s->path : "/",
	                        s->authority[0] ? s->authority : "pi.hole",
	                        (int)s->reqhdr_len, s->reqhdr,
	                        s->req_mode == REQ_CHUNKED ? "Transfer-Encoding: chunked\r\n" : "");
	if(hl < 0 || (size_t)hl >= sizeof(head) || h2_req_push(s, head, (size_t)hl) != 0)
	{
		h2_gateway_error(s, "500");
		return;
	}
	s->req_started = true;
}

// nghttp2 data provider: hand decoded response body bytes to nghttp2 on demand.
// Returns NGHTTP2_ERR_DEFERRED when the backend has not produced more body yet;
// h2_be_readable() resumes the stream once it does.
static nghttp2_ssize h2_body_read(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source, void *user_data)
{
	struct h2_stream *s = (struct h2_stream *)source->ptr;
	(void)session; (void)stream_id; (void)user_data;

	const size_t avail = s->body_len - s->body_off;
	if(avail == 0)
	{
		if(s->resp_complete)
		{
			*data_flags |= NGHTTP2_DATA_FLAG_EOF;
			return 0;
		}
		s->resp_deferred = true;
		return NGHTTP2_ERR_DEFERRED;
	}

	const size_t n = (avail < length) ? avail : length;
	memcpy(buf, s->body_buf + s->body_off, n);
	s->body_off += n;
	if(s->body_off == s->body_len)
		s->body_off = s->body_len = 0;
	if(s->resp_complete && s->body_len == 0)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	return (nghttp2_ssize)n;
}

// Lowercase the header name in place (HTTP/2 requires it) and append the
// name/value pair to the nghttp2 header list.
static void h2_add_nv(nghttp2_nv *nva, size_t *nvlen, char *name, char *value)
{
	for(char *c = name; *c != '\0'; c++)
		*c = (char)tolower((unsigned char)*c);
	nva[*nvlen].name = (uint8_t *)name; nva[*nvlen].namelen = strlen(name);
	nva[*nvlen].value = (uint8_t *)value; nva[*nvlen].valuelen = strlen(value);
	nva[*nvlen].flags = NGHTTP2_NV_FLAG_NONE;
	(*nvlen)++;
}

// Parse the HTTP/1.1 response header block hdr[0..hdrlen) (the bytes before the
// terminating CRLFCRLF), determine the body framing, and submit the HTTP/2
// response headers with a streaming data provider. nghttp2 copies the header
// list, so the in-place-parsed hdr buffer can be freed afterwards. Returns 0 or
// -1.
static int h2_parse_and_submit(struct h2_stream *s, char *hdr, size_t hdrlen)
{
	hdr[hdrlen] = '\0';

	char status3[4] = "502";
	const char *sp = strchr(hdr, ' ');
	if(sp != NULL && sp[1] && sp[2] && sp[3])
	{
		status3[0] = sp[1]; status3[1] = sp[2]; status3[2] = sp[3]; status3[3] = '\0';
	}

	nghttp2_nv nva[H2_MAX_HDRS];
	size_t nvlen = 0;
	nva[nvlen].name = (uint8_t *)":status"; nva[nvlen].namelen = 7;
	nva[nvlen].value = (uint8_t *)status3;  nva[nvlen].valuelen = 3;
	nva[nvlen].flags = NGHTTP2_NV_FLAG_NONE; nvlen++;

	bool chunked = false, have_clen = false;
	size_t clen = 0;
	char *line = strstr(hdr, "\r\n"); // skip the status line
	if(line != NULL)
	{
		line += 2;
		while(*line != '\0' && nvlen < H2_MAX_HDRS)
		{
			char *eol = strstr(line, "\r\n");
			if(eol != NULL)
				*eol = '\0';
			char *colon = strchr(line, ':');
			if(colon != NULL)
			{
				*colon = '\0';
				char *val = colon + 1;
				while(*val == ' ') val++;
				const size_t nlen = strlen(line);
				if(nlen == 17 && strncasecmp(line, "transfer-encoding", 17) == 0)
				{
					if(strcasestr(val, "chunked") != NULL)
						chunked = true; // decoded here, not forwarded
				}
				else if(nlen == 14 && strncasecmp(line, "content-length", 14) == 0)
				{
					have_clen = true;
					clen = (size_t)strtoull(val, NULL, 10);
					h2_add_nv(nva, &nvlen, line, val);
				}
				else if(nlen > 0 && !h2_skip_header(line, nlen))
				{
					h2_add_nv(nva, &nvlen, line, val);
				}
			}
			if(eol == NULL)
				break;
			line = eol + 2;
		}
	}

	// Determine the response body framing. HEAD requests and 1xx/204/304
	// responses carry no body regardless of any length header.
	bool no_body = false;
	if(strcasecmp(s->method, "HEAD") == 0)
		no_body = true;
	else if(status3[0] == '1' || strcmp(status3, "204") == 0 || strcmp(status3, "304") == 0)
		no_body = true;

	if(no_body)
		s->body_mode = BODY_NONE;
	else if(chunked)
	{
		s->body_mode = BODY_CHUNKED;
		s->chunk_state = CH_SIZE;
	}
	else if(have_clen)
	{
		s->body_mode = BODY_LENGTH;
		s->body_remaining = clen;
	}
	else
		s->body_mode = BODY_CLOSE; // length delimited by the backend closing

	s->resp_headers_parsed = true;

	const bool empty = (s->body_mode == BODY_NONE) ||
	                   (s->body_mode == BODY_LENGTH && s->body_remaining == 0);
	nghttp2_data_provider2 prd;
	prd.source.ptr = s;
	prd.read_callback = h2_body_read;
	const int rv = nghttp2_submit_response2(s->conn->session, s->stream_id,
	                                        nva, nvlen, empty ? NULL : &prd);
	s->resp_headers_sent = true;
	if(empty)
		s->resp_complete = true;
	return (rv == 0) ? 0 : -1;
}

// Incrementally de-chunk a Transfer-Encoding: chunked response body, appending
// decoded bytes to the stream body buffer. State persists across calls. Returns
// 0 or -1.
static int h2_feed_chunked(struct h2_stream *s, const char *data, size_t n)
{
	size_t i = 0;
	while(i < n && s->chunk_state != CH_DONE)
	{
		const char c = data[i];
		switch(s->chunk_state)
		{
			case CH_SIZE:
				if(c >= '0' && c <= '9') { s->chunk_size = s->chunk_size * 16u + (size_t)(c - '0'); i++; }
				else if(c >= 'a' && c <= 'f') { s->chunk_size = s->chunk_size * 16u + (size_t)(c - 'a' + 10); i++; }
				else if(c >= 'A' && c <= 'F') { s->chunk_size = s->chunk_size * 16u + (size_t)(c - 'A' + 10); i++; }
				else if(c == ';') { s->chunk_state = CH_EXT; i++; }
				else if(c == '\r') { s->chunk_state = CH_SIZE_LF; i++; }
				else i++; // tolerate stray bytes
				break;
			case CH_EXT: // chunk extension: skip to end of line
				if(c == '\r') s->chunk_state = CH_SIZE_LF;
				i++;
				break;
			case CH_SIZE_LF:
				i++; // consume '\n'
				if(s->chunk_size == 0) { s->chunk_state = CH_TRAILER; s->trailer_line_len = 0; }
				else { s->chunk_remaining = s->chunk_size; s->chunk_state = CH_DATA; }
				break;
			case CH_DATA:
			{
				const size_t avail = n - i;
				const size_t take = (avail < s->chunk_remaining) ? avail : s->chunk_remaining;
				if(take > 0)
				{
					if(h2_body_push(s, data + i, take) != 0)
						return -1;
					i += take;
					s->chunk_remaining -= take;
				}
				if(s->chunk_remaining == 0)
					s->chunk_state = CH_DATA_CR;
				break;
			}
			case CH_DATA_CR:
				if(c == '\r') s->chunk_state = CH_DATA_LF;
				i++;
				break;
			case CH_DATA_LF:
				if(c == '\n') { s->chunk_size = 0; s->chunk_state = CH_SIZE; }
				i++;
				break;
			case CH_TRAILER: // optional trailers terminated by a blank line
				if(c == '\n') { if(s->trailer_line_len == 0) s->chunk_state = CH_DONE; else s->trailer_line_len = 0; }
				else if(c != '\r') s->trailer_line_len++;
				i++;
				break;
		}
	}
	if(s->chunk_state == CH_DONE)
		s->resp_complete = true;
	return 0;
}

// Decode response body bytes according to the negotiated framing and append the
// result to the stream body buffer. Returns 0 or -1.
static int h2_feed_body(struct h2_stream *s, const char *data, size_t n)
{
	switch(s->body_mode)
	{
		case BODY_NONE:
			return 0;
		case BODY_LENGTH:
		{
			const size_t take = (n < s->body_remaining) ? n : s->body_remaining;
			if(take > 0 && h2_body_push(s, data, take) != 0)
				return -1;
			s->body_remaining -= take;
			if(s->body_remaining == 0)
				s->resp_complete = true;
			return 0;
		}
		case BODY_CHUNKED:
			return h2_feed_chunked(s, data, n);
		case BODY_CLOSE:
		default:
			if(n > 0 && h2_body_push(s, data, n) != 0)
				return -1;
			return 0; // completion is signalled by the backend closing
	}
}

// Feed raw bytes read from the backend socket: accumulate and parse the response
// header block first, then decode the body incrementally. Returns 0 or -1.
static int h2_feed(struct h2_stream *s, const char *data, size_t n)
{
	if(s->resp_headers_parsed)
		return h2_feed_body(s, data, n);

	if(buf_append(&s->resp_hdr, &s->resp_hdr_len, &s->resp_hdr_cap, data, n) != 0)
		return -1;
	char *end = memmem(s->resp_hdr, s->resp_hdr_len, "\r\n\r\n", 4);
	if(end == NULL)
		return (s->resp_hdr_len > H2_RESP_HDR_MAX) ? -1 : 0; // need more headers

	const size_t hdrlen = (size_t)(end - s->resp_hdr);
	const size_t consumed = hdrlen + 4;
	if(h2_parse_and_submit(s, s->resp_hdr, hdrlen) != 0)
		return -1;
	// Any bytes past the header terminator are the start of the body. Copy them
	// out (h2_body_push copies) before freeing the header buffer.
	const size_t leftover = s->resp_hdr_len - consumed;
	if(leftover > 0 && h2_feed_body(s, s->resp_hdr + consumed, leftover) != 0)
		return -1;
	free(s->resp_hdr);
	s->resp_hdr = NULL;
	s->resp_hdr_len = s->resp_hdr_cap = 0;
	return 0;
}

// Backend socket became writable: finish a pending non-blocking connect() and
// flush as much of the queued request as the socket accepts. Once the request
// buffer fully drains, credit the request body bytes back to nghttp2's flow
// control so the client may send more (backpressure follows the backend).
static void h2_be_writable(struct h2_stream *s)
{
	if(s->be_fd < 0)
		return;
	if(s->be_connecting)
	{
		int err = 0;
		socklen_t el = sizeof(err);
		if(getsockopt(s->be_fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0)
		{
			h2_gateway_error(s, "502");
			return;
		}
		s->be_connecting = false;
	}
	while(s->req_out_off < s->req_out_len)
	{
		const ssize_t w = write(s->be_fd, s->req_out + s->req_out_off,
		                        s->req_out_len - s->req_out_off);
		if(w > 0)
			s->req_out_off += (size_t)w;
		else if(w < 0 && errno == EINTR)
			continue;
		else if(w < 0 && WOULDBLOCK(errno))
			break;
		else
		{
			h2_gateway_error(s, "502");
			return;
		}
	}
	if(s->req_out_off == s->req_out_len)
	{
		s->req_out_off = s->req_out_len = 0;
		if(s->body_uncredited > 0)
		{
			nghttp2_session_consume(s->conn->session, s->stream_id, s->body_uncredited);
			s->body_uncredited = 0;
		}
	}
}

// Backend socket became readable: pull response bytes, feed the parser/decoder,
// and resume the stream's data provider if it was parked. Stops early at the
// body high-water mark to apply backpressure toward the client.
static void h2_be_readable(struct h2_stream *s)
{
	if(s->be_fd < 0)
		return;
	char tmp[16384];
	for(;;)
	{
		const ssize_t r = read(s->be_fd, tmp, sizeof(tmp));
		if(r > 0)
		{
			if(h2_feed(s, tmp, (size_t)r) != 0)
			{
				h2_gateway_error(s, "502");
				return;
			}
			if(s->resp_complete)
				break;
			if((s->body_len - s->body_off) >= H2_BODY_HIGH_WATER)
				break; // backpressure: let the client drain first
			continue;
		}
		if(r == 0)
		{
			// Backend closed. For close-delimited bodies this is the normal end;
			// for framed bodies it truncates, but we still finish the stream.
			if(!s->resp_headers_parsed)
			{
				h2_gateway_error(s, "502");
				return;
			}
			s->resp_complete = true;
			h2_be_close(s);
			break;
		}
		if(errno == EINTR)
			continue;
		if(WOULDBLOCK(errno))
			break;
		// Fatal read error
		if(!s->resp_headers_parsed)
		{
			h2_gateway_error(s, "502");
			return;
		}
		s->resp_complete = true;
		h2_be_close(s);
		break;
	}

	// The response is fully decoded; the backend socket is no longer needed.
	if(s->resp_complete && s->be_fd >= 0)
		h2_be_close(s);
	// Wake a parked data provider now that there is progress (more body or EOF).
	if(s->resp_deferred && ((s->body_len - s->body_off) > 0 || s->resp_complete))
	{
		s->resp_deferred = false;
		nghttp2_session_resume_data(s->conn->session, s->stream_id);
	}
}

static int h2_on_begin_headers(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	struct h2_conn *conn = (struct h2_conn *)user_data;
	if(frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
		return 0;
	struct h2_stream *s = calloc(1, sizeof(*s));
	if(s == NULL)
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	s->conn = conn;
	s->stream_id = frame->hd.stream_id;
	s->be_fd = -1;
	h2_stream_link(conn, s);
	nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, s);
	return 0;
}

static int h2_on_header(nghttp2_session *session, const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen,
                        uint8_t flags, void *user_data)
{
	(void)flags; (void)user_data;
	struct h2_stream *s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
	if(s == NULL)
		return 0;
	const char *n = (const char *)name;
	const char *v = (const char *)value;

	if(namelen > 0 && n[0] == ':')
	{
		if(namelen == 7 && memcmp(n, ":method", 7) == 0)
			snprintf(s->method, sizeof(s->method), "%.*s", (int)valuelen, v);
		else if(namelen == 5 && memcmp(n, ":path", 5) == 0)
			snprintf(s->path, sizeof(s->path), "%.*s", (int)valuelen, v);
		else if(namelen == 10 && memcmp(n, ":authority", 10) == 0)
			snprintf(s->authority, sizeof(s->authority), "%.*s", (int)valuelen, v);
		// :scheme is always https at the terminator and is not forwarded
		return 0;
	}

	if(h2_skip_header(n, namelen))
		return 0;
	if(namelen == 14 && strncasecmp(n, "content-length", 14) == 0)
		s->content_length_seen = true;

	const size_t need = namelen + 2 + valuelen + 2;
	if(s->reqhdr_len + need < sizeof(s->reqhdr))
	{
		char *p = s->reqhdr + s->reqhdr_len;
		memcpy(p, n, namelen); p += namelen;
		*p++ = ':'; *p++ = ' ';
		memcpy(p, v, valuelen); p += valuelen;
		*p++ = '\r'; *p++ = '\n';
		s->reqhdr_len += need;
	}
	return 0;
}

static int h2_on_data_chunk(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                            const uint8_t *data, size_t len, void *user_data)
{
	(void)flags; (void)user_data;
	struct h2_stream *s = nghttp2_session_get_stream_user_data(session, stream_id);
	if(s == NULL)
		return 0;
	// If the backend is gone (error, or it already responded and we closed the
	// socket), discard the body but keep the flow-control window moving so the
	// client is not stalled.
	if(s->error || s->be_fd < 0)
	{
		nghttp2_session_consume(session, stream_id, len);
		return 0;
	}
	s->body_uncredited += len;
	if(s->req_mode == REQ_CHUNKED)
	{
		if(len > 0)
		{
			char hdr[32];
			const int hn = snprintf(hdr, sizeof(hdr), "%zx\r\n", len);
			if(hn < 0 || h2_req_push(s, hdr, (size_t)hn) != 0 ||
			   h2_req_push(s, (const char *)data, len) != 0 ||
			   h2_req_push(s, "\r\n", 2) != 0)
				return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	else if(len > 0)
	{
		if(h2_req_push(s, (const char *)data, len) != 0)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

static int h2_on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	(void)user_data;
	// All request headers are in: open the backend and queue the request head.
	if(frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST)
	{
		struct h2_stream *s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
		if(s != NULL && !s->error)
			h2_start_backend(s, !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM));
	}
	// End of the request body: finish a chunked request with the terminator.
	if((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) &&
	   (frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA))
	{
		struct h2_stream *s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
		if(s != NULL && !s->error && s->req_mode == REQ_CHUNKED && s->be_fd >= 0)
			h2_req_push(s, "0\r\n\r\n", 5);
	}
	return 0;
}

static int h2_on_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
	(void)error_code;
	struct h2_conn *conn = (struct h2_conn *)user_data;
	struct h2_stream *s = nghttp2_session_get_stream_user_data(session, stream_id);
	if(s != NULL)
	{
		h2_stream_unlink(conn, s);
		h2_stream_free(s);
		nghttp2_session_set_stream_user_data(session, stream_id, NULL);
	}
	return 0;
}

// Pull serialized frames out of nghttp2 into the outbound TLS buffer, up to the
// soft cap. Returns 0 or -1. This may invoke the data provider and, on stream
// completion, on_stream_close (which frees stream state).
static int h2_pump_output(struct h2_conn *c)
{
	if(c->woff > 0)
	{
		memmove(c->wbuf, c->wbuf + c->woff, c->wlen - c->woff);
		c->wlen -= c->woff;
		c->woff = 0;
	}
	while((c->wlen - c->woff) < H2_WBUF_SOFT_CAP)
	{
		const uint8_t *data = NULL;
		const nghttp2_ssize len = nghttp2_session_mem_send2(c->session, &data);
		if(len < 0)
			return -1;
		if(len == 0)
			break;
		if(buf_append(&c->wbuf, &c->wlen, &c->wcap, (const char *)data, (size_t)len) != 0)
			return -1;
	}
	return 0;
}

// Flush the outbound TLS buffer to the client. On WANT_WRITE we stop and wait
// for the socket to become writable again (POLLOUT). Returns 0 or -1.
static int h2_drain_tls(struct h2_conn *c)
{
	c->ssl_want_write = false;
	while(c->woff < c->wlen)
	{
		const int n = SSL_write(c->ssl, c->wbuf + c->woff, (int)(c->wlen - c->woff));
		if(n > 0)
			c->woff += (size_t)n;
		else
		{
			const int err = SSL_get_error(c->ssl, n);
			if(err == SSL_ERROR_WANT_WRITE)
			{
				c->ssl_want_write = true;
				break;
			}
			if(err == SSL_ERROR_WANT_READ)
				break; // a read must happen before the write can proceed
			return -1;
		}
	}
	if(c->woff == c->wlen)
		c->woff = c->wlen = 0;
	return 0;
}

// Read all currently available TLS plaintext and hand it to nghttp2. Returns 0
// on success (including "nothing more to read right now"), -1 on a closed or
// broken connection. May free stream state via on_stream_close.
static int h2_read_tls(struct h2_conn *c)
{
	char buf[16384];
	for(;;)
	{
		const int n = SSL_read(c->ssl, buf, sizeof(buf));
		if(n > 0)
		{
			if(nghttp2_session_mem_recv2(c->session, (const uint8_t *)buf, (size_t)n) < 0)
				return -1;
			continue;
		}
		const int err = SSL_get_error(c->ssl, n);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0;
		return -1; // clean shutdown or fatal error
	}
}

// Serve one HTTP/2 connection: a single poll() loop over the client TLS socket
// and every active backend socket, streaming requests to the backend and
// responses back to the client with per-stream concurrency. Uses the
// module-global backend_port.
static void terminator_h2_serve(SSL *ssl, int client_fd)
{
	if(set_nonblocking(client_fd) != 0)
		return;
	// Allow partial writes and a moved buffer pointer, since the outbound TLS
	// buffer is compacted between SSL_write() retries.
	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	nghttp2_session_callbacks *cbs = NULL;
	if(nghttp2_session_callbacks_new(&cbs) != 0)
		return;
	nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, h2_on_begin_headers);
	nghttp2_session_callbacks_set_on_header_callback(cbs, h2_on_header);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, h2_on_data_chunk);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, h2_on_frame_recv);
	nghttp2_session_callbacks_set_on_stream_close_callback(cbs, h2_on_stream_close);

	struct h2_conn conn;
	memset(&conn, 0, sizeof(conn));
	conn.ssl = ssl;
	conn.client_fd = client_fd;

	nghttp2_option *opt = NULL;
	if(nghttp2_option_new(&opt) != 0)
	{
		nghttp2_session_callbacks_del(cbs);
		return;
	}
	// Manage flow-control windows by hand so request-body backpressure follows
	// the backend's drain rate (see h2_be_writable()).
	nghttp2_option_set_no_auto_window_update(opt, 1);
	if(nghttp2_session_server_new2(&conn.session, cbs, &conn, opt) != 0)
	{
		nghttp2_option_del(opt);
		nghttp2_session_callbacks_del(cbs);
		return;
	}
	nghttp2_option_del(opt);
	nghttp2_session_callbacks_del(cbs);

	const nghttp2_settings_entry iv[1] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
	};
	nghttp2_submit_settings(conn.session, NGHTTP2_FLAG_NONE, iv, 1);

	for(;;)
	{
		if(h2_pump_output(&conn) != 0)
			break;
		if(h2_drain_tls(&conn) != 0)
			break;

		// The session is finished once nghttp2 wants neither read nor write, no
		// streams remain, and the outbound buffer is empty.
		if(!nghttp2_session_want_read(conn.session) &&
		   !nghttp2_session_want_write(conn.session) &&
		   conn.streams == NULL && conn.wlen == conn.woff)
			break;

		// Grow the poll scratch buffers to fit the client fd plus every backend.
		size_t need = 1;
		for(struct h2_stream *s = conn.streams; s != NULL; s = s->next)
			if(s->be_fd >= 0)
				need++;
		if(need > conn.pcap)
		{
			struct pollfd *np = realloc(conn.pfds, need * sizeof(*np));
			struct h2_stream **nm = realloc(conn.pmap, need * sizeof(*nm));
			if(np != NULL) conn.pfds = np;
			if(nm != NULL) conn.pmap = nm;
			if(np == NULL || nm == NULL)
				break;
			conn.pcap = need;
		}

		conn.pfds[0].fd = client_fd;
		conn.pfds[0].events = POLLIN;
		if(conn.wlen > conn.woff || conn.ssl_want_write)
			conn.pfds[0].events |= POLLOUT;
		conn.pfds[0].revents = 0;
		conn.pmap[0] = NULL;

		nfds_t nfds = 1;
		for(struct h2_stream *s = conn.streams; s != NULL; s = s->next)
		{
			if(s->be_fd < 0)
				continue;
			short ev = 0;
			if(s->be_connecting)
				ev |= POLLOUT; // wait for connect() to complete
			else
			{
				if(s->req_out_off < s->req_out_len)
					ev |= POLLOUT; // request bytes still to flush
				if(!s->resp_complete && (s->body_len - s->body_off) < H2_BODY_HIGH_WATER)
					ev |= POLLIN;  // room for more response body
			}
			if(ev == 0)
				continue;
			conn.pfds[nfds].fd = s->be_fd;
			conn.pfds[nfds].events = ev;
			conn.pfds[nfds].revents = 0;
			conn.pmap[nfds] = s;
			nfds++;
		}

		const int pr = poll(conn.pfds, nfds, IO_TIMEOUT_SEC * 1000);
		if(pr < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		if(pr == 0)
			break; // idle timeout

		// Service backend fds first. These never free stream state, so the pmap
		// stays valid; the client read below may close and free streams.
		for(nfds_t i = 1; i < nfds; i++)
		{
			struct h2_stream *s = conn.pmap[i];
			if(s == NULL || s->be_fd < 0)
				continue;
			if(conn.pfds[i].revents & POLLOUT)
				h2_be_writable(s);
			if(conn.pfds[i].revents & (POLLIN | POLLHUP | POLLERR))
				h2_be_readable(s);
		}

		if(conn.pfds[0].revents & (POLLIN | POLLHUP | POLLERR))
		{
			if(h2_read_tls(&conn) != 0)
				break;
		}
	}

	// nghttp2_session_del() closes any remaining streams (invoking
	// on_stream_close, which unlinks and frees them); drain defensively in case
	// this version does not, then release the connection buffers.
	nghttp2_session_del(conn.session);
	while(conn.streams != NULL)
	{
		struct h2_stream *s = conn.streams;
		conn.streams = s->next;
		h2_stream_free(s);
	}
	free(conn.wbuf);
	free(conn.pfds);
	free(conn.pmap);
}
#endif /* HAVE_HTTP2 */

// Per-connection handler, run in a detached thread.
static void *handle_conn(void *arg)
{
	const int client_fd = (int)(intptr_t)arg;

	const struct timeval tv = { .tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	SSL *ssl = SSL_new(ssl_ctx);
	int be_fd = -1;
	if(ssl == NULL)
	{
		log_ssl_errors("SSL_new() failed");
		goto cleanup;
	}
	SSL_set_fd(ssl, client_fd);
	if(SSL_accept(ssl) != 1)
	{
		// A failed handshake (e.g. a plain-HTTP probe on the TLS port) is not
		// worth an error; keep it at debug level to avoid log flooding.
		log_debug(DEBUG_WEBSERVER, "Terminator: TLS handshake failed");
		goto cleanup;
	}

#ifdef HAVE_HTTP2
	// If the client negotiated HTTP/2 via ALPN, run the HTTP/2 gateway.
	{
		const unsigned char *alpn = NULL;
		unsigned int alpn_len = 0;
		SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
		if(alpn_len == 2 && memcmp(alpn, "h2", 2) == 0)
		{
			terminator_h2_serve(ssl, client_fd);
			goto cleanup;
		}
	}
#endif

	// HTTP/1.1: terminate TLS and relay the byte stream to the backend.
	be_fd = connect_backend();
	if(be_fd < 0)
		goto cleanup;

	// Announce the real client to the backend before relaying any request bytes
	if(send_proxy_v2(be_fd, client_fd) != 0)
	{
		log_debug(DEBUG_WEBSERVER, "Terminator: could not send PROXY header");
		goto cleanup;
	}

	relay(ssl, client_fd, be_fd);

cleanup:
	if(ssl != NULL)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if(be_fd >= 0)
		close(be_fd);
	close(client_fd);
	return NULL;
}

// Accept loop thread: hand each accepted connection to a detached handler.
static void *accept_loop(void *arg)
{
	(void)arg;
	prctl(PR_SET_NAME, "terminator", 0, 0, 0);

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	while(running)
	{
		const int client_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
		if(client_fd < 0)
		{
			if(errno == EINTR)
				continue;
			if(!running)
				break; // listener shut down by terminator_stop()
			// Transient error (e.g. EMFILE); avoid a tight spin.
			poll(NULL, 0, 100);
			continue;
		}

		// TODO(M1): bound the number of concurrent handler threads (a worker
		// pool) instead of one detached thread per connection.
		pthread_t tid;
		if(pthread_create(&tid, &attr, handle_conn, (void *)(intptr_t)client_fd) != 0)
		{
			log_err("Terminator: pthread_create() failed: %s", strerror(errno));
			close(client_fd);
		}
	}

	pthread_attr_destroy(&attr);
	return NULL;
}

bool terminator_start(int public_port, int be_port, const char *cert_path)
{
	if(running)
	{
		log_warn("Terminator: already running");
		return false;
	}
	if(cert_path == NULL || public_port <= 0 || be_port <= 0)
		return false;

	ssl_ctx = create_server_ctx(cert_path);
	if(ssl_ctx == NULL)
		return false;

	listen_fd = bind_listener(public_port);
	if(listen_fd < 0)
	{
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		return false;
	}

	backend_port = be_port;
	running = true;
	if(pthread_create(&accept_tid, NULL, accept_loop, NULL) != 0)
	{
		log_err("Terminator: failed to start accept thread: %s", strerror(errno));
		running = false;
		close(listen_fd);
		listen_fd = -1;
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		return false;
	}
	accept_tid_valid = true;

	log_info("TLS terminator listening on port %d, forwarding to 127.0.0.1:%d",
	         public_port, be_port);
	return true;
}

void terminator_stop(void)
{
	if(!running && listen_fd < 0 && ssl_ctx == NULL)
		return;

	running = false;
	// Break the blocking accept4() so the accept thread can exit.
	if(listen_fd >= 0)
		shutdown(listen_fd, SHUT_RDWR);
	if(accept_tid_valid)
	{
		pthread_join(accept_tid, NULL);
		accept_tid_valid = false;
	}
	if(listen_fd >= 0)
	{
		close(listen_fd);
		listen_fd = -1;
	}
	if(ssl_ctx != NULL)
	{
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
	// Note: in-flight detached handler threads are not joined here; they finish
	// on their own when their connection closes or times out (IO_TIMEOUT_SEC).
}
