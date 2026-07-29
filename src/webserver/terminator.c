/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  In-process TLS front terminator (HTTP/1.1, HTTP/2, HTTP/3)
*
*  Bind the public TLS port, terminate TLS, and forward plain HTTP/1.1 to the
*  CivetWeb backend on the loopback interface. TLS is the only thing this layer
*  understands for HTTP/1.1; everything above it (HTTP framing, keep-alive,
*  routing, Lua, auth) stays in CivetWeb, which now speaks plain HTTP/1.1 on
*  loopback. On top of the same public port the terminator also gateways HTTP/2
*  (nghttp2, ALPN "h2", over TLS/TCP) and HTTP/3 (nghttp3 over OpenSSL QUIC,
*  ALPN "h3", over UDP), bridging both to the same HTTP/1.1 backend.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/terminator.h"
// log_err(), log_info(), log_warn()
#include "log.h"

// The terminator is entirely OpenSSL-based; without TLS it does not exist. Guard
// the whole body (like tls_client.c) so a no-TLS build still compiles. webserver.c
// guards every terminator_start()/stop() call with HAVE_TLS; only the token
// accessor (referenced unconditionally by the civetweb PROXY parser) needs a stub.
#ifdef HAVE_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef HAVE_HTTP2
#include <nghttp2/nghttp2.h>
#endif

#ifdef HAVE_HTTP3
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>
#include <nghttp3/nghttp3.h>
#include <time.h>
// HTTP/3 forwards the real client IP via SSL_get_peer_addr(), a per-connection
// QUIC peer getter added in OpenSSL 4.0; refuse to build against older OpenSSL
// rather than attributing every request to the loopback terminator.
#if OPENSSL_VERSION_NUMBER < 0x40000000L
#error "HTTP/3 requires OpenSSL >= 4.0, which provides SSL_get_peer_addr() for QUIC (needed to forward the real client IP). Upgrade OpenSSL to 4.0 or later, or build without nghttp3 to disable HTTP/3."
#endif
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
#include <stdatomic.h>

// Bidirectional relay buffer size (per direction, per iteration).
#define RELAY_BUF 16384u
// Socket send/receive timeout so a stuck peer cannot pin a handler thread.
#define IO_TIMEOUT_SEC 30
// Cap on concurrent handler threads so a connection flood on the public TLS port
// cannot exhaust the FTL process (threads, fds, memory). A browser needs only a
// handful thanks to keep-alive and h2/h3 multiplexing, so this is generous for the
// admin UI yet fatal to a flood; connections beyond it are dropped immediately.
#define TERMINATOR_MAX_HANDLERS 256
// Same cap for concurrent HTTP/3 connections. The QUIC gateway runs on one thread
// and holds per-connection OpenSSL/nghttp3 state (plus a backend fd per request
// stream), so an uncapped handshake flood would exhaust memory/fds; connections
// beyond this are accepted and immediately closed, mirroring the TCP handler cap.
#define TERMINATOR_MAX_H3_CONNS 256
// Absolute wall-clock budget for the whole TLS handshake, independent of the
// per-recv SO_RCVTIMEO (which a byte-at-a-time peer resets on every recv).
#define HANDSHAKE_TIMEOUT_SEC 15

// Number of live handler threads, for the cap above.
static atomic_int active_handlers = 0;

// A per-boot secret carried in a custom PROXY v2 TLV so the loopback CivetWeb
// backend can tell a genuine terminator->backend header apart from one forged by
// another local process (the loopback bind is the only other trust gate, and the
// backend port is locally reachable). PP2_TYPE_MIN_CUSTOM..MAX_CUSTOM is 0xE0-EF.
#define PP2_TYPE_FTL_TOKEN 0xE0u
#define PROXY_TOKEN_LEN 16u
// Largest PROXY v2 header we emit: 16 header + 36 IPv6 address block + 8 SSL TLV
// + (3 + PROXY_TOKEN_LEN) token TLV.
#define PROXY_V2_MAX (16u + 36u + 8u + 3u + PROXY_TOKEN_LEN)
static unsigned char g_proxy_token[PROXY_TOKEN_LEN];
static bool g_proxy_token_ready = false;
// FTL's secure RNG (getrandom with a /dev/urandom fallback); declared here to
// avoid pulling the whole config/password.h (and its config types) into this TU.
extern bool get_secure_randomness(uint8_t *buffer, const size_t length);

// Generate the per-boot backend-auth token once; idempotent. A restart (e.g.
// cert renewal) must not rewrite it while leftover detached handlers may still
// be reading it. Returns false only if the RNG fails.
static bool ensure_proxy_token(void)
{
	if(g_proxy_token_ready)
		return true;
	if(!get_secure_randomness(g_proxy_token, sizeof(g_proxy_token)))
		return false;
	g_proxy_token_ready = true;
	return true;
}

// Hex-encode the per-boot token into out (needs 2*PROXY_TOKEN_LEN+1 bytes),
// generating it if necessary. webserver.c passes this to the loopback backend
// as its "proxy_protocol_secret", the shared secret the backend uses to
// authenticate our PROXY headers. Returns false if out is too small or the RNG
// fails.
bool terminator_proxy_token_hex(char *out, size_t outsz)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;
	if(outsz < 2 * PROXY_TOKEN_LEN + 1 || !ensure_proxy_token())
		return false;
	for(i = 0; i < PROXY_TOKEN_LEN; i++)
	{
		out[2 * i]     = hex[g_proxy_token[i] >> 4];
		out[2 * i + 1] = hex[g_proxy_token[i] & 0x0F];
	}
	out[2 * PROXY_TOKEN_LEN] = '\0';
	return true;
}

// Passed to each detached handler: the client fd plus our own reference to the
// SSL_CTX, taken while it is live, so terminator_stop() can free the context
// without racing a handler that has not yet reached SSL_new().
struct handler_arg { int client_fd; SSL_CTX *ctx; };

// Monotonic milliseconds, for wall-clock deadlines.
static uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// Terminator state. There is a single terminator instance for the whole
// process, mirroring the single CivetWeb context in webserver.c.
static SSL_CTX *ssl_ctx = NULL;
static int listen_fd = -1;
static int backend_port = 0;
static volatile bool running = false;
static pthread_t accept_tid;
static bool accept_tid_valid = false;

#ifdef HAVE_HTTP3
// HTTP/3 (QUIC) listener state, owned by the dedicated event-loop thread below
// (one UDP socket, one OpenSSL QUIC listener, all connections and streams).
static SSL_CTX *quic_ctx = NULL;
static int quic_fd = -1;
static pthread_t quic_tid;
static bool quic_tid_valid = false;
static volatile bool quic_running = false;
// Public UDP/TCP port the QUIC listener bound to, advertised to h2 clients via
// Alt-Svc so h3-capable browsers upgrade to HTTP/3.
static int quic_public_port = 0;
#endif

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

// ALPN selection: pick our most-preferred protocol the client offers ("h2" when
// HTTP/2 is compiled in, else "http/1.1"). Done by hand to avoid the confusing
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
// Fill a dual-stack sockaddr_in6 for the given bind address and port. addr may be
// NULL or empty (bind all interfaces), an IPv6 literal, or an IPv4 literal (bound
// as a v4-mapped address on the IPv6 socket, honouring IPV6_V6ONLY=off). Returns
// false on an unparsable address so the caller fails closed rather than silently
// widening the scope to all interfaces.
static bool fill_bind_addr(struct sockaddr_in6 *sa, const char *addr, int port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons((uint16_t)port);
	if(addr == NULL || addr[0] == '\0')
	{
		sa->sin6_addr = in6addr_any;
		return true;
	}
	if(inet_pton(AF_INET6, addr, &sa->sin6_addr) == 1)
		return true;
	struct in_addr v4;
	if(inet_pton(AF_INET, addr, &v4) == 1)
	{
		sa->sin6_addr.s6_addr[10] = 0xff; // ::ffff:a.b.c.d
		sa->sin6_addr.s6_addr[11] = 0xff;
		memcpy(&sa->sin6_addr.s6_addr[12], &v4, sizeof(v4));
		return true;
	}
	return false;
}

static int bind_listener(const char *addr, int port)
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
	if(!fill_bind_addr(&sa, addr, port))
	{
		log_err("Terminator: invalid bind address '%s'", addr);
		close(fd);
		return -1;
	}
	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		log_err("Terminator: bind() to %s#%d failed: %s",
		        (addr && addr[0]) ? addr : "*", port, strerror(errno));
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
// The socket carries SO_SNDTIMEO, so each SSL_write() waits at most IO_TIMEOUT_SEC
// for the peer to accept data; a WANT_WRITE then means a full timeout elapsed with
// no progress. Bound the total no-progress time so a client that stops reading a
// large response cannot pin this handler thread (and its active_handlers slot)
// forever. Any forward progress resets the budget, so a slow-but-live reader is fine.
static int write_all_ssl(SSL *ssl, const char *buf, size_t len)
{
	uint64_t deadline = mono_ms() + (uint64_t)IO_TIMEOUT_SEC * 1000u;
	while(len > 0)
	{
		const int n = SSL_write(ssl, buf, (int)len);
		if(n > 0)
		{
			buf += n;
			len -= (size_t)n;
			deadline = mono_ms() + (uint64_t)IO_TIMEOUT_SEC * 1000u;
		}
		else
		{
			const int err = SSL_get_error(ssl, n);
			if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
				return -1;
			if(mono_ms() >= deadline)
				return -1;
		}
	}
	return 0;
}

// Build a PROXY protocol v2 header (real client as source, local socket as
// destination) into hdr, which must hold at least PROXY_V2_MAX bytes. Returns 0 with the
// length in *out_len, or -1 for an unsupported family. CivetWeb parses it and
// attributes the request to the real client, not the loopback terminator, so
// client-IP logging and auth stay correct. Takes the addresses directly so
// callers without a client fd (the QUIC/HTTP3 gateway) can reuse it.
static int build_proxy_v2_sa(const struct sockaddr_storage *src,
                             const struct sockaddr_storage *dst,
                             unsigned char *hdr, size_t *out_len)
{
	static const unsigned char sig[12] =
		{ 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
	memcpy(hdr, sig, sizeof(sig));
	hdr[12] = 0x21; // version 2, PROXY command
	memset(hdr + 16, 0, 36); // clear the address block (dst may be partial)
	size_t len = 0;

	if(src->ss_family == AF_INET)
	{
		const struct sockaddr_in *s = (const struct sockaddr_in *)src;
		const struct sockaddr_in *d = (const struct sockaddr_in *)dst;
		hdr[13] = 0x11; // TCP over IPv4
		hdr[14] = 0; hdr[15] = 12;
		memcpy(hdr + 16, &s->sin_addr, 4);
		if(dst->ss_family == AF_INET)
			memcpy(hdr + 20, &d->sin_addr, 4);
		memcpy(hdr + 24, &s->sin_port, 2);
		memcpy(hdr + 26, &d->sin_port, 2);
		len = 16 + 12;
	}
	else if(src->ss_family == AF_INET6)
	{
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)src;
		const struct sockaddr_in6 *d = (const struct sockaddr_in6 *)dst;
		// The listener is dual-stack, so IPv4 clients arrive as v4-mapped IPv6;
		// emit them as IPv4 for a faithful, compact header.
		if(IN6_IS_ADDR_V4MAPPED(&s->sin6_addr))
		{
			hdr[13] = 0x11;
			hdr[14] = 0; hdr[15] = 12;
			memcpy(hdr + 16, s->sin6_addr.s6_addr + 12, 4);
			if(dst->ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&d->sin6_addr))
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
			if(dst->ss_family == AF_INET6)
				memcpy(hdr + 32, &d->sin6_addr, 16);
			memcpy(hdr + 48, &s->sin6_port, 2);
			memcpy(hdr + 50, &d->sin6_port, 2);
			len = 16 + 36;
		}
	}
	else
		return -1;

	// Announce that we terminated TLS via PP2_TYPE_SSL (0x20), value {client=
	// PP2_CLIENT_SSL (0x01), verify=0}. Without it the plaintext loopback hop
	// makes every request look like plain HTTP (no Secure cookie, wrong scheme).
	static const unsigned char ssl_tlv[8] =
		{ 0x20, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 };
	memcpy(hdr + len, ssl_tlv, sizeof(ssl_tlv));
	len += sizeof(ssl_tlv);

	// Authenticate this header to the backend with the per-boot token TLV, so a
	// PROXY header forged by another local process (which lacks the token) is
	// ignored rather than adopted as the client address / TLS status.
	hdr[len++] = PP2_TYPE_FTL_TOKEN;
	hdr[len++] = 0x00;
	hdr[len++] = (unsigned char)PROXY_TOKEN_LEN;
	memcpy(hdr + len, g_proxy_token, PROXY_TOKEN_LEN);
	len += PROXY_TOKEN_LEN;

	// Rewrite the v2 length field to cover the address block plus the TLVs.
	const size_t block = len - 16;
	hdr[14] = (unsigned char)(block >> 8);
	hdr[15] = (unsigned char)(block & 0xFF);

	*out_len = len;
	return 0;
}

// Same, but derive the source/destination addresses from a connected client
// socket via getpeername()/getsockname().
static int build_proxy_v2(int client_fd, unsigned char *hdr, size_t *out_len)
{
	struct sockaddr_storage src, dst;
	socklen_t sl = sizeof(src), dl = sizeof(dst);
	if(getpeername(client_fd, (struct sockaddr *)&src, &sl) != 0 ||
	   getsockname(client_fd, (struct sockaddr *)&dst, &dl) != 0)
		return -1;
	return build_proxy_v2_sa(&src, &dst, hdr, out_len);
}

// Announce the real client to the backend by writing a PROXY protocol v2 header
// once at the very start of the backend connection, before any request bytes.
// Returns 0 on success, -1 on error.
static int send_proxy_v2(int be_fd, int client_fd)
{
	unsigned char hdr[PROXY_V2_MAX]; // address block + SSL + token TLVs
	size_t len = 0;
	if(build_proxy_v2(client_fd, hdr, &len) != 0)
		return -1;
	return write_all_fd(be_fd, (const char *)hdr, len);
}

// Relay bytes both ways between the TLS'd client and the plaintext backend until
// either side closes. CivetWeb sees a normal HTTP/1.1 stream, so keep-alive,
// chunked bodies, ranges, etc. all work unchanged.
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

#if defined(HAVE_HTTP2) || defined(HAVE_HTTP3)
// ---------------------------------------------------------------------------
// Helpers shared by the HTTP/2 and HTTP/3 gateways. Both bridge every request to
// a plain HTTP/1.1 request against the CivetWeb backend, so the non-blocking
// backend socket, growing byte buffer, and hop-by-hop header filter are common.
// ---------------------------------------------------------------------------

// EAGAIN and EWOULDBLOCK are the same value on Linux; test both only where they
// actually differ so -Wlogical-op stays quiet.
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
#define WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
#define WOULDBLOCK(e) ((e) == EAGAIN)
#endif

// Put fd into non-blocking mode. Returns 0 or -1.
static int set_nonblocking(int fd)
{
	const int fl = fcntl(fd, F_GETFL, 0);
	if(fl < 0)
		return -1;
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

// Open a non-blocking plaintext TCP socket to the CivetWeb backend on loopback.
// Sets *connected to true if connect() completed immediately (common on
// loopback), false if still in progress (EINPROGRESS). Returns the fd or -1.
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

// Hop-by-hop / pseudo-reconstructed headers that must not be forwarded between
// the upgraded protocol and the HTTP/1.1 backend, in either direction.
static bool hbh_skip_header(const char *name, size_t len)
{
	static const char *const skip[] = {
		"connection", "keep-alive", "proxy-connection", "transfer-encoding",
		"upgrade", "te", "host", "http2-settings",
		// "expect" (100-continue) is dropped: the gateway does not relay interim
		// 1xx responses, and h2/h3 clients send the body via flow control anyway.
		"expect"
	};
	for(size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++)
		if(len == strlen(skip[i]) && strncasecmp(name, skip[i], len) == 0)
			return true;
	return false;
}

// Request body framing towards the HTTP/1.1 backend.
enum { REQ_NONE, REQ_RAW, REQ_CHUNKED };
// Response body framing from the HTTP/1.1 backend.
enum { BODY_NONE, BODY_LENGTH, BODY_CHUNKED, BODY_CLOSE };
// Incremental Transfer-Encoding: chunked decoder states.
enum { CH_SIZE, CH_EXT, CH_SIZE_LF, CH_DATA, CH_DATA_CR, CH_DATA_LF, CH_TRAILER, CH_DONE };

// Protocol-agnostic HTTP/1.1 backend-bridge state. Each streaming gateway embeds
// one per request stream and drives it through the be_* helpers: outbound
// request buffer, response-header accumulator, body de-framing state machine
// (Content-Length / chunked / close), and a decoded-body buffer.
struct be_bridge {
	// Outbound request buffer (PROXY header + HTTP/1.1 head + body), drained to
	// the backend from [req_out_off, req_out_len)
	char *req_out;
	size_t req_out_len, req_out_off, req_out_cap;
	int req_mode;
	bool req_started;

	// Response header accumulation and parse state
	char *resp_hdr;
	size_t resp_hdr_len, resp_hdr_cap;
	bool resp_headers_parsed;

	// Response body framing / decoder state
	int body_mode;
	size_t body_remaining;   // BODY_LENGTH: bytes still expected
	int chunk_state;
	size_t chunk_size;       // chunked: size being accumulated
	size_t chunk_remaining;  // chunked: bytes left in the current chunk
	size_t trailer_line_len; // chunked: length of the current trailer line

	// Decoded response body ready for the data provider, served from
	// [body_off, body_len)
	char *body_buf;
	size_t body_len, body_off, body_cap;
	bool resp_complete;      // full response body has been decoded
};

// Queue bytes to send to the backend, compacting already-sent data first so the
// buffer does not grow without bound. Returns 0 or -1.
static int be_req_push(struct be_bridge *b, const char *data, size_t n)
{
	if(b->req_out_off > 0)
	{
		memmove(b->req_out, b->req_out + b->req_out_off, b->req_out_len - b->req_out_off);
		b->req_out_len -= b->req_out_off;
		b->req_out_off = 0;
	}
	return buf_append(&b->req_out, &b->req_out_len, &b->req_out_cap, data, n);
}

// Queue decoded response body bytes for the data provider, compacting already-
// delivered data first. Returns 0 or -1.
static int be_body_push(struct be_bridge *b, const char *data, size_t n)
{
	if(b->body_off > 0)
	{
		memmove(b->body_buf, b->body_buf + b->body_off, b->body_len - b->body_off);
		b->body_len -= b->body_off;
		b->body_off = 0;
	}
	return buf_append(&b->body_buf, &b->body_len, &b->body_cap, data, n);
}

// Incrementally de-chunk a Transfer-Encoding: chunked response body, appending
// decoded bytes to the bridge body buffer. State persists across calls. Returns
// 0 or -1.
static int be_feed_chunked(struct be_bridge *b, const char *data, size_t n)
{
	size_t i = 0;
	while(i < n && b->chunk_state != CH_DONE)
	{
		const char c = data[i];
		switch(b->chunk_state)
		{
			case CH_SIZE:
				if(c >= '0' && c <= '9') { b->chunk_size = b->chunk_size * 16u + (size_t)(c - '0'); i++; }
				else if(c >= 'a' && c <= 'f') { b->chunk_size = b->chunk_size * 16u + (size_t)(c - 'a' + 10); i++; }
				else if(c >= 'A' && c <= 'F') { b->chunk_size = b->chunk_size * 16u + (size_t)(c - 'A' + 10); i++; }
				else if(c == ';') { b->chunk_state = CH_EXT; i++; }
				else if(c == '\r') { b->chunk_state = CH_SIZE_LF; i++; }
				else i++; // tolerate stray bytes
				break;
			case CH_EXT: // chunk extension: skip to end of line
				if(c == '\r') b->chunk_state = CH_SIZE_LF;
				i++;
				break;
			case CH_SIZE_LF:
				i++; // consume '\n'
				if(b->chunk_size == 0) { b->chunk_state = CH_TRAILER; b->trailer_line_len = 0; }
				else { b->chunk_remaining = b->chunk_size; b->chunk_state = CH_DATA; }
				break;
			case CH_DATA:
			{
				const size_t avail = n - i;
				const size_t take = (avail < b->chunk_remaining) ? avail : b->chunk_remaining;
				if(take > 0)
				{
					if(be_body_push(b, data + i, take) != 0)
						return -1;
					i += take;
					b->chunk_remaining -= take;
				}
				if(b->chunk_remaining == 0)
					b->chunk_state = CH_DATA_CR;
				break;
			}
			case CH_DATA_CR:
				if(c == '\r') b->chunk_state = CH_DATA_LF;
				i++;
				break;
			case CH_DATA_LF:
				if(c == '\n') { b->chunk_size = 0; b->chunk_state = CH_SIZE; }
				i++;
				break;
			case CH_TRAILER: // optional trailers terminated by a blank line
				if(c == '\n') { if(b->trailer_line_len == 0) b->chunk_state = CH_DONE; else b->trailer_line_len = 0; }
				else if(c != '\r') b->trailer_line_len++;
				i++;
				break;
		}
	}
	if(b->chunk_state == CH_DONE)
		b->resp_complete = true;
	return 0;
}

// Decode response body bytes according to the negotiated framing and append the
// result to the bridge body buffer. Returns 0 or -1.
static int be_feed_body(struct be_bridge *b, const char *data, size_t n)
{
	switch(b->body_mode)
	{
		case BODY_NONE:
			return 0;
		case BODY_LENGTH:
		{
			const size_t take = (n < b->body_remaining) ? n : b->body_remaining;
			if(take > 0 && be_body_push(b, data, take) != 0)
				return -1;
			b->body_remaining -= take;
			if(b->body_remaining == 0)
				b->resp_complete = true;
			return 0;
		}
		case BODY_CHUNKED:
			return be_feed_chunked(b, data, n);
		case BODY_CLOSE:
		default:
			if(n > 0 && be_body_push(b, data, n) != 0)
				return -1;
			return 0; // completion is signalled by the backend closing
	}
}

// True if the response body framing is known and has not reached its end, i.e.
// an early backend close or read error would truncate it. Close-delimited
// (BODY_CLOSE) and body-less (BODY_NONE) responses end legitimately on close.
static bool be_body_truncated(const struct be_bridge *b)
{
	if(b->body_mode == BODY_LENGTH)
		return b->body_remaining > 0;
	if(b->body_mode == BODY_CHUNKED)
		return b->chunk_state != CH_DONE;
	return false;
}

// Release the bridge's heap buffers. FTL's free() warns on NULL, so only free
// what was actually allocated (an unused stream leaves some fields NULL).
static void be_free(struct be_bridge *b)
{
	// Idempotent by construction: FTL's free() macro NULLs each pointer, and we
	// skip already-NULL ones, so calling this twice on the same bridge is safe
	// (the h3 reap path frees once in the nghttp3 stream_close callback and again
	// after nghttp3_conn_close_stream()), and control/QPACK streams that never
	// allocated a buffer do not trip FTLfree()'s NULL-pointer warning.
	if(b->req_out != NULL)
		free(b->req_out);
	if(b->resp_hdr != NULL)
		free(b->resp_hdr);
	if(b->body_buf != NULL)
		free(b->body_buf);
}

// Copy an h2/h3 request pseudo-header value into a fixed buffer. If it does not
// fit, set *oversize so the caller rejects the request with 414 instead of
// silently forwarding a truncated (i.e. different) request target to the backend.
static void copy_pseudo_header(char *dst, size_t cap, const char *v, size_t vlen, bool *oversize)
{
	if(vlen >= cap)
	{
		*oversize = true;
		return;
	}
	memcpy(dst, v, vlen);
	dst[vlen] = '\0';
}

// Format the plain HTTP/1.1 request head (request line + reconstructed headers)
// into out. Connection: close is added so responses are cleanly delimited.
// extra_headers, if non-NULL, is inserted verbatim (e.g. a framing header such
// as Transfer-Encoding). Returns the snprintf() result: the would-be length,
// negative on error, >= outcap if truncated.
static int be_format_request_head(char *out, size_t outcap,
                                         const char *method, const char *path,
                                         const char *authority, const char *reqhdr,
                                         size_t reqhdr_len, const char *extra_headers)
{
	return snprintf(out, outcap,
	                "%s %s HTTP/1.1\r\nHost: %s\r\n%.*s%sConnection: close\r\n\r\n",
	                method[0] ? method : "GET",
	                path[0] ? path : "/",
	                authority[0] ? authority : "pi.hole",
	                (int)reqhdr_len, reqhdr,
	                extra_headers ? extra_headers : "");
}
#endif /* HAVE_HTTP2 || HAVE_HTTP3 */

#ifdef HAVE_HTTP2
// ---------------------------------------------------------------------------
// HTTP/2 gateway (ALPN "h2")
//
// Runs an nghttp2 server session on the TLS connection and bridges every request
// stream to a plain HTTP/1.1 request against the CivetWeb backend, translating
// the response back to HTTP/2. CivetWeb never sees HTTP/2.
//
// Streams and multiplexes: each request stream gets its own non-blocking backend
// connection, the request body is streamed to the backend as it arrives
// (respecting HTTP/2 flow control), and the HTTP/1.1 response is parsed
// incrementally and pulled into HTTP/2 DATA frames on demand via an nghttp2 data
// provider. A single poll() loop drives the client TLS socket and every backend
// socket, so streams progress concurrently and none blocks the session.
// ---------------------------------------------------------------------------

#define H2_REQHDR_MAX 8192u
#define H2_MAX_HDRS 64u
// Response header block size cap before we give up parsing.
#define H2_RESP_HDR_MAX 65536u
// Per-stream decoded response body high-water mark: once this much undelivered
// body is buffered we stop reading the backend, applying backpressure toward the
// (slower) client.
#define H2_BODY_HIGH_WATER (256u * 1024u)
// Aggregate cap on decoded response body buffered across ALL streams of one
// connection. The per-stream high-water alone lets MAX_CONCURRENT_STREAMS x 256
// KiB accumulate in a single handler thread if a client stalls; this bounds the
// total so a slow/hostile multiplexed client cannot exhaust memory on a small
// device. Legit clients drain quickly and never reach it.
#define H2_CONN_BODY_CAP (4u * 1024u * 1024u)
// Soft cap on the outbound TLS buffer; we stop pulling more frames out of
// nghttp2 once this much is queued for SSL_write().
#define H2_WBUF_SOFT_CAP (512u * 1024u)
// Maximum PROXY protocol v2 header size (16 fixed + 36 for IPv6).
#define H2_PROXY_MAX PROXY_V2_MAX

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
	bool oversize;           // a pseudo-header did not fit -> answer 414, do not forward

	// Backend connection (non-blocking)
	int be_fd;
	bool be_connecting;

	// Shared HTTP/1.1 backend-bridge state: request-out buffer, response-header
	// accumulator, body de-framing, and the decoded-body buffer.
	struct be_bridge be;

	// Client DATA bytes appended but not yet acknowledged to nghttp2's flow
	// control; credited once they have been flushed to the backend.
	size_t body_uncredited;

	// Response submission / data-provider state (nghttp2-specific)
	bool resp_headers_sent;
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

// Total decoded response body buffered across all of a connection's streams.
static size_t __attribute__((pure)) h2_conn_buffered(const struct h2_conn *c)
{
	size_t total = 0;
	for(const struct h2_stream *s = c->streams; s != NULL; s = s->next)
		total += s->be.body_len - s->be.body_off;
	return total;
}

static void h2_stream_free(struct h2_stream *s)
{
	if(s == NULL)
		return;
	if(s->be_fd >= 0)
		close(s->be_fd);
	be_free(&s->be);
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
	s->be.resp_complete = true;
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
	// A pseudo-header that did not fit its buffer would forward a truncated
	// request target; reject cleanly instead of serving the wrong resource.
	if(s->oversize)
	{
		h2_gateway_error(s, "414");
		return;
	}
	if(!has_body)
		s->be.req_mode = REQ_NONE;
	else if(s->content_length_seen)
		s->be.req_mode = REQ_RAW;      // length known: forward the body verbatim
	else
		s->be.req_mode = REQ_CHUNKED;  // unknown length: chunk it to the backend

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
	   be_req_push(&s->be, (const char *)ph, phlen) != 0)
	{
		h2_gateway_error(s, "502");
		return;
	}

	char head[H2_REQHDR_MAX + 4096];
	const int hl = be_format_request_head(head, sizeof(head), s->method, s->path,
	                                      s->authority, s->reqhdr, s->reqhdr_len,
	                                      s->be.req_mode == REQ_CHUNKED ?
	                                          "Transfer-Encoding: chunked\r\n" : "");
	if(hl < 0 || (size_t)hl >= sizeof(head) || be_req_push(&s->be, head, (size_t)hl) != 0)
	{
		h2_gateway_error(s, "500");
		return;
	}
	s->be.req_started = true;
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

	const size_t avail = s->be.body_len - s->be.body_off;
	if(avail == 0)
	{
		if(s->be.resp_complete)
		{
			*data_flags |= NGHTTP2_DATA_FLAG_EOF;
			return 0;
		}
		s->resp_deferred = true;
		return NGHTTP2_ERR_DEFERRED;
	}

	const size_t n = (avail < length) ? avail : length;
	memcpy(buf, s->be.body_buf + s->be.body_off, n);
	s->be.body_off += n;
	if(s->be.body_off == s->be.body_len)
		s->be.body_off = s->be.body_len = 0;
	if(s->be.resp_complete && s->be.body_len == 0)
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
	char *clen_name = NULL, *clen_val = NULL; // Content-Length, forwarded after framing
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
					// Defer forwarding until the body framing is known: a
					// de-chunked body makes the original length wrong.
					clen_name = line; clen_val = val;
				}
				else if(nlen > 0 && !hbh_skip_header(line, nlen))
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
		s->be.body_mode = BODY_NONE;
	else if(chunked)
	{
		s->be.body_mode = BODY_CHUNKED;
		s->be.chunk_state = CH_SIZE;
	}
	else if(have_clen)
	{
		s->be.body_mode = BODY_LENGTH;
		s->be.body_remaining = clen;
	}
	else
		s->be.body_mode = BODY_CLOSE; // length delimited by the backend closing

	// Forward Content-Length unless the terminator de-chunked the body, in which
	// case the original length no longer matches the DATA the client receives
	// (the HTTP/3 path drops it unconditionally for the same reason).
	if(!chunked && clen_name != NULL && nvlen < H2_MAX_HDRS)
		h2_add_nv(nva, &nvlen, clen_name, clen_val);

#ifdef HAVE_HTTP3
	// Advertise HTTP/3 so an h3-capable browser on this h2 connection upgrades to
	// it, but only while the QUIC listener is actually up. h2_add_nv() lowercases
	// the name in place, so both name and value must be writable; nghttp2 copies
	// the nv, so these stack buffers only need to outlive the submit call below.
	char altsvc_name[] = "alt-svc";
	char altsvc[32];
	if(quic_running && nvlen < H2_MAX_HDRS)
	{
		snprintf(altsvc, sizeof(altsvc), "h3=\":%d\"; ma=86400", quic_public_port);
		h2_add_nv(nva, &nvlen, altsvc_name, altsvc);
	}
#endif

	s->be.resp_headers_parsed = true;

	const bool empty = (s->be.body_mode == BODY_NONE) ||
	                   (s->be.body_mode == BODY_LENGTH && s->be.body_remaining == 0);
	nghttp2_data_provider2 prd;
	prd.source.ptr = s;
	prd.read_callback = h2_body_read;
	const int rv = nghttp2_submit_response2(s->conn->session, s->stream_id,
	                                        nva, nvlen, empty ? NULL : &prd);
	s->resp_headers_sent = true;
	if(empty)
		s->be.resp_complete = true;
	return (rv == 0) ? 0 : -1;
}

// Feed raw bytes read from the backend socket: accumulate and parse the response
// header block first, then decode the body incrementally. Returns 0 or -1.
static int h2_feed(struct h2_stream *s, const char *data, size_t n)
{
	if(s->be.resp_headers_parsed)
		return be_feed_body(&s->be, data, n);

	if(buf_append(&s->be.resp_hdr, &s->be.resp_hdr_len, &s->be.resp_hdr_cap, data, n) != 0)
		return -1;
	char *end = memmem(s->be.resp_hdr, s->be.resp_hdr_len, "\r\n\r\n", 4);
	if(end == NULL)
		return (s->be.resp_hdr_len > H2_RESP_HDR_MAX) ? -1 : 0; // need more headers

	const size_t hdrlen = (size_t)(end - s->be.resp_hdr);
	const size_t consumed = hdrlen + 4;
	if(h2_parse_and_submit(s, s->be.resp_hdr, hdrlen) != 0)
		return -1;
	// Any bytes past the header terminator are the start of the body. Copy them
	// out (be_body_push copies) before freeing the header buffer.
	const size_t leftover = s->be.resp_hdr_len - consumed;
	if(leftover > 0 && be_feed_body(&s->be, s->be.resp_hdr + consumed, leftover) != 0)
		return -1;
	free(s->be.resp_hdr);
	s->be.resp_hdr = NULL;
	s->be.resp_hdr_len = s->be.resp_hdr_cap = 0;
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
	while(s->be.req_out_off < s->be.req_out_len)
	{
		const ssize_t w = write(s->be_fd, s->be.req_out + s->be.req_out_off,
		                        s->be.req_out_len - s->be.req_out_off);
		if(w > 0)
			s->be.req_out_off += (size_t)w;
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
	if(s->be.req_out_off == s->be.req_out_len)
	{
		s->be.req_out_off = s->be.req_out_len = 0;
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
	// Body already buffered by the OTHER streams on this connection (fixed for the
	// duration of this call), so the per-connection cap can be enforced with a
	// single walk rather than one per read.
	const size_t conn_other = h2_conn_buffered(s->conn) - (s->be.body_len - s->be.body_off);
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
			if(s->be.resp_complete)
				break;
			if((s->be.body_len - s->be.body_off) >= H2_BODY_HIGH_WATER)
				break; // per-stream backpressure: let the client drain first
			if(conn_other + (s->be.body_len - s->be.body_off) >= H2_CONN_BODY_CAP)
				break; // per-connection backpressure: aggregate body cap reached
			continue;
		}
		if(r == 0)
		{
			// Backend closed. Normal end for close-delimited bodies; for a
			// length/chunked body short of its end it is a truncation, signalled
			// to the client with RST_STREAM rather than a silently short body.
			if(!s->be.resp_headers_parsed || be_body_truncated(&s->be))
			{
				h2_gateway_error(s, "502");
				return;
			}
			s->be.resp_complete = true;
			h2_be_close(s);
			break;
		}
		if(errno == EINTR)
			continue;
		if(WOULDBLOCK(errno))
			break;
		// Fatal read error: never a legitimate end of a framed body.
		if(!s->be.resp_headers_parsed || be_body_truncated(&s->be))
		{
			h2_gateway_error(s, "502");
			return;
		}
		s->be.resp_complete = true;
		h2_be_close(s);
		break;
	}

	// The response is fully decoded; the backend socket is no longer needed.
	if(s->be.resp_complete && s->be_fd >= 0)
		h2_be_close(s);
	// Wake a parked data provider now that there is progress (more body or EOF).
	if(s->resp_deferred && ((s->be.body_len - s->be.body_off) > 0 || s->be.resp_complete))
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
			copy_pseudo_header(s->method, sizeof(s->method), v, valuelen, &s->oversize);
		else if(namelen == 5 && memcmp(n, ":path", 5) == 0)
			copy_pseudo_header(s->path, sizeof(s->path), v, valuelen, &s->oversize);
		else if(namelen == 10 && memcmp(n, ":authority", 10) == 0)
			copy_pseudo_header(s->authority, sizeof(s->authority), v, valuelen, &s->oversize);
		// :scheme is always https at the terminator and is not forwarded
		return 0;
	}

	if(hbh_skip_header(n, namelen))
		return 0;

	const size_t need = namelen + 2 + valuelen + 2;
	if(s->reqhdr_len + need < sizeof(s->reqhdr))
	{
		char *p = s->reqhdr + s->reqhdr_len;
		memcpy(p, n, namelen); p += namelen;
		*p++ = ':'; *p++ = ' ';
		memcpy(p, v, valuelen); p += valuelen;
		*p++ = '\r'; *p++ = '\n';
		s->reqhdr_len += need;
		// Only trust a Content-Length we actually forwarded: if the header did
		// not fit and was dropped, the request must instead be framed as chunked
		// (see h2_start_backend()), so leave content_length_seen false.
		if(namelen == 14 && strncasecmp(n, "content-length", 14) == 0)
			s->content_length_seen = true;
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
	if(s->be.req_mode == REQ_CHUNKED)
	{
		if(len > 0)
		{
			char hdr[32];
			const int hn = snprintf(hdr, sizeof(hdr), "%zx\r\n", len);
			if(hn < 0 || be_req_push(&s->be, hdr, (size_t)hn) != 0 ||
			   be_req_push(&s->be, (const char *)data, len) != 0 ||
			   be_req_push(&s->be, "\r\n", 2) != 0)
				return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	else if(len > 0)
	{
		if(be_req_push(&s->be, (const char *)data, len) != 0)
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
		if(s != NULL && !s->error && s->be.req_mode == REQ_CHUNKED && s->be_fd >= 0)
			be_req_push(&s->be, "0\r\n\r\n", 5);
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
		// Return any request-body bytes still charged against the connection
		// window (e.g. a stream reset mid-body before the backend flushed): the
		// session is still alive here, and h2_stream_free() would not reclaim
		// them. h2_be_close() is a no-op if already reclaimed (body_uncredited
		// zeroed).
		h2_be_close(s);
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

		// Aggregate body buffered across the connection, for the per-connection cap.
		const size_t conn_buffered = h2_conn_buffered(&conn);
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
				if(s->be.req_out_off < s->be.req_out_len)
					ev |= POLLOUT; // request bytes still to flush
				if(!s->be.resp_complete &&
				   (s->be.body_len - s->be.body_off) < H2_BODY_HIGH_WATER &&
				   conn_buffered < H2_CONN_BODY_CAP)
					ev |= POLLIN;  // room for more response body (per-stream + per-conn)
			}
			if(ev == 0)
				continue;
			conn.pfds[nfds].fd = s->be_fd;
			conn.pfds[nfds].events = ev;
			conn.pfds[nfds].revents = 0;
			conn.pmap[nfds] = s;
			nfds++;
		}

		// If nghttp2 still has data the H2_WBUF_SOFT_CAP throttle deferred and
		// the outbound TLS buffer is drained, poll with a zero timeout so the
		// next iteration pumps the next batch; otherwise a large response would
		// stall until the idle timeout and be truncated. When the buffer is not
		// drained the pollfds carry POLLOUT and we wait for the client.
		const bool more_to_pump = conn.wlen == conn.woff && !conn.ssl_want_write &&
		                          nghttp2_session_want_write(conn.session);
		const int pr = poll(conn.pfds, nfds, more_to_pump ? 0 : (IO_TIMEOUT_SEC * 1000));
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

	// nghttp2_session_del() closes remaining streams via on_stream_close (which
	// frees them); drain defensively in case it does not, then free the buffers.
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

#ifdef HAVE_HTTP3
// ---------------------------------------------------------------------------
// HTTP/3 gateway (ALPN "h3") over OpenSSL 3.5 native QUIC.
//
// A single dedicated thread owns one UDP socket, one OpenSSL QUIC listener, and
// every QUIC connection and HTTP/3 stream on top of it. OpenSSL performs the
// QUIC transport (congestion control, loss recovery, per-stream flow control);
// nghttp3 performs the HTTP/3 layer (QPACK, framing) over the per-stream byte
// streams OpenSSL exposes as child SSL objects.
//
// Each request is bridged to a plain HTTP/1.1 request against the CivetWeb
// backend and translated back, exactly like the HTTP/2 gateway and reusing the
// same be_* helpers: a per-stream non-blocking backend connection, the request
// body streamed as it arrives, and the HTTP/1.1 response parsed incrementally
// and pulled into HTTP/3 DATA frames on demand via an nghttp3 data reader (defer
// with NGHTTP3_ERR_WOULDBLOCK, resume with nghttp3_conn_resume_stream). One
// poll() set covers the UDP socket plus every backend socket, so a slow backend
// never blocks QUIC processing for the other connections.
//
// Client-IP note: each backend request carries a PROXY v2 header with the real
// client address from SSL_get_peer_addr() (OpenSSL 4.0's QUIC peer getter),
// identical to the TCP and HTTP/2 paths.
// ---------------------------------------------------------------------------

#define H3_REQHDR_MAX 8192u
#define H3_MAX_HDRS 64u
// Response header block size cap before we give up parsing.
#define H3_RESP_HDR_MAX 65536u
// Per-stream decoded response body high-water mark: once this much undelivered
// body is buffered we stop reading the backend, applying backpressure toward the
// (slower) client.
#define H3_BODY_HIGH_WATER (256u * 1024u)
// Outbound request buffer high-water mark: once this much request body is queued
// for a backend that has not drained it, we stop reading the client stream so
// QUIC flow control backpressures the client.
#define H3_REQ_HIGH_WATER (256u * 1024u)
// Maximum PROXY protocol v2 header size (16 fixed + 36 for IPv6).
#define H3_PROXY_MAX PROXY_V2_MAX

struct h3_conn;

struct h3_stream {
	struct h3_stream *next;
	struct h3_conn *conn;
	int64_t id;
	SSL *ssl;              // OpenSSL QUIC child stream object
	bool uni_local;        // control/QPACK stream we created (write-only)
	bool read_done;        // FIN (or reset) seen, no more reads

	// Request reconstruction (bidi request streams only)
	char method[16];
	char authority[256];
	char path[2048];
	char reqhdr[H3_REQHDR_MAX];
	bool oversize;           // a pseudo-header did not fit -> answer 414, do not forward
	size_t reqhdr_len;
	bool content_length_seen;

	// Backend connection (non-blocking)
	int be_fd;
	bool be_connecting;
	bool be_started;         // backend opened and request head queued

	// Shared HTTP/1.1 backend-bridge state: request-out buffer, response-header
	// accumulator, body de-framing, and the decoded-body buffer.
	struct be_bridge be;

	// Response submission / data-reader state (nghttp3-specific)
	bool resp_headers_sent;
	bool resp_deferred;      // data reader parked on NGHTTP3_ERR_WOULDBLOCK
	bool error;              // gateway error: backend torn down, stream ending
	bool reset;              // QUIC RESET_STREAM sent, stop writing this stream
};

struct h3_conn {
	struct h3_conn *next;
	SSL *ssl;              // OpenSSL QUIC connection object
	nghttp3_conn *h3;
	struct h3_stream *streams;
	bool dead;             // scheduled for teardown
	// Real QUIC client (source) and local UDP (destination) addresses, captured
	// at accept time so each backend request can carry a PROXY v2 header.
	struct sockaddr_storage client_addr;
	struct sockaddr_storage server_addr;
	bool have_client_addr;
};

// Monotonic timestamp in nanoseconds for nghttp3's rate limiter / bookkeeping.
static nghttp3_tstamp h3_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (nghttp3_tstamp)ts.tv_sec * 1000000000ull + (nghttp3_tstamp)ts.tv_nsec;
}

static struct h3_stream *__attribute__((pure)) h3_find_stream(struct h3_conn *c, int64_t id)
{
	for(struct h3_stream *s = c->streams; s != NULL; s = s->next)
		if(s->id == id)
			return s;
	return NULL;
}

static struct h3_stream *h3_stream_new(struct h3_conn *c, SSL *ssl, bool uni_local)
{
	struct h3_stream *s = calloc(1, sizeof(*s));
	if(s == NULL)
		return NULL;
	s->conn = c;
	s->ssl = ssl;
	s->uni_local = uni_local;
	s->be_fd = -1;
	s->id = (int64_t)SSL_get_stream_id(ssl);
	s->next = c->streams;
	c->streams = s;
	return s;
}

// Close the backend socket. QUIC flow control is handled by OpenSSL as we
// SSL_read the request stream, so there is no window credit to reclaim here.
static void h3_be_close(struct h3_stream *s)
{
	if(s->be_fd >= 0)
	{
		close(s->be_fd);
		s->be_fd = -1;
	}
	s->be_connecting = false;
}

// Reset the QUIC stream (send RESET_STREAM) and tell nghttp3 to stop writing it.
// Used when a framed response body is truncated by an early backend close.
static void h3_reset_stream(struct h3_stream *s)
{
	if(s->reset)
		return;
	const SSL_STREAM_RESET_ARGS rargs = { NGHTTP3_H3_INTERNAL_ERROR };
	SSL_stream_reset(s->ssl, &rargs, sizeof(rargs));
	nghttp3_conn_shutdown_stream_write(s->conn->h3, s->id);
	s->reset = true;
	s->be.resp_complete = true;
}

// nghttp3 data reader: hand decoded response body bytes to nghttp3 on demand,
// zero-copy from the bridge body buffer. Returns NGHTTP3_ERR_WOULDBLOCK when the
// backend has no more body yet; h3_be_readable() resumes the stream once it
// does. The buffer stays stable while nghttp3 references it because the event
// loop reads more backend data (which may realloc it) only after nghttp3 has
// flushed everything so far (nghttp3_conn_is_stream_flushed).
static nghttp3_ssize h3_read_data(nghttp3_conn *h3, int64_t stream_id,
                                  nghttp3_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *conn_user_data,
                                  void *stream_user_data)
{
	(void)h3; (void)veccnt; (void)stream_user_data;
	struct h3_conn *c = (struct h3_conn *)conn_user_data;
	struct h3_stream *s = h3_find_stream(c, stream_id);
	if(s == NULL)
	{
		*pflags |= NGHTTP3_DATA_FLAG_EOF;
		return 0;
	}
	const size_t avail = s->be.body_len - s->be.body_off;
	if(avail == 0)
	{
		if(s->be.resp_complete)
		{
			*pflags |= NGHTTP3_DATA_FLAG_EOF;
			return 0;
		}
		s->resp_deferred = true;
		return NGHTTP3_ERR_WOULDBLOCK;
	}
	vec[0].base = (uint8_t *)s->be.body_buf + s->be.body_off;
	vec[0].len = avail;
	s->be.body_off += avail;
	if(s->be.resp_complete && s->be.body_off == s->be.body_len)
		*pflags |= NGHTTP3_DATA_FLAG_EOF;
	return 1;
}

// Submit a status-only HTTP/3 response (used for gateway errors and bodiless
// responses). The empty data reader signals EOF immediately.
static void h3_submit_status(struct h3_stream *s, const char *status3)
{
	nghttp3_nv nv = {
		(uint8_t *)":status", (uint8_t *)status3, 7, strlen(status3),
		NGHTTP3_NV_FLAG_NONE
	};
	const nghttp3_data_reader dr = { h3_read_data };
	s->be.resp_complete = true;
	s->be.body_len = s->be.body_off = 0;
	nghttp3_conn_submit_response(s->conn->h3, s->id, &nv, 1, &dr);
	s->resp_headers_sent = true;
}

// Fail a stream at the gateway: tear down its backend socket and either submit a
// status-only response (if nothing has been sent yet) or reset the QUIC stream
// (if the response head is already on the wire).
static void h3_gateway_error(struct h3_stream *s, const char *status3)
{
	h3_be_close(s);
	s->error = true;
	if(s->resp_headers_sent)
		h3_reset_stream(s);
	else
		h3_submit_status(s, status3);
}

// Once the request headers are complete, decide the request body framing, open
// the non-blocking backend connection, and queue the PROXY header and HTTP/1.1
// request head. Mirrors h2_start_backend().
static void h3_start_backend(struct h3_stream *s, bool has_body)
{
	s->be_started = true;

	// A pseudo-header that did not fit its buffer would forward a truncated
	// request target; reject cleanly instead of serving the wrong resource.
	if(s->oversize)
	{
		h3_gateway_error(s, "414");
		return;
	}
	if(!has_body)
		s->be.req_mode = REQ_NONE;
	else if(s->content_length_seen)
		s->be.req_mode = REQ_RAW;      // length known: forward the body verbatim
	else
		s->be.req_mode = REQ_CHUNKED;  // unknown length: chunk it to the backend

	bool connected = false;
	s->be_fd = connect_backend_nb(&connected);
	if(s->be_fd < 0)
	{
		h3_gateway_error(s, "502");
		return;
	}
	s->be_connecting = !connected;

	// Announce the real client to the backend (PROXY v2) using the address we
	// captured at accept time, mirroring the TCP and HTTP/2 paths.
	if(s->conn->have_client_addr)
	{
		unsigned char ph[H3_PROXY_MAX];
		size_t phlen = 0;
		if(build_proxy_v2_sa(&s->conn->client_addr, &s->conn->server_addr,
		                     ph, &phlen) != 0 ||
		   be_req_push(&s->be, (const char *)ph, phlen) != 0)
		{
			h3_gateway_error(s, "502");
			return;
		}
	}

	char head[H3_REQHDR_MAX + 4096];
	const int hl = be_format_request_head(head, sizeof(head), s->method, s->path,
	                                      s->authority, s->reqhdr, s->reqhdr_len,
	                                      s->be.req_mode == REQ_CHUNKED ?
	                                          "Transfer-Encoding: chunked\r\n" : "");
	if(hl < 0 || (size_t)hl >= sizeof(head) || be_req_push(&s->be, head, (size_t)hl) != 0)
	{
		h3_gateway_error(s, "500");
		return;
	}
	s->be.req_started = true;
}

// Parse the HTTP/1.1 response header block hdr[0..hdrlen) (the bytes before the
// terminating CRLFCRLF), determine the body framing, and submit the HTTP/3
// response headers with a streaming data reader. nghttp3 copies the header list,
// so the in-place-parsed hdr buffer can be freed afterwards. Returns 0 or -1.
static int h3_parse_and_submit(struct h3_stream *s, char *hdr, size_t hdrlen)
{
	hdr[hdrlen] = '\0';

	char status3[4] = "502";
	const char *sp = memchr(hdr, ' ', hdrlen);
	if(sp != NULL && sp[1] && sp[2] && sp[3])
	{
		status3[0] = sp[1]; status3[1] = sp[2]; status3[2] = sp[3]; status3[3] = '\0';
	}

	nghttp3_nv nva[H3_MAX_HDRS];
	size_t nvlen = 0;
	nva[nvlen].name = (uint8_t *)":status"; nva[nvlen].namelen = 7;
	nva[nvlen].value = (uint8_t *)status3;  nva[nvlen].valuelen = 3;
	nva[nvlen].flags = NGHTTP3_NV_FLAG_NONE; nvlen++;

	bool chunked = false, have_clen = false;
	size_t clen = 0;
	char *line = strstr(hdr, "\r\n"); // skip the status line
	if(line != NULL)
	{
		line += 2;
		while(*line != '\0' && nvlen < H3_MAX_HDRS)
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
					// Content-Length is not forwarded: HTTP/3 frames the body by
					// stream FIN, and the terminator may de-chunk, changing the
					// length. nghttp3 rejects a content-length that does not match
					// what it observes, so leave it out.
				}
				else if(nlen > 0 && !hbh_skip_header(line, nlen))
				{
					// QPACK requires lowercase field names.
					for(char *ch = line; *ch != '\0'; ch++)
						*ch = (char)tolower((unsigned char)*ch);
					nva[nvlen].name = (uint8_t *)line; nva[nvlen].namelen = nlen;
					nva[nvlen].value = (uint8_t *)val; nva[nvlen].valuelen = strlen(val);
					nva[nvlen].flags = NGHTTP3_NV_FLAG_NONE; nvlen++;
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
		s->be.body_mode = BODY_NONE;
	else if(chunked)
	{
		s->be.body_mode = BODY_CHUNKED;
		s->be.chunk_state = CH_SIZE;
	}
	else if(have_clen)
	{
		s->be.body_mode = BODY_LENGTH;
		s->be.body_remaining = clen;
	}
	else
		s->be.body_mode = BODY_CLOSE; // length delimited by the backend closing

	s->be.resp_headers_parsed = true;

	const bool empty = (s->be.body_mode == BODY_NONE) ||
	                   (s->be.body_mode == BODY_LENGTH && s->be.body_remaining == 0);
	const nghttp3_data_reader dr = { h3_read_data };
	const int rv = nghttp3_conn_submit_response(s->conn->h3, s->id, nva, nvlen, &dr);
	s->resp_headers_sent = true;
	if(empty)
		s->be.resp_complete = true;
	return (rv == 0) ? 0 : -1;
}

// Feed raw bytes read from the backend socket: accumulate and parse the response
// header block first, then decode the body incrementally. Returns 0 or -1.
static int h3_feed(struct h3_stream *s, const char *data, size_t n)
{
	if(s->be.resp_headers_parsed)
		return be_feed_body(&s->be, data, n);

	if(buf_append(&s->be.resp_hdr, &s->be.resp_hdr_len, &s->be.resp_hdr_cap, data, n) != 0)
		return -1;
	char *end = memmem(s->be.resp_hdr, s->be.resp_hdr_len, "\r\n\r\n", 4);
	if(end == NULL)
		return (s->be.resp_hdr_len > H3_RESP_HDR_MAX) ? -1 : 0; // need more headers

	const size_t hdrlen = (size_t)(end - s->be.resp_hdr);
	const size_t consumed = hdrlen + 4;
	if(h3_parse_and_submit(s, s->be.resp_hdr, hdrlen) != 0)
		return -1;
	// Any bytes past the header terminator are the start of the body. Copy them
	// out (be_body_push copies) before freeing the header buffer.
	const size_t leftover = s->be.resp_hdr_len - consumed;
	if(leftover > 0 && be_feed_body(&s->be, s->be.resp_hdr + consumed, leftover) != 0)
		return -1;
	free(s->be.resp_hdr);
	s->be.resp_hdr = NULL;
	s->be.resp_hdr_len = s->be.resp_hdr_cap = 0;
	return 0;
}

// Backend socket became writable: finish a pending non-blocking connect() and
// flush as much of the queued request as the socket accepts.
static void h3_be_writable(struct h3_stream *s)
{
	if(s->be_fd < 0)
		return;
	if(s->be_connecting)
	{
		int err = 0;
		socklen_t el = sizeof(err);
		if(getsockopt(s->be_fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0)
		{
			h3_gateway_error(s, "502");
			return;
		}
		s->be_connecting = false;
	}
	while(s->be.req_out_off < s->be.req_out_len)
	{
		const ssize_t w = write(s->be_fd, s->be.req_out + s->be.req_out_off,
		                        s->be.req_out_len - s->be.req_out_off);
		if(w > 0)
			s->be.req_out_off += (size_t)w;
		else if(w < 0 && errno == EINTR)
			continue;
		else if(w < 0 && WOULDBLOCK(errno))
			break;
		else
		{
			h3_gateway_error(s, "502");
			return;
		}
	}
	if(s->be.req_out_off == s->be.req_out_len)
		s->be.req_out_off = s->be.req_out_len = 0;
}

// Backend socket became readable: pull response bytes, feed the parser/decoder,
// and resume the stream's data reader if it was parked. Stops early at the body
// high-water mark to apply backpressure toward the client.
static void h3_be_readable(struct h3_stream *s)
{
	if(s->be_fd < 0)
		return;
	char tmp[16384];
	for(;;)
	{
		const ssize_t r = read(s->be_fd, tmp, sizeof(tmp));
		if(r > 0)
		{
			if(h3_feed(s, tmp, (size_t)r) != 0)
			{
				h3_gateway_error(s, "502");
				return;
			}
			if(s->be.resp_complete)
				break;
			if((s->be.body_len - s->be.body_off) >= H3_BODY_HIGH_WATER)
				break; // backpressure: let the client drain first
			continue;
		}
		if(r == 0)
		{
			// Backend closed. For close-delimited bodies this is the normal end;
			// for a length/chunked-framed body that has not reached its end it is
			// a truncation, which we signal to the client with RESET_STREAM rather
			// than delivering a silently short body as if complete.
			if(!s->be.resp_headers_parsed || be_body_truncated(&s->be))
			{
				h3_gateway_error(s, "502");
				return;
			}
			s->be.resp_complete = true;
			h3_be_close(s);
			break;
		}
		if(errno == EINTR)
			continue;
		if(WOULDBLOCK(errno))
			break;
		// Fatal read error: never a legitimate end of a framed body.
		if(!s->be.resp_headers_parsed || be_body_truncated(&s->be))
		{
			h3_gateway_error(s, "502");
			return;
		}
		s->be.resp_complete = true;
		h3_be_close(s);
		break;
	}

	// The response is fully decoded; the backend socket is no longer needed.
	if(s->be.resp_complete && s->be_fd >= 0)
		h3_be_close(s);
	// Wake a parked data reader now that there is progress (more body or EOF).
	if(s->resp_deferred && ((s->be.body_len - s->be.body_off) > 0 || s->be.resp_complete))
	{
		s->resp_deferred = false;
		nghttp3_conn_resume_stream(s->conn->h3, s->id);
	}
}

// --- nghttp3 server callbacks ---------------------------------------------

static int h3_cb_recv_header(nghttp3_conn *h3, int64_t stream_id, int32_t token,
                             nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                             uint8_t flags, void *conn_user_data,
                             void *stream_user_data)
{
	(void)h3; (void)token; (void)flags; (void)stream_user_data;
	struct h3_conn *c = (struct h3_conn *)conn_user_data;
	struct h3_stream *s = h3_find_stream(c, stream_id);
	if(s == NULL)
		return 0;
	const nghttp3_vec nv = nghttp3_rcbuf_get_buf(name);
	const nghttp3_vec vv = nghttp3_rcbuf_get_buf(value);
	const char *n = (const char *)nv.base;
	const char *v = (const char *)vv.base;
	const size_t nl = nv.len, vl = vv.len;

	if(nl > 0 && n[0] == ':')
	{
		if(nl == 7 && memcmp(n, ":method", 7) == 0)
			copy_pseudo_header(s->method, sizeof(s->method), v, vl, &s->oversize);
		else if(nl == 5 && memcmp(n, ":path", 5) == 0)
			copy_pseudo_header(s->path, sizeof(s->path), v, vl, &s->oversize);
		else if(nl == 10 && memcmp(n, ":authority", 10) == 0)
			copy_pseudo_header(s->authority, sizeof(s->authority), v, vl, &s->oversize);
		// :scheme is always https at the terminator and is not forwarded
		return 0;
	}

	if(hbh_skip_header(n, nl))
		return 0;

	const size_t need = nl + 2 + vl + 2;
	if(s->reqhdr_len + need < sizeof(s->reqhdr))
	{
		char *p = s->reqhdr + s->reqhdr_len;
		memcpy(p, n, nl); p += nl;
		*p++ = ':'; *p++ = ' ';
		memcpy(p, v, vl); p += vl;
		*p++ = '\r'; *p++ = '\n';
		s->reqhdr_len += need;
		// Only trust a Content-Length we actually forwarded: if the header did not
		// fit and was dropped, the request must instead be framed as chunked (see
		// h3_start_backend()), so leave content_length_seen false in that case.
		if(nl == 14 && strncasecmp(n, "content-length", 14) == 0)
			s->content_length_seen = true;
	}
	return 0;
}

// The HTTP field section has ended: all request headers are in, so open the
// backend and queue the request head. |fin| is nonzero if the request has no
// body (the stream ends with the header section).
static int h3_cb_end_headers(nghttp3_conn *h3, int64_t stream_id, int fin,
                             void *conn_user_data, void *stream_user_data)
{
	(void)h3; (void)stream_user_data;
	struct h3_conn *c = (struct h3_conn *)conn_user_data;
	struct h3_stream *s = h3_find_stream(c, stream_id);
	if(s != NULL && !s->uni_local && !s->be_started && !s->error)
		h3_start_backend(s, fin == 0);
	return 0;
}

static int h3_cb_recv_data(nghttp3_conn *h3, int64_t stream_id,
                           const uint8_t *data, size_t datalen,
                           void *conn_user_data, void *stream_user_data)
{
	(void)h3; (void)stream_user_data;
	struct h3_conn *c = (struct h3_conn *)conn_user_data;
	struct h3_stream *s = h3_find_stream(c, stream_id);
	if(s == NULL)
		return 0;
	// The backend is gone (gateway error) or never opened: discard the body.
	// OpenSSL manages QUIC flow control as we SSL_read the stream, so there is no
	// separate credit to return here.
	if(s->error || s->be_fd < 0)
		return 0;
	// Stream the request body to the backend, framing it as the negotiated mode.
	if(s->be.req_mode == REQ_CHUNKED)
	{
		if(datalen > 0)
		{
			char hdr[32];
			const int hn = snprintf(hdr, sizeof(hdr), "%zx\r\n", datalen);
			if(hn < 0 || be_req_push(&s->be, hdr, (size_t)hn) != 0 ||
			   be_req_push(&s->be, (const char *)data, datalen) != 0 ||
			   be_req_push(&s->be, "\r\n", 2) != 0)
				return NGHTTP3_ERR_CALLBACK_FAILURE;
		}
	}
	else if(datalen > 0)
	{
		if(be_req_push(&s->be, (const char *)data, datalen) != 0)
			return NGHTTP3_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

static int h3_cb_end_stream(nghttp3_conn *h3, int64_t stream_id,
                            void *conn_user_data, void *stream_user_data)
{
	(void)h3; (void)stream_user_data;
	struct h3_conn *c = (struct h3_conn *)conn_user_data;
	struct h3_stream *s = h3_find_stream(c, stream_id);
	if(s == NULL)
		return 0;
	// End of the request body: finish a chunked request with the terminator.
	if(!s->error && s->be.req_mode == REQ_CHUNKED && s->be_fd >= 0)
		be_req_push(&s->be, "0\r\n\r\n", 5);
	return 0;
}

static int h3_cb_stream_close(nghttp3_conn *h3, int64_t stream_id,
                              uint64_t app_error_code, void *conn_user_data,
                              void *stream_user_data)
{
	(void)h3; (void)app_error_code; (void)stream_user_data;
	struct h3_conn *c = (struct h3_conn *)conn_user_data;
	struct h3_stream *s = h3_find_stream(c, stream_id);
	if(s != NULL)
	{
		// nghttp3 is done with the stream: release the HTTP buffers and the
		// backend socket. The node and its QUIC stream object are reclaimed by
		// h3_conn_reap_streams() once the send part is concluded/reset.
		h3_be_close(s);
		be_free(&s->be);
		s->be.req_out_len = s->be.req_out_off = s->be.req_out_cap = 0;
		s->be.resp_hdr_len = s->be.resp_hdr_cap = 0;
		s->be.body_len = s->be.body_off = s->be.body_cap = 0;
	}
	return 0;
}

// Read all currently available bytes from a stream and feed them to nghttp3.
// Returns 0 normally, -1 on a fatal nghttp3 error (connection must be torn down).
static int h3_stream_pump_read(struct h3_stream *s)
{
	uint8_t buf[16384];
	for(;;)
	{
		size_t nread = 0;
		const int r = SSL_read_ex(s->ssl, buf, sizeof(buf), &nread);
		if(r == 1 && nread > 0)
		{
			if(nghttp3_conn_read_stream2(s->conn->h3, s->id, buf, nread, 0,
			                             h3_now()) < 0)
				return -1;
			continue;
		}
		const int err = SSL_get_error(s->ssl, r);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0;
		if(err == SSL_ERROR_ZERO_RETURN)
		{
			// Clean end of the receiving side. Feed FIN to nghttp3 only for a
			// graceful finish; a reset just stops reads.
			s->read_done = true;
			if(SSL_get_stream_read_state(s->ssl) == SSL_STREAM_STATE_FINISHED &&
			   nghttp3_conn_read_stream2(s->conn->h3, s->id, NULL, 0, 1,
			                             h3_now()) < 0)
				return -1;
			return 0;
		}
		// Reset or connection-level error: stop reading this stream.
		s->read_done = true;
		return 0;
	}
}

// Drain nghttp3's pending stream writes to the QUIC streams. Returns 0 or -1.
static int h3_conn_pump_write(struct h3_conn *c)
{
	for(;;)
	{
		nghttp3_vec vec[16];
		int64_t sid = -1;
		int fin = 0;
		const nghttp3_ssize n = nghttp3_conn_writev_stream(c->h3, &sid, &fin,
		                                                   vec, 16);
		if(n < 0)
			return -1;
		if(n == 0 && sid == -1)
			break; // nothing more to write right now

		struct h3_stream *s = h3_find_stream(c, sid);
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
					// Stream send buffer full or not yet writable: retry later.
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

// Accept any newly arrived streams on a connection into the stream list.
static void h3_accept_streams(struct h3_conn *c)
{
	for(;;)
	{
		SSL *st = SSL_accept_stream(c->ssl, SSL_ACCEPT_STREAM_NO_BLOCK);
		if(st == NULL)
			break;
		if(h3_stream_new(c, st, false) == NULL)
		{
			SSL_free(st);
			break;
		}
	}
}

static const nghttp3_callbacks h3_callbacks = {
	.stream_close = h3_cb_stream_close,
	.recv_data    = h3_cb_recv_data,
	.recv_header  = h3_cb_recv_header,
	.end_headers  = h3_cb_end_headers,
	.end_stream   = h3_cb_end_stream,
};

// Set up nghttp3 and the mandatory outgoing control / QPACK streams for a freshly
// accepted QUIC connection. Returns the connection state or NULL on failure.
static struct h3_conn *h3_conn_new(SSL *cssl)
{
	struct h3_conn *c = calloc(1, sizeof(*c));
	if(c == NULL)
		return NULL;
	c->ssl = cssl;

	// Capture the real client address so each backend request can announce it
	// via PROXY v2, mirroring the TCP and HTTP/2 paths. OpenSSL hands us the
	// peer as a BIO_ADDR (network byte order for the raw port); convert it to a
	// sockaddr and remember the local UDP address as the PROXY destination.
	BIO_ADDR *ba = BIO_ADDR_new();
	if(ba != NULL && SSL_get_peer_addr(cssl, ba) == 1)
	{
		const int fam = BIO_ADDR_family(ba);
		if(fam == AF_INET)
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)&c->client_addr;
			size_t al = sizeof(sin->sin_addr);
			sin->sin_family = AF_INET;
			if(BIO_ADDR_rawaddress(ba, &sin->sin_addr, &al) == 1)
			{
				sin->sin_port = BIO_ADDR_rawport(ba);
				c->have_client_addr = true;
			}
		}
		else if(fam == AF_INET6)
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&c->client_addr;
			size_t al = sizeof(sin6->sin6_addr);
			sin6->sin6_family = AF_INET6;
			if(BIO_ADDR_rawaddress(ba, &sin6->sin6_addr, &al) == 1)
			{
				sin6->sin6_port = BIO_ADDR_rawport(ba);
				c->have_client_addr = true;
			}
		}
	}
	BIO_ADDR_free(ba);
	if(c->have_client_addr)
	{
		socklen_t dl = sizeof(c->server_addr);
		if(getsockname(quic_fd, (struct sockaddr *)&c->server_addr, &dl) != 0)
			c->server_addr.ss_family = AF_UNSPEC;
	}

	SSL_set_blocking_mode(cssl, 0);
	// We accept and drive streams by hand; do not auto-create a default stream.
	SSL_set_default_stream_mode(cssl, SSL_DEFAULT_STREAM_MODE_NONE);
	SSL_set_incoming_stream_policy(cssl, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

	nghttp3_settings settings;
	nghttp3_settings_default(&settings);
	if(nghttp3_conn_server_new(&c->h3, &h3_callbacks, &settings, NULL, c) != 0)
	{
		free(c);
		return NULL;
	}

	SSL *ctrl = SSL_new_stream(cssl, SSL_STREAM_FLAG_UNI);
	SSL *qenc = SSL_new_stream(cssl, SSL_STREAM_FLAG_UNI);
	SSL *qdec = SSL_new_stream(cssl, SSL_STREAM_FLAG_UNI);
	struct h3_stream *sc = ctrl ? h3_stream_new(c, ctrl, true) : NULL;
	struct h3_stream *se = qenc ? h3_stream_new(c, qenc, true) : NULL;
	struct h3_stream *sd = qdec ? h3_stream_new(c, qdec, true) : NULL;
	if(sc == NULL || se == NULL || sd == NULL ||
	   nghttp3_conn_bind_control_stream(c->h3, sc->id) != 0 ||
	   nghttp3_conn_bind_qpack_streams(c->h3, se->id, sd->id) != 0)
	{
		// h3_conn_free() frees whatever streams were linked; free any that were
		// created but not yet linked to avoid leaking them.
		if(ctrl && sc == NULL) SSL_free(ctrl);
		if(qenc && se == NULL) SSL_free(qenc);
		if(qdec && sd == NULL) SSL_free(qdec);
		nghttp3_conn_del(c->h3);
		for(struct h3_stream *s = c->streams; s != NULL; )
		{
			struct h3_stream *nx = s->next;
			SSL_free(s->ssl);
			free(s);
			s = nx;
		}
		free(c);
		return NULL;
	}
	return c;
}

static void h3_conn_free(struct h3_conn *c)
{
	if(c == NULL)
		return;
	if(c->h3 != NULL)
		nghttp3_conn_del(c->h3);
	for(struct h3_stream *s = c->streams; s != NULL; )
	{
		struct h3_stream *nx = s->next;
		if(s->ssl != NULL)
			SSL_free(s->ssl);
		if(s->be_fd >= 0)
			close(s->be_fd);
		be_free(&s->be);
		free(s);
		s = nx;
	}
	if(c->ssl != NULL)
		SSL_free(c->ssl);
	free(c);
}

// A finished request stream may be reclaimed once its QUIC send part is
// concluded or reset: a concluded send part keeps being flushed by the parent
// connection after the stream object is freed, so reaping loses no response
// data. For a normal finish we also wait for the receive part to end so we do
// not STOP_SENDING a request body still in flight; a reset stream is reaped
// regardless. Control/QPACK streams live for the whole connection.
static bool h3_stream_reapable(const struct h3_stream *s)
{
	if(s->uni_local)
		return false;
	const int ws = SSL_get_stream_write_state(s->ssl);
	if(ws == SSL_STREAM_STATE_OK || ws == SSL_STREAM_STATE_NONE ||
	   ws == SSL_STREAM_STATE_WRONG_DIR)
		return false; // send part still open: freeing now would truncate it
	if(ws == SSL_STREAM_STATE_FINISHED && !s->read_done)
		return false;
	return true;
}

// Reclaim completed request streams so per-connection memory and the event-loop
// scan do not grow with each request over a long-lived HTTP/3 connection (a
// browser multiplexing thousands of requests would otherwise leak a node each).
static void h3_conn_reap_streams(struct h3_conn *c)
{
	struct h3_stream **pp = &c->streams;
	while(*pp != NULL)
	{
		struct h3_stream *s = *pp;
		if(!h3_stream_reapable(s))
		{
			pp = &s->next;
			continue;
		}
		// Tell nghttp3 the stream is closed so it drops its per-stream state;
		// this also fires h3_cb_stream_close(), releasing the bridge buffers.
		nghttp3_conn_close_stream(c->h3, s->id, 0);
		*pp = s->next;
		h3_be_close(s);
		be_free(&s->be);
		if(s->ssl != NULL)
			SSL_free(s->ssl);
		free(s);
	}
}

// Compute how long poll() may sleep before an OpenSSL QUIC timer needs service,
// capped so a stopping terminator is noticed promptly.
static int h3_event_timeout_ms(SSL *listener, struct h3_conn *conns)
{
	int best = 1000; // cap in milliseconds
	struct timeval tv;
	int is_infinite = 0;
	if(SSL_get_event_timeout(listener, &tv, &is_infinite) == 1 && !is_infinite)
	{
		int ms = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
		if(ms < best) best = ms;
	}
	for(struct h3_conn *c = conns; c != NULL; c = c->next)
	{
		if(SSL_get_event_timeout(c->ssl, &tv, &is_infinite) == 1 && !is_infinite)
		{
			int ms = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
			if(ms < 0) ms = 0;
			if(ms < best) best = ms;
		}
	}
	return best;
}

// HTTP/3 event-loop thread: own the UDP socket, the QUIC listener, and every
// connection and stream. One poll() over the shared UDP socket drives OpenSSL's
// event handling; the rest is bookkeeping to bridge HTTP/3 to the backend.
static void *quic_accept_loop(void *arg)
{
	(void)arg;
	prctl(PR_SET_NAME, "terminator-h3", 0, 0, 0);

	SSL *listener = SSL_new_listener(quic_ctx, 0);
	if(listener == NULL)
	{
		log_ssl_errors("SSL_new_listener() failed");
		return NULL;
	}
	BIO *dbio = BIO_new_dgram(quic_fd, BIO_NOCLOSE);
	if(dbio == NULL)
	{
		log_ssl_errors("BIO_new_dgram() failed");
		SSL_free(listener);
		return NULL;
	}
	SSL_set_bio(listener, dbio, dbio); // listener takes ownership of dbio
	SSL_set_blocking_mode(listener, 0);
	if(SSL_listen(listener) <= 0)
	{
		log_ssl_errors("SSL_listen() failed");
		SSL_free(listener);
		return NULL;
	}

	// poll() scratch: index 0 is always the shared UDP socket, the rest are the
	// active per-stream backend sockets. pmap[i] maps pfds[i] back to its stream.
	struct pollfd *pfds = NULL;
	struct h3_stream **pmap = NULL;
	size_t pcap = 0;

	struct h3_conn *conns = NULL;
	unsigned int h3_live = 0; // live connections on `conns`, capped below
	while(quic_running)
	{
		// Size the poll set: the UDP socket plus every active backend socket.
		size_t need = 1;
		for(struct h3_conn *c = conns; c != NULL; c = c->next)
			for(struct h3_stream *s = c->streams; s != NULL; s = s->next)
				if(s->be_fd >= 0)
					need++;
		if(need > pcap)
		{
			struct pollfd *np = realloc(pfds, need * sizeof(*np));
			struct h3_stream **nm = realloc(pmap, need * sizeof(*nm));
			if(np != NULL) pfds = np;
			if(nm != NULL) pmap = nm;
			if(np != NULL && nm != NULL)
				pcap = need;
			// On a transient allocation failure keep the old capacity and poll
			// only what fits; the rest are serviced on a later iteration. Never
			// tear down live connections over a momentary memory spike.
		}
		if(pcap == 0)
		{
			// Cannot poll the UDP socket yet (allocation failed at startup).
			const struct timespec ts = { 0, 20 * 1000 * 1000 };
			nanosleep(&ts, NULL);
			continue;
		}

		pfds[0].fd = quic_fd;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
		pmap[0] = NULL;
		if(SSL_net_write_desired(listener))
			pfds[0].events |= POLLOUT;
		for(struct h3_conn *c = conns; c != NULL; c = c->next)
			if(SSL_net_write_desired(c->ssl))
				pfds[0].events |= POLLOUT;

		nfds_t nfds = 1;
		for(struct h3_conn *c = conns; c != NULL; c = c->next)
		{
			for(struct h3_stream *s = c->streams; s != NULL; s = s->next)
			{
				if(s->be_fd < 0)
					continue;
				short ev = 0;
				if(s->be_connecting || s->be.req_out_off < s->be.req_out_len)
					ev |= POLLOUT; // finish connect() or flush request bytes
				// Read more response only when there is buffer room and nghttp3 has
				// flushed everything produced so far, so the decoded-body buffer is
				// not reallocated while nghttp3 still references it.
				if(!s->be.resp_complete &&
				   (s->be.body_len - s->be.body_off) < H3_BODY_HIGH_WATER &&
				   (!s->be.resp_headers_parsed ||
				    nghttp3_conn_is_stream_flushed(c->h3, s->id)))
					ev |= POLLIN;
				if(ev == 0)
					continue;
				if((size_t)nfds >= pcap)
					break; // no room this round (grow failed): serve next loop
				pfds[nfds].fd = s->be_fd;
				pfds[nfds].events = ev;
				pfds[nfds].revents = 0;
				pmap[nfds] = s;
				nfds++;
			}
			if((size_t)nfds >= pcap)
				break;
		}

		const int pr = poll(pfds, nfds, h3_event_timeout_ms(listener, conns));
		if(pr < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}

		// Let OpenSSL process incoming datagrams and fire timers.
		SSL_handle_events(listener);
		for(struct h3_conn *c = conns; c != NULL; c = c->next)
			SSL_handle_events(c->ssl);

		// Accept any freshly handshaked connections.
		for(;;)
		{
			SSL *cs = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
			if(cs == NULL)
				break;
			// Over the cap: reject the connection but keep draining the accept
			// queue so a flood cannot pile up inside OpenSSL either.
			if(h3_live >= TERMINATOR_MAX_H3_CONNS)
			{
				SSL_free(cs);
				continue;
			}
			struct h3_conn *c = h3_conn_new(cs);
			if(c != NULL)
			{
				c->next = conns;
				conns = c;
				h3_live++;
			}
			else
				SSL_free(cs);
		}

		// Service the backend sockets first. Streams are reaped only at the end of
		// the iteration (h3_conn_reap_streams), so the pmap stays valid here; this
		// may parse a response and submit it, or resume a parked data reader.
		for(nfds_t i = 1; i < nfds; i++)
		{
			struct h3_stream *s = pmap[i];
			if(s == NULL || s->be_fd < 0)
				continue;
			if(pfds[i].revents & POLLOUT)
				h3_be_writable(s);
			if(pfds[i].revents & (POLLIN | POLLHUP | POLLERR))
				h3_be_readable(s);
		}

		// Service each connection: accept new streams, pump client reads (which
		// open backends and stream request bodies), then flush HTTP/3 writes.
		for(struct h3_conn *c = conns; c != NULL; c = c->next)
		{
			if(c->dead)
				continue;
			h3_accept_streams(c);
			for(struct h3_stream *s = c->streams; s != NULL; s = s->next)
			{
				if(s->uni_local || s->read_done)
					continue;
				// Backpressure: stop reading the request stream while its backend
				// has a large unflushed request backlog, letting QUIC flow control
				// throttle the client.
				if(s->be_fd >= 0 &&
				   (s->be.req_out_len - s->be.req_out_off) >= H3_REQ_HIGH_WATER)
					continue;
				if(h3_stream_pump_read(s) < 0)
				{
					c->dead = true;
					break;
				}
			}
			if(c->dead)
				continue;
			if(h3_conn_pump_write(c) < 0)
				c->dead = true;
			else
				h3_conn_reap_streams(c); // reclaim finished request streams
		}

		// Reap dead or closed connections.
		struct h3_conn **pp = &conns;
		while(*pp != NULL)
		{
			struct h3_conn *c = *pp;
			SSL_CONN_CLOSE_INFO info;
			const bool closed = SSL_get_conn_close_info(c->ssl, &info, sizeof(info)) == 1;
			if(c->dead || closed)
			{
				*pp = c->next;
				h3_conn_free(c);
				h3_live--;
			}
			else
				pp = &(*pp)->next;
		}
	}

	while(conns != NULL)
	{
		struct h3_conn *c = conns;
		conns = c->next;
		h3_conn_free(c);
	}
	free(pfds);
	free(pmap);
	SSL_free(listener);
	return NULL;
}

// ALPN selection on the QUIC side: accept only "h3". QUIC mandates ALPN, so a
// client that does not offer "h3" is rejected outright.
static int alpn_select_h3_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                             const unsigned char *in, unsigned int inlen, void *arg)
{
	(void)ssl;
	(void)arg;
	for(unsigned int i = 0; i + 1 <= inlen; )
	{
		const unsigned int l = in[i];
		if(i + 1 + l > inlen)
			break;
		if(l == 2 && memcmp(&in[i + 1], "h3", 2) == 0)
		{
			*out = &in[i + 1];
			*outlen = 2;
			return SSL_TLSEXT_ERR_OK;
		}
		i += 1 + l;
	}
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// Build the QUIC server SSL_CTX (certificate/key + ALPN "h3" only).
static SSL_CTX *create_quic_server_ctx(const char *cert_path)
{
	SSL_CTX *c = SSL_CTX_new(OSSL_QUIC_server_method());
	if(c == NULL)
	{
		log_ssl_errors("QUIC SSL_CTX_new() failed");
		return NULL;
	}
	if(SSL_CTX_use_certificate_chain_file(c, cert_path) != 1 ||
	   SSL_CTX_use_PrivateKey_file(c, cert_path, SSL_FILETYPE_PEM) != 1 ||
	   SSL_CTX_check_private_key(c) != 1)
	{
		log_ssl_errors("loading QUIC TLS certificate/key failed");
		SSL_CTX_free(c);
		return NULL;
	}
	SSL_CTX_set_alpn_select_cb(c, alpn_select_h3_cb, NULL);
	return c;
}

// Bind a dual-stack UDP socket on the given port for the QUIC listener.
static int bind_udp(const char *addr, int port)
{
	const int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(fd < 0)
	{
		log_err("Terminator: QUIC socket() failed: %s", strerror(errno));
		return -1;
	}
	const int on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	const int off = 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

	struct sockaddr_in6 sa;
	if(!fill_bind_addr(&sa, addr, port))
	{
		log_err("Terminator: invalid QUIC bind address '%s'", addr);
		close(fd);
		return -1;
	}
	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		log_err("Terminator: QUIC bind() to %s#%d failed: %s",
		        (addr && addr[0]) ? addr : "*", port, strerror(errno));
		close(fd);
		return -1;
	}
	if(set_nonblocking(fd) != 0)
	{
		log_err("Terminator: QUIC set_nonblocking() failed: %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

// Start the HTTP/3 listener alongside the TCP terminator. HTTP/3 is optional, so
// a failure here is logged and the terminator keeps serving HTTP/1.1 and HTTP/2.
static void terminator_quic_start(const char *bind_addr, int public_port, const char *cert_path)
{
	quic_ctx = create_quic_server_ctx(cert_path);
	if(quic_ctx == NULL)
		return;
	quic_fd = bind_udp(bind_addr, public_port);
	if(quic_fd < 0)
	{
		SSL_CTX_free(quic_ctx);
		quic_ctx = NULL;
		return;
	}
	quic_running = true;
	quic_public_port = public_port;
	if(pthread_create(&quic_tid, NULL, quic_accept_loop, NULL) != 0)
	{
		log_err("Terminator: failed to start HTTP/3 thread: %s", strerror(errno));
		quic_running = false;
		close(quic_fd);
		quic_fd = -1;
		SSL_CTX_free(quic_ctx);
		quic_ctx = NULL;
		return;
	}
	quic_tid_valid = true;
	log_info("HTTP/3 (QUIC) listening on UDP port %d", public_port);
}

static void terminator_quic_stop(void)
{
	if(quic_running)
	{
		quic_running = false;
		if(quic_tid_valid)
		{
			pthread_join(quic_tid, NULL);
			quic_tid_valid = false;
		}
	}
	if(quic_fd >= 0)
	{
		close(quic_fd);
		quic_fd = -1;
	}
	if(quic_ctx != NULL)
	{
		SSL_CTX_free(quic_ctx);
		quic_ctx = NULL;
	}
}
#endif /* HAVE_HTTP3 */

// Drive SSL_accept to completion in non-blocking mode against an absolute
// deadline, so a slow-drip client cannot pin a handler thread indefinitely
// (SO_RCVTIMEO only bounds a single idle recv, which a dribbling peer resets on
// every byte). Restores the fd's blocking mode on return for the post-handshake
// relay/gateway code. Returns true iff the handshake completed in time.
static bool terminator_handshake(SSL *ssl, int fd)
{
	const int fl = fcntl(fd, F_GETFL, 0);
	if(fl >= 0)
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
	const uint64_t deadline = mono_ms() + (uint64_t)HANDSHAKE_TIMEOUT_SEC * 1000u;
	bool ok = false;
	for(;;)
	{
		const int r = SSL_accept(ssl);
		if(r == 1)
		{
			ok = true;
			break;
		}
		const int err = SSL_get_error(ssl, r);
		if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
			break; // hard error or a plain-HTTP probe on the TLS port
		const uint64_t now = mono_ms();
		if(now >= deadline)
			break;
		struct pollfd pfd = { .fd = fd,
		                      .events = (short)((err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN),
		                      .revents = 0 };
		poll(&pfd, 1, (int)(deadline - now));
	}
	if(fl >= 0)
		fcntl(fd, F_SETFL, fl); // restore blocking for relay()/h2/h3
	return ok;
}

// Per-connection handler, run in a detached thread.
static void *handle_conn(void *arg)
{
	struct handler_arg *ha = arg;
	const int client_fd = ha->client_fd;
	SSL_CTX *const ctx = ha->ctx;
	free(ha);

	const struct timeval tv = { .tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	SSL *ssl = SSL_new(ctx);
	int be_fd = -1;
	if(ssl == NULL)
	{
		log_ssl_errors("SSL_new() failed");
		goto cleanup;
	}
	SSL_set_fd(ssl, client_fd);
	if(!terminator_handshake(ssl, client_fd))
	{
		// A failed/slow handshake (e.g. a plain-HTTP probe on the TLS port) is
		// not worth an error; keep it at debug level to avoid log flooding.
		log_debug(DEBUG_WEBSERVER, "Terminator: TLS handshake failed or timed out");
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
	SSL_CTX_free(ctx); // release our reference (keeps the ctx alive across stop)
	atomic_fetch_sub(&active_handlers, 1);
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

		// Cap concurrent handlers so a connection flood cannot exhaust the
		// process. fetch_add reserves a slot; drop the connection if over cap.
		if(atomic_fetch_add(&active_handlers, 1) >= TERMINATOR_MAX_HANDLERS)
		{
			atomic_fetch_sub(&active_handlers, 1);
			log_debug(DEBUG_WEBSERVER, "Terminator: handler cap reached, dropping connection");
			close(client_fd);
			continue;
		}

		// Hand the detached handler its own SSL_CTX reference, taken now while
		// the context is live, so terminator_stop() can free it without racing a
		// handler that has not yet reached SSL_new().
		struct handler_arg *ha = malloc(sizeof(*ha));
		if(ha == NULL)
		{
			atomic_fetch_sub(&active_handlers, 1);
			close(client_fd);
			continue;
		}
		ha->client_fd = client_fd;
		SSL_CTX_up_ref(ssl_ctx);
		ha->ctx = ssl_ctx;

		pthread_t tid;
		if(pthread_create(&tid, &attr, handle_conn, ha) != 0)
		{
			log_err("Terminator: pthread_create() failed: %s", strerror(errno));
			SSL_CTX_free(ha->ctx);
			free(ha);
			atomic_fetch_sub(&active_handlers, 1);
			close(client_fd);
		}
	}

	pthread_attr_destroy(&attr);
	return NULL;
}

bool terminator_start(const char *bind_addr, int public_port, int be_port, const char *cert_path)
{
	if(running)
	{
		log_warn("Terminator: already running");
		return false;
	}
	if(cert_path == NULL || public_port <= 0 || be_port <= 0)
		return false;

	// Per-boot secret authenticating our PROXY headers to the loopback backend.
	// Usually already generated by webserver.c (it passes the hex form to the
	// backend as proxy_protocol_secret); ensure it here too. Fail closed if the
	// RNG fails: without it the backend would ignore every header.
	if(!ensure_proxy_token())
	{
		log_err("Terminator: could not obtain secure randomness, cannot start");
		return false;
	}

	ssl_ctx = create_server_ctx(cert_path);
	if(ssl_ctx == NULL)
		return false;

	listen_fd = bind_listener(bind_addr, public_port);
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

	log_info("TLS terminator listening on %s#%d, forwarding to 127.0.0.1:%d",
	         (bind_addr && bind_addr[0]) ? bind_addr : "*", public_port, be_port);

#ifdef HAVE_HTTP3
	// Serve HTTP/3 over QUIC on the same public port (UDP). Optional: on failure
	// the terminator keeps serving HTTP/1.1 and (if built) HTTP/2 over TCP.
	terminator_quic_start(bind_addr, public_port, cert_path);
#endif
	return true;
}

void terminator_stop(void)
{
#ifdef HAVE_HTTP3
	terminator_quic_stop();
#endif

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
		// Drops our reference only. Each in-flight handler holds its own ref
		// (taken in accept_loop before SSL_new()), so the context stays valid
		// until the last handler exits - no use-after-free on SSL_new().
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
	// Note: in-flight detached handler threads are not joined here; they finish
	// on their own when their connection closes or times out (IO_TIMEOUT_SEC),
	// then release their SSL_CTX reference.
}

#else // !HAVE_TLS

// No-TLS build: the terminator does not exist. webserver.c still links
// terminator_proxy_token_hex() (its call is guarded by terminator_port > 0,
// which stays 0 here), so provide a stub. terminator_start()/stop() are only
// ever called under HAVE_TLS, so they need no stubs.
bool terminator_proxy_token_hex(char *out, size_t outsz)
{
	(void)out;
	(void)outsz;
	return false;
}

#endif // HAVE_TLS
