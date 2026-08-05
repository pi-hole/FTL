/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Shared outbound QUIC transport
*
*  The socket, handshake and timer plumbing every outbound QUIC upstream needs.
*  DoH3 puts HTTP/3 on top of it, DoQ puts the DNS message on a stream directly;
*  both share one client SSL_CTX so the trust store is loaded once and the
*  fail-closed verify behaves identically on either transport.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "quic_common.h"

#if defined(HAVE_TLS) && defined(HAVE_QUIC)

#include <openssl/quic.h>
#include <openssl/x509_vfy.h>
#include <openssl/opensslv.h>

// OpenSSL's QUIC client is used by both DoQ and DoH3 and needs the 4.0 API.
// Refuse to build rather than link against a QUIC API that is not there.
#if OPENSSL_VERSION_NUMBER < 0x40000000L
#error "QUIC requires OpenSSL >= 4.0. Upgrade OpenSSL to 4.0 or later, or build without QUIC."
#endif

#include <string.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

// Trust-anchor locations when no CA path is set, kept in step with tls_client.c.
// FTL's musl binary runs on any of these distros, so this is not Debian-only.
static const char *const QUIC_DEFAULT_CA_FILES[] = {
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine, Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL, Fedora, CentOS
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // Alpine, *BSD, macOS
};
#define QUIC_DEFAULT_CA_DIR "/etc/ssl/certs"

// Shared, read-only-after-init QUIC context. Built once (single-threaded) in
// quic_client_global_init(), so a plain flag is enough.
static bool g_ready = false;
static SSL_CTX *g_qctx = NULL;

uint64_t quic_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// Milliseconds left until deadline, clamped to [0, cap].
static int ms_left(uint64_t deadline, int cap)
{
	const uint64_t n = quic_now_ms();
	if(n >= deadline)
		return 0;
	const uint64_t left = deadline - n;
	return left < (uint64_t)cap ? (int)left : cap;
}

// Load trust anchors into ctx exactly like tls_client.c: an explicit path wins,
// otherwise try each well-known system bundle and finally the hashed directory.
static bool load_ca(SSL_CTX *ctx, const char *ca_file)
{
	if(ca_file != NULL && ca_file[0] != '\0')
		return SSL_CTX_load_verify_file(ctx, ca_file) == 1;
	for(size_t i = 0; i < sizeof(QUIC_DEFAULT_CA_FILES) / sizeof(*QUIC_DEFAULT_CA_FILES); i++)
		if(SSL_CTX_load_verify_file(ctx, QUIC_DEFAULT_CA_FILES[i]) == 1)
			return true;
	return SSL_CTX_load_verify_dir(ctx, QUIC_DEFAULT_CA_DIR) == 1;
}

bool quic_client_global_init(const char *ca_file)
{
	if(g_ready)
		return true;

	g_qctx = SSL_CTX_new(OSSL_QUIC_client_method());
	if(g_qctx == NULL)
	{
		log_err("dotdoh: QUIC SSL_CTX_new() failed");
		return false;
	}

	// Fail-closed heart of the client: a bad chain aborts the handshake. The
	// hostname/IP is bound per-connection in quic_bind_verify_name(). QUIC
	// mandates TLS 1.3, so no min-version call is needed.
	SSL_CTX_set_verify(g_qctx, SSL_VERIFY_PEER, NULL);

	if(!load_ca(g_qctx, ca_file))
	{
		log_err("dotdoh: could not load a CA trust store for encrypted QUIC upstreams "
		        "(set dns.upstreamCA or install a system CA bundle)");
		SSL_CTX_free(g_qctx);
		g_qctx = NULL;
		return false;
	}

	g_ready = true;
	return true;
}

void quic_client_global_free(void)
{
	if(!g_ready)
		return;
	SSL_CTX_free(g_qctx);
	g_qctx = NULL;
	g_ready = false;
}

SSL_CTX *quic_client_ctx(void)
{
	return g_ready ? g_qctx : NULL;
}

bool quic_udp_connect(const char *host, int port, uint64_t deadline,
                      int *out_fd, BIO_ADDR **out_peer)
{
	char portstr[8];
	snprintf(portstr, sizeof(portstr), "%d", port);

	struct addrinfo hints = { 0 };
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	struct addrinfo *res = NULL;
	if(getaddrinfo(host, portstr, &hints, &res) != 0)
		return false;

	bool ok = false;
	for(struct addrinfo *cur = res; cur != NULL && !ok; cur = cur->ai_next)
	{
		if(quic_now_ms() >= deadline)
			break;
		// SOCK_CLOEXEC so a connected upstream socket is not inherited across
		// FTL's execvp() self-restart.
		const int fd = socket(cur->ai_family, cur->ai_socktype | SOCK_CLOEXEC, cur->ai_protocol);
		if(fd < 0)
			continue;
		// A connected UDP socket lets the kernel drop stray datagrams from other
		// peers before OpenSSL ever sees them. connect() on UDP does not block.
		if(connect(fd, cur->ai_addr, cur->ai_addrlen) != 0)
		{
			close(fd);
			continue;
		}
		const int flags = fcntl(fd, F_GETFL, 0);
		if(flags >= 0)
			fcntl(fd, F_SETFL, flags | O_NONBLOCK);

		BIO_ADDR *peer = BIO_ADDR_new();
		if(peer == NULL)
		{
			close(fd);
			break;
		}
		// Copy into aligned storage before reading family-specific fields;
		// ai_addr has only sockaddr alignment, so a direct cast trips -Wcast-align.
		struct sockaddr_storage ss;
		memcpy(&ss, cur->ai_addr, cur->ai_addrlen < sizeof(ss) ? cur->ai_addrlen : sizeof(ss));
		unsigned short nport = 0;
		const void *raw = NULL;
		size_t rawlen = 0;
		if(cur->ai_family == AF_INET)
		{
			struct sockaddr_in sin;
			memcpy(&sin, &ss, sizeof(sin));
			nport = sin.sin_port;          // already network byte order
			raw = &((struct sockaddr_in *)&ss)->sin_addr;
			rawlen = sizeof(sin.sin_addr);
		}
		else if(cur->ai_family == AF_INET6)
		{
			struct sockaddr_in6 sin6;
			memcpy(&sin6, &ss, sizeof(sin6));
			nport = sin6.sin6_port;
			raw = &((struct sockaddr_in6 *)&ss)->sin6_addr;
			rawlen = sizeof(sin6.sin6_addr);
		}
		if(raw != NULL &&
		   BIO_ADDR_rawmake(peer, cur->ai_family, raw, rawlen, nport) == 1)
		{
			*out_fd = fd;
			*out_peer = peer;
			ok = true;
		}
		else
		{
			BIO_ADDR_free(peer);
			close(fd);
		}
	}

	freeaddrinfo(res);
	return ok;
}

void quic_wait(SSL *ssl, int fd, uint64_t deadline)
{
	struct pollfd pfd = { .fd = fd, .events = 0, .revents = 0 };
	if(SSL_net_read_desired(ssl))
		pfd.events |= POLLIN;
	if(SSL_net_write_desired(ssl))
		pfd.events |= POLLOUT;

	int tmo = ms_left(deadline, 1000);
	struct timeval tv;
	int is_infinite = 0;
	if(SSL_get_event_timeout(ssl, &tv, &is_infinite) == 1 && !is_infinite)
	{
		int ev = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
		if(ev < 0)
			ev = 0;
		if(ev < tmo)
			tmo = ev;
	}
	poll(pfd.events != 0 ? &pfd : NULL, pfd.events != 0 ? 1 : 0, tmo);
}

bool quic_do_handshake(SSL *ssl, int fd, uint64_t deadline)
{
	for(;;)
	{
		const int rc = SSL_connect(ssl);
		if(rc == 1)
			return true;
		const int err = SSL_get_error(ssl, rc);
		if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
			return false;
		if(quic_now_ms() >= deadline)
			return false;
		quic_wait(ssl, fd, deadline);
	}
}

bool quic_bind_verify_name(SSL *ssl, const char *verify_name)
{
	struct in_addr v4;
	struct in6_addr v6;
	if(inet_pton(AF_INET, verify_name, &v4) == 1 ||
	   inet_pton(AF_INET6, verify_name, &v6) == 1)
		return X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), verify_name) == 1;

	if(X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), verify_name, 0) != 1)
		return false;
	return SSL_set_tlsext_host_name(ssl, verify_name) == 1;
}

#else // no QUIC support in this build

// Without OpenSSL QUIC there is no QUIC transport at all: the context never
// comes up and every pool creation fails closed. These trivial stubs are
// const-folding candidates, so silence the GCC-only -Wsuggest-attribute hints.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#endif
bool quic_client_global_init(const char *ca_file) { (void)ca_file; return false; }
void quic_client_global_free(void) { }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif // HAVE_TLS && HAVE_QUIC
