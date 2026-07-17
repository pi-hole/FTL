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
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "tls_client.h"

#ifdef HAVE_MBEDTLS

#include "framing.h"
#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/x509_crt.h>
// For the bounded, non-blocking connect and the socket-level send timeout below.
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#if MBEDTLS_VERSION_NUMBER < 0x04000000
// Before Mbed TLS 4.0 the RNG was wired up by hand from a CTR_DRBG seeded off
// an entropy source; 4.0+ draws randomness from PSA and needs neither header.
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif
#ifdef MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#endif

// Read timeout (ms) applied to the handshake and to reading the answer. Keeps a
// dead or slow upstream from stalling the query indefinitely; on timeout the
// exchange fails and dnsmasq fails over.
#define TLS_READ_TIMEOUT_MS 5000

// Timeout (ms) for the TCP connect to the upstream, plus an overall wall-clock
// budget for the whole exchange (connect + handshake + write + read). The
// per-op read timeout above only bounds an idle peer; it does not bound a
// black-holed connect(), a blocking write to a peer whose receive window is
// full, or a peer that trickles one byte before each idle timeout. These hard
// deadlines do, so a single unreachable or misbehaving upstream cannot pin the
// single worker thread and stall every other encrypted upstream with it.
#define TLS_CONNECT_TIMEOUT_MS 5000
#define TLS_EXCHANGE_TIMEOUT_MS 10000

// Where to look for trust anchors when no explicit CA path is configured.
// Distributions place the system bundle differently, so try the common
// single-file locations in turn and finally the hashed directory. FTL ships as
// a musl binary that can run on any of these, so this is deliberately not
// Debian-only.
static const char *const TLS_DEFAULT_CA_FILES[] = {
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine, Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL, Fedora, CentOS
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // Alpine, *BSD, macOS
};
#define TLS_DEFAULT_CA_DIR  "/etc/ssl/certs"

// Shared, read-only-after-init crypto state. One trust store and (pre-4.0) one
// DRBG are enough for all upstreams; each connection gets its own SSL context.
static bool g_ready = false;
static mbedtls_x509_crt g_cacert;
#if MBEDTLS_VERSION_NUMBER < 0x04000000
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr;
#endif

// One pooled connection per upstream. The scratch buffers live here (not on the
// stack and not shared) so that concurrent exchanges on different connections
// never clobber each other.
struct tls_conn {
	bool connected;
	mbedtls_net_context net;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	uint8_t req[DNS_MSG_MAX + 512];                 // framed request we send
	uint8_t rbuf[DNS_MSG_MAX + DOH_HEADER_MAX];     // response accumulation buffer
};

bool tls_client_global_init(const char *ca_file)
{
	// Idempotent: the proxy may be (re)started, but the trust store only
	// needs to be built once.
	if(g_ready)
		return true;

#ifdef MBEDTLS_PSA_CRYPTO_C
	// PSA must be up before any TLS work. On 4.0+ it is also the RNG
	// source, which is why no explicit DRBG is wired below on that branch.
	if(psa_crypto_init() != PSA_SUCCESS)
	{
		log_err("dotdoh: psa_crypto_init() failed");
		return false;
	}
#endif

#if MBEDTLS_VERSION_NUMBER < 0x04000000
	// Pre-4.0: seed the DRBG handed to mbedtls_ssl_conf_rng() at connect
	// time.
	mbedtls_entropy_init(&g_entropy);
	mbedtls_ctr_drbg_init(&g_ctr);
	if(mbedtls_ctr_drbg_seed(&g_ctr, mbedtls_entropy_func, &g_entropy,
	                         (const unsigned char *)"pihole-dotdoh", 15) != 0)
	{
		log_err("dotdoh: CTR_DRBG seeding failed");
		mbedtls_ctr_drbg_free(&g_ctr);
		mbedtls_entropy_free(&g_entropy);
		return false;
	}
#endif

	// Load the trust anchors. An explicit path (dns.upstreamCA, or the test CA
	// during E2E) always wins. Otherwise try each well-known system bundle and
	// finally the hashed directory. mbedtls_x509_crt_parse_file() returns the
	// number of certs it could not parse (>= 0) or a negative error, so only a
	// negative result means nothing at all was loaded.
	mbedtls_x509_crt_init(&g_cacert);
	int rc = -1;
	if(ca_file != NULL && ca_file[0] != '\0')
		rc = mbedtls_x509_crt_parse_file(&g_cacert, ca_file);
	else
	{
		for(size_t i = 0; rc < 0 && i < sizeof(TLS_DEFAULT_CA_FILES) / sizeof(*TLS_DEFAULT_CA_FILES); i++)
			rc = mbedtls_x509_crt_parse_file(&g_cacert, TLS_DEFAULT_CA_FILES[i]);
		if(rc < 0)
			rc = mbedtls_x509_crt_parse_path(&g_cacert, TLS_DEFAULT_CA_DIR);
	}
	if(rc < 0)
	{
		log_err("dotdoh: could not load a CA trust store "
		        "(set dns.upstreamCA or install a system CA bundle)");
		mbedtls_x509_crt_free(&g_cacert);
#if MBEDTLS_VERSION_NUMBER < 0x04000000
		mbedtls_ctr_drbg_free(&g_ctr);
		mbedtls_entropy_free(&g_entropy);
#endif
		return false;
	}

	g_ready = true;
	return true;
}

void tls_client_global_free(void)
{
	if(!g_ready)
		return;
	mbedtls_x509_crt_free(&g_cacert);
#if MBEDTLS_VERSION_NUMBER < 0x04000000
	mbedtls_ctr_drbg_free(&g_ctr);
	mbedtls_entropy_free(&g_entropy);
#endif
	g_ready = false;
}

struct tls_conn *tls_conn_new(void)
{
	return calloc(1, sizeof(struct tls_conn));
}

// Tear down an established connection so the next exchange reconnects cleanly.
static void conn_close(struct tls_conn *c)
{
	if(!c->connected)
		return;
	// Best-effort notify; we do not care whether the peer sees it.
	mbedtls_ssl_close_notify(&c->ssl);
	mbedtls_ssl_free(&c->ssl);
	mbedtls_ssl_config_free(&c->conf);
	mbedtls_net_free(&c->net);
	c->connected = false;
}

void tls_conn_free(struct tls_conn *c)
{
	if(c == NULL)
		return;
	conn_close(c);
	free(c);
}

// Monotonic clock in milliseconds, for the exchange deadline.
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

// Bounded, non-blocking TCP connect. mbedtls_net_connect() does a blocking
// connect() with no timeout, so a black-holed upstream (dropped SYN) would pin
// the single worker thread for the kernel's full SYN timeout (~2 min) and stall
// every other encrypted upstream with it. Connect non-blocking and poll() for
// the deadline instead, then hand the ready socket to mbedTLS.
static int net_connect_timeout(mbedtls_net_context *net, const char *host,
                               const char *port, int timeout_ms)
{
	struct addrinfo hints = { 0 };
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *res = NULL;
	if(getaddrinfo(host, port, &hints, &res) != 0)
		return MBEDTLS_ERR_NET_UNKNOWN_HOST;

	// timeout_ms is the budget for the whole connect, not per address: share
	// the remaining time across every A/AAAA record rather than restarting the
	// full timeout for each, so a multi-homed host cannot blow the deadline.
	const uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

	int ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
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
			fcntl(fd, F_SETFL, flags); // restore blocking mode for mbedTLS I/O
			net->fd = fd;
			ret = 0;
			break;
		}
		close(fd);
	}

	freeaddrinfo(res);
	return ret;
}

// Open a TCP connection and drive the TLS handshake to the upstream described
// by u. Returns true only once the connection is verified and ready. deadline
// bounds the connect and handshake so a stalled peer cannot pin the worker.
static bool conn_connect(struct tls_conn *c, const struct upstream_uri *u, uint64_t deadline)
{
	mbedtls_net_init(&c->net);
	mbedtls_ssl_init(&c->ssl);
	mbedtls_ssl_config_init(&c->conf);

	// net_connect_timeout() wants the port as a string.
	char portstr[8];
	snprintf(portstr, sizeof(portstr), "%d", u->port);

	int rc;
	if((rc = net_connect_timeout(&c->net, u->connect_host, portstr,
	                             ms_left(deadline, TLS_CONNECT_TIMEOUT_MS))) != 0)
	{
		log_warn("dotdoh: connect to %s#%d failed (mbedtls -0x%04x)",
		         u->connect_host, u->port, (unsigned)-rc);
		goto fail;
	}

	// Bound blocking sends too: the write BIO (mbedtls_net_send) has no timeout
	// of its own, so without this a peer that stops reading would block
	// ssl_write_all() forever once its receive window fills.
	const struct timeval sndto = { .tv_sec = TLS_READ_TIMEOUT_MS / 1000, .tv_usec = 0 };
	setsockopt(c->net.fd, SOL_SOCKET, SO_SNDTIMEO, &sndto, sizeof(sndto));

	if(mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_CLIENT,
	                               MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
		goto fail;

	// This is the fail-closed heart of the client: REQUIRED means a bad
	// chain or hostname mismatch aborts the handshake instead of merely
	// being reported after the fact.
	mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&c->conf, &g_cacert, NULL);
	mbedtls_ssl_conf_read_timeout(&c->conf, TLS_READ_TIMEOUT_MS);
#if MBEDTLS_VERSION_NUMBER < 0x04000000
	// 4.0+ pulls randomness from PSA automatically; only older versions need
	// the DRBG wired in explicitly.
	mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &g_ctr);
#endif

	if(mbedtls_ssl_setup(&c->ssl, &c->conf) != 0)
		goto fail;

	// verify_name is the hostname the certificate is checked against and
	// the SNI sent to the server. For a pinned "sni-host@ip" upstream this
	// is the hostname, not the IP, so verification still matches the real
	// cert.
	if(mbedtls_ssl_set_hostname(&c->ssl, u->verify_name) != 0)
		goto fail;

	// Use the timeout-aware receive callback so the read timeout above
	// applies.
	mbedtls_ssl_set_bio(&c->ssl, &c->net, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

	// Blocking sockets should not normally yield WANT_READ/WANT_WRITE, but
	// the read timeout can surface them; loop until the handshake resolves.
	while((rc = mbedtls_ssl_handshake(&c->ssl)) != 0)
	{
		if(rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			log_warn("dotdoh: TLS handshake with %s (%s#%d) failed (mbedtls -0x%04x)",
			         u->verify_name, u->connect_host, u->port, (unsigned)-rc);
			goto fail;
		}
		if(now_ms() >= deadline)
		{
			log_warn("dotdoh: TLS handshake with %s (%s#%d) timed out",
			         u->verify_name, u->connect_host, u->port);
			goto fail;
		}
	}

	c->connected = true;
	return true;

fail:
	// We never reached the "connected" state, so free the half-initialised
	// contexts directly rather than via conn_close().
	mbedtls_ssl_free(&c->ssl);
	mbedtls_ssl_config_free(&c->conf);
	mbedtls_net_free(&c->net);
	c->connected = false;
	return false;
}

// Write the whole buffer, tolerating short writes and the transient
// WANT_READ/WANT_WRITE conditions. Returns true once everything is sent.
static bool ssl_write_all(struct tls_conn *c, const uint8_t *buf, size_t len, uint64_t deadline)
{
	size_t off = 0;
	while(off < len)
	{
		int w = mbedtls_ssl_write(&c->ssl, buf + off, len - off);
		if(w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			if(now_ms() >= deadline)
				return false;
			continue;
		}
		if(w <= 0)
			return false;
		off += (size_t)w;
	}
	return true;
}

// Send one query and read back the framed answer over the established
// connection. Returns the answer length, or -1 on any protocol/transport error
// (which makes the caller drop and, once, rebuild the connection).
static ssize_t conn_do(struct tls_conn *c, const struct upstream_uri *u,
                       const uint8_t *query, size_t qlen,
                       uint8_t *answer, size_t answer_sz, uint64_t deadline)
{
	// Frame the request: DoT prepends a 2-byte length, DoH wraps it in a
	// POST.
	ssize_t reqlen;
	if(u->type == UST_DOT)
		reqlen = dot_frame(query, qlen, c->req, sizeof(c->req));
	else
		reqlen = doh_build_request(u->verify_name, u->doh_path, query, qlen, c->req, sizeof(c->req));
	if(reqlen < 0)
		return -1;

	if(!ssl_write_all(c, c->req, (size_t)reqlen, deadline))
		return -1;

	// Accumulate the response until the framer says a full message is
	// present. The buffer is bounded, so a misbehaving upstream cannot make
	// us grow it.
	uint8_t *buf = c->rbuf;
	const size_t bufcap = sizeof(c->rbuf);
	size_t have = 0;
	for(;;)
	{
		// Bounds both a full buffer and a peer that trickles a byte at a time:
		// such reads return r > 0 and would otherwise loop until the buffer
		// fills (many hours) without ever hitting the WANT_READ deadline below.
		if(have >= bufcap || now_ms() >= deadline)
			return -1;
		int r = mbedtls_ssl_read(&c->ssl, buf + have, bufcap - have);
		// TLS 1.3 delivers post-handshake messages to the application
		// as these non-fatal returns: a NewSessionTicket arrives right
		// after the handshake (which the upstream sends before our
		// answer). They are not errors - just read again for the actual
		// response.
		if(r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE
#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
		   // Only present on mbedTLS builds with TLS 1.3 post-handshake tickets;
		   // guarded so older versions still compile (they never return it).
		   || r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
#endif
		   )
			continue; // deadline is enforced at the top of the loop
		if(r <= 0)
			return -1; // timeout, close_notify or hard error
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

ssize_t tls_exchange(struct tls_conn *c, const struct upstream_uri *u,
                     const uint8_t *query, size_t qlen,
                     uint8_t *answer, size_t answer_sz)
{
	if(!g_ready || c == NULL || u == NULL)
		return -1;

	// Two attempts at most: a pooled keep-alive connection the upstream
	// closed while idle is transparently rebuilt once. A second failure is
	// real and we give up (fail-closed) rather than retry forever.
	// One overall budget for the whole exchange (both attempts share it) so a
	// stalled connect, handshake, read or write cannot pin the single worker
	// thread and starve every other encrypted upstream.
	const uint64_t deadline = now_ms() + TLS_EXCHANGE_TIMEOUT_MS;

	for(int attempt = 0; attempt < 2; attempt++)
	{
		if(!c->connected && !conn_connect(c, u, deadline))
			continue;

		const ssize_t r = conn_do(c, u, query, qlen, answer, answer_sz, deadline);
		if(r >= 0)
			return r;

		conn_close(c);
	}
	return -1;
}

#else // !HAVE_MBEDTLS

// Without mbedTLS there is no TLS client; encrypted upstreams are unavailable
// and every exchange fails closed. The config layer refuses to enable them.
bool tls_client_global_init(const char *ca_file) { (void)ca_file; return false; }
void tls_client_global_free(void) { }
struct tls_conn *tls_conn_new(void) { return NULL; }
void tls_conn_free(struct tls_conn *c) { (void)c; }
ssize_t tls_exchange(struct tls_conn *c, const struct upstream_uri *u,
                     const uint8_t *query, size_t qlen,
                     uint8_t *answer, size_t answer_sz)
{
	(void)c; (void)u; (void)query; (void)qlen; (void)answer; (void)answer_sz;
	return -1;
}

#endif // HAVE_MBEDTLS
