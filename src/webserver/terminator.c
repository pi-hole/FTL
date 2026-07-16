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

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
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

// ALPN: this milestone only serves HTTP/1.1. Offer nothing else so clients
// negotiate http/1.1 (or fall back to it when they send no ALPN).
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
	static const unsigned char http11[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
	(void)ssl;
	(void)arg;
	if(SSL_select_next_proto((unsigned char **)out, outlen, http11, sizeof(http11),
	                         in, inlen) != OPENSSL_NPN_NEGOTIATED)
		return SSL_TLSEXT_ERR_NOACK;
	return SSL_TLSEXT_ERR_OK;
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

// Announce the real client to the backend with a PROXY protocol v2 header,
// written once at the very start of the backend connection (before any request
// bytes). CivetWeb parses it and attributes the request to the actual client
// instead of the loopback terminator, so client-IP-based logging and auth stay
// correct. Returns 0 on success, -1 on error.
static int send_proxy_v2(int be_fd, int client_fd)
{
	struct sockaddr_storage src, dst;
	socklen_t sl = sizeof(src), dl = sizeof(dst);
	if(getpeername(client_fd, (struct sockaddr *)&src, &sl) != 0 ||
	   getsockname(client_fd, (struct sockaddr *)&dst, &dl) != 0)
		return -1;

	static const unsigned char sig[12] =
		{ 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
	unsigned char hdr[16 + 36];
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
