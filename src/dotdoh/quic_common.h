/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Shared outbound QUIC transport
*
*  Public interface of the QUIC primitives both encrypted-upstream QUIC clients
*  need: DoH3 (HTTP/3 on top) and DoQ (DNS directly on a stream). One client
*  SSL_CTX carries the trust store and the fail-closed verify for both; ALPN and
*  the verification name are bound per connection.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_QUIC_COMMON_H
#define DOTDOH_QUIC_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Build / tear down the shared QUIC client context (trust store, ca_file NULL or
// empty = system bundle; fail-closed verify), mirroring tls_client_global_init().
// Idempotent; returns false in a build without OpenSSL QUIC. Call before any
// QUIC pool is created.
bool quic_client_global_init(const char *ca_file);
void quic_client_global_free(void);

#if defined(HAVE_TLS) && defined(HAVE_QUIC)

#include <openssl/ssl.h>
#include <openssl/bio.h>

// The shared client context, or NULL before a successful global init.
SSL_CTX *quic_client_ctx(void) __attribute__((pure));

// Monotonic clock in milliseconds, for exchange deadlines.
uint64_t quic_now_ms(void);

// Resolve host:port and open a connected, non-blocking UDP socket, returning the
// fd and the peer address (for SSL_set1_initial_peer_addr). The connect budget
// spans all resolved records. On success the caller owns both *out_fd and
// *out_peer.
bool quic_udp_connect(const char *host, int port, uint64_t deadline,
                      int *out_fd, BIO_ADDR **out_peer);

// Wait for the QUIC socket to be ready or an OpenSSL timer to fire, bounded by
// the deadline - OpenSSL drives its own timers, so we wake to run loss recovery
// too.
void quic_wait(SSL *ssl, int fd, uint64_t deadline);

// Drive the QUIC handshake to completion (non-blocking), bounded by the
// deadline. A verification failure surfaces as a hard SSL_connect() error.
bool quic_do_handshake(SSL *ssl, int fd, uint64_t deadline);

// Bind the certificate verification name to this connection: a bare IP is
// checked against iPAddress SANs (and RFC 6066 forbids an IP literal as SNI), a
// hostname against dNSName/CN and doubles as the SNI. Returns false if either
// could not be set, which the caller must treat as fatal (fail-closed).
bool quic_bind_verify_name(SSL *ssl, const char *verify_name);

#endif // HAVE_TLS && HAVE_QUIC

#endif // DOTDOH_QUIC_COMMON_H
