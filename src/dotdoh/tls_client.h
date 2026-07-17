/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound TLS client for encrypted upstreams (DoT/DoH)
*
*  Public interface of the strict, fail-closed mbedTLS client that talks to the
*  real upstream resolver and never falls back to plaintext.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_TLS_CLIENT_H
#define DOTDOH_TLS_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "upstream_uri.h"

struct tls_conn; // opaque per-upstream connection state

// Load the CA bundle and seed the RNG. ca_file NULL selects the system default
 // bundle. Returns true on success.
bool tls_client_global_init(const char *ca_file);
void tls_client_global_free(void);

// Allocate / free a reusable per-upstream connection handle.
struct tls_conn *tls_conn_new(void) __attribute__((malloc));
void tls_conn_free(struct tls_conn *c);

// Perform one DNS exchange over TLS for upstream u, (re)establishing the pooled
 // connection as needed. query/qlen is the DNS wire message; the answer is
 // written into answer[answer_sz]. Returns the answer length, or -1 on any
 // failure (the caller returns SERVFAIL so dnsmasq fails over). Fail-closed.
ssize_t tls_exchange(struct tls_conn *c, const struct upstream_uri *u,
                     const uint8_t *query, size_t qlen,
                     uint8_t *answer, size_t answer_sz);

#endif // DOTDOH_TLS_CLIENT_H
