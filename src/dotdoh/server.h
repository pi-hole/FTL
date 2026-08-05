/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Inbound DoT/DoH server
*
*  Public interface of the inbound encrypted-DNS server (serving downstream
*  clients). Throughout this module "client" always means the downstream device
*  that queries us - as in Pi-hole's client tables (clientsData/getClient) - never
*  our own TLS-client role (that is the outbound "upstream" side). DoH is served
*  natively by the front TLS terminator over HTTP/1.1, HTTP/2 and HTTP/3 (see
*  terminator.c). DoT has its own raw-TLS listener as it is not HTTP.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_SERVER_H
#define DOTDOH_SERVER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

// Append the Pi-hole-private client option (the real downstream client IP) to
// the DNS query in buf[0..plen) with capacity cap, and return the new packet
// length (unchanged if client_ip is not a valid address or there is no room).
// Implemented in src/edns0.c (which has the dnsmasq wire helpers); declared here
// rather than in edns0.h so the dotdoh translation units can call it without
// pulling dnsmasq.h (and its wire types) into these TLS units.
size_t dotdoh_inject_client(unsigned char *buf, size_t plen, size_t cap,
                            const char *client_ip, const char *dest_ip);

// Assemble the loopback handoff for one decrypted query: copy query[0..qlen)
// into framed[2..], append the private client/dest attribution options, and
// write the 2-byte DoT length prefix into framed[0..1]. `framed` must hold at
// least 2 + DNS_MSG_MAX bytes. Returns the total framed length (2 + attributed
// query) or -1 on an empty query or insufficient room. The single place the DoT
// reactor and the DoH handler build the query they hand to dnsmasq.
ssize_t dotdoh_prepare_query(const uint8_t *query, size_t qlen,
                             const char *client, const char *dest,
                             uint8_t *framed, size_t framed_cap);

// Whether an inbound DoT/DoH connection from client_ip (a numeric IPv4/IPv6
// string) may be served under the current dns.listeningMode. Only LISTEN_ALL
// serves every origin; otherwise only loopback and local-subnet clients are
// served, so an on-by-default server is not an open resolver. Fails closed.
bool dotdoh_source_allowed(const char *client_ip);

// Whether inbound DoH is enabled (config.dns.doh). Lets the h2/h3 terminator gate
// its native /dns-query handling without pulling in the config headers.
bool dotdoh_doh_enabled(void) __attribute__((pure));

// DoH wire helpers (implemented in server.c), shared with the
// terminator-native h2/h3 DoH path. base64url_decode decodes the GET "dns"
// parameter; doh_answer_min_ttl yields the Cache-Control max-age (RFC 8484).
ssize_t base64url_decode(const char *in, size_t inlen, uint8_t *out, size_t outcap);
uint32_t doh_answer_min_ttl(const uint8_t *msg, size_t len) __attribute__((pure));

// Resolve one decrypted DNS query (from client `client`) through dnsmasq over
// the loopback handoff, injecting the private client option so it is attributed
// to the real client. `dest` is the local address the client connected to (or
// NULL), conveyed so pi.hole/<hostname> answers use it instead of the loopback
// forward address. Returns the answer length in `answer` (capacity `answer_sz`)
// or -1. Shared by the DoH handler and the DoT listener.
ssize_t dotdoh_server_resolve(const char *client, const char *dest,
                              const uint8_t *query, size_t qlen,
                              uint8_t *answer, size_t answer_sz);

// FTL worker thread entry for the inbound DoT (DNS-over-TLS) listener on port
// 853. Runs only when dns.dot is enabled. Terminates TLS itself (DoT is not
// HTTP, so it needs its own raw-TLS listener) and resolves via
// dotdoh_server_resolve().
void *dotdoh_dot_thread(void *val);

#endif // DOTDOH_SERVER_H
