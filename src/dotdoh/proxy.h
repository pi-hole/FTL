/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted-upstream forward proxy
*
*  Public interface of the forward proxy: arms the encrypted upstreams and runs
*  the worker thread that re-encrypts dnsmasq's plaintext DNS over DoT/DoH.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_PROXY_H
#define DOTDOH_PROXY_H

#include <stdbool.h>
#include <stddef.h>
#include "upstream_uri.h"

// Arm the proxy from the global config: for every encrypted dns.upstreams entry
 // bind its deterministic loopback listener (127.47.11.N#(5300+N)) and prepare a
 // connection. Plaintext entries are ignored (dnsmasq talks to them directly).
 //
 // This MUST run late - from FTL_fork_and_bind_sockets(), after dnsmasq's own
 // startup has finished closing stray fds - otherwise the listener fds would be
 // closed and their numbers reused by dnsmasq. The dnsmasq server= list is
 // emitted earlier using the same deterministic tuples, so the two agree without
 // needing the sockets to be bound at emission time.
void dotdoh_init(void);

// Number of encrypted upstreams that are armed and being served.
int dotdoh_count(void) __attribute__((pure));

// FTL worker thread entry: services every armed listener until shutdown.
void *dotdoh_thread(void *val);

// Release listeners, connections and the CA store.
void dotdoh_cleanup(void);

// Map a loopback proxy tuple (127.47.11.N#(5300+N)) back to the encrypted
// upstream it represents, so it is recorded/displayed as the real upstream
// rather than the internal address dnsmasq forwards to. Returns false if
// (ip, port) is not a dotdoh proxy tuple; otherwise copies the URI
// (NUL-terminated) into out and, if real_port is non-NULL, stores the upstream's
// actual port (853/443 or an explicit one) there.
bool dotdoh_uri_for_listener(const char *ip, int port, char *out, size_t outlen, int *real_port);

#endif // DOTDOH_PROXY_H
