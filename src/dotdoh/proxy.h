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
#include <stdint.h>
#include "upstream_uri.h"

// Arm the proxy from the global config: for every encrypted dns.upstreams entry
// bind its randomised loopback listener (see registry.h) and prepare a
// connection. Plaintext entries are ignored (dnsmasq talks to them directly).
//
// MUST run late - from FTL_fork_and_bind_sockets(), after dnsmasq finished
// closing stray fds - or the listener fds would be closed and reused. The
// server= list is emitted earlier from the same tuple table, so the two agree.
void dotdoh_init(void);

// Number of encrypted upstreams that are armed and being served.
int dotdoh_count(void) __attribute__((pure));

// Release the worker pool, listeners, connection pools and the CA store.
void dotdoh_cleanup(void);

// Map a loopback proxy tuple back to the encrypted upstream it represents, so it
// is recorded/displayed as the real upstream. Returns false if (ip, port) is not
// a dotdoh tuple; otherwise copies the URI into out and, if real_port is
// non-NULL, stores the upstream's actual port (853/443 or explicit) there.
bool dotdoh_uri_for_listener(const char *ip, int port, char *out, size_t outlen, int *real_port);

// Whether dnsmasq may forward to (addr_h, port), addr_h in host byte order. True
// for anything that is not one of our encrypted-upstream tuples, and for a tuple
// only when its upstream is armed. Backs FTL_is_forward_available() - hot path.
bool dotdoh_forward_available(uint32_t addr_h, int port);

#endif // DOTDOH_PROXY_H
