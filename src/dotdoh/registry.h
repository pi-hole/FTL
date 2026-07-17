/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted-upstream proxy listener registry
*
*  Public interface for binding the loopback listeners in 127.47.11.0/24 that
*  dnsmasq forwards plaintext DNS to, one pair per encrypted upstream.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_REGISTRY_H
#define DOTDOH_REGISTRY_H

#include <stdbool.h>
#include <arpa/inet.h>

// Deterministic tuple for upstream slot i (0-based):
 // 127.47.11.(i+1)#(5300+i+1). Both the address and the port are deliberately !=
 // 53 so a dnsmasq wildcard bind on :53 cannot collide. The tuple is fixed (not
 // iterated) because the dnsmasq config is emitted with the very same formula
 // before the sockets are bound.
#define DOTDOH_NET_PREFIX  "127.47.11."
#define DOTDOH_PORT_BASE   5300
#define DOTDOH_MAX_UPSTREAMS 32

struct proxy_listener {
	int  udp_fd;
	int  tcp_fd;
	char ip[INET_ADDRSTRLEN]; // 127.47.11.N
	int  port; // the port actually bound
	bool active;
};

// Atomically bind the UDP+TCP listener pair for upstream slot `index` on its
 // fixed deterministic tuple. On success fills *l and returns true (l->active ==
 // true). If the tuple cannot be fully owned it returns false and l is inactive
 // (the upstream is left disabled). Never sets SO_REUSEADDR/SO_REUSEPORT, so a
 // squatter cannot co-bind.
bool proxy_listener_bind(int index, struct proxy_listener *l);

// Close both sockets and mark the listener inactive.
void proxy_listener_close(struct proxy_listener *l);

#endif // DOTDOH_REGISTRY_H
