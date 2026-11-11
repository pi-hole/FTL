/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted-upstream proxy listener registry
*
*  Public interface for binding the loopback listeners on a per-process randomised
*  127.0.0.0/8 tuple that dnsmasq forwards plaintext DNS to, one pair per upstream.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_REGISTRY_H
#define DOTDOH_REGISTRY_H

#include <stdbool.h>
#include <arpa/inet.h>

// Loopback tuple for upstream slot i (0-based): a per-process randomised
// 127.0.0.0/8 address and unprivileged port (see dotdoh_tuple_addr()/_port()),
// unguessable to a local attacker. DOTDOH_NET_PREFIX / DOTDOH_PORT_BASE are only
// the deterministic fallback for when the CSPRNG is unavailable at early boot.
#define DOTDOH_NET_PREFIX  "127.47.11."
#define DOTDOH_PORT_BASE   5300
#define DOTDOH_MAX_UPSTREAMS 32

// The loopback address (host byte order) and port for slot `index`, drawn once
// per process from the CSPRNG and cached, so config emission, proxy bind and
// reverse lookup all agree (embedded dnsmasq inherits the table across its fork).
// addr returns 0 / port returns -1 out of range; dotdoh_tuple_ip() writes the
// dotted-quad form.
uint32_t dotdoh_tuple_addr(int index);
int dotdoh_tuple_port(int index);
void dotdoh_tuple_ip(int index, char *buf, size_t buflen);

// Draw a fresh random tuple for one slot (used by the config-generation retry).
void dotdoh_tuple_redraw(int index);

// Ensure slot `index` has a bindable tuple, redrawing on a collision up to 5
// times so a chance clash does not needlessly disable an upstream. Test-binds
// (no SO_REUSEADDR) and releases; the real bind is later in dotdoh_init().
// Returns false only if all 5 tries were unbindable, which the forward gate then
// keeps fail-closed.
bool dotdoh_tuple_ensure_bindable(int index);

struct proxy_listener {
	int  udp_fd;
	int  tcp_fd;
	char ip[INET_ADDRSTRLEN]; // randomised 127.0.0.0/8 address, dotted-quad
	int  port; // the port actually bound
	bool active;
};

// Atomically bind the UDP+TCP listener pair for slot `index` on its tuple. On
// success fills *l and returns true; otherwise returns false with l inactive
// (upstream left disabled). Never sets SO_REUSEADDR, so a squatter cannot co-bind.
bool proxy_listener_bind(int index, struct proxy_listener *l);

// Close both sockets and mark the listener inactive.
void proxy_listener_close(struct proxy_listener *l);

#endif // DOTDOH_REGISTRY_H
