/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Inbound DoT/DoH source-address filter
*
*  See source_filter.h. Kept free of FTL globals (config) and of civetweb so it
*  can be #included straight into the dotdoh regression harness and exercised in
*  isolation.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h> // snprintf
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h> // IFF_POINTOPOINT, IFNAMSIZ
#include <pthread.h>
#include <time.h>

#include "source_filter.h"

// Short-lived snapshot of local interface prefixes. Without it, a connection
// flood to the default-on :853 listener would trigger one getifaddrs() (a
// netlink syscall + allocation) per rejected connection in the single-threaded
// accept loop, amplifying into a DoS. A few seconds of staleness only fails
// safe (a just-removed subnet is briefly still accepted, a just-added one
// briefly rejected).
// Generous cap on snapshotted interface addresses; far above any real host so
// truncation effectively never happens. If it ever did, the overflow addresses
// are simply not matched (a local client on such a subnet is denied, i.e. fails
// safe), never wrongly allowed.
#define DOTDOH_IF_MAX 256
#define DOTDOH_IF_TTL 4 // seconds
struct dotdoh_ifentry {
	sa_family_t family;    // AF_INET / AF_INET6 of addr/mask
	sa_family_t dst_family;
	bool has_mask;
	bool is_ptp;
	unsigned char addr[16]; // network-order bytes (4 used for v4)
	unsigned char mask[16];
	unsigned char dst[16];  // point-to-point peer
	char ifname[IFNAMSIZ];  // interface name (for LISTEN_SINGLE/BIND matching)
};
static pthread_mutex_t dotdoh_if_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dotdoh_ifentry dotdoh_if[DOTDOH_IF_MAX];
static size_t dotdoh_if_n;
static time_t dotdoh_if_at; // last refresh (0 = never)

// Rebuild the snapshot from getifaddrs(). Caller holds dotdoh_if_lock.
static void dotdoh_if_refresh(void)
{
	struct ifaddrs *ifap = NULL;
	if(getifaddrs(&ifap) != 0)
	{
		dotdoh_if_n = 0; // fail closed until the next refresh succeeds
		return;
	}
	size_t n = 0;
	for(struct ifaddrs *ifa = ifap; ifa != NULL && n < DOTDOH_IF_MAX; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == NULL)
			continue;
		const sa_family_t fam = ifa->ifa_addr->sa_family;
		if(fam != AF_INET && fam != AF_INET6)
			continue;
		struct dotdoh_ifentry *e = &dotdoh_if[n];
		memset(e, 0, sizeof(*e));
		e->family = fam;
		if(ifa->ifa_name != NULL)
			snprintf(e->ifname, sizeof(e->ifname), "%s", ifa->ifa_name);
		const size_t len = (fam == AF_INET) ? 4 : 16;
		const void *a = (fam == AF_INET)
		    ? (void *)&((struct sockaddr_in *)(void *)ifa->ifa_addr)->sin_addr
		    : (void *)&((struct sockaddr_in6 *)(void *)ifa->ifa_addr)->sin6_addr;
		memcpy(e->addr, a, len);
		if(ifa->ifa_netmask != NULL)
		{
			const void *m = (fam == AF_INET)
			    ? (void *)&((struct sockaddr_in *)(void *)ifa->ifa_netmask)->sin_addr
			    : (void *)&((struct sockaddr_in6 *)(void *)ifa->ifa_netmask)->sin6_addr;
			memcpy(e->mask, m, len);
			// An all-zero netmask (a /0 prefix) would make the same-subnet test
			// match every peer - i.e. serve the whole internet. Only treat the
			// entry as having a usable subnet if at least one mask bit is set.
			for(size_t i = 0; i < len; i++)
				if(e->mask[i] != 0) { e->has_mask = true; break; }
		}
		if((ifa->ifa_flags & IFF_POINTOPOINT) && ifa->ifa_dstaddr != NULL &&
		   ifa->ifa_dstaddr->sa_family == fam)
		{
			e->is_ptp = true;
			e->dst_family = fam;
			const void *d = (fam == AF_INET)
			    ? (void *)&((struct sockaddr_in *)(void *)ifa->ifa_dstaddr)->sin_addr
			    : (void *)&((struct sockaddr_in6 *)(void *)ifa->ifa_dstaddr)->sin6_addr;
			memcpy(e->dst, d, len);
		}
		n++;
	}
	freeifaddrs(ifap);
	dotdoh_if_n = n;
}

// Whether `peer` (network-order bytes, family fam) sits on a directly-attached
// subnet or is a point-to-point peer, using the cached (refreshed) snapshot. When
// `iface` is non-NULL and non-empty, only that interface's entries are considered
// (LISTEN_SINGLE/BIND restrict to the one configured interface).
static bool dotdoh_peer_is_local(sa_family_t fam, const unsigned char *peer, const char *iface)
{
	const bool by_iface = (iface != NULL && iface[0] != '\0');
	const size_t len = (fam == AF_INET) ? 4 : 16;
	bool local = false;
	pthread_mutex_lock(&dotdoh_if_lock);
	const time_t now = time(NULL);
	if(dotdoh_if_at == 0 || now < dotdoh_if_at || now - dotdoh_if_at >= DOTDOH_IF_TTL)
	{
		dotdoh_if_refresh();
		dotdoh_if_at = now;
	}
	for(size_t k = 0; k < dotdoh_if_n && !local; k++)
	{
		const struct dotdoh_ifentry *e = &dotdoh_if[k];
		if(by_iface && strcmp(e->ifname, iface) != 0)
			continue; // restricted to one interface, and this is not it
		// Point-to-point peer (e.g. a VPN /32): exact match of the other end.
		if(e->is_ptp && e->dst_family == fam && memcmp(e->dst, peer, len) == 0)
		{
			local = true;
			break;
		}
		// Same-subnet membership.
		if(e->has_mask && e->family == fam)
		{
			bool match = true;
			for(size_t i = 0; i < len; i++)
				if((e->addr[i] & e->mask[i]) != (peer[i] & e->mask[i]))
				{
					match = false;
					break;
				}
			if(match)
				local = true;
		}
	}
	pthread_mutex_unlock(&dotdoh_if_lock);
	return local;
}

bool dotdoh_source_allowed_mode(const enum listening_mode mode, const char *client_ip,
                                const char *iface)
{
	// Fail closed when the caller could not determine the peer (contract in the
	// header): an unknown source is denied regardless of mode, so a lookup that
	// silently lost the address can never be treated as "allow everything".
	if(client_ip == NULL)
		return false;
	if(mode == LISTEN_ALL)
		return true;

	// LISTEN_SINGLE / LISTEN_BIND serve only the one configured interface, so
	// match the peer against that interface's subnet alone; other modes (and an
	// unset/auto interface) match any directly-attached subnet.
	const char *match_iface = (mode == LISTEN_SINGLE || mode == LISTEN_BIND) ? iface : NULL;

	// Strip an IPv6 zone id ("fe80::1%eth0"): inet_pton rejects it, and the
	// scope does not change subnet membership.
	char ipbuf[INET6_ADDRSTRLEN + IFNAMSIZ];
	const char *pct = strchr(client_ip, '%');
	if(pct != NULL)
	{
		const size_t n = (size_t)(pct - client_ip);
		if(n >= sizeof(ipbuf))
			return false;
		memcpy(ipbuf, client_ip, n);
		ipbuf[n] = '\0';
		client_ip = ipbuf;
	}

	struct in_addr v4;
	struct in6_addr v6;
	bool is_v4 = inet_pton(AF_INET, client_ip, &v4) == 1;
	bool is_v6 = !is_v4 && inet_pton(AF_INET6, client_ip, &v6) == 1;
	if(!is_v4 && !is_v6)
		return false;

	// Fold an IPv4-mapped IPv6 address (::ffff:a.b.c.d) - as a v4 client can
	// present on a dual-stack listener - back to IPv4, so it is matched against
	// the v4 interface subnets (and v4 loopback) rather than never matching.
	if(is_v6 && IN6_IS_ADDR_V4MAPPED(&v6))
	{
		memcpy(&v4.s_addr, &v6.s6_addr[12], 4);
		is_v4 = true;
		is_v6 = false;
	}

	// Loopback is always local.
	if(is_v4 && (ntohl(v4.s_addr) & 0xFF000000) == 0x7F000000)
		return true;
	if(is_v6 && IN6_IS_ADDR_LOOPBACK(&v6))
		return true;

	// An IPv6 link-local peer (fe80::/10) cannot be pinned to one interface here:
	// the /64 prefix is identical on every link and the zone id was stripped
	// above. Under an interface-restricted mode (SINGLE/BIND with a named
	// interface) we therefore cannot confirm the peer arrived on the configured
	// link, so deny it (fail closed) instead of accepting it from any attached
	// interface. Without an interface restriction it is still a one-hop peer and
	// falls through to the normal subnet match below.
	if(is_v6 && match_iface != NULL && match_iface[0] != '\0' &&
	   v6.s6_addr[0] == 0xfe && (v6.s6_addr[1] & 0xc0) == 0x80)
		return false;

	// Otherwise the peer must sit on a directly-attached subnet (or be a
	// point-to-point peer), matched against the cached interface snapshot.
	if(is_v4)
	{
		unsigned char peer[4];
		memcpy(peer, &v4.s_addr, sizeof(peer));
		return dotdoh_peer_is_local(AF_INET, peer, match_iface);
	}
	unsigned char peer[16];
	memcpy(peer, &v6, sizeof(peer));
	return dotdoh_peer_is_local(AF_INET6, peer, match_iface);
}
