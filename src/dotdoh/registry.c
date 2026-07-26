/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted-upstream proxy listener registry
*
*  Binds one UDP+TCP listener pair per encrypted upstream on a per-process
*  randomised loopback tuple in 127.0.0.0/8 (dotdoh_tuple_addr()/_port()). A pair
*  is only reported active once BOTH sockets are owned exclusively, and
*  SO_REUSEADDR / SO_REUSEPORT is never set, so a local squatter cannot co-bind
*  our tuple. Randomising the tuple across the whole /8 x ~64k ports means an
*  attacker cannot pre-bind it. It is defence-in-depth, not the guarantee: the
*  fail-closed guarantee comes from dnsmasq's FTL_is_forward_available() gate,
*  which skips any tuple the proxy did not actually arm, so an unowned tuple is
*  never forwarded to in plaintext.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "registry.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
// getrandom() needs glibc 2.25+; mirror FTL's shim rather than include the heavy
// daemon.h, since this file also builds standalone in the dotdoh harness.
// USE_GETRANDOM is set when <sys/random.h> is present (see src/CMakeLists.txt).
#if defined(USE_GETRANDOM)
#include <sys/random.h>
#else
#define GRND_NONBLOCK 0x0001
#define getrandom getrandom_fallback
ssize_t getrandom_fallback(void *buf, size_t buflen, unsigned int flags);
#endif

// Per-process randomised loopback tuples (a 127.0.0.0/8 address + unprivileged
// port), one per slot, filled lazily on first query. Unguessability is
// defence-in-depth; the fail-closed guarantee is dnsmasq's
// FTL_is_forward_available() gate, which skips any tuple the proxy did not arm.
static uint32_t g_tuple_addr[DOTDOH_MAX_UPSTREAMS];
static int g_tuple_port[DOTDOH_MAX_UPSTREAMS];
static bool g_tuple_ready = false;

// Skip addresses in active use (127.0.0.1, 127.0.0.53) and a .0/.255 last octet.
static bool addr_excluded(uint32_t a)
{
	const uint8_t last = a & 0xff;
	if(last == 0 || last == 255)
		return true;
	return a == 0x7f000001u || a == 0x7f000035u; // 127.0.0.1, 127.0.0.53
}

// Is address `a` already used by a slot other than `except`?
static bool addr_used(uint32_t a, int except)
{
	for(int j = 0; j < DOTDOH_MAX_UPSTREAMS; j++)
		if(j != except && g_tuple_addr[j] == a)
			return true;
	return false;
}

// (Re)draw a random tuple for one slot: a distinct non-excluded 127.0.0.0/8
// address and an unbiased unprivileged port. GRND_NONBLOCK so an unseeded CSPRNG
// at early boot cannot stall DNS; a short read falls back to the deterministic
// 127.47.11.N#(5300+N) tuple, still gated fail-closed.
static void fill_slot(int i)
{
	uint32_t a;
	for(;;)
	{
		uint8_t r[3];
		if(getrandom(r, sizeof(r), GRND_NONBLOCK) != (ssize_t)sizeof(r))
		{
			g_tuple_addr[i] = 0x7f000000u | (47u << 16) | (11u << 8) | (uint32_t)(i + 1);
			g_tuple_port[i] = DOTDOH_PORT_BASE + i + 1;
			return;
		}
		a = 0x7f000000u | ((uint32_t)r[0] << 16) | ((uint32_t)r[1] << 8) | (uint32_t)r[2];
		if(!addr_excluded(a) && !addr_used(a, i))
			break;
	}
	g_tuple_addr[i] = a;

	// Unprivileged port, drawn without modulo bias by rejection sampling over the
	// 64512 values in [1024,65535] (a uint16 has 1024 extra values).
	for(;;)
	{
		uint16_t r;
		if(getrandom(&r, sizeof(r), GRND_NONBLOCK) != (ssize_t)sizeof(r))
		{
			g_tuple_port[i] = DOTDOH_PORT_BASE + i + 1;
			return;
		}
		if(r < 65536 - 1024)
		{
			g_tuple_port[i] = 1024 + (int)r;
			return;
		}
	}
}

static void init_tuples(void)
{
	for(int i = 0; i < DOTDOH_MAX_UPSTREAMS; i++)
		fill_slot(i);
	g_tuple_ready = true;
}

void dotdoh_tuple_redraw(int index)
{
	if(index < 0 || index >= DOTDOH_MAX_UPSTREAMS)
		return;
	if(!g_tuple_ready)
		init_tuples();
	fill_slot(index);
}

uint32_t dotdoh_tuple_addr(int index)
{
	if(index < 0 || index >= DOTDOH_MAX_UPSTREAMS)
		return 0;
	if(!g_tuple_ready)
		init_tuples();
	return g_tuple_addr[index];
}

int dotdoh_tuple_port(int index)
{
	if(index < 0 || index >= DOTDOH_MAX_UPSTREAMS)
		return -1;
	if(!g_tuple_ready)
		init_tuples();
	return g_tuple_port[index];
}

void dotdoh_tuple_ip(int index, char *buf, size_t buflen)
{
	const uint32_t a = dotdoh_tuple_addr(index);
	snprintf(buf, buflen, "%u.%u.%u.%u",
	         (a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff);
}

// Bind a single socket of the given type to ip:port. Deliberately does NOT set
 // SO_REUSEADDR/SO_REUSEPORT. Returns fd or -1.
static int bind_one(const char *ip, int port, int socktype)
{
	// SOCK_CLOEXEC so the listener fd is not inherited across FTL's execvp()
	// self-restart, where it would keep the loopback tuple busy and make the
	// new process fail to re-bind it.
	const int fd = socket(AF_INET, socktype | SOCK_CLOEXEC, 0);
	if(fd < 0)
		return -1;

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	if(inet_pton(AF_INET, ip, &sa.sin_addr) != 1)
	{
		close(fd);
		return -1;
	}
	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		close(fd);
		return -1;
	}
	if(socktype == SOCK_STREAM && listen(fd, SOMAXCONN) != 0)
	{
		close(fd);
		return -1;
	}
	return fd;
}

bool proxy_listener_bind(int index, struct proxy_listener *l)
{
	if(l == NULL || index < 0 || index >= DOTDOH_MAX_UPSTREAMS)
		return false;

	memset(l, 0, sizeof(*l));
	l->udp_fd = -1;
	l->tcp_fd = -1;

	char ip[INET_ADDRSTRLEN];
	dotdoh_tuple_ip(index, ip, sizeof(ip));

	const int port = dotdoh_tuple_port(index);
	if(port < 0)
		return false;

	// The tuple matches what dnsmasq was pointed at (same per-process table), so we
	// bind both transports or leave the upstream disabled for the gate to skip. No
	// SO_REUSEADDR, so a squatter cannot co-bind.
	const int ufd = bind_one(ip, port, SOCK_DGRAM);
	if(ufd < 0)
		return false;
	const int tfd = bind_one(ip, port, SOCK_STREAM);
	if(tfd < 0)
	{
		close(ufd);
		return false;
	}

	l->udp_fd = ufd;
	l->tcp_fd = tfd;
	snprintf(l->ip, sizeof(l->ip), "%s", ip);
	l->port = port;
	l->active = true;
	return true;
}

void proxy_listener_close(struct proxy_listener *l)
{
	if(l == NULL)
		return;
	if(l->udp_fd >= 0)
		close(l->udp_fd);
	if(l->tcp_fd >= 0)
		close(l->tcp_fd);
	l->udp_fd = -1;
	l->tcp_fd = -1;
	l->active = false;
}

bool dotdoh_tuple_ensure_bindable(int index)
{
	// Called at config generation, before dotdoh_init() binds for real: test-bind
	// the slot's tuple and redraw on a collision with a local service, up to 5
	// tries, so a chance clash does not needlessly disable an upstream (the fds are
	// released immediately). Returns false only if all 5 were unbindable, and
	// FTL_is_forward_available() then blocks plaintext to the unowned tuple.
	for(int attempt = 0; attempt < 5; attempt++)
	{
		struct proxy_listener l;
		if(proxy_listener_bind(index, &l))
		{
			proxy_listener_close(&l);
			return true;
		}
		if(attempt < 4)
			dotdoh_tuple_redraw(index);
	}
	return false;
}
