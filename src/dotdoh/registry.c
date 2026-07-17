/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted-upstream proxy listener registry
*
*  Binds one UDP+TCP listener pair per encrypted upstream in 127.47.11.0/24 and
*  enforces the bind-first invariant: a pair is only reported active once BOTH
*  sockets are owned exclusively. No SO_REUSEADDR / SO_REUSEPORT is ever set, so
*  a local squatter can neither co-bind our tuple nor be silently forwarded to
*  (dnsmasq only ever learns a tuple we own).
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
	snprintf(ip, sizeof(ip), DOTDOH_NET_PREFIX "%d", index + 1);

	const int port = DOTDOH_PORT_BASE + index + 1;

	// The port is deterministic: dnsmasq has already been pointed at
	// exactly this tuple, so we do NOT iterate. Either we own both
	// transports or the upstream stays disabled. No SO_REUSEADDR, so a
	// squatter cannot co-bind.
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
