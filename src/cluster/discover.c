/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster discovery
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "cluster/discover.h"
// config
#include "config/config.h"
// log_*()
#include "log.h"
// get_https_port()
#include "webserver/webserver.h"
// double_time()
#include "timers.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>

// A node joining a cluster has to find one that is already in it, and it cannot
// ask the cluster because it is not a member yet. DNS would have to travel
// through whatever upstream that node happens to be configured with, so the
// nodes say so themselves, on the segment, on a port of their own
#define BEACON_QUERY "PIHOLE-CLUSTER? 1"
#define BEACON_REPLY "PIHOLE-CLUSTER! 1 "

// The beacon is unauthenticated by nature - it is what somebody talks to before
// they have any credentials - so it answers at a rate that makes it useless as
// an amplifier and says nothing that a port scan would not have found anyway
#define BEACON_BURST 10
#define BEACON_PER_SECOND 5

static int beaconfd = -1;

bool cluster_beacon_open(void)
{
	// One socket for both families: bound to the unspecified IPv6 address
	// with V6ONLY off, it receives IPv4 broadcasts and IPv6 all-nodes
	// multicast alike
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	bool dual = true;
	if(fd < 0)
	{
		fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		dual = false;
	}
	if(fd < 0)
	{
		log_warn("cluster: cannot open the discovery socket: %s", strerror(errno));
		return false;
	}

	// Deliberately no SO_REUSEADDR. A UDP socket does not linger the way a
	// TCP one does, so nothing here needs it - and with it, any other process
	// on this machine may bind the same port and be handed the queries
	// instead. Whoever answers them is the node a Pi-hole is invited to join,
	// and the password of the node being joined crosses that connection
	const int off = 0;
	if(dual)
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

	struct sockaddr_in6 sa6 = { 0 };
	struct sockaddr_in sa4 = { 0 };
	sa6.sin6_family = AF_INET6;
	sa6.sin6_addr = in6addr_any;
	sa6.sin6_port = htons(CLUSTER_BEACON_PORT);
	sa4.sin_family = AF_INET;
	sa4.sin_addr.s_addr = htonl(INADDR_ANY);
	sa4.sin_port = htons(CLUSTER_BEACON_PORT);

	const struct sockaddr *sa = dual ? (struct sockaddr *)&sa6 : (struct sockaddr *)&sa4;
	const socklen_t salen = dual ? sizeof(sa6) : sizeof(sa4);
	if(bind(fd, sa, salen) != 0)
	{
		log_warn("cluster: cannot bind port %d for discovery: %s",
		         CLUSTER_BEACON_PORT, strerror(errno));
		close(fd);
		return false;
	}

	beaconfd = fd;
	return true;
}

void cluster_beacon_close(void)
{
	if(beaconfd < 0)
		return;
	close(beaconfd);
	beaconfd = -1;
}

// Answer whatever has arrived since the last tick
void cluster_beacon_poll(void)
{
	static double bucket_time = 0.0;
	static unsigned int budget = BEACON_BURST;

	if(beaconfd < 0)
		return;

	// Refill before answering, so a burst that arrives after a quiet minute
	// is still answered in full
	const double now = double_time();
	if(now < bucket_time)
	{
		// The clock stepped backwards. Waiting it out would leave this
		// node undiscoverable for as long as the step was, silently
		bucket_time = now;
		budget = BEACON_BURST;
	}
	else if(now - bucket_time >= 1.0)
	{
		const double elapsed = now - bucket_time;
		const unsigned int refill = elapsed > (double)BEACON_BURST ?
		                            BEACON_BURST : (unsigned int)(elapsed * BEACON_PER_SECOND);
		budget = budget + refill > BEACON_BURST ? BEACON_BURST : budget + refill;
		bucket_time = now;
	}

	char reply[64] = "";
	const int replylen = snprintf(reply, sizeof(reply), BEACON_REPLY "%u",
	                              (unsigned int)get_bound_https_port());

	// Bounded so a flood cannot hold the cluster thread here
	for(unsigned int i = 0; i < 2 * BEACON_BURST; i++)
	{
		char buf[128];
		struct sockaddr_storage from = { 0 };
		socklen_t fromlen = sizeof(from);
		const ssize_t len = recvfrom(beaconfd, buf, sizeof(buf) - 1, 0,
		                             (struct sockaddr *)&from, &fromlen);
		if(len < 0)
			break;

		buf[len] = '\0';
		if(strncmp(buf, BEACON_QUERY, sizeof(BEACON_QUERY) - 1) != 0)
			continue;

		if(budget == 0)
			continue;
		budget--;

		if(sendto(beaconfd, reply, replylen, 0, (struct sockaddr *)&from, fromlen) < 0)
			log_debug(DEBUG_API, "cluster: cannot answer a discovery query: %s",
			          strerror(errno));
	}
}

// Whether this address is one of ours, so a node does not find itself
static bool is_local_address(const struct ifaddrs *ifa, const struct sockaddr_storage *sa)
{
	for(; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != sa->ss_family)
			continue;

		if(sa->ss_family == AF_INET &&
		   ((const struct sockaddr_in *)(const void *)ifa->ifa_addr)->sin_addr.s_addr ==
		   ((const struct sockaddr_in *)sa)->sin_addr.s_addr)
			return true;

		if(sa->ss_family == AF_INET6 &&
		   memcmp(&((const struct sockaddr_in6 *)(const void *)ifa->ifa_addr)->sin6_addr,
		          &((const struct sockaddr_in6 *)sa)->sin6_addr, sizeof(struct in6_addr)) == 0)
			return true;
	}

	return false;
}

// Ask the segment who else is here, and collect what comes back until the
// timeout. Returns the number of nodes found
unsigned int cluster_discover(struct cluster_found *found, const unsigned int max,
                              const double timeout)
{
	struct ifaddrs *ifaddr = NULL;
	if(getifaddrs(&ifaddr) != 0)
	{
		log_warn("cluster: cannot enumerate the interfaces: %s", strerror(errno));
		return 0;
	}

	// The same fallback the answering side has: a host booted with
	// ipv6.disable=1 cannot open an AF_INET6 socket at all, and asking over
	// IPv4 alone is better than not asking
	bool dual = true;
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if(fd < 0)
	{
		fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		dual = false;
	}
	if(fd < 0)
	{
		freeifaddrs(ifaddr);
		log_warn("cluster: cannot open a discovery socket: %s", strerror(errno));
		return 0;
	}

	const int on = 1, off = 0, hops = 1;
	if(dual)
	{
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
		setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
	}
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

	// One query per interface rather than one to the default route: a Pi-hole
	// with several interfaces is the normal case, not the exception
	unsigned int sent = 0;
	char query[] = BEACON_QUERY;
	for(const struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP) || ifa->ifa_flags & IFF_LOOPBACK)
			continue;

		if(ifa->ifa_addr->sa_family == AF_INET && ifa->ifa_flags & IFF_BROADCAST &&
		   ifa->ifa_broadaddr != NULL)
		{
			const struct in_addr *bcast =
				&((const struct sockaddr_in *)(const void *)ifa->ifa_broadaddr)->sin_addr;

			if(dual)
			{
				// Written as IPv4-mapped, as the socket serves both
				struct sockaddr_in6 to = { 0 };
				to.sin6_family = AF_INET6;
				to.sin6_port = htons(CLUSTER_BEACON_PORT);
				to.sin6_addr.s6_addr[10] = 0xff;
				to.sin6_addr.s6_addr[11] = 0xff;
				memcpy(&to.sin6_addr.s6_addr[12], bcast, 4);
				if(sendto(fd, query, sizeof(query) - 1, 0,
				          (struct sockaddr *)&to, sizeof(to)) > 0)
					sent++;
			}
			else
			{
				struct sockaddr_in to = { 0 };
				to.sin_family = AF_INET;
				to.sin_port = htons(CLUSTER_BEACON_PORT);
				to.sin_addr = *bcast;
				if(sendto(fd, query, sizeof(query) - 1, 0,
				          (struct sockaddr *)&to, sizeof(to)) > 0)
					sent++;
			}
		}
		else if(ifa->ifa_addr->sa_family == AF_INET6 && dual)
		{
			// ff02::1 is every node on the link, and needs no membership
			struct sockaddr_in6 to = { 0 };
			to.sin6_family = AF_INET6;
			to.sin6_port = htons(CLUSTER_BEACON_PORT);
			to.sin6_addr.s6_addr[0] = 0xff;
			to.sin6_addr.s6_addr[1] = 0x02;
			to.sin6_addr.s6_addr[15] = 0x01;
			to.sin6_scope_id = if_nametoindex(ifa->ifa_name);
			if(sendto(fd, query, sizeof(query) - 1, 0,
			          (struct sockaddr *)&to, sizeof(to)) > 0)
				sent++;
		}
	}

	if(sent == 0)
		log_debug(DEBUG_API, "cluster: no interface to ask for other nodes");

	unsigned int num = 0;
	const double deadline = double_time() + timeout;
	while(num < max)
	{
		const double left = deadline - double_time();
		if(left <= 0.0)
			break;

		struct pollfd p = { .fd = fd, .events = POLLIN };
		if(poll(&p, 1, (int)(left * 1000)) < 1)
			break;

		char buf[128];
		struct sockaddr_storage from = { 0 };
		socklen_t fromlen = sizeof(from);
		const ssize_t len = recvfrom(fd, buf, sizeof(buf) - 1, 0,
		                             (struct sockaddr *)&from, &fromlen);
		if(len < 0)
			continue;

		buf[len] = '\0';
		if(strncmp(buf, BEACON_REPLY, sizeof(BEACON_REPLY) - 1) != 0)
			continue;

		// An IPv4 answer arrives mapped, and is worth showing as the
		// address the administrator knows it by
		struct sockaddr_storage addr = from;
		if(addr.ss_family == AF_INET6 &&
		   IN6_IS_ADDR_V4MAPPED(&((const struct sockaddr_in6 *)&addr)->sin6_addr))
		{
			struct sockaddr_in v4 = { 0 };
			v4.sin_family = AF_INET;
			memcpy(&v4.sin_addr,
			       &((const struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr[12], 4);
			memcpy(&addr, &v4, sizeof(v4));
		}

		if(is_local_address(ifaddr, &addr))
			continue;

		char address[INET6_ADDRSTRLEN + IF_NAMESIZE + 1] = "";
		if(addr.ss_family == AF_INET)
			inet_ntop(AF_INET, &((const struct sockaddr_in *)&addr)->sin_addr,
			          address, INET6_ADDRSTRLEN);
		else
		{
			const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)&addr;
			inet_ntop(AF_INET6, &sa6->sin6_addr, address, INET6_ADDRSTRLEN);

			// A link-local address means nothing without the interface
			// it is on - written the way a URL carries it, so what we
			// publish is something somebody can actually connect to
			char iface[IF_NAMESIZE] = "";
			if(IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) && sa6->sin6_scope_id != 0 &&
			   if_indextoname(sa6->sin6_scope_id, iface) != NULL)
			{
				strncat(address, "%", sizeof(address) - strlen(address) - 1);
				strncat(address, iface, sizeof(address) - strlen(address) - 1);
			}
		}

		// The same node answers once per interface it heard the query on
		bool known = false;
		for(unsigned int i = 0; i < num; i++)
			if(strcmp(found[i].address, address) == 0)
				known = true;
		if(known)
			continue;

		strncpy(found[num].address, address, sizeof(found[num].address) - 1);
		found[num].address[sizeof(found[num].address) - 1] = '\0';
		found[num].port = (in_port_t)strtoul(buf + sizeof(BEACON_REPLY) - 1, NULL, 10);
		num++;
	}

	close(fd);
	freeifaddrs(ifaddr);

	return num;
}
