/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster virtual IP address
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "config/config.h"
#include "cluster/vip.h"
// get_gateway_name()
#include "tools/netlink.h"
// check_capability()
#include "capabilities.h"
// lock_shm()
#include "shmem.h"
// CLUSTER_STRLEN
#include "cluster/cluster.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

// The interface the virtual IP address is added to: the configured one, or the
// interface holding the route to the default gateway
static bool vip_interface(char iface[IF_NAMESIZE])
{
	char configured[CLUSTER_STRLEN] = "";
	lock_shm();
	strncpy(configured, config.cluster.vip.interface.v.s, sizeof(configured) - 1);
	unlock_shm();
	configured[sizeof(configured) - 1] = '\0';

	if(strlen(configured) > 0)
	{
		strncpy(iface, configured, IF_NAMESIZE - 1);
		iface[IF_NAMESIZE - 1] = '\0';
		return true;
	}

	char gateway[MAXIFACESTRLEN] = { 0 };
	get_gateway_name(gateway);
	if(strlen(gateway) == 0)
	{
		log_debug(DEBUG_CLUSTER, "cluster: no interface for the virtual IP, set cluster.vip.interface");
		return false;
	}

	strncpy(iface, gateway, IF_NAMESIZE - 1);
	iface[IF_NAMESIZE - 1] = '\0';

	return true;
}

static bool parse_address(const char *address, int *family, void *buf)
{
	if(inet_pton(AF_INET, address, buf) == 1)
	{
		*family = AF_INET;
		return true;
	}

	if(inet_pton(AF_INET6, address, buf) == 1)
	{
		*family = AF_INET6;
		return true;
	}

	return false;
}

// Which interface the address is on, when it is on one at all. An address left
// behind by an earlier FTL is not necessarily on the interface this node would
// choose for it, and giving it back needs the one it is really on
static bool vip_present_on(const char *address, char iface[IF_NAMESIZE])
{
	int family = 0;
	unsigned char want[sizeof(struct in6_addr)] = { 0 };
	if(!parse_address(address, &family, want))
		return false;

	struct ifaddrs *ifap = NULL;
	if(getifaddrs(&ifap) != 0)
	{
		log_debug(DEBUG_CLUSTER, "cluster: getifaddrs() failed: %s", strerror(errno));
		return false;
	}

	bool found = false;
	for(struct ifaddrs *ifa = ifap; ifa != NULL && !found; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != family)
			continue;

		if(family == AF_INET)
		{
			const struct sockaddr_in *sa = (const struct sockaddr_in *)(const void *)ifa->ifa_addr;
			found = memcmp(&sa->sin_addr, want, sizeof(struct in_addr)) == 0;
		}
		else
		{
			const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)(const void *)ifa->ifa_addr;
			found = memcmp(&sa->sin6_addr, want, sizeof(struct in6_addr)) == 0;
		}

		if(found && iface != NULL && ifa->ifa_name != NULL)
		{
			strncpy(iface, ifa->ifa_name, IF_NAMESIZE - 1);
			iface[IF_NAMESIZE - 1] = '\0';
		}
	}

	freeifaddrs(ifap);

	return found;
}

bool vip_present(const char *address)
{
	return vip_present_on(address, NULL);
}

// Add or remove the address through netlink. This is what "ip addr add" does,
// and it needs the same privilege - CAP_NET_ADMIN, which FTL holds for DHCP
static bool netlink_address(const bool add, const char *address, const char *iface)
{
	int family = 0;
	unsigned char addr[sizeof(struct in6_addr)] = { 0 };
	if(!parse_address(address, &family, addr))
	{
		log_debug(DEBUG_CLUSTER, "cluster: \"%s\" is not a valid IP address", address);
		return false;
	}

	const unsigned int ifindex = if_nametoindex(iface);
	if(ifindex == 0)
	{
		log_debug(DEBUG_CLUSTER, "cluster: interface \"%s\" does not exist: %s", iface, strerror(errno));
		return false;
	}

	const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if(fd < 0)
	{
		log_debug(DEBUG_CLUSTER, "cluster: cannot open netlink socket: %s", strerror(errno));
		return false;
	}

	// This runs while FTL is shutting down as well, where waiting forever for
	// an answer would keep the daemon from exiting
	const struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
	if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		log_warn("cluster: cannot set netlink timeout: %s", strerror(errno));

	const size_t addrlen = family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		char attrbuf[64];
	} req = { 0 };

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if(add)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	req.nlh.nlmsg_seq = 1;
	req.ifa.ifa_family = (unsigned char)family;
	// A host route (/32 or /128) keeps the kernel from touching the subnet
	// route the interface's own address already provides
	req.ifa.ifa_prefixlen = family == AF_INET ? 32 : 128;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
	req.ifa.ifa_index = ifindex;
	// An IPv6 address is tentative until duplicate address detection has run,
	// and the kernel answers our request before that. A floating address is
	// by definition one another node held a moment ago, so DAD would often
	// fail - leaving a permanently unusable address that still shows up as
	// present. It is ours to place, so it is placed without asking
	if(family == AF_INET6)
		req.ifa.ifa_flags = IFA_F_NODAD;

	// A delete carries the address alone: the kernel then matches on it
	// whatever prefix length it was added with, so an address somebody else
	// placed as part of a subnet still goes away. On an add both attributes
	// are wanted, identical as they are on a non-peer-to-peer link
	struct rtattr *rta = (struct rtattr *)(void *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
	rta->rta_type = IFA_LOCAL;
	rta->rta_len = (unsigned short)RTA_LENGTH(addrlen);
	memcpy(RTA_DATA(rta), addr, addrlen);
	req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

	// Both on an add, and on a delete as well: with IFA_ADDRESS present the
	// v4 path compares the prefix, so a delete can only remove an address
	// that was added exactly as this one was, and never a /24 the machine
	// answers on
	rta = (struct rtattr *)(void *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
	rta->rta_type = IFA_ADDRESS;
	rta->rta_len = (unsigned short)RTA_LENGTH(addrlen);
	memcpy(RTA_DATA(rta), addr, addrlen);
	req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

	struct sockaddr_nl sa = { 0 };
	sa.nl_family = AF_NETLINK;

	if(sendto(fd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
		log_debug(DEBUG_CLUSTER, "cluster: cannot %s the virtual IP: %s",
		        add ? "add" : "remove", strerror(errno));
		close(fd);
		return false;
	}

	// Read the acknowledgment: without it we would not notice being denied
	char buf[4096] __attribute__((aligned(NLMSG_ALIGNTO))) = { 0 };
	const ssize_t received = recv(fd, buf, sizeof(buf), 0);
	close(fd);

	if(received < 0)
	{
		log_debug(DEBUG_CLUSTER, "cluster: no answer from netlink: %s", strerror(errno));
		return false;
	}

	int len = (int)received;
	for(struct nlmsghdr *nlh = (struct nlmsghdr *)(void *)buf; NLMSG_OK(nlh, (unsigned int)len);
	    nlh = NLMSG_NEXT(nlh, len))
	{
		if(nlh->nlmsg_type != NLMSG_ERROR)
			continue;

		const struct nlmsgerr *err = (const struct nlmsgerr *)(const void *)NLMSG_DATA(nlh);
		// error == 0 is the plain acknowledgment
		if(err->error == 0)
			return true;

		// Removing an address we do not hold, or adding one we already
		// hold, is the state we wanted either way
		if((add && err->error == -EEXIST) || (!add && err->error == -EADDRNOTAVAIL))
			return true;

		log_debug(DEBUG_CLUSTER, "cluster: cannot %s %s on %s: %s",
		        add ? "add" : "remove", address, iface, strerror(-err->error));
		return false;
	}

	return true;
}

// The MAC of an interface, which both announcements need
static bool interface_mac(const int fd, const char *iface, unsigned char mac[ETH_ALEN])
{
	struct ifreq ifr = { 0 };
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		log_warn("cluster: cannot read MAC of %s: %s", iface, strerror(errno));
		return false;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return true;
}

// The ones-complement sum ICMPv6 is checked with, taken over the pseudo-header
// and the message together
static uint16_t icmp6_checksum(const struct in6_addr *src, const struct in6_addr *dst,
                               const unsigned char *msg, const size_t len)
{
	uint32_t sum = 0;

	const uint16_t *words = (const uint16_t *)(const void *)src;
	for(size_t i = 0; i < sizeof(*src) / 2; i++)
		sum += words[i];
	words = (const uint16_t *)(const void *)dst;
	for(size_t i = 0; i < sizeof(*dst) / 2; i++)
		sum += words[i];

	sum += htons((uint16_t)len);   // upper-layer length, the high half is zero
	sum += htons(IPPROTO_ICMPV6);  // next header, the rest of the field is zero

	for(size_t i = 0; i + 1 < len; i += 2)
		sum += (uint16_t)(msg[i] | (msg[i + 1] << 8));
	if(len % 2 != 0)
		sum += msg[len - 1];

	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

// The IPv6 counterpart of a gratuitous ARP: an unsolicited neighbor
// advertisement for the address, sent to every node on the link. Without it the
// switches and the neighbors keep sending the address to the node that held it
// before, for as long as their caches say so
static void unsolicited_na(const char *address, const char *iface)
{
	struct in6_addr addr = { 0 };
	if(inet_pton(AF_INET6, address, &addr) != 1)
		return;

	const int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IPV6));
	if(fd < 0)
	{
		log_warn("cluster: cannot open raw socket for neighbor advertisement: %s",
		         strerror(errno));
		return;
	}

	unsigned char mac[ETH_ALEN] = { 0 };
	if(!interface_mac(fd, iface, mac))
	{
		close(fd);
		return;
	}

	// All nodes on this link, and the Ethernet address that stands for it
	struct in6_addr all_nodes = { 0 };
	all_nodes.s6_addr[0] = 0xff;
	all_nodes.s6_addr[1] = 0x02;
	all_nodes.s6_addr[15] = 0x01;

	// The advertisement itself: type 136, the Override flag, the address
	// being announced, and the MAC to send it to from now on
	unsigned char icmp[32] = { 0 };
	icmp[0] = 136;                                  // neighbor advertisement
	icmp[4] = 0x20;                                 // Override, not Solicited
	memcpy(icmp + 8, &addr, sizeof(addr));          // target address
	icmp[24] = 0x02;                                // target link-layer address
	icmp[25] = 0x01;                                // ...one 8-byte unit long
	memcpy(icmp + 26, mac, ETH_ALEN);

	const uint16_t sum = icmp6_checksum(&addr, &all_nodes, icmp, sizeof(icmp));
	memcpy(icmp + 2, &sum, sizeof(sum));

	unsigned char frame[14 + 40 + sizeof(icmp)] = { 0 };
	// 33:33 followed by the last four bytes of the multicast address
	frame[0] = 0x33; frame[1] = 0x33;
	memcpy(frame + 2, &all_nodes.s6_addr[12], 4);
	memcpy(frame + ETH_ALEN, mac, ETH_ALEN);
	frame[12] = 0x86; frame[13] = 0xdd;             // ETH_P_IPV6

	frame[14] = 0x60;                               // version 6
	frame[18] = 0x00; frame[19] = sizeof(icmp);     // payload length
	frame[20] = IPPROTO_ICMPV6;
	frame[21] = 255;                                // hop limit, as ND requires
	memcpy(frame + 22, &addr, sizeof(addr));        // source: the address itself
	memcpy(frame + 38, &all_nodes, sizeof(all_nodes));
	memcpy(frame + 54, icmp, sizeof(icmp));

	struct sockaddr_ll sll = { 0 };
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex = (int)if_nametoindex(iface);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, frame, ETH_ALEN);

	// Three of them, for the same reason the ARP path sends three
	for(unsigned int i = 0; i < 3; i++)
		if(sendto(fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		{
			log_warn("cluster: cannot send neighbor advertisement for %s: %s",
			         address, strerror(errno));
			break;
		}

	close(fd);
}

// Tell the network that the address moved here. Without this, switches keep
// forwarding to the port of the previous holder and clients keep using the
// stale ARP entry until it expires - which is a minute of broken DNS for them
static void gratuitous_arp(const char *address, const char *iface)
{
	struct in_addr addr = { 0 };
	if(inet_pton(AF_INET, address, &addr) != 1)
	{
		unsolicited_na(address, iface);
		return;
	}

	const int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ARP));
	if(fd < 0)
	{
		log_warn("cluster: cannot open raw socket for ARP: %s", strerror(errno));
		return;
	}

	unsigned char mac[ETH_ALEN] = { 0 };
	if(!interface_mac(fd, iface, mac))
	{
		close(fd);
		return;
	}

	// Ethernet header followed by an ARP request in which sender and target
	// are both the virtual IP address - the classic gratuitous ARP
	unsigned char frame[42] = { 0 };
	memset(frame, 0xff, ETH_ALEN);                  // destination: broadcast
	memcpy(frame + ETH_ALEN, mac, ETH_ALEN);        // source
	frame[12] = 0x08; frame[13] = 0x06;             // ETH_P_ARP
	frame[14] = 0x00; frame[15] = 0x01;             // hardware type: Ethernet
	frame[16] = 0x08; frame[17] = 0x00;             // protocol type: IPv4
	frame[18] = ETH_ALEN;
	frame[19] = sizeof(struct in_addr);
	frame[20] = 0x00; frame[21] = 0x01;             // opcode: request
	memcpy(frame + 22, mac, ETH_ALEN);              // sender MAC
	memcpy(frame + 28, &addr, sizeof(addr));        // sender IP
	memset(frame + 32, 0x00, ETH_ALEN);             // target MAC
	memcpy(frame + 38, &addr, sizeof(addr));        // target IP

	struct sockaddr_ll sll = { 0 };
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = (int)if_nametoindex(iface);
	sll.sll_halen = ETH_ALEN;
	memset(sll.sll_addr, 0xff, ETH_ALEN);

	// Three of them: ARP is unacknowledged and this is the only announcement
	// a client gets
	for(unsigned int i = 0; i < 3; i++)
		if(sendto(fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		{
			log_warn("cluster: cannot send ARP for %s: %s", address, strerror(errno));
			break;
		}

	close(fd);
}

// Set once this process put the address there. An address FTL did not place is
// an address FTL does not remove: a user converting a single Pi-hole into a
// cluster naturally sets cluster.vip.address to the address the clients already
// use, which is that node's own, and the v4 delete matches on the address alone
// What this process put there, remembered as it was placed. Reading the address
// and the interface out of the configuration at release time would have a node
// that had cluster.vip.address changed under it delete the new address off the
// new interface - neither of which it ever added
static bool claimed = false;
static char claimed_address[CLUSTER_STRLEN] = "";
static char claimed_iface[IF_NAMESIZE] = "";

bool vip_claimed(void)
{
	return claimed;
}

bool vip_claimed_address(char *buf, const size_t size)
{
	if(!claimed)
		return false;

	strncpy(buf, claimed_address, size - 1);
	buf[size - 1] = '\0';

	return true;
}



bool vip_claim(const char *address)
{
	// An address somebody changed cluster.vip.address away from is still on
	// this interface, and the clients still have it in their ARP caches.
	// Given back before the new one is taken, or this node answers for two
	if(claimed && strcmp(claimed_address, address) != 0)
	{
		log_info("cluster: the virtual IP address changed, giving %s back",
		         claimed_address);
		vip_release(claimed_address);
	}

	char present_on[IF_NAMESIZE] = "";
	if(vip_present_on(address, present_on))
	{
		// Already there. Ours if we put it there, and ours to keep
		// either way while we are the node the clients should reach
		if(!claimed)
		{
			strncpy(claimed_address, address, sizeof(claimed_address) - 1);

			// The interface it is on, not the one we would have
			// picked: giving it back later goes through the same
			// netlink call that put it there, and that call needs the
			// interface the address really sits on
			strncpy(claimed_iface, present_on, sizeof(claimed_iface) - 1);
			claimed_iface[sizeof(claimed_iface) - 1] = '\0';
			claimed = true;

			// Left behind by an FTL that was killed, and the switches
			// still send it to whoever answered for it last. Taking
			// it over silently would leave them doing that
			log_info("cluster: %s was already on %s, taking it over",
			         address, claimed_iface);
			gratuitous_arp(address, claimed_iface);
		}
		claimed = true;
		return true;
	}

	char iface[IF_NAMESIZE] = { 0 };
	if(!vip_interface(iface))
		return false;

	if(!netlink_address(true, address, iface))
		return false;

	claimed = true;
	strncpy(claimed_address, address, sizeof(claimed_address) - 1);
	claimed_address[sizeof(claimed_address) - 1] = '\0';
	strncpy(claimed_iface, iface, sizeof(claimed_iface) - 1);
	claimed_iface[sizeof(claimed_iface) - 1] = '\0';
	log_info("cluster: claimed %s on %s", address, iface);
	gratuitous_arp(address, iface);

	return true;
}

bool vip_release(const char *address)
{
	// Never an address this node did not place. Deleting one that was
	// already on the interface takes its subnet route with it, and with it
	// this machine's own reachability
	if(!claimed)
		return true;

	// ...and exactly the one that was placed, on the interface it went on,
	// whatever the configuration says today
	(void)address;
	char iface[IF_NAMESIZE] = { 0 };
	strncpy(iface, claimed_iface, sizeof(iface) - 1);
	address = claimed_address;

	if(!vip_present(address))
	{
		claimed = false;
		return true;
	}

	if(!netlink_address(false, address, iface))
		return false;

	// The kernel accepted the request, which is not the same as the address
	// being gone - somebody else may hold it in a way we may not remove.
	// Saying "released" once per round about an address that is still there
	// points the person reading the log away from the fault
	if(vip_present(address))
	{
		log_debug(DEBUG_CLUSTER, "cluster: %s is still on %s after releasing it",
		          address, iface);
		return false;
	}

	claimed = false;
	log_info("cluster: released %s on %s", address, iface);

	return true;
}
