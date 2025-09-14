/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Netlink prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef NETLINK_H
#define NETLINK_H

#include <arpa/inet.h>
#include "webserver/cJSON/cJSON.h"
#include "webserver/json_macros.h"

// ICMPV6_PREF_LOW, etc.
#include <linux/icmpv6.h>
#include <linux/rtnetlink.h>
// IFF_UP, etc.
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#ifndef _NET_IF_ARP_H
#include <linux/if_arp.h>
#endif

bool nlroutes(cJSON *routes, const bool detailed);
bool nladdrs(cJSON *interfaces, const bool detailed);
bool nllinks(cJSON *interfaces, const bool detailed);
bool nlneigh(cJSON *arp_entries);
void get_gateway_name(char gateway[MAXIFACESTRLEN]);

// Netlink expects that the user buffer will be at least 8kB or a page size of
// the CPU architecture, whichever is bigger. Particular Netlink families may,
// however, require a larger buffer. 32kB buffer is recommended for most
// efficient handling of dumps (larger buffer fits more dumped objects and
// therefore fewer recvmsg() calls are needed).
// (see https://www.kernel.org/doc/html/v6.1/userspace-api/netlink/intro.html)
#define BUFLEN		(32 * 1024)

#define for_each_nlmsg(n, buf, len)					\
	for (n = (struct nlmsghdr*)buf;					\
	     NLMSG_OK(n, (uint32_t)len) && n->nlmsg_type != NLMSG_DONE;	\
	     n = NLMSG_NEXT(n, len))

#define for_each_rattr(n, buf, len)					\
	for (n = (struct rtattr*)buf; RTA_OK(n, len); n = RTA_NEXT(n, len))

struct flag_names {
	uint32_t flag;
	const char *name;
};

// Manually taken from kernel source code in include/net/ipv6.h
#define	IFA_GLOBAL	0x0000U
#define	IFA_HOST	0x0010U
#define	IFA_LINK	0x0020U
#define	IFA_SITE	0x0040U
#define IFA_COMPATv4	0x0080U

#endif // NETLINK_H
