/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Network implementation for netlink
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "netlink.h"
#include "netlink_consts.h"
#include "log.h"
// struct config
#include "config/config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

// defined in src/dnsmasq/rfc1035.c
extern int private_net(struct in_addr addr, int ban_localhost);

static bool nlrequest(int fd, struct sockaddr_nl *sa, int nlmsg_type)
{
	char buf[BUFLEN] = { 0 };
	// Assemble the message according to the netlink protocol
	struct nlmsghdr *nl = (struct nlmsghdr*)(void*)buf;
	// Prepare the netlink message header
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;

	if(nlmsg_type == RTM_GETADDR)
	{
		// Request address information
		nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

		struct ifaddrmsg *ifa = (struct ifaddrmsg*)NLMSG_DATA(nl);
		ifa->ifa_family = AF_LOCAL;
	}
	else if(nlmsg_type == RTM_GETROUTE)
	{
		// Request route information
		nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

		struct rtmsg *rt = (struct rtmsg*)NLMSG_DATA(nl);
		rt->rtm_family = AF_LOCAL;
	}
	else if(nlmsg_type == RTM_GETLINK)
	{
		// Request link information
		nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

		struct ifinfomsg *link = (struct ifinfomsg*)NLMSG_DATA(nl);
		link->ifi_family = AF_UNSPEC;
	}
	else if(nlmsg_type == RTM_GETNEIGH)
	{
		// Request ARP information
		nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));

		struct ndmsg *ndm = (struct ndmsg*)NLMSG_DATA(nl);
		ndm->ndm_family = AF_UNSPEC;
	}
	nl->nlmsg_type = nlmsg_type;

	// Prepare struct msghdr for sending
	struct iovec iov = { nl, nl->nlmsg_len };
	struct msghdr msg = { 0 };
	msg.msg_name = sa;
	msg.msg_namelen = sizeof(*sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send netlink message to kernel
	return sendmsg(fd, &msg, 0) >= 0;
}

static ssize_t nlgetmsg(int fd, struct sockaddr_nl *sa, void *buf, size_t len)
{
	// Prepare struct msghdr for receiving, iov is the buffer
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = { 0 };
	msg.msg_name = sa;
	msg.msg_namelen = sizeof(*sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Receive netlink message from kernel
	const ssize_t rcv = recvmsg(fd, &msg, 0);

	// Netlink sockets are datagram sockets rather than stream sockets,
	// meaning that each message must be received in its entirety by a
	// single recvmsg() system call. If the provided buffer is too short,
	// the message will be truncated and the MSG_TRUNC flag set
	if(msg.msg_flags & MSG_TRUNC)
		log_warn("Netlink message truncated!");

	// Upon truncation the remaining part of the message is discarded and
	// cannot be retrieved - this information is lost. We, nonetheless,
	// return the truncated message to the caller, as it still contains
	// partial information
	// Additional checking during parsing will log additional warnings,
	// indicating how much (at least) of the message was truncated
	return rcv;
}

static int nlparsemsg_route(struct rtmsg *rt, void *buf, size_t len, cJSON *routes, const bool detailed)
{
	char ifname[IF_NAMESIZE];
	cJSON *route = cJSON_CreateObject();
	cJSON_AddNumberToObject(route, "table", rt->rtm_table);
	cJSON_AddStringReferenceToObject(route, "family", family_name(rt->rtm_family));

	// Print human-readable protocol
	for(unsigned int i = 0; i < sizeof(rtprots)/sizeof(rtprots[0]); i++)
		if (rtprots[i].flag == rt->rtm_protocol)
		{
			cJSON_AddStringReferenceToObject(route, "protocol", rtprots[i].name);
			break;
		}
	// If the protocol is not found, add it as a number
	if (cJSON_GetObjectItem(route, "protocol") == NULL) {
		cJSON_AddNumberToObject(route, "protocol", rt->rtm_protocol);
	}

	// Print human-readable scope
	for(unsigned int i = 0; i < sizeof(rtscopes)/sizeof(rtscopes[0]); i++)
		if (rtscopes[i].flag == rt->rtm_scope)
		{
			cJSON_AddStringReferenceToObject(route, "scope", rtscopes[i].name);
			break;
		}
	// If the scope is not found, add it as a number
	if (cJSON_GetObjectItem(route, "scope") == NULL)
		cJSON_AddNumberToObject(route, "scope", rt->rtm_scope);

	// Print human-readable type
	for(unsigned int i = 0; i < sizeof(rttypes)/sizeof(rttypes[0]); i++)
		if (rttypes[i].flag == rt->rtm_type)
		{
			cJSON_AddStringReferenceToObject(route, "type", rttypes[i].name);
			break;
		}
	// If the type is not found, add it as a number
	if (cJSON_GetObjectItem(route, "type") == NULL)
		cJSON_AddNumberToObject(route, "type", rt->rtm_type);

	// Add array of human-readable flags
	cJSON *flags = cJSON_CreateArray();
	for(unsigned int i = 0; i < sizeof(rtmflags)/sizeof(rtmflags[0]); i++)
		if (rtmflags[i].flag & rt->rtm_flags)
			cJSON_AddStringReferenceToArray(flags, rtmflags[i].name);
	for(unsigned int i = 0; i < sizeof(rtnhflags)/sizeof(rtnhflags[0]); i++)
		if (rtnhflags[i].flag & rt->rtm_flags)
			cJSON_AddStringReferenceToArray(flags, rtnhflags[i].name);
	cJSON_AddItemToObject(route, "flags", flags);
	if(detailed)
		cJSON_AddNumberToObject(route, "iflags", rt->rtm_flags);

	// Parse the route attributes
	struct rtattr *rta = NULL;
	static char ip[INET6_ADDRSTRLEN];
	for_each_rattr(rta, buf, len)
	{
		switch (rta->rta_type)
		{
			case RTA_DST: // route destination address
			case RTA_SRC: // route source address
			case RTA_GATEWAY: // gateway of the route
			case RTA_PREFSRC: // preferred source address
			case RTA_NEWDST: // change package destination address
				inet_ntop(rt->rtm_family, RTA_DATA(rta), ip, INET6_ADDRSTRLEN);
				cJSON_AddStringToObject(route, rtaTypeToString(rta->rta_type), ip);
				break;

			case RTA_IIF: // incoming interface
			case RTA_OIF: // outgoing interface
			{
				const uint32_t ifidx = *(uint32_t*)RTA_DATA(rta);
				if_indextoname(ifidx, ifname);
				cJSON_AddStringToObject(route, rtaTypeToString(rta->rta_type), ifname);
				break;
			}

			case RTA_FLOW: // route realm
			case RTA_METRICS: // route metric
			case RTA_MARK: // route mark
			case RTA_EXPIRES: // route expires (in seconds)
			case RTA_UID: // user id
			case RTA_TTL_PROPAGATE: // propagate TTL
			case RTA_IP_PROTO: // IP protocol
			case RTA_SPORT:
			case RTA_DPORT:
			case RTA_NH_ID:
			{
				if(!detailed)
					break;
				const uint32_t number = *(uint32_t*)RTA_DATA(rta);
				cJSON_AddNumberToObject(route, rtaTypeToString(rta->rta_type), number);
				break;
			}

			case RTA_TABLE: // routing table id
				// Already added above
				break;

			case RTA_PRIORITY: // route priority
			case RTA_PREF: // route preference
			{
				const uint32_t num = *(uint32_t*)RTA_DATA(rta);
				cJSON_AddNumberToObject(route, rtaTypeToString(rta->rta_type), num);
				break;
			}

			case RTA_MULTIPATH: // multipath route
			{
				if(!detailed)
					break;
				struct rtnexthop *rtnh = (struct rtnexthop *) RTA_DATA (rta);
				cJSON *multipath = cJSON_CreateObject();
				cJSON_AddNumberToObject(multipath, "len", rtnh->rtnh_len); // Length of struct + length of RTAs

				// Add array of human-readable nexthop flags
				cJSON *nhflags = cJSON_CreateArray();
				for(unsigned int i = 0; i < sizeof(rtnhflags)/sizeof(rtnhflags[0]); i++)
					if (rtnhflags[i].flag & rtnh->rtnh_flags)
						cJSON_AddStringReferenceToArray(nhflags, rtnhflags[i].name);
				cJSON_AddItemToObject(route, "mflags", nhflags);
				cJSON_AddNumberToObject(route, "imflags", rtnh->rtnh_flags);

				cJSON_AddNumberToObject(multipath, "hops", rtnh->rtnh_hops); // Nexthop priority
				if_indextoname(rtnh->rtnh_ifindex, ifname);
				cJSON_AddStringToObject(multipath, "if", ifname); // Interface for this nexthop
				cJSON_AddItemToObject(route, rtaTypeToString(rta->rta_type), multipath);
				break;
			}

			case RTA_VIA: // next hop address
			{
				struct rtvia *via = (struct rtvia*)RTA_DATA(rta);
				inet_ntop(via->rtvia_family, &via->rtvia_addr, ip, INET6_ADDRSTRLEN);
				cJSON_AddStringToObject(route, rtaTypeToString(rta->rta_type), ip);
				break;
			}

			case RTA_MFC_STATS: // multicast forwarding cache statistics
			{
				if(!detailed)
					break;
				const struct rta_mfc_stats *mfc = (struct rta_mfc_stats*)RTA_DATA(rta);
				cJSON_AddNumberToObject(route, "mfcs_packets", mfc->mfcs_packets);
				cJSON_AddNumberToObject(route, "mfcs_bytes", mfc->mfcs_bytes);
				cJSON_AddNumberToObject(route, "mfcs_wrong_if", mfc->mfcs_wrong_if);
				break;
			}

			case RTA_CACHEINFO:
			{
				if(!detailed)
					break;
				const struct rta_cacheinfo *ci = (struct rta_cacheinfo*)RTA_DATA(rta);
				// Get seconds the system is already up ("uptime")
				struct timespec wall_clock;
				clock_gettime(CLOCK_REALTIME, &wall_clock);
				struct timespec boot_clock;
				clock_gettime(CLOCK_BOOTTIME, &boot_clock);
				const time_t delta_time = wall_clock.tv_sec - boot_clock.tv_sec;
				cJSON_AddNumberToObject(route, "cstamp", delta_time + ci->rta_clntref);
				cJSON_AddNumberToObject(route, "tstamp", delta_time + ci->rta_lastuse);
				cJSON_AddNumberToObject(route, "expires", ci->rta_expires);
				cJSON_AddNumberToObject(route, "error", ci->rta_error);
				cJSON_AddNumberToObject(route, "used", ci->rta_used);
				break;
			}

			default:
			{
				// Unknown rta_type
				// Add the rta_type as a number to an array of
				// unknown types if in detailed mode
				if(!detailed)
					break;

				cJSON *unknown = cJSON_GetObjectItem(route, "unknown");
				if(unknown == NULL)
				{
					unknown = cJSON_CreateArray();
					cJSON_AddItemToObject(route, "unknown", unknown);
				}
				cJSON_AddNumberToArray(unknown, rta->rta_type);
				break;
			}
		}
	}

	// The default route is the one which does not have a "dst" attribute
	if(cJSON_GetObjectItem(route, "dst") == NULL)
		cJSON_AddStringToObject(route, "dst", "default");

	// Debug output
	if(config.debug.netlink.v.b)
	{
		const cJSON* dst = cJSON_GetObjectItem(route, "dst");
		const cJSON *via = cJSON_GetObjectItem(route, "via");

		log_debug(DEBUG_NETLINK, "Parsing IPv%d route: table %u is %s via %s",
		          rt->rtm_family == AF_INET ? 4 : 6,
		          rt->rtm_table, dst ? dst->valuestring : "N/A",
		          via ? via->valuestring : "direct");
	}

	cJSON_AddItemToArray(routes, route);
	return 0;
}

static int nlparsemsg_address(struct ifaddrmsg *ifa, void *buf, size_t len, cJSON *links, const bool detailed)
{
	cJSON *addr = cJSON_CreateObject();

	// Add interface ID
	if(detailed)
		cJSON_AddNumberToObject(addr, "index", ifa->ifa_index);

	// Add family
	cJSON_AddStringReferenceToObject(addr, "family", family_name(ifa->ifa_family));

	// Print human-readable scope
	for(unsigned int i = 0; i < sizeof(rtscopes)/sizeof(rtscopes[0]); i++)
		if (rtscopes[i].flag == ifa->ifa_scope)
		{
			cJSON_AddStringReferenceToObject(addr, "scope", rtscopes[i].name);
			break;
		}
	// If the scope is not found, add it as a number
	if (cJSON_GetObjectItem(addr, "scope") == NULL)
		cJSON_AddNumberToObject(addr, "scope", ifa->ifa_scope);

	// Add array of human-readable flags
	cJSON *flags = cJSON_CreateArray();
	for(unsigned int i = 0; i < sizeof(ifaf_flags)/sizeof(ifaf_flags[0]); i++)
		if (ifaf_flags[i].flag & ifa->ifa_flags)
			cJSON_AddStringReferenceToArray(flags, ifaf_flags[i].name);
	cJSON_AddItemToObject(addr, "flags", flags);

	// Add prefix length
	cJSON_AddNumberToObject(addr, "prefixlen", ifa->ifa_prefixlen);

	// Parse the address attributes
	struct rtattr *rta = NULL;
	char ifname[IF_NAMESIZE] = { 0 };
	for_each_rattr(rta, buf, len){
		switch(rta->rta_type)
		{
			case IFA_ADDRESS:
			case IFA_LOCAL:
			case IFA_BROADCAST:
			case IFA_ANYCAST:
			{
				char ip[INET6_ADDRSTRLEN] = { 0 };
				inet_ntop(ifa->ifa_family, RTA_DATA(rta), ip, INET6_ADDRSTRLEN);
				cJSON_AddStringToObject(addr, ifaTypeToString(rta->rta_type), ip);

				// Determine and add address type (GUA, ULA, LL, ...)
				const char *type_str = "unknown";
				if(rta->rta_type == IFA_ADDRESS)
					type_str = "address_type";
				else if(rta->rta_type == IFA_LOCAL)
					type_str = "local_type";
				else if(rta->rta_type == IFA_BROADCAST)
					type_str = "broadcast_type";
				else if(rta->rta_type == IFA_ANYCAST)
					type_str = "anycast_type";

				if(ifa->ifa_family == AF_INET6)
				{
					const struct in6_addr *in6 = (struct in6_addr*)RTA_DATA(rta);
					if(IN6_IS_ADDR_UNSPECIFIED(in6))
						cJSON_AddStringToObject(addr, type_str, "unspecified");
					else if(IN6_IS_ADDR_LOOPBACK(in6))
						cJSON_AddStringToObject(addr, type_str, "loopback");
					else if(IN6_IS_ADDR_MULTICAST(in6))
						cJSON_AddStringToObject(addr, type_str, "multicast");
					else if(IN6_IS_ADDR_LINKLOCAL(in6))
						cJSON_AddStringToObject(addr, type_str, "link-local (LL)");
					else if(IN6_IS_ADDR_SITELOCAL(in6))
						cJSON_AddStringToObject(addr, type_str, "site-local (ULA)");
					else if(IN6_IS_ADDR_V4MAPPED(in6))
						cJSON_AddStringToObject(addr, type_str, "IPv4-mapped");
					else if(IN6_IS_ADDR_V4COMPAT(in6))
						cJSON_AddStringToObject(addr, type_str, "IPv4-compatible");
					else if(IN6_IS_ADDR_MC_NODELOCAL(in6))
						cJSON_AddStringToObject(addr, type_str, "node-local");
					else if(IN6_IS_ADDR_MC_LINKLOCAL(in6))
						cJSON_AddStringToObject(addr, type_str, "link-local (LL)");
					else if(IN6_IS_ADDR_MC_SITELOCAL(in6))
						cJSON_AddStringToObject(addr, type_str, "site-local (ULA)");
					else if(IN6_IS_ADDR_MC_ORGLOCAL(in6))
						cJSON_AddStringToObject(addr, type_str, "organization-local");
					else if(IN6_IS_ADDR_MC_GLOBAL(in6))
						cJSON_AddStringToObject(addr, type_str, "global (GUA)");
					else
					{
						uint8_t bytes[2];
						memcpy(&bytes, in6, 2);
						// Global Unicast Address (2000::/3, RFC 4291)
						if((bytes[0] & 0x70) == 0x20)
							cJSON_AddStringToObject(addr, type_str, "global (GUA)");
						// Unique Local Address   (fc00::/7, RFC 4193)
						else if((bytes[0] & 0xfe) == 0xfc)
							cJSON_AddStringToObject(addr, type_str, "site-local (ULA)");
						// Link Local Address   (fe80::/10, RFC 4291)
						else if((bytes[0] & 0xff) == 0xfe && (bytes[1] & 0x30) == 0)
							cJSON_AddStringToObject(addr, type_str, "link-local (LL)");
						else
							cJSON_AddStringToObject(addr, type_str, "unknown");
					}
				}
				else if(ifa->ifa_family == AF_INET)
				{
					const struct in_addr *in = (struct in_addr*)RTA_DATA(rta);
					if(in->s_addr == INADDR_ANY)
						cJSON_AddStringToObject(addr, type_str, "unspecified");
					else if(in->s_addr == INADDR_LOOPBACK ||
					        (in->s_addr & htonl(0xff000000)) == htonl(0x7f000000))
						cJSON_AddStringToObject(addr, type_str, "loopback");
					else if((in->s_addr & htonl(0xf0000000)) == htonl(0xe0000000))
						cJSON_AddStringToObject(addr, type_str, "multicast");
					else if(private_net(*in, false))
						cJSON_AddStringToObject(addr, type_str, "private");
					else if((in->s_addr & htonl(0xffc00000)) == htonl(0x64400000))
						// RFC 6598: Carrier-Grade NAT (CGN) 100.64.0.0/10
						cJSON_AddStringToObject(addr, type_str, "Carrier-Grade NAT");
					else
						cJSON_AddStringToObject(addr, type_str, "public");
				}
				else
					cJSON_AddStringToObject(addr, type_str, "unknown");
				break;
			}

			case IFA_LABEL:
				strncpy(ifname, (char*)RTA_DATA(rta), IF_NAMESIZE);
				cJSON_AddStringToObject(addr, ifaTypeToString(rta->rta_type), (char*)RTA_DATA(rta));
				break;

			case IFA_CACHEINFO:
			{
				const struct ifa_cacheinfo *ci = (struct ifa_cacheinfo*)RTA_DATA(rta);
				cJSON_AddNumberToObject(addr, "prefered", ci->ifa_prefered);
				cJSON_AddNumberToObject(addr, "valid", ci->ifa_valid);
				// Get seconds the system is already up ("uptime")
				struct timespec wall_clock;
				clock_gettime(CLOCK_REALTIME, &wall_clock);
				struct timespec boot_clock;
				clock_gettime(CLOCK_BOOTTIME, &boot_clock);
				const time_t delta_time = wall_clock.tv_sec - boot_clock.tv_sec;
				cJSON_AddNumberToObject(addr, "cstamp", delta_time + 0.01*ci->cstamp); // created timestamp
				cJSON_AddNumberToObject(addr, "tstamp", delta_time + 0.01*ci->tstamp); // updated timestamp
				break;
			}

			case IFA_FLAGS:
				// Already added above, ignore this duplicate
				break;

			case IFA_RT_PRIORITY:
			{
				if(!detailed)
					break;
				const uint32_t prio = *(uint32_t*)RTA_DATA(rta);
				cJSON_AddStringToObject(addr, rtaTypeToString(rta->rta_type), rt_priority(prio));
				break;
			}

			case IFA_TARGET_NETNSID:
			{
				if(!detailed)
					break;
				const uint32_t number = *(uint32_t*)RTA_DATA(rta);
				cJSON_AddNumberToObject(addr, ifaTypeToString(rta->rta_type), number);
				break;
			}

			default:
			{
				// Unknown rta_type
				// Add the rta_type as a number to an array of
				// unknown types if in detailed mode
				if(!detailed)
					break;

				cJSON *unknown = cJSON_GetObjectItem(addr, "unknown");
				if(unknown == NULL)
				{
					unknown = cJSON_CreateArray();
					cJSON_AddItemToObject(addr, "unknown", unknown);
				}
				cJSON_AddNumberToArray(unknown, rta->rta_type);
				break;
			}
		}
	}

	// Get the interface name if it is not already set
	if(!ifname[0])
		if_indextoname(ifa->ifa_index, ifname);

	// Debug output
	if(config.debug.netlink.v.b)
	{
		const cJSON *address = cJSON_GetObjectItem(addr, "address");
		const cJSON *prefixlen = cJSON_GetObjectItem(addr, "prefixlen");
		log_debug(DEBUG_NETLINK, "Parsing %s address of iface %u (%s): %s/%d",
		          family_name(ifa->ifa_family), ifa->ifa_index, ifname,
		          address ? address->valuestring : "N/A",
		          prefixlen ? prefixlen->valueint : -1);
	}

	// Return early if the interface is not in the list of known interfaces
	cJSON *ifobj = cJSON_GetObjectItem(links, ifname);
	if(ifobj == NULL)
	{
		log_debug(DEBUG_NETLINK, "Interface %s undefined, skipping", ifname);
		cJSON_Delete(addr);
		return 0;
	}

	// Ensure there is an addresses object for the interface
	if(cJSON_GetObjectItem(ifobj, "addresses") == NULL)
		cJSON_AddItemToObject(ifobj, "addresses", cJSON_CreateArray());

	// Get the addresses object
	cJSON *addrsobj = cJSON_GetObjectItem(ifobj, "addresses");

	// Add the address to the object
	cJSON_AddItemToArray(addrsobj, addr);
	return 0;
}

static int nlparsemsg_link(struct ifinfomsg *ifi, void *buf, size_t len, cJSON *links, const bool detailed)
{
	cJSON *link = cJSON_CreateObject();

	// Add ifname at the top of the JSON object
	char ifname[IF_NAMESIZE] = { 0 };
	if_indextoname(ifi->ifi_index, ifname);
	cJSON_AddStringToObject(link, "name", ifname);

	// Add interface ID and family if detailed
	if(detailed)
	{
		cJSON_AddNumberToObject(link, "index", ifi->ifi_index);
		cJSON_AddStringReferenceToObject(link, "family", family_name(ifi->ifi_family));
	}

	// Get link speed (not available through netlink)
	// (may not be possible, e.g., for WiFi devices with dynamic link speeds)
	int speed = -1;
	char fname[64];
	snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/speed", ifname);
	FILE *f = fopen(fname, "r");
	if(f != NULL)
	{
		if(fscanf(f, "%i", &(speed)) != 1)
			speed = -1;
		fclose(f);
	}
	if(speed > -1)
		cJSON_AddNumberToObject(link, "speed", speed);
	else
		cJSON_AddNullToObject(link, "speed");

	// Add human-readable type
	for(unsigned int i = 0; i < sizeof(iflatypes)/sizeof(iflatypes[0]); i++)
		if (iflatypes[i].flag == ifi->ifi_type)
		{
			cJSON_AddStringReferenceToObject(link, "type", iflatypes[i].name);
			break;
		}

	// Add interface flags
	cJSON *flags = cJSON_CreateArray();
	for(unsigned int i = 0; i < sizeof(iff_flags)/sizeof(iff_flags[0]); i++)
		if (iff_flags[i].flag & ifi->ifi_flags)
			cJSON_AddStringReferenceToArray(flags, iff_flags[i].name);
	cJSON_AddItemToObject(link, "flags", flags);

	// Parse the link attributes
	struct rtattr *rta = NULL;
	cJSON *jstats = NULL, *jstats64 = NULL;
	for_each_rattr(rta, buf, len){
		switch(rta->rta_type)
		{
			case IFLA_ADDRESS:
			case IFLA_BROADCAST:
			case IFLA_PERM_ADDRESS:
			{
				char mac[18];
				const unsigned char *addr = RTA_DATA(rta);
				snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
				         addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

				// Addresses may be empty, so only add them if they are not
				cJSON_AddStringToObject(link, iflaTypeToString(rta->rta_type), mac);
				break;
			}

			case IFLA_IFNAME:
			case IFLA_ALT_IFNAME:
			case IFLA_PHYS_PORT_NAME:
			case IFLA_QDISC:
			case IFLA_PARENT_DEV_NAME:
			case IFLA_PARENT_DEV_BUS_NAME:
			{
				if(!detailed)
					break;
				const char *string = (char*)RTA_DATA(rta);
				cJSON_AddStringToObject(link, iflaTypeToString(rta->rta_type), string);
				break;
			}

			case IFLA_CARRIER:
			case IFLA_PROTO_DOWN:
			{
				const uint8_t carrier = *(uint8_t*)RTA_DATA(rta);
				cJSON_AddBoolToObject(link, iflaTypeToString(rta->rta_type), carrier == 0 ? false : true);
				break;
			}

			case IFLA_OPERSTATE:
				for(unsigned int i = 0; i < sizeof(ifstates)/sizeof(ifstates[0]); i++)
					if (ifstates[i].flag == *(unsigned int*)RTA_DATA(rta))
					{
						cJSON_AddStringReferenceToObject(link, "state", ifstates[i].name);
						break;
					}
				break;

			case IFLA_LINK: // Interface index
			case IFLA_PHYS_PORT_ID:
			case IFLA_PHYS_SWITCH_ID:
			case IFLA_CARRIER_CHANGES:
			case IFLA_MTU:
			case IFLA_MASTER:
			case IFLA_TXQLEN:
			case IFLA_MAP:
			case IFLA_WEIGHT:
			case IFLA_LINKMODE:
			case IFLA_COST:
			case IFLA_PRIORITY:
			case IFLA_GROUP:
			case IFLA_NET_NS_PID:
			case IFLA_NET_NS_FD:
			case IFLA_EXT_MASK:
			case IFLA_PROMISCUITY:
			case IFLA_NUM_TX_QUEUES:
			case IFLA_NUM_RX_QUEUES:
			case IFLA_CARRIER_UP_COUNT:
			case IFLA_CARRIER_DOWN_COUNT:
			case IFLA_GSO_MAX_SEGS:
			case IFLA_GSO_MAX_SIZE:
			case IFLA_NEW_NETNSID:
			case IFLA_MIN_MTU:
			case IFLA_MAX_MTU:
			case IFLA_LINK_NETNSID:
			{
				if(!detailed)
					break;
				const uint32_t number = *(uint32_t*)RTA_DATA(rta);
				cJSON_AddNumberToObject(link, iflaTypeToString(rta->rta_type), number);
				break;
			}

			case IFLA_STATS:
			{
				// Don't collect 32 bit statistics if we
				// already have their 64 bit equivalent
				if(jstats64 != NULL)
					break;
				// See description of the individual statistics
				// below in the IFLA_STATS64 case
				jstats = JSON_NEW_OBJECT();
				if(jstats == NULL)
				{
					log_err("Memory allocation failed in %s(IFLA_STATS64)", __FUNCTION__);
					break;
				}
				const struct rtnl_link_stats *stats = (struct rtnl_link_stats*)RTA_DATA(rta);
				{
					// Warning: May be overflown if the interface has been up for a long time
					// and has transferred a lot of data as 32 bits are used for the counters
					// resulting in a maximum of 4 GiB. It is recommended to use the 64 bit
					// counters if available.
					char prefix[2] = { 0 };
					double formatted_size;
					format_memory_size(prefix, stats->rx_bytes, &formatted_size);
					cJSON *rx_bytes = cJSON_CreateObject();
					cJSON_AddNumberToObject(rx_bytes, "value", formatted_size);
					cJSON_AddStringToObject(rx_bytes, "unit", prefix);
					cJSON_AddItemToObject(jstats, "rx_bytes", rx_bytes);
				}
				{
					// Warning: May be overflown if the interface has been up for a long time
					// and has transferred a lot of data as 32 bits are used for the counters
					// resulting in a maximum of 4 GiB. It is recommended to use the 64 bit
					// counters if available.
					char prefix[2] = { 0 };
					double formatted_size;
					format_memory_size(prefix, stats->tx_bytes, &formatted_size);
					cJSON *tx_bytes = cJSON_CreateObject();
					cJSON_AddNumberToObject(tx_bytes, "value", formatted_size);
					cJSON_AddStringToObject(tx_bytes, "unit", prefix);
					cJSON_AddItemToObject(jstats, "tx_bytes", tx_bytes);
				}
				cJSON_AddNumberToObject(jstats, "bits", 32);
				if(!detailed)
					break;
				cJSON_AddNumberToObject(jstats, "rx_packets", stats->rx_packets);
				cJSON_AddNumberToObject(jstats, "tx_packets", stats->tx_packets);
				cJSON_AddNumberToObject(jstats, "rx_errors", stats->rx_errors);
				cJSON_AddNumberToObject(jstats, "tx_errors", stats->tx_errors);
				cJSON_AddNumberToObject(jstats, "rx_dropped", stats->rx_dropped);
				cJSON_AddNumberToObject(jstats, "tx_dropped", stats->tx_dropped);
				cJSON_AddNumberToObject(jstats, "multicast", stats->multicast);
				cJSON_AddNumberToObject(jstats, "collisions", stats->collisions);
				cJSON_AddNumberToObject(jstats, "rx_length_errors", stats->rx_length_errors);
				cJSON_AddNumberToObject(jstats, "rx_over_errors", stats->rx_over_errors);
				cJSON_AddNumberToObject(jstats, "rx_crc_errors", stats->rx_crc_errors);
				cJSON_AddNumberToObject(jstats, "rx_frame_errors", stats->rx_frame_errors);
				cJSON_AddNumberToObject(jstats, "rx_fifo_errors", stats->rx_fifo_errors);
				cJSON_AddNumberToObject(jstats, "rx_missed_errors", stats->rx_missed_errors);
				cJSON_AddNumberToObject(jstats, "tx_aborted_errors", stats->tx_aborted_errors);
				cJSON_AddNumberToObject(jstats, "tx_carrier_errors", stats->tx_carrier_errors);
				cJSON_AddNumberToObject(jstats, "tx_fifo_errors", stats->tx_fifo_errors);
				cJSON_AddNumberToObject(jstats, "tx_heartbeat_errors", stats->tx_heartbeat_errors);
				cJSON_AddNumberToObject(jstats, "tx_window_errors", stats->tx_window_errors);
				cJSON_AddNumberToObject(jstats, "rx_compressed", stats->rx_compressed);
				cJSON_AddNumberToObject(jstats, "tx_compressed", stats->tx_compressed);
				cJSON_AddNumberToObject(jstats, "rx_nohandler", stats->rx_nohandler);
				break;
			}

			case IFLA_STATS64:
			{
				jstats64 = JSON_NEW_OBJECT();
				if(jstats64 == NULL)
				{
					log_err("Memory allocation failed in %s(IFLA_STATS64)", __FUNCTION__);
					break;
				}
				// Free 32 bit statistics if we already
				// collected them before. We only want to keep
				// the most accurate statistics
				if(jstats)
				{
					cJSON_Delete(jstats);
					jstats = NULL;
				}
				const struct rtnl_link_stats64 *stats64 = (struct rtnl_link_stats64*)RTA_DATA(rta);
				{
					char prefix[2] = { 0 };
					double formatted_size;
					format_memory_size(prefix, stats64->rx_bytes, &formatted_size);
					cJSON *rx_bytes = cJSON_CreateObject();
					cJSON_AddNumberToObject(rx_bytes, "value", formatted_size);
					cJSON_AddStringToObject(rx_bytes, "unit", prefix);
					// @rx_bytes: Number of good received
					// bytes, corresponding to @rx_packets.
					cJSON_AddItemToObject(jstats64, "rx_bytes", rx_bytes);
				}
				{
					char prefix[2] = { 0 };
					double formatted_size;
					format_memory_size(prefix, stats64->tx_bytes, &formatted_size);
					cJSON *tx_bytes = cJSON_CreateObject();
					cJSON_AddNumberToObject(tx_bytes, "value", formatted_size);
					cJSON_AddStringToObject(tx_bytes, "unit", prefix);
					// @tx_bytes: Number of transmitted bytes,
					// corresponding to @tx_packets.
					cJSON_AddItemToObject(jstats64, "tx_bytes", tx_bytes);
				}
				cJSON_AddNumberToObject(jstats64, "bits", 64);
				if(!detailed)
					break;
				// @rx_packets: Number of good packets received
				// by the interface. For hardware interfaces
				// counts all good packets received from the
				// device by the host, including packets which
				// host had to drop at various stages of
				// processing (even in the driver).
				cJSON_AddNumberToObject(jstats64, "rx_packets", stats64->rx_packets);
				// @tx_packets: Number of packets successfully
				// transmitted. For hardware interfaces counts
				// packets which host was able to successfully
				// hand over to the device, which does not
				// necessarily mean that packets had been
				// successfully transmitted out of the device,
				// only that device acknowledged it copied them
				// out of host memory.
				cJSON_AddNumberToObject(jstats64, "tx_packets", stats64->tx_packets);
				// @rx_errors: Total number of bad packets
				// received on this network device. This counter
				// must include events counted by
				// @rx_length_errors, @rx_crc_errors,
				// @rx_frame_errors and other errors not
				// otherwise counted.
				cJSON_AddNumberToObject(jstats64, "rx_errors", stats64->rx_errors);
				// @tx_errors: Total number of transmit
				// problems. This counter must include events
				// counter by @tx_aborted_errors,
				// @tx_carrier_errors, @tx_fifo_errors,
				// @tx_heartbeat_errors,
				// @tx_window_errors and other errors not
				// otherwise counted.
				cJSON_AddNumberToObject(jstats64, "tx_errors", stats64->tx_errors);
				// @rx_dropped: Number of packets received but
				// not processed, e.g. due to lack of resources
				// or unsupported protocol. For hardware
				// interfaces this counter may include packets
				// discarded due to L2 address filtering but
				// should not include packets dropped by the
				// device due to buffer exhaustion which are
				// counted separately in
				// @rx_missed_errors (since procfs folds those
				// two counters together).
				cJSON_AddNumberToObject(jstats64, "rx_dropped", stats64->rx_dropped);
				// @tx_dropped: Number of packets dropped on
				// their way to transmission, e.g. due to lack
				// of resources.
				cJSON_AddNumberToObject(jstats64, "tx_dropped", stats64->tx_dropped);
				// @multicast: Multicast packets received. For
				// hardware interfaces this statistic is
				// commonly calculated at the device level
				// (unlike @rx_packets) and therefore may
				// include packets which did not reach the host.
				cJSON_AddNumberToObject(jstats64, "multicast", stats64->multicast);
				// @collisions: Number of collisions during
				// packet transmissions.
				cJSON_AddNumberToObject(jstats64, "collisions", stats64->collisions);
				// @rx_length_errors: Number of packets dropped
				// due to invalid length. Part of aggregate
				// "frame" errors in `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "rx_length_errors", stats64->rx_length_errors);
				// @rx_over_errors: Receiver FIFO overflow event
				// counter. Historically the count of overflow
				// events. Such events may be reported in the
				// receive descriptors or via interrupts, and
				// may not correspond one-to-one with dropped
				// packets.
				//
				// The recommended interpretation for high speed
				// interfaces is - number of packets dropped
				// because they did not fit into buffers
				// provided by the host, e.g. packets larger
				// than MTU or next buffer in the ring was not
				// available for a scatter transfer.
				//
				// Part of aggregate "frame" errors in `/proc/net/dev`.
				//
				// This statistics was historically used
				// interchangeably with @rx_fifo_errors.
				//
				// This statistic corresponds to hardware events
				// and is not commonly used on software devices.
				cJSON_AddNumberToObject(jstats64, "rx_over_errors", stats64->rx_over_errors);
				// @rx_crc_errors: Number of packets received
				// with a CRC error. Part of aggregate "frame"
				// errors in `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "rx_crc_errors", stats64->rx_crc_errors);
				// @rx_frame_errors: Receiver frame alignment
				// errors. Part of aggregate "frame" errors in
				// `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "rx_frame_errors", stats64->rx_frame_errors);
				// @rx_fifo_errors: Receiver FIFO error counter.
				//
				// Historically the count of overflow events.
				// Those events may be reported in the receive
				// descriptors or via interrupts, and may not
				// correspond one-to-one with dropped packets.
				//
				// This statistics was used interchangeably with
				// @rx_over_errors. Not recommended for use in
				// drivers for high speed interfaces.
				//
				// This statistic is used on software devices,
				// e.g. to count software packet queue overflow
				// (can) or sequencing errors (GRE).
				cJSON_AddNumberToObject(jstats64, "rx_fifo_errors", stats64->rx_fifo_errors);
				// @rx_missed_errors: Count of packets missed by
				// the host. Folded into the "drop" counter in
				// `/proc/net/dev`.
				//
				// Counts number of packets dropped by the device due to lack
				// of buffer space. This usually indicates that the host interface
				// is slower than the network interface, or host is not keeping up
				// with the receive packet rate.
				//
				// This statistic corresponds to hardware events and is not used
				// on software devices.
				cJSON_AddNumberToObject(jstats64, "rx_missed_errors", stats64->rx_missed_errors);
				// @tx_aborted_errors: Part of aggregate
				// "carrier" errors in `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "tx_aborted_errors", stats64->tx_aborted_errors);
				// @tx_carrier_errors: Number of frame
				// transmission errors due to loss of carrier
				// during transmission. Part of aggregate
				// "carrier" errors in `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "tx_carrier_errors", stats64->tx_carrier_errors);
				// @tx_fifo_errors: Number of frame transmission
				// errors due to device FIFO underrun /
				// underflow. This condition occurs when the
				// device begins transmission of a frame but is
				// unable to deliver the entire frame to the
				// transmitter in time for transmission. Part of
				// aggregate "carrier" errors in
				// `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "tx_fifo_errors", stats64->tx_fifo_errors);
				// @tx_heartbeat_errors: Number of Heartbeat /
				// SQE Test errors for old half-duplex Ethernet.
				// Part of aggregate "carrier" errors in
				// `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "tx_heartbeat_errors", stats64->tx_heartbeat_errors);
				// @tx_window_errors: Number of frame
				// transmission errors due to late collisions
				// (for Ethernet - after the first 64B of
				// transmission). Part of aggregate "carrier"
				// errors in `/proc/net/dev`.
				cJSON_AddNumberToObject(jstats64, "tx_window_errors", stats64->tx_window_errors);
				// @rx_compressed: Number of received compressed
				// packets. This counters is only meaningful for
				// interfaces which support packet compression
				// (e.g. CSLIP, PPP).
				cJSON_AddNumberToObject(jstats64, "rx_compressed", stats64->rx_compressed);
				// @tx_compressed: Number of transmitted
				// compressed packets. This counters is only
				// meaningful for interfaces which support
				// packet compression (e.g. CSLIP, PPP).
				cJSON_AddNumberToObject(jstats64, "tx_compressed", stats64->tx_compressed);
				// @rx_nohandler: Number of packets received on
				// the interface but dropped by the networking
				// stack because the device is not designated to
				// receive packets (e.g. backup link in a bond).
				cJSON_AddNumberToObject(jstats64, "rx_nohandler", stats64->rx_nohandler);
				break;
			}

			case IFLA_LINKINFO:
			{
				if(!detailed)
					break;
				struct rtattr *nlinkinfo = NULL;
				size_t nlen = RTA_PAYLOAD(rta);
				void *ndata = RTA_DATA(rta);
				for_each_rattr(nlinkinfo, ndata, nlen){
					switch(nlinkinfo->rta_type)
					{
						case IFLA_INFO_KIND:
							cJSON_AddStringToObject(link, "link_kind", (char*)RTA_DATA(nlinkinfo));
							break;
						case IFLA_INFO_SLAVE_KIND:
							cJSON_AddStringToObject(link, "slave_kind", (char*)RTA_DATA(nlinkinfo));
							break;
						case IFLA_INFO_DATA:
						case IFLA_INFO_SLAVE_DATA:
							// Needs a very complex
							// disassembler, out of
							// scope here
							break;
						default:
						{
							// Unknown rta_type
							cJSON *unknown = cJSON_GetObjectItem(link, "linkinfo_unknown");
							if(unknown == NULL)
							{
								unknown = cJSON_CreateArray();
								cJSON_AddItemToObject(link, "linkinfo_unknown", unknown);
							}
							cJSON_AddNumberToArray(unknown, nlinkinfo->rta_type);
							break;
						}
					}
				}
				break;
			}

			case IFLA_VFINFO_LIST:
			{
				if(!detailed)
					break;
				struct rtattr *vfinfo = RTA_DATA(rta);
				if (vfinfo->rta_type != IFLA_VF_INFO)
					break;

				const struct ifla_vf_mac *vf_mac;
				const struct ifla_vf_broadcast *vf_broadcast;
				const struct ifla_vf_tx_rate *vf_tx_rate;
				struct rtattr *vf[IFLA_VF_MAX + 1] = {};

				parse_rtattr_nested(vf, IFLA_VF_MAX, vfinfo);

				vf_mac = RTA_DATA(vf[IFLA_VF_MAC]);
				vf_broadcast = RTA_DATA(vf[IFLA_VF_BROADCAST]);
				vf_tx_rate = RTA_DATA(vf[IFLA_VF_TX_RATE]);

				if (vf[IFLA_VF_BROADCAST])
				{
					char mac[18];
					snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
					         vf_broadcast->broadcast[0], vf_broadcast->broadcast[1],
					         vf_broadcast->broadcast[2], vf_broadcast->broadcast[3],
					         vf_broadcast->broadcast[4], vf_broadcast->broadcast[5]);
					cJSON_AddStringToObject(link, "vf_broadcast", mac);
				}
				if(vf[IFLA_VF_MAC])
				{
					char mac[18];
					snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
					         vf_mac->mac[0], vf_mac->mac[1], vf_mac->mac[2],
					         vf_mac->mac[3], vf_mac->mac[4], vf_mac->mac[5]);
					cJSON_AddStringToObject(link, "vf_mac", mac);
				}
				if(vf[IFLA_VF_TX_RATE])
				{
					cJSON_AddNumberToObject(link, "vf_tx_rate", vf_tx_rate->rate);
				}
				if(vf[IFLA_VF_LINK_STATE])
				{
					const uint32_t link_state = *(uint32_t*)RTA_DATA(vf[IFLA_VF_LINK_STATE]);
					cJSON_AddNumberToObject(link, "vf_link_state", link_state);
				}

				break;
			}

			case IFLA_EVENT:
			{
				if(!detailed)
					break;
				const uint32_t event = *(uint32_t*)RTA_DATA(rta);
				for(unsigned int i = 0; i < sizeof(link_events)/sizeof(link_events[0]); i++)
					if (link_events[i].flag == event)
					{
						cJSON_AddStringReferenceToObject(link, "event", link_events[i].name);
						break;
					}
				if(cJSON_GetObjectItem(link, "event") == NULL)
					cJSON_AddNumberToObject(link, "event", event);
				break;
			}

			case IFLA_AF_SPEC:
			{
				if(!detailed)
					break;
				struct rtattr *af_spec = RTA_DATA(rta);
				struct rtattr *inet6_attr = parse_rtattr_one_nested(AF_INET6, af_spec);
				if(!inet6_attr)
					break;

				struct rtattr *tb[IFLA_INET6_MAX + 1];
				parse_rtattr_nested(tb, IFLA_INET6_MAX, inet6_attr);

				if(tb[IFLA_INET6_ADDR_GEN_MODE])
				{
					const uint8_t mode = *(uint8_t*)RTA_DATA(tb[IFLA_INET6_ADDR_GEN_MODE]);
					for(unsigned int i = 0; i < sizeof(addr_gen_modes)/sizeof(addr_gen_modes[0]); i++)
						if (addr_gen_modes[i].flag == mode)
						{
							cJSON_AddStringReferenceToObject(link, "addr_gen_mode", addr_gen_modes[i].name);
							break;
						}
					if(cJSON_GetObjectItem(link, "addr_gen_mode") == NULL)
						cJSON_AddNumberToObject(link, "addr_gen_mode", mode);
				}
				cJSON *af_specs = cJSON_CreateArray();
				for(unsigned int i = 0; i < __IFLA_INET6_MAX; i++)
					if(tb[i])
					{
						cJSON *jaf_spec = cJSON_CreateObject();
						cJSON_AddNumberToObject(jaf_spec, "type", i);
						cJSON_AddNumberToObject(jaf_spec, "len", RTA_PAYLOAD(tb[i]));
						cJSON_AddItemToArray(af_specs, jaf_spec);
					}
				cJSON_AddItemToObject(link, "af_specs", af_specs);
				break;
			}

			case IFLA_XDP:
				// Parsing XDP needs a full BPF program
				// disassembler which is clearly out of scope
				// here
				break;

			default:
			{
				// Unknown rta_type
				// Add the rta_type as a number to an array of
				// unknown types if in detailed mode
				if(!detailed)
					break;

				cJSON *unknown = cJSON_GetObjectItem(link, "unknown");
				if(unknown == NULL)
				{
					unknown = cJSON_CreateArray();
					cJSON_AddItemToObject(link, "unknown", unknown);
				}
				cJSON_AddNumberToArray(unknown, rta->rta_type);
				break;
			}
		}
	}

	// Add 64 bit statistics if available
	if(jstats64 != NULL)
		cJSON_AddItemToObject(link, "stats", jstats64);
	// otherwise add the 32 bit statistics
	else if(jstats)
		cJSON_AddItemToObject(link, "stats", jstats);

	log_debug(DEBUG_NETLINK, "Parsing link %d -> %s",
	          ifi->ifi_index, ifname);

	// Add the link to the object
	cJSON_AddItemToObject(links, ifname, link);

	return 0;
}

static int nlparsemsg_arp(struct ndmsg *ndm, struct rtattr *rta, int rta_len, cJSON *arp_entries, const bool detailed)
{
	char ip[INET6_ADDRSTRLEN] = {0};
	char mac[18] = {0};
	char ifname[IF_NAMESIZE] = {0};
	for(; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
		if(rta->rta_type == NDA_DST) {
			if(ndm->ndm_family == AF_INET)
				inet_ntop(AF_INET, RTA_DATA(rta), ip, sizeof(ip));
			else if(ndm->ndm_family == AF_INET6)
				inet_ntop(AF_INET6, RTA_DATA(rta), ip, sizeof(ip));
		}
		else if(rta->rta_type == NDA_LLADDR) {
			const unsigned char *addr = RTA_DATA(rta);
			snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
				addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		}
	}
	if_indextoname(ndm->ndm_ifindex, ifname);
	cJSON *entry = cJSON_CreateObject();
	cJSON_AddStringToObject(entry, "ip", ip);
	cJSON_AddStringToObject(entry, "mac", mac);
	cJSON_AddStringToObject(entry, "iface", ifname);
	if(config.debug.arp.v.b || config.debug.netlink.v.b)
	{
		cJSON_AddNumberToObject(entry, "state", ndm->ndm_state);
		cJSON_AddNumberToObject(entry, "type", ndm->ndm_type);
		cJSON_AddNumberToObject(entry, "flags", ndm->ndm_flags);

		log_debug(DEBUG_NETLINK, "ARP entry: %s -> %s on %s",
		          ip, mac, ifname);
	}
	cJSON_AddItemToArray(arp_entries, entry);
	return 0;
}

/**
 * @brief Parses Netlink messages from a buffer and populates a JSON object.
 *
 * Iterates over Netlink messages in the provided buffer, dispatching each message
 * to the appropriate handler based on its type (e.g., route, address, link, neighbor).
 * Handles special Netlink flags such as NLM_F_DUMP_INTR, and logs relevant information
 * for debugging and error handling. Supports detailed output based on the 'detailed' flag.
 *
 * @param buf      Pointer to the buffer containing Netlink messages.
 * @param len      Length of the buffer in bytes.
 * @param json     Pointer to a cJSON object to be populated with parsed data.
 * @param detailed Boolean flag indicating whether to include detailed information.
 *
 * @return The type of the last Netlink message processed (nlmsg_type).
 */
static uint32_t parse_nl_msg(void *buf, size_t len, cJSON *json, const bool detailed)
{
	struct nlmsghdr *nl = NULL;
	for_each_nlmsg(nl, buf, len)
	{
		log_debug(DEBUG_NETLINK, "Parsing Netlink message (type %u, len %u/%zu, flags 0x%x, sqe %u)",
		          nl->nlmsg_type, nl->nlmsg_len, len, nl->nlmsg_flags, nl->nlmsg_seq);

		// Check if the message dump got interrupted
		// Some of the data structures kernel uses for storing objects
		// make it hard to provide an atomic snapshot of all the objects
		// in a dump (without impacting the fast-paths updating them).
		// Kernel may set the NLM_F_DUMP_INTR flag on any message in a
		// dump (including the NLMSG_DONE message) if the dump was
		// interrupted and may be inconsistent (e.g. missing objects).
		// User space should retry the dump if it sees the flag set.
		if(nl->nlmsg_flags & NLM_F_DUMP_INTR)
			log_info("Netlink message dump interrupted, some information may be missing");

		// Evaluate the message type
		if (nl->nlmsg_type == RTM_NEWROUTE)
		{
			struct rtmsg *rt = (struct rtmsg*)NLMSG_DATA(nl);
			nlparsemsg_route(rt, RTM_RTA(rt), RTM_PAYLOAD(nl), json, detailed);
			continue;
		}
		else if (nl->nlmsg_type == RTM_NEWADDR)
		{
			struct ifaddrmsg *ifa = (struct ifaddrmsg*)NLMSG_DATA(nl);
			nlparsemsg_address(ifa, IFA_RTA(ifa), IFA_PAYLOAD(nl), json, detailed);
			continue;
		}
		else if (nl->nlmsg_type == RTM_NEWLINK)
		{
			struct ifinfomsg *ifi = (struct ifinfomsg*)NLMSG_DATA(nl);
			nlparsemsg_link(ifi, IFLA_RTA(ifi), IFLA_PAYLOAD(nl), json, detailed);
			continue;
		}
		else if (nl->nlmsg_type == RTM_NEWNEIGH)
		{
			struct ndmsg *ndm = (struct ndmsg*)NLMSG_DATA(nl);
			struct rtattr *rta = (struct rtattr*)(((void*)ndm) + NLMSG_ALIGN(sizeof(struct ndmsg)));
			const int rta_len = nl->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
			nlparsemsg_arp(ndm, rta, rta_len, json, detailed);
			continue;
		}
		else
		{
			log_warn("Unknown Netlink message type: %d", nl->nlmsg_type);
		}
	}

	// Print message properties in debug mode
	if(config.debug.netlink.v.b)
	{
		const char *nltype = "<unknown>";
		if(nl->nlmsg_type == NLMSG_DONE)
			nltype = " (NLMSG_DONE)";
		else if(nl->nlmsg_type == NLMSG_ERROR)
			nltype = " (NLMSG_ERROR)";
		else if(nl->nlmsg_type == NLMSG_NOOP)
			nltype = " (NLMSG_NOOP)";
		else if(nl->nlmsg_type == NLMSG_OVERRUN)
			nltype = " (NLMSG_OVERRUN)";
		else if(nl->nlmsg_type == RTM_NEWROUTE)
			nltype = " (RTM_NEWROUTE)";
		else if(nl->nlmsg_type == RTM_NEWADDR)
			nltype = " (RTM_NEWADDR)";
		else if(nl->nlmsg_type == RTM_NEWLINK)
			nltype = " (RTM_NEWLINK)";
		else if(nl->nlmsg_type == RTM_NEWNEIGH)
			nltype = " (RTM_NEWNEIGH)";

		log_debug(DEBUG_NETLINK, "Returning next nl_msg_type: %u%s, remaining len: %u/%zu",
		          nl->nlmsg_type, nltype, nl->nlmsg_len, len);
	}

	// Return human-readable warning if receive buffer is too small
	if(nl->nlmsg_len > len)
		log_warn("Netlink message (type %u) length exceeds buffer length (%u > %zu), some information will be missing",
		         nl->nlmsg_type, nl->nlmsg_len, len);

	// Evaluate DONE and ERROR messages only in debug mode
	if(config.debug.netlink.v.b && (nl->nlmsg_type == NLMSG_ERROR || nl->nlmsg_type == NLMSG_DONE))
	{
		// Evaluate the error code (negative errno or 0 for acknowledgements)
		const struct nlmsgerr *msgerr = (struct nlmsgerr*)NLMSG_DATA(nl);
		const char *msgtype = nl->nlmsg_type == NLMSG_ERROR ? "error" : "done";
		log_debug(DEBUG_NETLINK, "netlink %s: %s (%d)", msgtype, strerror(-msgerr->error), msgerr->error);
	}

	return nl->nlmsg_type;
}

/**
 * @brief Sends a netlink request of the specified type and parses the response.
 *
 * This function creates a netlink socket, configures it, and sends a request of the given
 * type (e.g., RTM_GETROUTE, RTM_GETADDR, RTM_GETLINK, RTM_GETNEIGH) to the kernel. It then
 * receives and parses the response messages, storing the results in the provided cJSON object.
 * The function continues to receive messages until a NLMSG_DONE, NLMSG_ERROR, or NLMSG_OVERRUN
 * message is encountered, or no more data is received.
 *
 * @param type     The netlink message type to request (e.g., RTM_GETROUTE).
 * @param json     Pointer to a cJSON object where the parsed response will be stored.
 * @param detailed If true, requests detailed information in the response.
 * @return true on success, false on failure.
 */
static bool nlquery(const int type, cJSON *json, const bool detailed)
{
	// First of all, we need to create a socket with the AF_NETLINK domain
	const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if(fd < 0)
	{
		log_err("netlink socket error: %s", strerror(errno));
		return false;
	}

	// Set the buffer size for the socket (this is the maximum size of a
	// message that can be received). The buffer size is set to 32 KiB as
	// this is the maximum size of a netlink message.
	const int buffer_size = 32768;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));

	// Enable NETLINK_EXT_ACK
	int on = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &on, sizeof(on));

	// Prepare source address
	struct sockaddr_nl local = { 0 };
	local.nl_family = AF_NETLINK;
	local.nl_pid = 0; // Port ID, 0 = assigned automatically by bind()
	local.nl_groups = 0; // unicast

	// Prepare destination address
	struct sockaddr_nl kernel = { 0 };
	kernel.nl_family = AF_NETLINK;
	kernel.nl_pid = 0; // Kernel
	kernel.nl_groups = 0; // unicast

	// Bind the socket to the netlink address
	bind(fd, (struct sockaddr*)&local, sizeof(local));

	// Send the request
	const char *nltype = "<unknown>";
	switch(type)
	{
		case RTM_GETROUTE:
			nltype = "route";
			break;
		case RTM_GETADDR:
			nltype = "addr";
			break;
		case RTM_GETLINK:
			nltype = "link";
			break;
		case RTM_GETNEIGH:
			nltype = "neigh";
			break;
	}
	log_debug(DEBUG_NETLINK, "Calling nlrequest(type = %s, %d)", nltype, type);
	if(!nlrequest(fd, &kernel, type))
	{
		log_err("nlrequest error(type = %s, %d): %s", nltype, type, strerror(errno));
		close(fd);
		return false;
	}

	// Receive and parse the response, continue until we receive a
	// NLMSG_DONE which indicates the end of the message (we explicitly
	// request it via NLM_F_DUMP). We do NOT set NLM_F_ACK as we do not
	// want to receive an ERROR-typed ACK message here.
	while(true)
	{
		char buf[BUFLEN] = { 0 };
		log_debug(DEBUG_NETLINK, "Calling nlgetmsg(type = %d)", type);
		ssize_t len = nlgetmsg(fd, &kernel, buf, BUFLEN);
		if(len < 0)
		{
			log_err("nlgetmsg error: %s", strerror(errno));
			close(fd);
			return false;
		}

		// Parse the contained messages
		log_debug(DEBUG_NETLINK, "Calling parse_nl_msg (len = %zd)", len);
		const uint32_t nl_msg_type = parse_nl_msg(buf, len, json, detailed);

		// Break if nothing was received or the last received message
		// was either a NLMSG_DONE or NLMSG_ERROR message. The latter
		// indicates an error and the error code is contained in the
		// message. Also break if the message type is NLMSG_OVERRUN
		// which indicates that the socket buffer has overflown.
		if(len == 0 ||
		   nl_msg_type == NLMSG_DONE ||
		   nl_msg_type == NLMSG_ERROR ||
		   nl_msg_type == NLMSG_OVERRUN)
			break;
	}

	// Close the socket
	close(fd);
	return true;
}

/**
 * @brief Queries network route information and populates a cJSON object.
 * This function logs the invocation and calls nlquery() to retrieve network
 * route information using the RTM_GETROUTE netlink message. The results
 * are stored in the provided cJSON object.
 *
 * @param interfaces Pointer to a cJSON object where interface routing data will be stored.
 * @param detailed   Boolean flag indicating whether to retrieve detailed information.
 * @return true on success, false on failure.
 */
bool nlroutes(cJSON *routes, const bool detailed)
{
	log_debug(DEBUG_NETLINK, "Called nlroutes (detailed = %s)", detailed ? "true" : "false");
	return nlquery(RTM_GETROUTE, routes, detailed);
}

/**
 * @brief Queries network link address information and populates a cJSON object.
 *
 * This function logs the invocation and calls nlquery() to retrieve network
 * interface address information using the RTM_GETADDR netlink message. The results
 * are stored in the provided cJSON object.
 *
 * @param interfaces Pointer to a cJSON object where interface address data will be stored.
 * @param detailed   Boolean flag indicating whether to retrieve detailed information.
 * @return true on success, false on failure.
 */
bool nladdrs(cJSON *interfaces, const bool detailed)
{
	log_debug(DEBUG_NETLINK, "Called nladdrs (detailed = %s)", detailed ? "true" : "false");
	return nlquery(RTM_GETADDR, interfaces, detailed);
}

/**
 * @brief Queries network link information and populates a cJSON object.
 *
 * This function logs the invocation and calls nlquery() to retrieve network
 * interface information using the RTM_GETLINK netlink message. The results
 * are stored in the provided cJSON object.
 *
 * @param interfaces Pointer to a cJSON object where interface data will be stored.
 * @param detailed   Boolean flag indicating whether to retrieve detailed information.
 * @return true on success, false on failure.
 */
bool nllinks(cJSON *interfaces, const bool detailed)
{
	log_debug(DEBUG_NETLINK, "Called nllinks (detailed = %s)", detailed ? "true" : "false");
	return nlquery(RTM_GETLINK, interfaces, detailed);
}

/**
 * @brief Reads the ARP cache using netlink and fills a cJSON array with entries.
 *
 * Each entry contains IP address, MAC address, interface, and state.
 * @param arp_entries cJSON array to fill with ARP entries
 * @return true on success, false on failure
 */
bool nlneigh(cJSON *arp_entries)
{
	log_debug(DEBUG_NETLINK, "Called nlneigh");
	return nlquery(RTM_GETNEIGH, arp_entries, false);
}

/**
 * @brief Retrieves the name of the default gateway.
 *
 * This function queries the system's routing table to find the default
 * gateway and stores its name in the provided buffer.
 *
 * @return No return value, this function always succeeds
 *
 * @note The function uses JSON objects to parse and process routing
 *       information. Ensure that the required JSON handling utilities
 *       (e.g., cJSON) are available and properly linked.
 */
void get_gateway_name(char gateway[MAXIFACESTRLEN])
{
	cJSON *json = cJSON_CreateObject();
	cJSON *routes = cJSON_CreateArray();
	nlroutes(routes, false);
	cJSON_AddItemToObject(json, "routes", routes);

	// Loop through the routes and find the default gateway
	cJSON *route = NULL;
	cJSON_ArrayForEach(route, routes)
	{
		cJSON *dst = cJSON_GetObjectItem(route, "dst");
		if(dst != NULL &&
		   cJSON_IsString(dst) &&
		   strcmp(cJSON_GetStringValue(dst), "default") == 0)
		{
			strncpy(gateway, cJSON_GetStringValue(cJSON_GetObjectItem(route, "oif")), MAXIFACESTRLEN - 1);
			gateway[MAXIFACESTRLEN - 1] = '\0';
			break;
		}
	}

	// Fallback to "eth0" if no default gateway is found (unlikely to
	// happen)
	if(gateway[0] == '\0')
		strncpy(gateway, "eth0", MAXIFACESTRLEN - 1);

	cJSON_Delete(json);
}
