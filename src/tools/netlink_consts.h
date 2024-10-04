/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Netlink constants
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "netlink.h"

static struct flag_names iflatypes[] =
{
	{ ARPHRD_NETROM, "netrom" },
	{ ARPHRD_ETHER, "ether" },
	{ ARPHRD_EETHER, "eether" },
	{ ARPHRD_AX25, "ax25" },
	{ ARPHRD_PRONET, "pronet" },
	{ ARPHRD_CHAOS, "chaos" },
	{ ARPHRD_IEEE802, "ieee802" },
	{ ARPHRD_ARCNET, "arcnet" },
	{ ARPHRD_APPLETLK, "appletlk" },
	{ ARPHRD_DLCI, "dlci" },
	{ ARPHRD_ATM, "atm" },
	{ ARPHRD_METRICOM, "metricom" },
	{ ARPHRD_IEEE1394, "ieee1394" },
	{ ARPHRD_EUI64, "eui64" },
	{ ARPHRD_INFINIBAND, "infiniband" },
	{ ARPHRD_SLIP, "slip" },
	{ ARPHRD_CSLIP, "cslip" },
	{ ARPHRD_SLIP6, "slip6" },
	{ ARPHRD_CSLIP6, "cslip6" },
	{ ARPHRD_RSRVD, "rsrvd" },
	{ ARPHRD_ADAPT, "adapt" },
	{ ARPHRD_ROSE, "rose" },
	{ ARPHRD_X25, "x25" },
	{ ARPHRD_HWX25, "hwx25" },
	{ ARPHRD_CAN, "can" },
	{ ARPHRD_MCTP, "mctp" },
	{ ARPHRD_PPP, "ppp" },
	{ ARPHRD_CISCO, "cisco" },
	{ ARPHRD_HDLC, "hdlc" },
	{ ARPHRD_CISCO, "cisco" },
	{ ARPHRD_LAPB, "lapb" },
	{ ARPHRD_DDCMP, "ddcmp" },
	{ ARPHRD_RAWHDLC, "rawhdlc" },
	{ ARPHRD_RAWIP, "rawip" },
	{ ARPHRD_TUNNEL, "tunnel" },
	{ ARPHRD_TUNNEL6, "tunnel6" },
	{ ARPHRD_FRAD, "frad" },
	{ ARPHRD_SKIP, "skip" },
	{ ARPHRD_LOOPBACK, "loopback" },
	{ ARPHRD_LOCALTLK, "localtlk" },
	{ ARPHRD_FDDI, "fddi" },
	{ ARPHRD_BIF, "bif" },
	{ ARPHRD_SIT, "sit" },
	{ ARPHRD_IPDDP, "ipddp" },
	{ ARPHRD_IPGRE, "ipgre" },
	{ ARPHRD_PIMREG, "pimreg" },
	{ ARPHRD_HIPPI, "hippi" },
	{ ARPHRD_ASH, "ash" },
	{ ARPHRD_ECONET, "econet" },
	{ ARPHRD_IRDA, "irda" },
	{ ARPHRD_FCPP, "fcpp" },
	{ ARPHRD_FCAL, "fcal" },
	{ ARPHRD_FCPL, "fcpl" },
	{ ARPHRD_FCFABRIC, "fcfabric" },
	{ ARPHRD_IEEE802_TR, "ieee802_tr" },
	{ ARPHRD_IEEE80211, "ieee80211" },
	{ ARPHRD_IEEE80211_PRISM, "ieee80211_prism" },
	{ ARPHRD_IEEE80211_RADIOTAP, "ieee80211_radiotap" },
	{ ARPHRD_IEEE802154, "ieee802154" },
	{ ARPHRD_IEEE802154_MONITOR, "ieee802154_monitor" },
	{ ARPHRD_PHONET, "phonet" },
	{ ARPHRD_PHONET_PIPE, "phonet_pipe" },
	{ ARPHRD_CAIF, "caif" },
	{ ARPHRD_IP6GRE, "ip6gre" },
	{ ARPHRD_NETLINK, "netlink" },
	{ ARPHRD_6LOWPAN, "6lowpan" },
	{ ARPHRD_VSOCKMON, "vsockmon" },
	{ ARPHRD_VOID, "void" },
	{ ARPHRD_NONE, "none" },
};

static struct flag_names ifaf_flags[] = {
	{ IFA_F_SECONDARY, "secondary" },
	{ IFA_F_TEMPORARY, "temporary" },
	{ IFA_F_NODAD, "nodad" },
	{ IFA_F_OPTIMISTIC, "optimistic" },
	{ IFA_F_DADFAILED, "dadfailed" },
	{ IFA_F_HOMEADDRESS, "homeaddress" },
	{ IFA_F_DEPRECATED, "deprecated" },
	{ IFA_F_TENTATIVE, "tentative" },
	{ IFA_F_PERMANENT, "permanent" },
	{ IFA_F_MANAGETEMPADDR, "managetempaddr" },
	{ IFA_F_NOPREFIXROUTE, "noprefixroute" },
	{ IFA_F_MCAUTOJOIN, "mcautojoin" },
	{ IFA_F_STABLE_PRIVACY, "stable_privacy" },
};

static struct flag_names iff_flags[] = {
	{ IFF_UP, "up" },
	{ IFF_BROADCAST, "broadcast" },
	{ IFF_DEBUG, "debug" },
	{ IFF_LOOPBACK, "loopback" },
	{ IFF_POINTOPOINT, "pointopoint" },
	{ IFF_NOTRAILERS, "notrailers" },
	{ IFF_RUNNING, "running" },
	{ IFF_NOARP, "noarp" },
	{ IFF_PROMISC, "promisc" },
	{ IFF_ALLMULTI, "allmulti" },
	{ IFF_MASTER, "master" },
	{ IFF_SLAVE, "slave" },
	{ IFF_MULTICAST, "multicast" },
	{ IFF_PORTSEL, "portsel" },
	{ IFF_AUTOMEDIA, "automedia" },
	{ IFF_DYNAMIC, "dynamic" },
#ifdef IFF_LOWER_UP
	{ IFF_LOWER_UP, "lower_up" },
#endif
#ifdef IFF_DORMANT
	{ IFF_DORMANT, "dormant" },
#endif
#ifdef IFF_ECHO
	{ IFF_ECHO, "echo" },
#endif
};

static struct flag_names rtprots[] = {
	{ RTPROT_UNSPEC, "unspec" },
	{ RTPROT_REDIRECT, "redirect" },
	{ RTPROT_KERNEL, "kernel" },
	{ RTPROT_BOOT, "boot" },
	{ RTPROT_STATIC, "static" },
	{ RTPROT_GATED, "gated" },
	{ RTPROT_RA, "ra" },
	{ RTPROT_MRT, "mrt" },
	{ RTPROT_ZEBRA, "zebra" },
	{ RTPROT_BIRD, "bird" },
	{ RTPROT_DNROUTED, "dnrouted" },
	{ RTPROT_XORP, "xorp" },
	{ RTPROT_NTK, "ntk" },
	{ RTPROT_DHCP, "dhcp" },
	{ RTPROT_MROUTED, "mrouted" },
	{ RTPROT_KEEPALIVED, "keepalived" },
	{ RTPROT_BABEL, "babel" },
	{ RTPROT_OPENR, "openr" },
	{ RTPROT_BGP, "bgp" },
	{ RTPROT_ISIS, "isis" },
	{ RTPROT_OSPF, "ospf" },
	{ RTPROT_RIP, "rip" },
	{ RTPROT_EIGRP, "eigrp" },
};

static struct flag_names rtscopes[] = {
	{ RT_SCOPE_UNIVERSE, "universe" },
	{ RT_SCOPE_SITE, "site" },
	{ RT_SCOPE_LINK, "link" },
	{ RT_SCOPE_HOST, "host" },
	{ RT_SCOPE_NOWHERE, "nowhere" },
};

static struct flag_names rttypes[] = {
	{ RTN_UNSPEC, "unspec" },
	{ RTN_UNICAST, "unicast" },
	{ RTN_LOCAL, "local" },
	{ RTN_BROADCAST, "broadcast" },
	{ RTN_ANYCAST, "anycast" },
	{ RTN_MULTICAST, "multicast" },
	{ RTN_BLACKHOLE, "blackhole" },
	{ RTN_UNREACHABLE, "unreachable" },
	{ RTN_PROHIBIT, "prohibit" },
	{ RTN_THROW, "throw" },
	{ RTN_NAT, "nat" },
	{ RTN_XRESOLVE, "xresolve" },
};

static struct flag_names rtmflags[] = {
	{ RTM_F_NOTIFY, "notify" },
	{ RTM_F_CLONED, "cloned" },
	{ RTM_F_EQUALIZE, "equalize" },
	{ RTM_F_PREFIX, "prefix" },
	{ RTM_F_LOOKUP_TABLE, "lookup_table" },
	{ RTM_F_FIB_MATCH, "fib_match" },
	{ RTM_F_OFFLOAD, "offload" },
	{ RTM_F_TRAP, "trap" },
	{ RTM_F_OFFLOAD_FAILED, "offload_failed" },
};

static struct flag_names rtnhflags[] = {
	{ RTNH_F_DEAD, "dead" },
	{ RTNH_F_PERVASIVE, "pervasive" },
	{ RTNH_F_ONLINK, "onlink" },
	{ RTNH_F_OFFLOAD, "offload" },
	{ RTNH_F_LINKDOWN, "linkdown" },
	{ RTNH_F_UNRESOLVED, "unresolved" },
	{ RTNH_F_TRAP, "trap" },
};

static struct flag_names ifstates[] = {
	{ IF_OPER_UNKNOWN, "unknown" },
	{ IF_OPER_NOTPRESENT, "notpresent" },
	{ IF_OPER_DOWN, "down" },
	{ IF_OPER_LOWERLAYERDOWN, "lower_layer_down" },
	{ IF_OPER_TESTING, "testing" },
	{ IF_OPER_DORMANT, "dormant" },
	{ IF_OPER_UP, "up" },
};

static struct flag_names link_events[] = {
	{ IFLA_EVENT_NONE, "none" },
	{ IFLA_EVENT_REBOOT, "reboot" },
	{ IFLA_EVENT_FEATURES, "feature change" },
	{ IFLA_EVENT_BONDING_FAILOVER, "bonding failover" },
	{ IFLA_EVENT_NOTIFY_PEERS, "notify peers" },
	{ IFLA_EVENT_IGMP_RESEND, "resend igmp" },
	{ IFLA_EVENT_BONDING_OPTIONS, "bonding option" },
};

static struct flag_names addr_gen_modes[] = {
	{ IN6_ADDR_GEN_MODE_EUI64, "eui64" },
	{ IN6_ADDR_GEN_MODE_NONE, "none" },
	{ IN6_ADDR_GEN_MODE_STABLE_PRIVACY, "stable_secret" },
	{ IN6_ADDR_GEN_MODE_RANDOM, "random" },
};

static const char *__attribute__ ((const)) rtaTypeToString(const int rta_type)
{
	switch (rta_type) {
		case RTA_UNSPEC:
			return "unspec";
		case RTA_DST:
			return "dst";
		case RTA_SRC:
			return "src";
		case RTA_IIF:
			return "iif";
		case RTA_OIF:
			return "oif";
		case RTA_GATEWAY:
			return "gateway";
		case RTA_PRIORITY:
			return "priority";
		case RTA_PREFSRC:
			return "prefsrc";
		case RTA_METRICS:
			return "metrics";
		case RTA_MULTIPATH:
			return "multipath";
		case RTA_PROTOINFO:
			return "protoinfo";
		case RTA_FLOW:
			return "flow";
		case RTA_CACHEINFO:
			return "cacheinfo";
		case RTA_SESSION:
			return "session";
		case RTA_MP_ALGO:
			return "mp_algo";
		case RTA_TABLE:
			return "table";
		case RTA_MARK:
			return "mark";
		case RTA_MFC_STATS:
			return "mfc_stats";
		case RTA_VIA:
			return "via";
		case RTA_NEWDST:
			return "newdst";
		case RTA_PREF:
			return "pref";
		case RTA_ENCAP_TYPE:
			return "encap_type";
		case RTA_ENCAP:
			return "encap";
		case RTA_EXPIRES:
			return "expires";
		case RTA_PAD:
			return "pad";
		case RTA_UID:
			return "uid";
		case RTA_TTL_PROPAGATE:
			return "ttl_propagate";
		case RTA_IP_PROTO:
			return "ip_proto";
		case RTA_SPORT:
			return "sport";
		case RTA_DPORT:
			return "dport";
		case RTA_NH_ID:
			return "nh_id";
		default:
			return "unknown";
	}
}

static const char *__attribute__ ((const)) ifaTypeToString(const int ifa_type)
{
	switch (ifa_type) {
		case IFA_ADDRESS:
			return "address";
		case IFA_LOCAL:
			return "local";
		case IFA_LABEL:
			return "label";
		case IFA_BROADCAST:
			return "broadcast";
		case IFA_ANYCAST:
			return "anycast";
		case IFA_CACHEINFO:
			return "cacheinfo";
		case IFA_MULTICAST:
			return "multicast";
		case IFA_FLAGS:
			return "flags";
		case IFA_RT_PRIORITY:
			return "rt_priority";
		case IFA_TARGET_NETNSID:
			return "target_netnsid";
		default:
			return "unknown";
	}
}

static const char *__attribute__ ((const)) iflaTypeToString(const int ifla_type)
{
	switch (ifla_type)
	{
		case IFLA_UNSPEC:
			return "unspec";
		case IFLA_ADDRESS:
			return "address";
		case IFLA_BROADCAST:
			return "broadcast";
		case IFLA_IFNAME:
			return "ifname";
		case IFLA_MTU:
			return "mtu";
		case IFLA_LINK:
			return "link";
		case IFLA_QDISC:
			return "qdisc";
		case IFLA_STATS:
			return "stats";
		case IFLA_COST:
			return "cost";
		case IFLA_PRIORITY:
			return "priority";
		case IFLA_MASTER:
			return "master";
		case IFLA_WIRELESS:
			return "wireless";
		case IFLA_PROTINFO:
			return "protinfo";
		case IFLA_TXQLEN:
			return "txqlen";
		case IFLA_MAP:
			return "map";
		case IFLA_WEIGHT:
			return "weight";
		case IFLA_OPERSTATE:
			return "operstate";
		case IFLA_LINKMODE:
			return "linkmode";
		case IFLA_LINKINFO:
			return "linkinfo";
		case IFLA_NET_NS_FD:
			return "net_ns_fd";
		case IFLA_IFALIAS:
			return "ifalias";
		case IFLA_NUM_VF:
			return "num_vf";
		case IFLA_VFINFO_LIST:
			return "vfinfo_list";
		case IFLA_STATS64:
			return "stats64";
		case IFLA_VF_PORTS:
			return "vf_ports";
		case IFLA_PORT_SELF:
			return "port_self";
		case IFLA_AF_SPEC:
			return "af_spec";
		case IFLA_GROUP:
			return "group";
		case IFLA_NET_NS_PID:
			return "net_ns_pid";
		case IFLA_EXT_MASK:
			return "ext_mask";
		case IFLA_PROMISCUITY:
			return "promiscuity";
		case IFLA_NUM_TX_QUEUES:
			return "num_tx_queues";
		case IFLA_NUM_RX_QUEUES:
			return "num_rx_queues";
		case IFLA_CARRIER:
			return "carrier";
		case IFLA_PHYS_PORT_ID:
			return "phys_port_id";
		case IFLA_CARRIER_CHANGES:
			return "carrier_changes";
		case IFLA_PHYS_SWITCH_ID:
			return "phys_switch_id";
		case IFLA_LINK_NETNSID:
			return "link_netnsid";
		case IFLA_PHYS_PORT_NAME:
			return "phys_port_name";
		case IFLA_PROTO_DOWN:
			return "proto_down";
		case IFLA_GSO_MAX_SEGS:
			return "gso_max_segs";
		case IFLA_GSO_MAX_SIZE:
			return "gso_max_size";
		case IFLA_PAD:
			return "pad";
		case IFLA_XDP:
			return "xdp";
		case IFLA_EVENT:
			return "event";
		case IFLA_NEW_NETNSID:
			return "new_netnsid";
		case IFLA_IF_NETNSID:
			return "if_netnsid";
		case IFLA_CARRIER_UP_COUNT:
			return "carrier_up_count";
		case IFLA_CARRIER_DOWN_COUNT:
			return "carrier_down_count";
		case IFLA_NEW_IFINDEX:
			return "new_ifindex";
		case IFLA_MIN_MTU:
			return "min_mtu";
		case IFLA_MAX_MTU:
			return "max_mtu";
		case IFLA_PROP_LIST:
			return "prop_list";
		case IFLA_ALT_IFNAME:
			return "alt_ifname";
		case IFLA_PERM_ADDRESS:
			return "perm_address";
		case IFLA_PROTO_DOWN_REASON:
			return "proto_down_reason";
		case IFLA_PARENT_DEV_NAME:
			return "parent_dev_name";
		case IFLA_PARENT_DEV_BUS_NAME:
			return "parent_dev_bus_name";
		default:
			return "unknown";
	}
}

static const char *__attribute__ ((const)) rt_priority(const uint32_t pref)
{
	switch (pref) {
		case ICMPV6_ROUTER_PREF_HIGH:
			return "high";
		case ICMPV6_ROUTER_PREF_MEDIUM:
			return "medium";
		case ICMPV6_ROUTER_PREF_LOW:
			return "low";
		case ICMPV6_ROUTER_PREF_INVALID:
			return "invalid";
		default:
			return "unknown";
	}
}

static const char *__attribute__ ((const)) family_name(int family)
{
	switch(family)
	{
		case PF_UNSPEC:
			return "unspec";
		case PF_LOCAL:
			return "local";
		case PF_INET:
			return "inet";
		case PF_AX25:
			return "ax25";
		case PF_IPX:
			return "ipx";
		case PF_APPLETALK:
			return "appletalk";
		case PF_NETROM:
			return "netrom";
		case PF_BRIDGE:
			return "bridge";
		case PF_ATMPVC:
			return "atmpvc";
		case PF_X25:
			return "x25";
		case PF_INET6:
			return "inet6";
		case PF_ROSE:
			return "rose";
		case PF_DECnet:
			return "decnet";
		case PF_NETBEUI:
			return "netbeui";
		case PF_SECURITY:
			return "security";
		case PF_KEY:
			return "key";
		case PF_NETLINK:
			return "netlink";
		case PF_PACKET:
			return "packet";
		case PF_ASH:
			return "ash";
		case PF_ECONET:
			return "econet";
		case PF_ATMSVC:
			return "atmsvc";
		case PF_RDS:
			return "rds";
		case PF_SNA:
			return "sna";
		case PF_IRDA:
			return "irda";
		case PF_PPPOX:
			return "pppox";
		case PF_WANPIPE:
			return "wanpipe";
		case PF_LLC:
			return "llc";
		case PF_IB:
			return "ib";
		case PF_MPLS:
			return "mpls";
		case PF_CAN:
			return "can";
		case PF_TIPC:
			return "tipc";
		case PF_BLUETOOTH:
			return "bluetooth";
		case PF_IUCV:
			return "iucv";
		case PF_RXRPC:
			return "rxrpc";
		case PF_ISDN:
			return "isdn";
		case PF_PHONET:
			return "phonet";
		case PF_IEEE802154:
			return "ieee802154";
		case PF_CAIF:
			return "caif";
		case PF_ALG:
			return "alg";
		case PF_NFC:
			return "nfc";
		case PF_VSOCK:
			return "vsock";
		case PF_KCM:
			return "kcm";
		case PF_QIPCRTR:
			return "qipcrtr";
		case PF_SMC:
			return "smc";
		case PF_XDP:
			return "xdp";
#ifdef PF_MCTP
		// 2024-July: defined by glibc but not musl
		case PF_MCTP:
			return "mctp";
#endif
		default:
			return "unknown";
	}
}

// Taken from https://github.com/Gandi/packet-journey/blob/master/lib/libnetlink/netlink.c
#define parse_rtattr_nested(tb, max, rta) \
        (parse_rtattr_flags((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta), 0))
#define parse_rtattr_one_nested(type, rta) \
	(parse_rtattr_one(type, RTA_DATA(rta), RTA_PAYLOAD(rta)))

static int parse_rtattr_flags(struct rtattr *tb[], int max,
                              struct rtattr *rta, int len,
                              unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	return 0;
}

static struct rtattr * __attribute__((pure)) parse_rtattr_one(int type, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type == type)
			return rta;
		rta = RTA_NEXT(rta, len);
	}
	return NULL;
}
