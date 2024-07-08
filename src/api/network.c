/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/network
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// Routing information and flags
#include <net/route.h>
// Iterate through directories
#include <dirent.h>
// networkrecord
#include "database/network-table.h"
// dbopen(false, )
#include "database/common.h"
// attach_database()
#include "database/query-table.h"
// config struct
#include "config/config.h"
// PRIx64
#include <inttypes.h>
#include <linux/rtnetlink.h>
// IFA_LINK and friends
#include <linux/if_addr.h>


struct flag_names {
	uint32_t flag;
	const char *name;
};

static struct flag_names iff_flags[] = {
	{ IFF_UP, "UP" },
	{ IFF_BROADCAST, "BROADCAST" },
	{ IFF_DEBUG, "DEBUG" },
	{ IFF_LOOPBACK, "LOOPBACK" },
	{ IFF_POINTOPOINT, "POINTOPOINT" },
	{ IFF_NOTRAILERS, "NOTRAILERS" },
	{ IFF_RUNNING, "RUNNING" },
	{ IFF_NOARP, "NOARP" },
	{ IFF_PROMISC, "PROMISC" },
	{ IFF_ALLMULTI, "ALLMULTI" },
	{ IFF_MASTER, "MASTER" },
	{ IFF_SLAVE, "SLAVE" },
	{ IFF_MULTICAST, "MULTICAST" },
	{ IFF_PORTSEL, "PORTSEL" },
	{ IFF_AUTOMEDIA, "AUTOMEDIA" },
	{ IFF_DYNAMIC, "DYNAMIC" },
#ifdef IFF_LOWER_UP
	{ IFF_LOWER_UP, "LOWER_UP" },
#endif
#ifdef IFF_DORMANT
	{ IFF_DORMANT, "DORMANT" },
#endif
#ifdef IFF_ECHO
	{ IFF_ECHO, "ECHO" },
#endif
};

static struct flag_names ifaf_flags[] = {
	{ IFA_F_TEMPORARY, "TEMPORARY" },
	{ IFA_F_NODAD, "NODAD" },
	{ IFA_F_OPTIMISTIC, "OPTIMISTIC" },
	{ IFA_F_DADFAILED, "DADFAILED" },
	{ IFA_F_HOMEADDRESS, "HOMEADDRESS" },
	{ IFA_F_DEPRECATED, "DEPRECATED" },
	{ IFA_F_TENTATIVE, "TENTATIVE" },
	{ IFA_F_PERMANENT, "PERMANENT" },
	{ IFA_F_MANAGETEMPADDR, "MANAGETEMPADDR" },
	{ IFA_F_NOPREFIXROUTE, "NOPREFIXROUTE" },
	{ IFA_F_MCAUTOJOIN, "MCAUTOJOIN" },
	{ IFA_F_STABLE_PRIVACY, "STABLE_PRIVACY" },
};

static struct flag_names ripv4[] = {
	{ RTF_UP, "UP" },
	{ RTF_GATEWAY, "GATEWAY" },
	{ RTF_HOST, "HOST" },
	{ RTF_REINSTATE, "REINSTATE" },
	{ RTF_DYNAMIC, "DYNAMIC" },
	{ RTF_MODIFIED, "MODIFIED" },
	{ RTF_MTU, "MTU" },
	{ RTF_MSS, "MSS" },
	{ RTF_WINDOW, "WINDOW" },
	{ RTF_IRTT, "IRTT" },
	{ RTF_REJECT, "REJECT" },
	{ RTF_STATIC, "STATIC" },
	{ RTF_XRESOLVE, "XRESOLVE" },
	{ RTF_NOFORWARD, "NOFORWARD" },
	{ RTF_THROW, "THROW" },
	{ RTF_NOPMTUDISC, "NOPMTUDISC" },
};

static struct flag_names ripv6[] = {
	{ RTF_DEFAULT, "DEFAULT" },
	{ RTF_ALLONLINK, "ALLONLINK" },
	{ RTF_ADDRCONF, "ADDRCONF" },
	{ RTF_LINKRT, "LINKRT" },
	{ RTF_NONEXTHOP, "NONEXTHOP" },
	{ RTF_CACHE, "CACHE" },
	{ RTF_FLOW, "FLOW" },
	{ RTF_POLICY, "POLICY" },
	{ RTF_LOCAL, "LOCAL" },
	{ RTF_INTERFACE, "INTERFACE" },
	{ RTF_MULTICAST, "MULTICAST" },
	{ RTF_BROADCAST, "BROADCAST" },
	{ RTF_NAT, "NAT" },
	{ RTF_ADDRCLASSMASK, "ADDRCLASSMASK" },
};

// Manually taken from kernel source code in include/net/ipv6.h
#define	IFA_GLOBAL	0x0000U
#define	IFA_HOST	0x0010U
#define	IFA_LINK	0x0020U
#define	IFA_SITE	0x0040U
#define IFA_COMPATv4	0x0080U


static struct flag_names scopes[] = {
	{ IFA_GLOBAL, "GLOBAL" },
	{ IFA_HOST, "HOST" },
	{ IFA_LINK, "LINK" },
	{ IFA_SITE, "SITE" },
	{ IFA_COMPATv4, "COMPATv4" },
};

static bool ipv6_hex_to_human(const char oct[33], char human[INET6_ADDRSTRLEN], const char **addr_type)
{
	strncpy(human, oct, 32);
	// Insert ":" into address string
	for(size_t i = 1; i < 8; i++)
	{
		const size_t m = 4*i + i - 1;
		memmove(&human[m + 1], &human[m], INET6_ADDRSTRLEN - m);
		human[m] = ':';
	}
	// Add trailing null byte
	human[INET6_ADDRSTRLEN - 1] = '\0';

	// Format address into most-compact form, e.g.
	// "fe80:0000:0000:0000:0042:3dff:feb1:d93d" -> "fe80::42:3dff:feb1:d93d"
	// If conversion fails, return false and keep the non-compact form
	struct in6_addr addr6 = { 0 };
	if(inet_pton(AF_INET6, human, &addr6))
	{
		if(addr_type != NULL)
		{
			// Extract first byte
			// We do not directly access the underlying union as
			// MUSL defines it differently than GNU C
			uint8_t bytes[2];
			memcpy(&bytes, &addr6, 2);
			// Global Unicast Address (2000::/3, RFC 4291)
			if((bytes[0] & 0x70) == 0x20)
				*addr_type = "GUA";
			// Unique Local Address   (fc00::/7, RFC 4193)
			if((bytes[0] & 0xfe) == 0xfc)
				*addr_type = "ULA";
			// Link Local Address   (fe80::/10, RFC 4291)
			if((bytes[0] & 0xff) == 0xfe && (bytes[1] & 0x30) == 0)
				*addr_type = "LL";
		}

		return inet_ntop(AF_INET6, &addr6, human, INET6_ADDRSTRLEN);
	}

	return false;
}

static bool read_proc_net_if_inet6(cJSON *addresses)
{
	// 4.1. if_inet6
	//
	// Type: One line per address containing multiple values
	//
	// Here all configured IPv6 addresses are shown in a special format. The
	// example displays for loopback interface only. The meaning is shown
	// below (see "net/ipv6/addrconf.c" for more).
	//
	// # cat /proc/net/if_inet6
	// 00000000000000000000000000000001 01 80 10 80 lo
	// +------------------------------+ ++ ++ ++ ++ ++
	// |                                |  |  |  |  |
	// 1                                2  3  4  5  6
	//
	// 1. IPv6 address displayed in 32 hexadecimal chars without colons as separator
	// 2. Netlink device number (interface index) in hexadecimal (see "ip addr" , too)
	// 3. Prefix length in hexadecimal
	// 4. Scope value (see kernel source " include/net/ipv6.h" and "net/ipv6/addrconf.c" for more)
	// 5. Interface flags (see "include/linux/rtnetlink.h" and "net/ipv6/addrconf.c" for more)
	// 6. Device name

	// Open /proc/net/if_inet6
	FILE *file;
	if((file = fopen("/proc/net/if_inet6", "r")))
	{
		// Parse /proc/net/if_inet6 - the kernel's IPv6 address table
		char buf[1024] = { 0 };
		while(fgets(buf, sizeof(buf), file))
		{
			char oct[33] = { 0 };
			unsigned int ifaceid = 0;
			char iface[IF_NAMESIZE] = { 0 };
			unsigned int prefix = 0;
			unsigned int scope = 0;
			unsigned int flags = 0;

			// Parse address information
			if(sscanf(buf, "%32s %x %x %x %x %15s", oct, &ifaceid, &prefix, &scope, &flags, iface) != 6)
				continue;

			char addr_str[INET6_ADDRSTRLEN] = { 0 };
			const char *addr_type = "UNKNOWN";
			ipv6_hex_to_human(oct, addr_str, &addr_type);

			// Format flags into human-readable array of strings
			cJSON *flag_array = cJSON_CreateArray();
			for(size_t i = 0; i < sizeof(ifaf_flags) / sizeof(ifaf_flags[0]); i++)
				if(flags & ifaf_flags[i].flag)
					cJSON_AddItemToArray(flag_array, cJSON_CreateStringReference(ifaf_flags[i].name));

			// Create new address record
			cJSON *address = cJSON_CreateObject();
			cJSON_AddStringToObject(address, "address", addr_str);
			cJSON_AddItemReferenceToObject(address, "type", cJSON_CreateStringReference(addr_type));
			cJSON_AddStringToObject(address, "interface", iface);
			cJSON_AddNumberToObject(address, "prefix", prefix);
			const char *scope_str = "UNSPEC";
			for(size_t i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++)
				if(scope == scopes[i].flag)
					scope_str = scopes[i].name;
			cJSON_AddItemToObject(address, "scope", cJSON_CreateStringReference(scope_str));
			cJSON_AddItemToObject(address, "flags", flag_array);

			// Add address to JSON array
			cJSON_AddItemToArray(addresses, address);
		}

		fclose(file);
	}
	else
	{
		log_err("Cannot read /proc/net/if_inet6: %s", strerror(errno));
		return false;
	}

	return true;
}

static bool read_proc_net_route(cJSON *routes)
{
	// Open /proc/net/route
	FILE *file;
	if((file = fopen("/proc/net/route", "r")))
	{
		// Parse /proc/net/route - the kernel's IPv4 routing table
		cJSON *ipv4 = cJSON_CreateArray();
		char buf[1024] = { 0 };
		while(fgets(buf, sizeof(buf), file))
		{
			char iface[IF_NAMESIZE] = { 0 };
			unsigned long dest = 0, gw = 0;
			unsigned int flags = 0;
			int metric = 0;

			// Parse route information
			if(sscanf(buf, "%15s %lx %lx %x %*i %*i %i", iface, &dest, &gw, &flags, &metric) != 5)
				continue;

			cJSON *entry = cJSON_CreateObject();

			// Format destination and gateway addresses
			char dest_addr[INET_ADDRSTRLEN] = { 0 };
			char gw_addr[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &dest, dest_addr, sizeof(dest_addr));
			inet_ntop(AF_INET, &gw, gw_addr, sizeof(gw_addr));

			// Format flags into human-readable array of strings
			cJSON *flag_array = cJSON_CreateArray();
			for(size_t i = 0; i < sizeof(ripv4) / sizeof(ripv4[0]); i++)
				if(flags & ripv4[i].flag)
					cJSON_AddItemToArray(flag_array, cJSON_CreateStringReference(ripv4[i].name));

			// Add route information to JSON object
			cJSON_AddStringToObject(entry, "destination", dest_addr);
			cJSON_AddStringToObject(entry, "gateway", gw_addr);
			cJSON_AddNumberToObject(entry, "metric", metric);
			cJSON_AddItemToObject(entry, "flags", flag_array);
			cJSON_AddStringToObject(entry, "interface", iface);

			// Add route information to JSON array
			cJSON_AddItemToArray(ipv4, entry);
		}

		fclose(file);

		// Add IPv4 routes to JSON object
		cJSON_AddItemToObject(routes, "ipv4", ipv4);
	}
	return true;
}

static bool read_proc_net_ipv6_route(cJSON *routes)
{
	// Open /proc/net/route
	FILE *file;

	// Open /proc/net/ipv6_route
	if((file = fopen("/proc/net/ipv6_route", "r")))
	{
		// Parse /proc/net/ipv6_route - the kernel's IPv6 routing table
		// 4.2. ipv6_route
		//
		// Type: One line per route containing multiple values
		//
		// Here all configured IPv6 routes are shown in a special
		// format. The example displays for loopback interface only. The
		// meaning is shown below (see ”net/ipv6/route.c” for more).
		//
		// # cat /proc/net/ipv6_route
		// 00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000001 00200200 lo
		// +------------------------------+ ++ +------------------------------+ ++ +------------------------------+ +------+ +------+ +------+ +------+ ++
		// |                                |  |                                |  |                                |        |        |        |        |
		// 1                                2  3                                4  5                                6        7        8        9        10
		//
		// 1.  IPv6 destination network displayed in 32 hexadecimal chars without colons as separator
		// 2.  IPv6 destination prefix length in hexadecimal
		// 3.  IPv6 source network displayed in 32 hexadecimal chars without colons as separator
		// 4.  IPv6 source prefix length in hexadecimal
		// 5.  IPv6 next hop displayed in 32 hexadecimal chars without colons as separator
		// 6.  Metric in hexadecimal
		// 7.  Reference counter
		// 8.  Use counter
		// 9.  Flags
		// 10. Device name

		cJSON *ipv6 = cJSON_CreateArray();

		char buf[1024] = { 0 };
		while(fgets(buf, sizeof(buf), file))
		{
			char iface[IF_NAMESIZE] = { 0 };
			char dest[33] = { 0 };
			char src[33] = { 0 };
			char gw[33] = { 0 };
			unsigned int prefix_dest = 0;
			unsigned int prefix_src = 0;
			unsigned int metric = 0;
			unsigned int ref = 0;
			unsigned int use = 0;
			unsigned int flags = 0;

			// Parse route information
			if(sscanf(buf, "%32s %x %32s %x %32s %x %x %x %x %15s",
			           dest, &prefix_dest, src, &prefix_src, gw, &metric, &ref, &use, &flags, iface) != 10)
				continue;

			// Format flags into human-readable array of strings
			cJSON *flag_array = cJSON_CreateArray();
			for(size_t i = 0; i < sizeof(ripv4) / sizeof(ripv4[0]); i++)
				if(flags & ripv4[i].flag)
					cJSON_AddItemToArray(flag_array, cJSON_CreateStringReference(ripv4[i].name));
			for(size_t i = 0; i < sizeof(ripv6) / sizeof(ripv6[0]); i++)
				if(flags & ripv6[i].flag)
					cJSON_AddItemToArray(flag_array, cJSON_CreateStringReference(ripv6[i].name));

			// Format destination, source, and gateway addresses
			char dest_addr[INET6_ADDRSTRLEN] = { 0 };
			const char *dest_addr_type = "UNSPEC";
			char src_addr[INET6_ADDRSTRLEN] = { 0 };
			const char *src_addr_type = "UNSPEC";
			char gw_addr[INET6_ADDRSTRLEN] = { 0 };
			const char *gw_addr_type = "UNSPEC";
			ipv6_hex_to_human(dest, dest_addr, &dest_addr_type);
			ipv6_hex_to_human(src, src_addr, &src_addr_type);
			ipv6_hex_to_human(gw, gw_addr, &gw_addr_type);

			// Create new route record
			cJSON *entry = cJSON_CreateObject();

			cJSON *destination = cJSON_CreateObject();
			cJSON_AddStringToObject(destination, "address", dest_addr);
			cJSON_AddNumberToObject(destination, "prefix", prefix_dest);
			cJSON_AddItemToObject(destination, "type", cJSON_CreateStringReference(dest_addr_type));
			cJSON_AddItemToObject(entry, "destination", destination);

			cJSON *source = cJSON_CreateObject();
			cJSON_AddStringToObject(source, "address", src_addr);
			cJSON_AddNumberToObject(source, "prefix", prefix_src);
			cJSON_AddItemToObject(source, "type", cJSON_CreateStringReference(src_addr_type));
			cJSON_AddItemToObject(entry, "source", source);

			cJSON *gateway = cJSON_CreateObject();
			cJSON_AddStringToObject(gateway, "address", gw_addr);
			cJSON_AddItemToObject(gateway, "type", cJSON_CreateStringReference(gw_addr_type));
			cJSON_AddItemToObject(entry, "gateway", gateway);

			cJSON_AddNumberToObject(entry, "metric", metric);
			cJSON_AddNumberToObject(entry, "ref", ref);
			cJSON_AddNumberToObject(entry, "use", use);
			cJSON_AddItemToObject(entry, "flags", flag_array);
			cJSON_AddStringToObject(entry, "interface", iface);

			// Add route information to JSON array
			cJSON_AddItemToArray(ipv6, entry);
		}

		// Add IPv6 routes to JSON object
		cJSON_AddItemToObject(routes, "ipv6", ipv6);

		fclose(file);
	}

	return true;
}

int api_network_gateway(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();

	// Get JSON routes
	cJSON *routes = cJSON_CreateObject();
	read_proc_net_route(routes);
	read_proc_net_ipv6_route(routes);

	// Search for route with GATEWAY flag set
	cJSON *ipv4 = cJSON_GetObjectItem(routes, "ipv4");
	cJSON *r_ipv4 = cJSON_CreateObject();
	cJSON *route = NULL;
	cJSON_ArrayForEach(route, ipv4)
	{
		cJSON *flags = cJSON_GetObjectItem(route, "flags");
		if(cJSON_IsArray(flags))
		{
			cJSON *flag = NULL;
			cJSON_ArrayForEach(flag, flags)
			{
				if(strcmp(cJSON_GetStringValue(flag), "GATEWAY") == 0)
				{
					// Extract interface name
					const char *iface_name = cJSON_GetStringValue(cJSON_GetObjectItem(route, "interface"));
					JSON_COPY_STR_TO_OBJECT(r_ipv4, "interface", iface_name);

					// Extract gateway address
					const char *gw_addr = cJSON_GetStringValue(cJSON_GetObjectItem(route, "gateway"));
					JSON_COPY_STR_TO_OBJECT(r_ipv4, "address", gw_addr);

					break;
				}
			}
		}
	}

	// else: Search ipv6 routes
	cJSON *ipv6 = cJSON_GetObjectItem(routes, "ipv6");
	cJSON *r_ipv6 = cJSON_CreateObject();
	cJSON_ArrayForEach(route, ipv6)
	{
		cJSON *flags = cJSON_GetObjectItem(route, "flags");
		if(cJSON_IsArray(flags))
		{
			cJSON *flag = NULL;
			cJSON_ArrayForEach(flag, flags)
			{
				if(strcmp(cJSON_GetStringValue(flag), "GATEWAY") == 0)
				{
					// Extract interface name
					const char *iface_name = cJSON_GetStringValue(cJSON_GetObjectItem(route, "interface"));
					JSON_COPY_STR_TO_OBJECT(r_ipv6, "interface", iface_name);

					// Extract gateway address
					const char *gw_addr = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(route, "gateway"), "address"));

					JSON_COPY_STR_TO_OBJECT(r_ipv6, "address", gw_addr);
					break;
				}
			}
		}
	}

	// Add gateway information to JSON object
	JSON_ADD_ITEM_TO_OBJECT(json, "ipv4", r_ipv4);
	JSON_ADD_ITEM_TO_OBJECT(json, "ipv6", r_ipv6);

	cJSON_Delete(routes);

	JSON_SEND_OBJECT(json);
}

int api_network_routes(struct ftl_conn *api)
{
	// Add routing information
	cJSON *routes = JSON_NEW_OBJECT();
	read_proc_net_route(routes);
	read_proc_net_ipv6_route(routes);
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "routes", routes);
	JSON_SEND_OBJECT(json);
}

int api_network_interfaces(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();

	// Enumerate and list interfaces
	// Loop over interfaces and extract information
	DIR *dfd;
	FILE *f;
	struct dirent *dp;
	size_t tx_sum = 0, rx_sum = 0;
	char fname[64 + IF_NAMESIZE] = { 0 };
	char readbuffer[1024] = { 0 };

	// Open /sys/class/net directory
	if ((dfd = opendir("/sys/class/net")) == NULL)
	{
		log_err("API: Cannot access /sys/class/net");
		return 500;
	}

	// Get IP addresses of all interfaces on this machine
	struct ifaddrs *ifap = NULL;
	if(getifaddrs(&ifap) == -1)
		log_err("API: Cannot get interface addresses: %s", strerror(errno));

	// Parse IPv6 address details
	cJSON *ipv6a = JSON_NEW_ARRAY();
	read_proc_net_if_inet6(ipv6a);

	cJSON *interfaces = JSON_NEW_ARRAY();
	// Walk /sys/class/net directory
	while ((dp = readdir(dfd)) != NULL)
	{
		// Skip "." and ".."
		if(strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		// Create new interface record
		cJSON *iface = JSON_NEW_OBJECT();

		// Extract interface name
		const char *iface_name = dp->d_name;
		JSON_COPY_STR_TO_OBJECT(iface, "name", iface_name);

		// Extract carrier status
		bool carrier = false;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/carrier", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fgets(readbuffer, sizeof(readbuffer)-1, f) != NULL)
				carrier = readbuffer[0] == '1';
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));
		JSON_ADD_BOOL_TO_OBJECT(iface, "carrier", carrier);

		// Extract link speed (may not be possible, e.g., for WiFi devices with dynamic link speeds)
		int speed = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/speed", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%i", &(speed)) != 1)
				speed = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));
		JSON_ADD_NUMBER_TO_OBJECT(iface, "speed", speed);

		// Get total transmitted bytes
		ssize_t tx_bytes = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/tx_bytes", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(tx_bytes)) != 1)
				tx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Format transmitted bytes
		double tx = 0.0;
		char tx_unit[3] = { 0 };
		format_memory_size(tx_unit, tx_bytes, &tx);
		if(tx_unit[0] != '\0')
			tx_unit[1] = 'B';

		// Add transmitted bytes to interface record
		cJSON *tx_json = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(tx_json, "num", tx);
		JSON_COPY_STR_TO_OBJECT(tx_json, "unit", tx_unit);
		JSON_ADD_ITEM_TO_OBJECT(iface, "tx", tx_json);

		// Get total received bytes
		ssize_t rx_bytes = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/rx_bytes", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(rx_bytes)) != 1)
				rx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Format received bytes
		double rx = 0.0;
		char rx_unit[3] = { 0 };
		format_memory_size(rx_unit, rx_bytes, &rx);
		if(rx_unit[0] != '\0')
			rx_unit[1] = 'B';

		// Add received bytes to JSON object
		cJSON *rx_json = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(rx_json, "num", rx);
		JSON_COPY_STR_TO_OBJECT(rx_json, "unit", rx_unit);
		JSON_ADD_ITEM_TO_OBJECT(iface, "rx", rx_json);

		// Get IP address(es) of this interface
		if(ifap)
		{
			// Walk through linked list of interface addresses
			cJSON *ipv4 = JSON_NEW_ARRAY();
			cJSON *ipv6 = JSON_NEW_ARRAY();
			for(struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
			{
				// Skip interfaces without an address and those
				// not matching the current interface
				if(ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, iface_name) != 0)
					continue;

				// If we reach this point, we found the correct interface
				const sa_family_t family = ifa->ifa_addr->sa_family;
				char host[NI_MAXHOST] = { 0 };
				if(family != AF_INET && family != AF_INET6)
					continue;
				// Get IP address
				const int s = getnameinfo(ifa->ifa_addr,
				                          (family == AF_INET) ?
				                          sizeof(struct sockaddr_in) :
				                          sizeof(struct sockaddr_in6),
				                          host, NI_MAXHOST,
				                          NULL, 0, NI_NUMERICHOST);
				if (s != 0)
				{
					log_warn("API: getnameinfo(1) failed: %s\n", gai_strerror(s));
					continue;
				}
				// Get netmask
				char netmask[NI_MAXHOST] = { 0 };
				const int s2 = getnameinfo(ifa->ifa_netmask,
				                           (family == AF_INET) ?
				                           sizeof(struct sockaddr_in) :
				                           sizeof(struct sockaddr_in6),
				                           netmask, NI_MAXHOST,
				                           NULL, 0, NI_NUMERICHOST);
				if (s2 != 0)
				{
					log_warn("API: getnameinfo(2) failed: %s\n", gai_strerror(s2));
					continue;
				}

				cJSON *new_addr = JSON_NEW_OBJECT();
				JSON_COPY_STR_TO_OBJECT(new_addr, "address", host);
				JSON_COPY_STR_TO_OBJECT(new_addr, "netmask", netmask);

				if(family == AF_INET)
				{
					// Add IPv4 address to array
					JSON_ADD_ITEM_TO_ARRAY(ipv4, new_addr);
				}
				else if(family == AF_INET6)
				{
					// Search address in ipv6a array and add further details
					cJSON *ipv6_entry = NULL;
					cJSON_ArrayForEach(ipv6_entry, ipv6a)
					{
						// Compare interface and address
						const char *arr_name = cJSON_GetStringValue(cJSON_GetObjectItem(ipv6_entry, "interface"));
						const char *arr_addr = cJSON_GetStringValue(cJSON_GetObjectItem(ipv6_entry, "address"));
						// We compare only the first part of the address as the second part may be an interface specifier (%veth...)
						if(strcmp(arr_name, iface_name) == 0 && strncmp(arr_addr, host, min(strlen(arr_addr), strlen(host))) == 0)
						{
							// Copy details from ipv6a array to new_addr (prefix, scope, flags)
							JSON_ADD_ITEM_TO_OBJECT(new_addr, "type", cJSON_Duplicate(cJSON_GetObjectItem(ipv6_entry, "type"), true));
							JSON_ADD_NUMBER_TO_OBJECT(new_addr, "prefix", cJSON_GetNumberValue(cJSON_GetObjectItem(ipv6_entry, "prefix")));
							JSON_ADD_ITEM_TO_OBJECT(new_addr, "scope", cJSON_Duplicate(cJSON_GetObjectItem(ipv6_entry, "scope"), true));
							JSON_ADD_ITEM_TO_OBJECT(new_addr, "flags", cJSON_Duplicate(cJSON_GetObjectItem(ipv6_entry, "flags"), true));
							break;
						}
					}

					// Add IPv6 address to array
					JSON_ADD_ITEM_TO_ARRAY(ipv6, new_addr);
				}

				// Format flags into human-readable array of strings
				cJSON *flag_array = cJSON_CreateArray();
				for(size_t i = 0; i < sizeof(iff_flags) / sizeof(iff_flags[0]); i++)
					if(ifa->ifa_flags & iff_flags[i].flag)
					cJSON_AddItemToArray(flag_array, cJSON_CreateStringReference(iff_flags[i].name));
				JSON_ADD_ITEM_TO_OBJECT(iface, "flags", flag_array);
			}
			JSON_ADD_ITEM_TO_OBJECT(iface, "ipv4", ipv4);
			JSON_ADD_ITEM_TO_OBJECT(iface, "ipv6", ipv6);
		}

		// Sum up transmitted and received bytes
		if(tx_bytes > 0)
			tx_sum += tx_bytes;
		if(rx_bytes > 0)
			rx_sum += rx_bytes;

		// Add interface to array
		JSON_ADD_ITEM_TO_ARRAY(interfaces, iface);
	}

	freeifaddrs(ifap);
	closedir(dfd);
	cJSON_Delete(ipv6a);
	ipv6a = NULL;

	cJSON *sum = JSON_NEW_OBJECT();
	JSON_COPY_STR_TO_OBJECT(sum, "name", "sum");
	JSON_ADD_BOOL_TO_OBJECT(sum, "carrier", true);
	JSON_ADD_NUMBER_TO_OBJECT(sum, "speed", 0);

	// Format transmitted bytes
	double tx = 0.0;
	char tx_unit[3] = { 0 };
	format_memory_size(tx_unit, tx_sum, &tx);
	if(tx_unit[0] != '\0')
		tx_unit[1] = 'B';

	// Add transmitted bytes to interface record
	cJSON *tx_json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(tx_json, "num", tx);
	JSON_COPY_STR_TO_OBJECT(tx_json, "unit", tx_unit);
	JSON_ADD_ITEM_TO_OBJECT(sum, "tx", tx_json);

	// Format received bytes
	double rx = 0.0;
	char rx_unit[3] = { 0 };
	format_memory_size(rx_unit, rx_sum, &rx);
	if(rx_unit[0] != '\0')
		rx_unit[1] = 'B';

	// Add received bytes to JSON object
	cJSON *rx_json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(rx_json, "num", rx);
	JSON_COPY_STR_TO_OBJECT(rx_json, "unit", rx_unit);
	JSON_ADD_ITEM_TO_OBJECT(sum, "rx", rx_json);

	cJSON *ipv4 = JSON_NEW_ARRAY();
	cJSON *ipv6 = JSON_NEW_ARRAY();
	JSON_ADD_ITEM_TO_OBJECT(sum, "ipv4", ipv4);
	JSON_ADD_ITEM_TO_OBJECT(sum, "ipv6", ipv6);

	// Add interface to array
	JSON_ADD_ITEM_TO_ARRAY(interfaces, sum);
	JSON_ADD_ITEM_TO_OBJECT(json, "interfaces", interfaces);
	JSON_SEND_OBJECT(json);
}

static int api_network_devices_GET(struct ftl_conn *api)
{
	// Does the user request a custom number of devices to be included?
	unsigned int device_count = 10;
	get_uint_var(api->request->query_string, "max_devices", &device_count);

	// Does the user request a custom number of addresses per device to be included?
	unsigned int address_count = 3;
	get_uint_var(api->request->query_string, "max_addresses", &address_count);

	// Open pihole-FTL.db database file
	sqlite3_stmt *device_stmt = NULL, *ip_stmt = NULL;
	sqlite3 *db = dbopen(true, false);
	if(db == NULL)
	{
		log_warn("Failed to open database in networkTable_readDevices()");
		return false;
	}

	const char *sql_msg = NULL;
	if(!networkTable_readDevices(db, &device_stmt, &sql_msg))
	{
		// Add SQL message (may be NULL = not available)
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not read network details from database table",
		                       sql_msg);
	}

	// Read record for a single device
	cJSON *devices = JSON_NEW_ARRAY();
	network_record network;
	unsigned int device_counter = 0;
	while(networkTable_readDevicesGetRecord(device_stmt, &network, &sql_msg) &&
	      device_counter++ < device_count)
	{
		cJSON *item = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(item, "id", network.id);
		JSON_COPY_STR_TO_OBJECT(item, "hwaddr", network.hwaddr);
		JSON_COPY_STR_TO_OBJECT(item, "interface", network.iface);
		JSON_ADD_NUMBER_TO_OBJECT(item, "firstSeen", network.firstSeen);
		JSON_ADD_NUMBER_TO_OBJECT(item, "lastQuery", network.lastQuery);
		JSON_ADD_NUMBER_TO_OBJECT(item, "numQueries", network.numQueries);
		JSON_COPY_STR_TO_OBJECT(item, "macVendor", network.macVendor);

		// Build array of all IP addresses known associated to this client
		cJSON *ips = JSON_NEW_ARRAY();
		if(networkTable_readIPs(db, &ip_stmt, network.id, &sql_msg))
		{
			// Walk known IP addresses + names
			network_addresses_record network_address;
			unsigned int address_counter = 0;
			while(networkTable_readIPsGetRecord(ip_stmt, &network_address, &sql_msg) &&
			      address_counter++ < address_count)
			{
				cJSON *ip = JSON_NEW_OBJECT();
				JSON_COPY_STR_TO_OBJECT(ip, "ip", network_address.ip);
				JSON_COPY_STR_TO_OBJECT(ip, "name", network_address.name);
				JSON_ADD_NUMBER_TO_OBJECT(ip, "lastSeen", network_address.lastSeen);
				JSON_ADD_NUMBER_TO_OBJECT(ip, "nameUpdated", network_address.nameUpdated);
				JSON_ADD_ITEM_TO_ARRAY(ips, ip);
			}

			// Possible error handling
			if(sql_msg != NULL)
			{
				cJSON_Delete(ips);
				cJSON_Delete(devices);
				return send_json_error(api, 500,
				                       "database_error",
				                       "Could not read network details from database table (getting IP records)",
				                       sql_msg);
			}

			// Finalize sub-query
			networkTable_readIPsFinalize(ip_stmt);
		}

		// Add array of IP addresses to device
		JSON_ADD_ITEM_TO_OBJECT(item, "ips", ips);

		// Add device to array of all devices
		JSON_ADD_ITEM_TO_ARRAY(devices, item);
	}

	if(sql_msg != NULL)
	{
		cJSON_Delete(devices);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not read network details from database table (step)",
		                       sql_msg);
	}

	// Finalize query
	networkTable_readDevicesFinalize(device_stmt);
	dbclose(&db);

	// Return data to user
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "devices", devices);
	JSON_SEND_OBJECT(json);
}

static int api_network_devices_DELETE(struct ftl_conn *api)
{
	// Get device ID
	int device_id = 0;
	if(sscanf(api->item, "%i", &device_id) != 1)
	{
		return send_json_error(api, 400,
		                       "invalid_request",
		                       "Missing or invalid {id} parameter",
		                       NULL);
	}

	// Open pihole-FTL.db database file
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
	{
		log_warn("Failed to open database in networkTable_readDevices()");
		return false;
	}

	// Delete row from network table by ID
	const char *sql_msg = NULL;
	int deleted = 0;
	if(!networkTable_deleteDevice(db, device_id, &deleted, &sql_msg))
	{
		// Add SQL message (may be NULL = not available)
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not delete network details from database table",
		                       sql_msg);
	}

	// Close database
	dbclose(&db);

	// Send empty reply with codes:
	// - 204 No Content (if any items were deleted)
	// - 404 Not Found (if no items were deleted)
	cJSON *json = JSON_NEW_OBJECT();
	JSON_SEND_OBJECT_CODE(json, deleted > 0 ? 204 : 404);
}

int api_network_devices(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
	{
		return api_network_devices_GET(api);
	}
	else if(api->method == HTTP_DELETE)
	{
		return api_network_devices_DELETE(api);
	}
	else
	{
		return send_json_error(api, 405,
		                       "method_not_allowed",
		                       "Method not allowed",
		                       NULL);
	}
}

int api_client_suggestions(struct ftl_conn *api)
{
	// Get client suggestions
	if(api->method != HTTP_GET)
	{
		// This results in error 404
		return 0;
	}

	// Does the user request a custom number of addresses per device to be included?
	unsigned int count = 50;
	get_uint_var(api->request->query_string, "count", &count);

	bool ipv4_only = true;
	get_bool_var(api->request->query_string, "ipv4_only", &ipv4_only);

	// Open pihole-FTL.db database file connection
	sqlite3 *db = dbopen(true, false);

	// Attach gravity database
	const char *message = "";
	if(!attach_database(db, &message, config.files.gravity.v.s, "g"))
	{
		log_err("Failed to attach gravity database: %s", message);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not attach gravity database",
		                       message);
	}

	// Prepare SQL statement
	sqlite3_stmt *stmt = NULL;
	const char *sql = "SELECT n.hwaddr,n.macVendor,n.lastQuery,"
	                  "(SELECT GROUP_CONCAT(DISTINCT na.ip) "
	                    "FROM network_addresses na "
	                      "WHERE na.network_id = n.id),"
	                  "(SELECT GROUP_CONCAT(DISTINCT na.name) "
	                    "FROM network_addresses na "
	                      "WHERE na.network_id = n.id) "
	                  "FROM network n "
	                  "ORDER BY lastQuery DESC LIMIT ?";

	if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		log_err("Failed to prepare SQL statement: %s", sqlite3_errmsg(db));
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not prepare SQL statement",
		                       sqlite3_errmsg(db));
	}

	// Bind parameters
	if(sqlite3_bind_int(stmt, 1, count) != SQLITE_OK)
	{
		log_err("Failed to bind parameter: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not bind parameter",
		                       sqlite3_errmsg(db));
	}

	// Execute SQL statement
	cJSON *clients = JSON_NEW_ARRAY();
	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		cJSON *client = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(client, "hwaddr", sqlite3_column_text(stmt, 0));
		JSON_COPY_STR_TO_OBJECT(client, "macVendor", sqlite3_column_text(stmt, 1));
		JSON_ADD_NUMBER_TO_OBJECT(client, "lastQuery", sqlite3_column_int(stmt, 2));
		JSON_COPY_STR_TO_OBJECT(client, "addresses", sqlite3_column_text(stmt, 3));
		JSON_COPY_STR_TO_OBJECT(client, "names", sqlite3_column_text(stmt, 4));
		JSON_ADD_ITEM_TO_ARRAY(clients, client);
	}

	// Finalize query
	sqlite3_finalize(stmt);

	// Detach gravity database
	if(!detach_database(db, &message, "g"))
	{
		log_err("Failed to detach gravity database: %s", message);
		dbclose(&db);
		return send_json_error(api, 500,
		                       "database_error",
		                       "Could not detach gravity database",
		                       message);
	}

	// Close database connection
	dbclose(&db);

	// Return data to user
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "clients", clients);
	JSON_SEND_OBJECT(json);
}

