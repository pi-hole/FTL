/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DHCPv6 / ICMPv6 discovery routines
*
*  Inspired by the ndisc6 project
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "dhcpv6-discover.h"
#include "dhcp-discover.h"

// check_capability()
#include "capabilities.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

/**
 * @brief Resolves an IPv6 address by hostname and interface name.
 *
 * This function takes a hostname and an interface name, resolves the hostname
 * to an IPv6 address, and fills the provided sockaddr_in6 structure with the
 * resolved address.
 *
 * @param name The hostname to resolve.
 * @param ifname The name of the network interface.
 * @param addr A pointer to a sockaddr_in6 structure to be filled with the resolved address.
 * @return 0 on success, -1 on failure.
 */
static int get_ipv6_by_name(const char *name, const char *ifname, struct sockaddr_in6 *addr)
{
	struct addrinfo hints = { 0 }, *res = NULL;
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST; // don't resolve hostnames

	// Resolve the hostname to an IPv6 address
	const int val = getaddrinfo(name, NULL, &hints, &res);
	if(val)
	{
		printf("ERROR: get_ipv6_by_name(%s): %s\n", name, gai_strerror(val));
		return -1;
	}

	memcpy(addr, res->ai_addr, sizeof (struct sockaddr_in6));
	freeaddrinfo(res);

	// Get the interface index
	addr->sin6_scope_id = if_nametoindex(ifname);
	if(addr->sin6_scope_id == 0)
	{
		printf("Error while trying to resolve interface %s: %s\n",
		       ifname, strerror(errno));
		return -1;
	}

	return 0;
}


/**
 * @brief Sets the hop limit for both multicast and unicast packets on a given socket.
 *
 * This function sets the hop limit (TTL) for both IPv6 multicast and unicast packets
 * on the specified socket file descriptor.
 *
 * @param fd The file descriptor of the socket.
 * @param value The hop limit value to be set.
 * @return Returns 0 on success, or -1 on failure.
 */
static inline int set_hop_limit(const int fd, const int value)
{
	return(setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &value, sizeof (value)) ||
	       setsockopt (fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &value, sizeof (value))) ? -1 : 0;
}

/**
 * @brief Prints a MAC address in hexadecimal format.
 *
 * This function prints a MAC address from the given pointer to a buffer
 * containing the MAC address bytes. Each byte is printed in hexadecimal
 * format, separated by colons. The last byte is printed without a trailing colon.
 *
 * @param ptr Pointer to the buffer containing the MAC address bytes.
 * @param len Length of the buffer.
 */
static void print_mac(const uint8_t *ptr, size_t len)
{
	while(len > 1)
	{
		printf("%02X:", *ptr);
		ptr++;
		len--;
	}

	if (len == 1)
		printf("%02X\n", *ptr);
}

/**
 * build_solicit - Initializes a router solicitation message.
 * @rs: Pointer to a nd_router_solicit structure to be initialized.
 *
 * This function sets the memory of the provided nd_router_solicit structure
 * to zero and assigns the ND_ROUTER_SOLICIT type to the nd_rs_type field.
 *
 * Return: The size of the initialized nd_router_solicit structure.
 */
static ssize_t build_solicit(struct nd_router_solicit *rs)
{
	memset(rs, 0, sizeof(*rs));
	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	return sizeof(*rs);
}

/**
 * @brief Prints the given 32-bit time value in a human-readable format.
 *
 * This function converts a 32-bit time value from network byte order to host byte order
 * and prints it. If the value is 0xffffffff, it prints "infinite". Otherwise, it prints
 * the value in seconds.
 *
 * @param opt32 The 32-bit time value in network byte order.
 */
static void print_u32_time(const uint32_t opt32)
{
	const uint32_t lifetime = ntohl(opt32);

	if(lifetime == 0xffffffff)
		puts("infinite\n");
	else
		printf("%u sec\n", lifetime);
}

/**
 * @brief Prints the time represented by an 8-byte option.
 *
 * This function extracts a 32-bit lifetime value from the given 8-byte option
 * and prints it using the print_u32_time function.
 *
 * @param opt8 Pointer to the 8-byte option containing the lifetime value.
 */
static void print_u8_time(const uint8_t *opt8)
{
	uint32_t lifetime = 0;
	// Get the lifetime value from the option. It is located at the 5th to
	// 8th byte.
	memcpy(&lifetime, opt8 + 4, 4);
	print_u32_time(lifetime);
}

/**
 * @brief Parses and prints information from a DHCPv6 prefix information option.
 *
 * This function checks if the provided option length is sufficient for the prefix
 * information structure, translates the prefix to a human-readable string, and prints
 * various details about the prefix, including its length, flags, and valid/preferred times.
 *
 * @param pi Pointer to the prefix information option structure.
 * @param optlen Length of the option data.
 * @return 0 on success, -1 on failure (e.g., if the option length is insufficient or
 *         if the prefix cannot be translated to a string).
 */
static int parse_prefix(const struct nd_opt_prefix_info *pi, size_t optlen)
{
	// Check if the option length is at least the size of the prefix info structure
	if(optlen < sizeof (*pi))
		return -1;

	// Translate the prefix to a human-readable string
	char str[INET6_ADDRSTRLEN] = { 0 };
	if(inet_ntop(AF_INET6, &pi->nd_opt_pi_prefix, str, sizeof (str)) == NULL)
		return -1;

	printf("  - Prefix: %s/%u\n", str, pi->nd_opt_pi_prefix_len);

	const uint8_t opt = pi->nd_opt_pi_flags_reserved;
	printf("    Valid lifetime: ");
	print_u32_time(pi->nd_opt_pi_valid_time);
	printf("    Preferred lifetime: ");
	print_u32_time(pi->nd_opt_pi_preferred_time);
	printf("    On-link: %s\n", (opt & ND_OPT_PI_FLAG_ONLINK) ? "Yes" : "No");
	printf("    Autonomous address conf.: %s\n",(opt & ND_OPT_PI_FLAG_AUTO) ? "Yes" : "No");

	return 0;
}

/**
 * @brief Parses and prints the MTU (Maximum Transmission Unit) from the given ND option.
 *
 * This function takes a pointer to an nd_opt_mtu structure, extracts the MTU value,
 * converts it from network byte order to host byte order, and prints the MTU value
 * along with its validity status.
 *
 * @param m Pointer to the nd_opt_mtu structure containing the MTU option.
 */
static void parse_mtu(const struct nd_opt_mtu *m)
{
	const uint32_t mtu = ntohl (m->nd_opt_mtu_mtu);
	// Minimum of 1280 bytes for IPv6 is defined in RFC8200, Section 5
	printf("  MTU: %u bytes (%s)\n", mtu, (mtu >= 1280) ? "valid" : "invalid");
}

/**
 * @brief Converts a preference value to its corresponding string representation.
 *
 * This function takes an unsigned integer value, extracts the relevant bits,
 * and returns a string that represents the preference level.
 *
 * @param val The unsigned integer value representing the preference.
 * @return A string representing the preference level. Possible return values are:
 *         - "medium"
 *         - "high"
 *         - "medium (invalid)"
 *         - "low"
 *         - "unknown" (if the value does not match any known preference level)
 */
static const char *parse_pref(unsigned int val)
{
	static const char *values[] = { "Medium", "High", "Medium (invalid)", "Low" };
	// Returning right away here is safe as the value is only 2 bits so the
	// result will be in the range [0, 3] which is a valid index for the
	// array above.
	return values[(val >> 3) & 3];
}


/**
 * @brief Parses a DHCPv6 route option.
 *
 * This function parses a DHCPv6 route option and prints the route information.
 *
 * @param opt Pointer to the DHCPv6 option data.
 * @return 0 on success, -1 on failure.
 *
 * The function performs the following steps:
 * 1. Validates the option length and prefix length.
 * 2. Converts the destination address to a human-readable string.
 * 3. Prints the route information, including the route preference and lifetime.
 *
 * The option data is expected to be in the following format:
 * - opt[0]: Option code
 * - opt[1]: Option length
 * - opt[2]: Prefix length
 * - opt[3]: Route preference
 * - opt[4-7]: Reserved
 * - opt[8+]: Destination address
 */
static int parse_route(const uint8_t *opt)
{
	const uint8_t optlen = opt[1], plen = opt[2];
	// Check if the option length is valid
	if ((optlen > 3) || (plen > 128) || (optlen < ((plen + 127) >> 6)))
		return -1;

	char str[INET6_ADDRSTRLEN] = { 0 };
	struct in6_addr dst = in6addr_any;
	memcpy(dst.s6_addr, opt + 8, (optlen - 1) << 3);
	if(inet_ntop (AF_INET6, &dst, str, sizeof (str)) == NULL)
		return -1;

	printf("  - Route: %s/%"PRIu8"\n", str, plen);
	printf("    Route preference: %s\n", parse_pref(opt[3]));
	printf("    Route lifetime: ");
	print_u8_time(opt);
	return 0;
}


/**
 * @brief Parses the Recursive DNS Server (RDNSS) option from a DHCPv6 message.
 *
 * This function extracts and prints the IPv6 addresses of the recursive DNS servers
 * from the provided option data. It also prints the DNS server lifetime.
 *
 * @param opt Pointer to the option data.
 * @return 0 on success, -1 on failure (e.g., invalid option length or inet_ntop failure).
 */
static int parse_rdnss(const uint8_t *opt)
{
	uint8_t optlen = opt[1];
	// Check if the option length is valid
	if (((optlen & 1) == 0) || (optlen < 3))
		return -1;

	// Divide the option length by 2 to get the number of DNS servers
	optlen /= 2;
	for(unsigned i = 0; i < optlen; i++)
	{
		char str[INET6_ADDRSTRLEN] = { 0 };
		if(inet_ntop(AF_INET6, opt + (16 * i + 8), str, sizeof (str)) == NULL)
			return -1;

		printf("  Recursive DNS server %u/%u: %s\n", i + 1, optlen, str);
	}

	printf("  DNS server lifetime:");
	print_u8_time(opt);
	return 0;
}


/**
 * @brief Parses the DNS Search List (DNSSL) option from a DHCPv6 message.
 *
 * This function processes the DNSSL option, extracting and printing the domain names
 * included in the option. It also prints the DNS search list lifetime.
 *
 * @param opt Pointer to the DNSSL option data.
 * @return 0 on success, -1 on failure (e.g., invalid option length).
 */
static int parse_dnssl(const uint8_t *opt)
{
	const uint8_t *base;
	uint16_t optlen = opt[1];
	// Check if the option length is valid
	if (optlen < 2)
		return -1;

	printf("  DNS search list: ");

	// Do the necessary calculations to get the domain names
	optlen *= 8;
	optlen -= 8;
	base = opt + 8;

	for(unsigned int i = 0; i < optlen; i++)
	{
		char str[256] = { 0 };

		// Check if the base is empty
		if (!base[i])
			break;

		do
		{
			// Check if the base is too long
			if (base[i] + i + 1 >= optlen)
			{
				printf("\n");
				return -1;
			}

			// Copy the domain name to the string
			memcpy(str, &base[i + 1], base[i]);
			str[base[i]] = 0;

			// Move to the next domain name
			i += base[i] + 1;

			// Print the domain name
			printf("%s%s", str, base[i] ? "." : "");

		} while(base[i]);

		printf(" ");

	}

	puts("");

	printf("   DNS search list lifetime: ");
	print_u8_time(opt);
	return 0;
}


/**
 * parse_pref64 - Parses the PREF64 option from a DHCPv6 message.
 * @opt: Pointer to the option data.
 *
 * This function extracts and prints the NAT64 prefix and its lifetime from
 * the given DHCPv6 option data. The option data is expected to contain a
 * 16-bit lifetime and prefix length code, followed by the NAT64 prefix.
 *
 * Return: 0 on success, -1 on failure.
 */
static int parse_pref64(const uint8_t *opt)
{
	uint16_t lifetime_plc;
	memcpy(&lifetime_plc, opt + sizeof(uint16_t), sizeof(uint16_t));
	// 0x0007: mask for the prefix length code
	const uint32_t plc = lifetime_plc & 0x0007;
	// 0xfff8: mask for the lifetime
	const uint32_t lifetime = lifetime_plc & 0xfff8;
	struct in6_addr pref64 = { 0 };
	char str[INET6_ADDRSTRLEN] = { 0 };

	// Check if the option length and prefix length are valid
	if (opt[1] != 2 || plc > 5)
		return -1;

	memcpy(&pref64, opt + sizeof(uint32_t), 3*sizeof(uint32_t));
	pref64.s6_addr32[3] = 0;
	if(inet_ntop(AF_INET6, &pref64, str, sizeof (str)) == NULL)
		return -1;

	const uint8_t preflen[] = { 96, 64, 56, 48, 40, 32 };
	const uint8_t plc_val = (plc < (sizeof(preflen) / sizeof(preflen[0])) - 1) ? plc : 0;
	printf("  NAT64 prefix: %s/%"PRIu8"\n", str, plc_val);
	printf("   Lifetime: %u sec\n", lifetime);
	return 0;
}


/**
 * parse_ra - Parses a Router Advertisement (RA) message.
 * @buf: Pointer to the buffer containing the RA message.
 * @len: Length of the buffer.
 *
 * This function parses a Router Advertisement message as defined in RFC 4861.
 * It extracts and prints various fields from the RA message, including hop limit,
 * stateful address configuration, router lifetime, reachable time, and retransmit time.
 * It also parses and prints information from RA options such as source link-layer address,
 * target link-layer address, prefix information, MTU, route information, recursive DNS server,
 * DNS search list, and prefix64.
 *
 * Return: 0 on success, -1 if the buffer is too small or the RA message is invalid.
 */
static int parse_ra(const uint8_t *buf, size_t len)
{
	const struct nd_router_advert *ra;
	memcpy(&ra, &buf, sizeof(ra));
	const uint8_t *ptr;

	// Ensure the buffer is large enough and contains a valid Router
	// Advertisement message
	if ((len < sizeof (struct nd_router_advert)) ||
	    (ra->nd_ra_type != ND_ROUTER_ADVERT) ||
	    (ra->nd_ra_code != 0))
		return -1;

	printf("  Hop limit: ");
	if (ra->nd_ra_curhoplimit != 0)
		printf("%u\n", ra->nd_ra_curhoplimit);
	else
		puts("undefined");

	printf("  Stateful address conf.: %s\n", (ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED) ? "Yes" : "No");
	printf("  Stateful other conf.: %s\n", (ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER) ? "Yes" : "No");
	printf("  Mobile home agent: %s\n", (ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT) ? "Yes" : "No");
	printf("  Router preference: %s\n", parse_pref(ra->nd_ra_flags_reserved));
	printf("  Neighbor discovery proxy: %s\n", (ra->nd_ra_flags_reserved & 0x04) ? "Yes" : "No");

	/* Router lifetime */
	const uint16_t router_lifetime = ntohs(ra->nd_ra_router_lifetime);
	printf("  Router lifetime: %u s\n", router_lifetime);

	/* ND Reachable time */
	const uint16_t reachable = ntohs(ra->nd_ra_reachable);
	printf("  Reachable time: ");
	if(reachable != 0)
		printf("%u ms\n", reachable);
	else
		puts("N/A");

	/* ND Retransmit time */
	printf("  Retransmit time: ");
	const uint16_t retransmit = ntohl (ra->nd_ra_retransmit);
	if (retransmit != 0)
		printf("%u ms\n", retransmit);
	else
		puts("N/A");

	// Jump past the Router Advertisement header for option parsing
	len -= sizeof (struct nd_router_advert);
	ptr = buf + sizeof (struct nd_router_advert);

	while(len >= 8)
	{
		const uint16_t optlen = ((uint16_t)(ptr[1])) << 3;
		if ((optlen == 0) || (len < optlen))
			break;

		// Subtract the option length from the remaining buffer length
		len -= optlen;

		// Interpret the option
		switch(ptr[0])
		{
			// RFC2292 (Target Link-Layer Address)
			case ND_OPT_SOURCE_LINKADDR: // RFC4861 (Source Link-Layer Address)
				printf("  Source link-layer address: ");
				print_mac(ptr + 2, optlen - 2);
				break;

			case ND_OPT_TARGET_LINKADDR: // RFC2292 (Target Link-Layer Address)
				printf("  Target link-layer address: ");
				print_mac(ptr + 2, optlen - 2);
				break;

			case ND_OPT_PREFIX_INFORMATION: // RFC2292 (Prefix Information)
			{
				const struct nd_opt_prefix_info *pi = NULL;
				memcpy(&pi, &ptr, sizeof(pi));
				parse_prefix(pi, optlen);
				break;
			}

			case ND_OPT_MTU:
			{
				const struct nd_opt_mtu *m;
				memcpy(&m, &ptr, sizeof(m));
				parse_mtu(m);
				break;
			}

			case 24: // RFC4191 (Route Information)
				parse_route(ptr);
				break;

			case 25: // RFC5006 (Recursive DNS Server)
				parse_rdnss(ptr);
				break;

			case 31: // RFC6106 (DNS Search List)
				parse_dnssl(ptr);
				break;

			case 38: // RFC8781 (Prefix64)
				parse_pref64(ptr);
				break;

			default:
				// Report unknown options
				printf(" Unknown option %u: ", ptr[0]);
				for(unsigned i = 0; i < optlen; i++)
					printf(" %02x", ptr[i]);
				puts("");
				break;
		}

		// Advance the pointer to the next option
		ptr += optlen;
	}

	puts("");
	return 0;
}

/**
 * @brief Receives a message from a socket and ensures the hop limit is 255.
 *
 * This function receives a message from a socket using the recvmsg() system call.
 * It sets up the necessary message headers and control data to receive ancillary data.
 * After receiving the message, it checks the hop limit (TTL) of the received packet
 * to ensure it is 255. If the hop limit is not 255, the function returns -1 and sets
 * errno to EAGAIN.
 *
 * @param fd The file descriptor of the socket to receive the message from.
 * @param buf A pointer to the buffer where the received message will be stored.
 * @param len The length of the buffer.
 * @param flags Flags to pass to the recvmsg() system call.
 * @param addr A pointer to a sockaddr_in6 structure to store the source address of the message.
 * @return The number of bytes received on success, or -1 on error with errno set appropriately.
 */
static ssize_t recvfromLL(int fd, void *buf, size_t len, int flags, struct sockaddr_in6 *addr)
{
	uint8_t cbuf[CMSG_SPACE (sizeof (int))] = { 0 };
	// Set up the message header (scatter-gather I/O)
	struct iovec iov =
	{
		.iov_base = buf,
		.iov_len = len
	};
	// Set up the message header (control data)
	struct msghdr hdr =
	{
		.msg_name = addr,
		.msg_namelen = sizeof (*addr),
		.msg_iov = &iov,
		.msg_iovlen = 1, // one record
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	// Receive the message
	const ssize_t val = recvmsg(fd, &hdr, flags);
	if (val == -1)
		return val;

// Circumvent a warning from inside sys/socket.h preventing clang from compiling
// the code with -Wsign-compare
// /app/src/tools/dhcpv6-discover.c:593:72: error: comparison of integers of different signs: 'unsigned long' and 'long' [-Werror,-Wsign-compare]
//   593 |         for(struct cmsghdr *cmsg = CMSG_FIRSTHDR (&hdr); cmsg != NULL; cmsg = CMSG_NXTHDR (&hdr, cmsg))
//       |                                                                               ^~~~~~~~~~~~~~~~~~~~~~~~
// /usr/include/sys/socket.h:358:44: note: expanded from macro 'CMSG_NXTHDR'
//   358 |         __CMSG_LEN(cmsg) + sizeof(struct cmsghdr) >= __MHDR_END(mhdr) - (unsigned char *)(cmsg)
//       |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ^  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// 1 error generated.
//
#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wsign-compare"
#endif // __clang__

	// Loop through the control data to find the hop limit value
	for(struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&hdr, cmsg))
	{
		if((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_HOPLIMIT))
		{
			// Extract the hop limit value
			int hoplimit;
			memcpy(&hoplimit, CMSG_DATA (cmsg), sizeof (hoplimit));
			if (255 != hoplimit)
			{
				// Might be a spurious wake-up
				errno = EAGAIN;
				return -1;
			}
		}
	}
#ifdef __clang__
# pragma clang diagnostic pop
#endif // __clang__

	return val;
}


/**
 * @brief Receives and processes ICMPv6 Router Advertisement messages.
 *
 * This function waits for ICMPv6 Router Advertisement messages on the specified
 * file descriptor until the specified timeout is reached. It processes each
 * received message and counts the number of valid responses.
 *
 * @param fd The file descriptor to read from.
 * @param tgt The target sockaddr_in6 structure containing the expected source address.
 * @param ifname The name of the network interface.
 * @return The number of valid Router Advertisement responses received, or -1 on error.
 */
static ssize_t recv_adv(int fd, const struct sockaddr_in6 *tgt, const char *ifname, const unsigned int timeout)
{
	struct timespec end = { 0 };
	unsigned responses = 0;

	// Get the current time and add the timeout
	clock_gettime(CLOCK_MONOTONIC, &end);
	end.tv_sec += timeout;

	// Receiving packets until timeout
	while(true)
	{
		// Wait for reply until timeout
		ssize_t val = 0;

		struct timespec now = { 0 };
		clock_gettime(CLOCK_MONOTONIC, &now);
		if(end.tv_sec >= now.tv_sec)
		{
			// Calculate the remaining time
			val = (end.tv_sec - now.tv_sec) * 1000 + (int)((end.tv_nsec - now.tv_nsec) / 1000000);
			if (val <= 0) // Timeout
				return responses;
		}

		// Wait for reply (retries on EINTR)
		struct pollfd pollfd = { .fd = fd, .events = POLLIN, .revents = 0 };
		do {
			val = poll(&pollfd, 1, val);
		} while (val == -1 && errno == EINTR);

		// Check for errors, logging happens in the calling function
		if(val < 0)
			break;

		// Check for timeout
		if(val == 0)
			return responses;

		// Received a packet
		uint8_t buf[1460];
		struct sockaddr_in6 addr = { 0 };
		val = recvfromLL(fd, &buf, sizeof(buf), MSG_DONTWAIT, &addr);
		if (val == -1)
		{
			// Ignore EAGAIN as we can retry
			if (errno != EAGAIN)
			{
				start_lock();
				printf("Error while receiving Router Advertisements on %s: %s\n",
				       ifname, strerror(errno));
				end_lock();
			}
			continue;
		}

		// Check that the response came through the right interface
		if (addr.sin6_scope_id && (addr.sin6_scope_id != tgt->sin6_scope_id))
			continue;

		// Print the received packet's size and the source address
		char str[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, &addr.sin6_addr, str,sizeof (str));
		start_lock();
		printf("* Received %zd bytes from %s @ %s\n", val, str, ifname);

		// Parse the Router Advertisement
		if(parse_ra(buf, val) == 0)
			responses++;
		end_lock();
	}

	return -1;
}

/**
 * @brief Sends a Router Solicitation message and waits for a Router Advertisement response.
 *
 * This function performs Neighbor Discovery (ND) by sending a Router Solicitation (RS)
 * message to the specified target and waits for a Router Advertisement (RA) response.
 *
 * @param fd The file descriptor of the socket to use for sending and receiving messages.
 * @param ifname The name of the network interface to use for sending the message.
 *
 * @return 0 on success, -1 on error.
 */
static int do_discoverv6(const int fd, const char *ifname, const unsigned int timeout)
{
	struct sockaddr_in6 tgt = { 0 };

	// Automatically close the socket on exec
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	// Set ICMPv6 filter
	struct icmp6_filter filter = { 0 };
	ICMP6_FILTER_SETBLOCKALL(&filter); // block all ICMPv6 messages
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter); // pass Router Advertisement
	setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));

	// Avoid routing by specifying that outgoing messages should bypass the
	// standard routing facilities. Instead, they should be sent directly to
	// the appropriate network interface.
	setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &(int){ 1 }, sizeof(int));

	// Sets Hop-by-hop limit to 255. The hop limit in IPv6 is analogous to
	// the Time-To-Live (TTL) field in IPv4. It specifies the maximum number
	// of hops (routers) that the packet can traverse before being
	// discarded. Setting the hop limit to 255 ensures that the packet can
	// travel through up to 255 routers.
	set_hop_limit(fd, 255);
	setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &(int){ 1 }, sizeof(int));

	// Resolves target's IPv6 address
	const char *hostname = "ff02::2"; // All routers multicast address
	if(get_ipv6_by_name(hostname, ifname, &tgt) != 0)
	{
		close(fd);
		return -1;
	}

	// Initialize and build the Router Solicitation message
	struct nd_router_solicit packet = { 0 };
	struct sockaddr_in6 dst = { 0 };
	memcpy(&dst, &tgt, sizeof(dst));

	const ssize_t plen = build_solicit(&packet);
	if(plen == -1)
	{
		close(fd);
		return -1;
	}

	/* sends a Solitication */
	if(sendto(fd, &packet, plen, 0,
	   (const struct sockaddr *)&dst,
	   sizeof(dst)) != plen)
	{
		start_lock();
		printf("Error while sending Router Solicitation on %s: %s\n",
		       ifname, strerror(errno));
		end_lock();
		close(fd);
		return -1;
	}

	/* receives an Advertisement */
	const ssize_t val = recv_adv(fd, &tgt, ifname, timeout);
	if(val > 0)
	{
		close(fd);
		return val;
	}
//	else if(val == 0) // Timed out
	if(val < 0)
	{
		// Error
		start_lock();
		printf("Error while receiving Router Advertisements on %s: %s\n",
		       ifname, strerror(errno));
		end_lock();
		close(fd);
		return -1;
	}

	// No DHCPv6 responses received
	close(fd);
	return 0;
}

int dhcpv6_discover_iface(const char *ifname, const unsigned int timeout)
{
	const int fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	const int errval = errno;

	// Drop root privileges after creating the raw socket for security
	// measures. This is a no-op if the process is not running as sudo.
	if (setuid(getuid()))
		return 1;

	errno = errval; /* restore socket() error value */
	return do_discoverv6(fd, ifname, timeout);
}
