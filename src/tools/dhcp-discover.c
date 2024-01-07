/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DHCP discover routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "dhcp-discover.h"
// format_time()
#include "log.h"
// readFTLconf()
#include "config/config.h"
// cli_bold(), etc.
#include "args.h"
// check_capability()
#include "capabilities.h"

#include <sys/time.h>
// SIOCGIFHWADDR
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

// strncpy()
#include <string.h>

//*** DHCP definitions **
#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312

#define DHCP_SERVER_PORT   67
#define DHCP_CLIENT_PORT   68

// Maximum time we wait for incoming DHCPOFFERs
// (seconds)
#define DHCPOFFER_TIMEOUT 10

// How many threads do we spawn at maximum?
// This is also the limit for interfaces
// we scan for DHCP activity.
#define MAXTHREADS 32

// Probe DHCP servers responding to the broadcast address
#define PROBE_BCAST

// Should we generate test data for DHCP option 249?
//#define TEST_OPT_249

// Global lock used by all threads
static pthread_mutex_t lock;
static void __attribute__((format(gnu_printf, 1, 2))) printf_locked(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	pthread_mutex_lock(&lock);
	vprintf(format, args);
	pthread_mutex_unlock(&lock);
	va_end(args);
}

extern const struct opttab_t {
  char *name;
  u16 val, size;
} opttab[];

// creates a socket for DHCP communication
static int create_dhcp_socket(const char *iname)
{
	struct sockaddr_in dhcp_socket;
	struct ifreq interface;
	int flag = 1;

	// Set up the address we're going to bind to (we will listen on any address).
	memset(&interface, 0, sizeof(interface));
	memset(&dhcp_socket, 0, sizeof(dhcp_socket));
	dhcp_socket.sin_family = AF_INET;
	dhcp_socket.sin_port = htons(DHCP_CLIENT_PORT);
	dhcp_socket.sin_addr.s_addr = INADDR_ANY;

	// create a socket for DHCP communications
	const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0)
	{
		printf_locked("Error: Could not create socket for interface %s!\n", iname);
		return -1;
	}

#ifdef DEBUG
	printf_locked("DHCP socket: %d\n", sock);
#endif
	// set the reuse address flag so we don't get errors when restarting
	if(setsockopt(sock,SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag))<0)
	{
		printf_locked("Error: Could not set reuse address option on DHCP socket (%s)!\n", iname);
		close(sock);
		return -1;
	}

	// set the broadcast option - we need this to listen to DHCP broadcast messages
	if(setsockopt(sock, SOL_SOCKET,SO_BROADCAST, (char *)&flag, sizeof flag) < 0)
	{
		printf_locked("Error: Could not set broadcast option on DHCP socket (%s)!\n", iname);
		close(sock);
		return -1;
	}

	// bind socket to interface
	strncpy(interface.ifr_ifrn.ifrn_name, iname, IFNAMSIZ-1);
	if(setsockopt(sock,SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0)
	{
		printf_locked("Error: Could not bind socket to interface %s (%s)\n",
		              iname, strerror(errno));
		close(sock);
		return -1;
	}

	// bind the socket
	if(bind(sock, (struct sockaddr *)&dhcp_socket, sizeof(dhcp_socket)) < 0)
	{
		printf_locked("Error: Could not bind to DHCP socket (interface %s, port %d, %s)\n",
		              iname, DHCP_CLIENT_PORT, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

// determines hardware address on client machine
int get_hardware_address(const int sock, const char *iname, unsigned char *mac)
{
	struct ifreq ifr;
	strncpy((char *)&ifr.ifr_name, iname, sizeof(ifr.ifr_name)-1);

	// try and grab hardware address of requested interface
	int ret = 0;
	if((ret = ioctl(sock, SIOCGIFHWADDR, &ifr)) < 0)
	{
		printf_locked(" Error: Could not get hardware address of interface %s: %s\n", iname, strerror(errno));
		return false;
	}
	memcpy(&mac[0], &ifr.ifr_hwaddr.sa_data, 6);
#ifdef DEBUG
	printf_locked("Hardware address of this interface: ");
	for (uint8_t i = 0; i < 6; ++i)
		printf_locked("%02x%s", mac[i], i < 5 ? ":" : "");
	printf_locked("\n");
#endif
	return true;
}

struct dhcp_packet_data
{
	u_int8_t op;                                    // packet type
	u_int8_t htype;                                 // type of hardware address for this machine (Ethernet, etc)
	u_int8_t hlen;                                  // length of hardware address (of this machine)
	u_int8_t hops;                                  // hops
	u_int32_t xid;                                  // random transaction id number - chosen by this machine
	u_int16_t secs;                                 // seconds used in timing
	u_int16_t flags;                                // flags
	struct in_addr ciaddr;                          // IP address of this machine (if we already have one)
	struct in_addr yiaddr;                          // IP address of this machine (offered by the DHCP server)
	struct in_addr siaddr;                          // IP address of DHCP server
	struct in_addr giaddr;                          // IP address of DHCP relay
	unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];  // hardware address of this machine
	char sname [MAX_DHCP_SNAME_LENGTH];             // name of DHCP server
	char file [MAX_DHCP_FILE_LENGTH];               // boot file name (used for diskless booting?)
	char options[MAX_DHCP_OPTIONS_LENGTH];          // options
};

// sends a DHCPDISCOVER message to the specified in an attempt to find DHCP servers
static bool send_dhcp_discover(const int sock, const uint32_t xid, const char *iface, unsigned char *mac)
{
	struct dhcp_packet_data discover_packet = { 0 };

	// Boot request flag (backward compatible with BOOTP servers)
	discover_packet.op = 1; // BOOTREQUEST

	// Hardware address type
	discover_packet.htype = 1; // ETHERNET_HARDWARE_ADDRESS

	// Length of our hardware address
	discover_packet.hlen = 6; // ETHERNET_HARDWARE_ADDRESS_LENGTH
	discover_packet.hops = 0;

	// Transaction id is supposed to be random
	discover_packet.xid = htonl(xid);
	discover_packet.secs = 0x00;

	// Tell server it should broadcast its response
	discover_packet.flags = htons(32768); // DHCP_BROADCAST_FLAG

	// Our hardware address
	memcpy(discover_packet.chaddr, mac, 6);

	// First four bytes of options field are the magic cookie (as per RFC 2132)
	discover_packet.options[0] = '\x63';
	discover_packet.options[1] = '\x82';
	discover_packet.options[2] = '\x53';
	discover_packet.options[3] = '\x63';

	// DHCP message type is embedded in options field
	discover_packet.options[4] = 53; // DHCP message type option identifier
	discover_packet.options[5] = 1;  // DHCP message option length in bytes
	discover_packet.options[6] = 1;  // DHCP message type code for DHCPDISCOVER

	// Place end option at the end of the options
	discover_packet.options[7] = 255;

	// Send the DHCPDISCOVER packet to the specified address
	struct sockaddr_in target = { 0 };
	target.sin_family = AF_INET;
	target.sin_port = htons(DHCP_SERVER_PORT);
	target.sin_addr.s_addr = INADDR_BROADCAST;

#ifdef DEBUG
	printf_locked("Sending DHCPDISCOVER on interface %s@%s ... \n", inet_ntoa(target.sin_addr), iface);
	printf_locked("DHCPDISCOVER XID: %lu (0x%X)\n", (unsigned long) ntohl(discover_packet.xid), ntohl(discover_packet.xid));
	printf_locked("DHCDISCOVER ciaddr:  %s\n", inet_ntoa(discover_packet.ciaddr));
	printf_locked("DHCDISCOVER yiaddr:  %s\n", inet_ntoa(discover_packet.yiaddr));
	printf_locked("DHCDISCOVER siaddr:  %s\n", inet_ntoa(discover_packet.siaddr));
	printf_locked("DHCDISCOVER giaddr:  %s\n", inet_ntoa(discover_packet.giaddr));
#endif
	// send the DHCPDISCOVER packet
	const int bytes = sendto(sock, (char *)&discover_packet, sizeof(discover_packet), 0, (struct sockaddr *)&target, sizeof(target));
	if(bytes < 0)
	{
		// strerror() returns "Required key not available" for ENOKEY
		// which is not helpful at all so we substitute a more
		// meaningful error message for ENOKEY returned by wireguard interfaces
		// (see https://www.wireguard.com/papers/wireguard.pdf, page 5)
		const char *error = errno == ENOKEY ? "No route to host (no such peer available)" : strerror(errno);
		printf_locked("Error: Could not send DHCPDISCOVER to %s@%s: %s\n",
		              inet_ntoa(target.sin_addr), iface, error);
		return false;
	}

#ifdef DEBUG
	printf_locked("Sent %d bytes\n", bytes);
#endif
	return true;
}

#ifdef TEST_OPT_249
static void gen_249_test_data(dhcp_packet_data *offer_packet)
{
	// Test data for DHCP option 249 (length 14)
	// See https://discourse.pi-hole.net/t/pi-hole-unbound-via-wireguard-stops-working-over-night/49149
	char test_data[] = { 249, 14, 0x20, 0xAC, 0x1F, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAC, 0x1F, 0x01, 0x01};
	// The first 4 bytes are DHCP magic cookie
	memcpy(&offer_packet->options[4], test_data, sizeof(test_data));
	offer_packet->options[sizeof(test_data)+4] = 0;
}
#endif

// adds a DHCP OFFER to list in memory
static void print_dhcp_offer(struct in_addr source, struct dhcp_packet_data *offer_packet)
{
	if(offer_packet == NULL)
		return;

	// Generate option test data
#ifdef TEST_OPT_249
	gen_249_test_data(offer_packet);
#endif

	// process all DHCP options present in the packet
	// We start from 4 as the first 32 bit are the DHCP magic coockie (verified before)
	for(unsigned int x = 4; x < MAX_DHCP_OPTIONS_LENGTH;)
	{
		// End of options
		if(offer_packet->options[x] == 0)
			break;

		// Sanity check
		if(x >= MAX_DHCP_OPTIONS_LENGTH-2)
		{
			printf(" OVERFLOWING DHCP OPTION (invalid size)\n");
			break;
		}

		// get option type
		const uint8_t opttype = offer_packet->options[x++];

		// get option length
		const uint8_t optlen = offer_packet->options[x++];

		printf("   ");

		// Sanity check
		if(x + optlen > MAX_DHCP_OPTIONS_LENGTH)
		{
			printf(" OVERFLOWING DHCP OPTION (invalid size)\n");
			break;
		}

		// Interpret option data, see RFC 1497 and RFC 2132, Section 3 for further details
		// A nice summary can be found in https://tools.ietf.org/html/rfc2132#section-3
		bool found = false;
		for (unsigned int i = 0; opttab[i].name != NULL; i++)
		{
			if(opttab[i].val != opttype)
				continue;

			found = true;
			if(opttab[i].size & OT_ADDR_LIST)
			{
				for(unsigned int n = 0; n < optlen/4; n++)
				{
					struct in_addr addr_list = { 0 };
					memcpy(&addr_list.s_addr, &offer_packet->options[x+n*4], sizeof(addr_list.s_addr));
					if(n > 0)
						printf("   ");

					printf("%s: %s\n", opttab[i].name, inet_ntoa(addr_list));
				}

				// Special case: optlen == 0
				if(optlen == 0)
					printf("--- end of options ---\n");
			}
			else if(opttab[i].size & OT_NAME)
			{
				// We may need to escape this, buffer size: 4
				// chars per control character plus room for
				// possible "(empty)"
				const size_t bufsiz = 4*optlen + 9;
				char *buffer = calloc(bufsiz, sizeof(char));
				binbuf_to_escaped_C_literal(&offer_packet->options[x], optlen, buffer, bufsiz);
				printf("%s: \"%s\"\n", opttab[i].name, buffer);
				free(buffer);
			}
			else if(opttab[i].size & OT_TIME)
			{
				uint32_t time = 0;
				memcpy(&time, &offer_packet->options[x], sizeof(time));
				time = ntohl(time);
				const char *optname = opttab[i].name;
				// Some timers deserve a more user-friedly name
				if(opttype == 58)
					optname = "renewal-time"; // "T1" in dnsmasq-notation
				else if(opttype == 59)
					optname = "rebinding-time"; // "T2" in dnsmasq-notation

				if(time == 0xFFFFFFFF)
					printf("%s: Infinite\n", optname);
				else
				{
					char buffer[42] = { 0 };
					format_time(buffer, time, 0.0);
					printf("%s: %lu (%s)\n", optname, (unsigned long)time, buffer);
				}
			}
			else if(opttab[i].size & OT_DEC)
			{
				if(opttype == 53) // DHCP MESSAGE TYPE
				{
					switch(offer_packet->options[x])
					{
						case 1:
							printf("Message type: DHCPDISCOVER (1)\n");
							break;
						case 2:
							printf("Message type: DHCPOFFER (2)\n");
							break;
						case 3:
							printf("Message type: DHCPREQUEST (3)\n");
							break;
						case 4:
							printf("Message type: DHCPDECLINE (4)\n");
							break;
						case 5:
							printf("Message type: DHCPACK (5)\n");
							break;
						case 6:
							printf("Message type: DHCPNAK (6)\n");
							break;
						case 7:
							printf("Message type: DHCPRELEASE (7)\n");
							break;
						case 8:
							printf("Message type: DHCPINFORM (8)\n");
							break;
						default:
							printf("Message type: UNKNOWN (%hhu)\n",
							       (unsigned char)offer_packet->options[x]);
							break;
					}
				}
				else
				{
					// Log generic (unsigned) number
					uint32_t number = 0;
					if(optlen <= 4)
					{
						memcpy(&number, &offer_packet->options[x], optlen);
						if(optlen == 2)
							number = ntohs(number);
						else if(optlen == 4)
							number = ntohl(number);
						printf("%s: %u\n", opttab[i].name, number);
					}
				}
			}
		}

		// Log some special messages that are not handled by dnsmasq
		if(!found)
		{
			if(opttype == 252) // WPAD configuration (this is a non-standard extension)
			{                  // see INTERNET-DRAFT Web Proxy Auto-Discovery Protocol
			                   // https://tools.ietf.org/html/draft-ietf-wrec-wpad-01
				// We may need to escape this, buffer size: 4
				// chars per control character plus room for
				// possible "(empty)"
				char *buffer = calloc(4*optlen + 9, sizeof(char));
				binbuf_to_escaped_C_literal(&offer_packet->options[x], optlen, buffer, sizeof(buffer));
				printf("wpad-server: \"%s\"\n", buffer);
				free(buffer);
			}
			else if(opttype == 158) // DHCPv4 PCP Option (RFC 7291)
			{                       // https://tools.ietf.org/html/rfc7291#section-4
				uint16_t list_length = offer_packet->options[x++] / 4; // 4 bytes per list entry
				// Loop over IPv4 lists
				for(unsigned int n = 0; n < list_length; n++)
				{
					struct in_addr addr_list = { 0 };
					if(optlen < (n+1)*sizeof(addr_list.s_addr))
						break;
					memcpy(&addr_list.s_addr, &offer_packet->options[x+n*sizeof(addr_list.s_addr)], sizeof(addr_list.s_addr));
					if(n > 0)
						printf("   ");

					printf("Port Control Protocol (PCP) server: %s\n", inet_ntoa(addr_list));
				}
			}
			else if((opttype == 121 || opttype == 249) && optlen > 4)
			{
				// RFC 3442 / Microsoft Classless Static Route Option
				// see
				// - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpe/f9c19c79-1c7f-4746-b555-0c0fc523f3f9
				// - https://datatracker.ietf.org/doc/html/rfc3442 (page 3)
				printf("%s Classless Static Route:\n", opttype == 121 ? "RFC 3442" : "Microsoft");
				// Loop over contained routes
				unsigned int n = 0;
				for(unsigned int i = 1; n < optlen; i++)
				{
					// Extract destination descriptor
					unsigned char cidr = offer_packet->options[x+n++];
					unsigned char addr[4] = { 0 };
					if(cidr > 0)
						addr[0] = offer_packet->options[x+n++];
					if(cidr > 8)
						addr[1] = offer_packet->options[x+n++];
					if(cidr > 16)
						addr[2] = offer_packet->options[x+n++];
					if(cidr > 24)
						addr[3] = offer_packet->options[x+n++];

					// Extract router address
					unsigned char router[4] = { 0 };
					for(int j = 0; j < 4; j++)
						router[j] = offer_packet->options[x+n++];

					if(cidr == 0)
					{
						// default route (0.0.0.0/0)
						printf("     %u: default via %u.%u.%u.%u\n\n", i,
						       router[0], router[1], router[2], router[3]);
					}
					else
					{
						// specific route
						printf("     %u: %u.%u.%u.%u/%u via %u.%u.%u.%u\n", i,
						       addr[0], addr[1], addr[2], addr[3], cidr,
						       router[0], router[1], router[2], router[3]);
					}
				}
			}
			else
			{
				printf("Unknown option %d:", opttype);
				// Print bytes
				for(unsigned i = 0; i < optlen; i++)
					printf(" %02X", (unsigned char)offer_packet->options[x+i]);
				// Add newline when done above
				printf(" (length %d)\n", optlen);
			}
		}

		// Advance option pointer index
		x += optlen;
	}

	// Add one empty line for readability
	printf("\n");
}

// receives a DHCP packet
static bool receive_dhcp_packet(void *buffer, int buffer_size, const char *iface, int sock, const time_t start_time, struct sockaddr_in *address)
{
	struct timeval tv;
	fd_set readfds;
	int recv_result;
	socklen_t address_size;

	// Wait for data to arrive
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	// see "man select" for the "sock + 1"
	select(sock + 1, &readfds, NULL, NULL, &tv);

	// make sure some data has arrived
	if(!FD_ISSET(sock, &readfds))
		return false;

	address_size = sizeof(struct sockaddr_in);
	recv_result = recvfrom(sock, (char *)buffer, buffer_size, 0, (struct sockaddr *)address, &address_size);

	printf_locked("\n* Received %d bytes from %s @ %s\n", recv_result, inet_ntoa(address->sin_addr), iface);
#ifdef DEBUG
	printf_locked("  after waiting for %f seconds\n", difftime(time(NULL), start_time));
#endif
	// Return on error
	if(recv_result == -1)
	{
		printf_locked(" recvfrom() failed on %s, error: %s\n", iface, strerror(errno));
		return false;
	}

	return true;
}

// waits for a DHCPOFFER message from one or more DHCP servers
static void get_dhcp_offer(const int sock, const uint32_t xid, const char *iface, unsigned char *mac)
{
	struct dhcp_packet_data offer_packet;
	struct sockaddr_in source;
	unsigned int responses = 0;
	unsigned int valid_responses = 0;
	time_t start_time;
	time_t current_time;

	time(&start_time);

	// receive as many responses as we can
	while(time(&current_time) && (current_time-start_time) < DHCPOFFER_TIMEOUT)
	{
		memset(&source, 0, sizeof(source));
		memset(&offer_packet, 0, sizeof(offer_packet));

		if(!receive_dhcp_packet(&offer_packet, sizeof(offer_packet), iface, sock, start_time, &source))
			continue;
		else
			responses++;

#ifdef DEBUG
		printf(" DHCPOFFER XID: %lu (0x%X)\n", (unsigned long) ntohl(offer_packet.xid), ntohl(offer_packet.xid));
#endif

		// check packet xid to see if its the same as the one we used in the discover packet
		if(ntohl(offer_packet.xid) != xid)
		{
			printf("  DHCPOFFER XID (%lu) does not match our DHCPDISCOVER XID (%lu) - ignoring packet (not for us)\n",
			       (unsigned long) ntohl(offer_packet.xid), (unsigned long) xid);

			pthread_mutex_unlock(&lock);
			continue;
		}

		// check hardware address
		if(memcmp(offer_packet.chaddr, mac, 6) != 0)
		{
			printf("  DHCPOFFER hardware address did not match our own - ignoring packet (not for us)\n");

			printf("  DHCPREQUEST chaddr: ");
			for(uint8_t x = 0; x < 6; x++)
				printf("%02x%s", mac[x], x < 5 ? ":" : "");
			printf(" (our MAC address)\n");

			printf("  DHCPOFFER   chaddr: ");
			for(uint8_t x = 0; x < 6; x++)
				printf("%02x%s", offer_packet.chaddr[x], x < 5 ? ":" : "");
			printf(" (response MAC address)\n");

			pthread_mutex_unlock(&lock);
			continue;
		}

		printf("  Offered IP address: ");
		if(offer_packet.yiaddr.s_addr != 0)
			printf("%s\n", inet_ntoa(offer_packet.yiaddr));
		else
			printf("N/A\n");

		printf("  Server IP address: ");
		if(offer_packet.siaddr.s_addr != 0)
			printf("%s\n", inet_ntoa(offer_packet.siaddr));
		else
			printf("N/A\n");

		printf("  Relay-agent IP address: ");
		if(offer_packet.giaddr.s_addr != 0)
			printf("%s\n", inet_ntoa(offer_packet.giaddr));
		else
			printf("N/A\n");

		printf("  BOOTP server: ");
		if(offer_packet.sname[0] != 0)
		{
			size_t len = strlen(offer_packet.sname);
			char *buffer = calloc(4*len + 9, sizeof(char));
			binbuf_to_escaped_C_literal(offer_packet.sname, len, buffer, sizeof(buffer));
			printf("%s\n", buffer);
			free(buffer);
		}
		else
			printf("(empty)\n");

		printf("  BOOTP file: ");
		if(offer_packet.file[0] != 0)
		{
			size_t len = strlen(offer_packet.file);
			char *buffer = calloc(4*len + 9, sizeof(char));
			binbuf_to_escaped_C_literal(offer_packet.file, len, buffer, sizeof(buffer));
			printf("%s\n", buffer);
			free(buffer);
		}
		else
			printf("(empty)\n");

		printf("  DHCP options:\n");
		print_dhcp_offer(source.sin_addr, &offer_packet);
		pthread_mutex_unlock(&lock);

		valid_responses++;
	}
	if(responses == valid_responses)
		printf("DHCP packets received on %s%s%s: %u\n",
		       cli_bold(), iface, cli_normal(), valid_responses);
	else
		printf("DHCP packets received on %s%s%s: %u (%u seen for other machines)\n",
		       cli_bold(), iface, cli_normal(), valid_responses, responses);

#ifdef DEBUG
	printf(" Responses seen while scanning:    %u\n", responses);
	printf(" Responses meant for this machine: %u\n\n", valid_responses);
#endif
}

static void *dhcp_discover_iface(void *args)
{
	// Get interface details
	const char *iface = ((struct ifaddrs*)args)->ifa_name;

	// Set interface name as thread name
	prctl(PR_SET_NAME, iface, 0, 0, 0);

	// create socket for DHCP communications
	const int dhcp_socket = create_dhcp_socket(iface);

	// Cannot create socket, likely a permission error
	if(dhcp_socket < 0)
		goto end_dhcp_discover_iface;

	// get hardware address of client machine
	unsigned char mac[MAX_DHCP_CHADDR_LENGTH] = { 0 };
	get_hardware_address(dhcp_socket, iface, mac);

	// Generate pseudo-random transaction ID
	srand((unsigned int)time(NULL));
	const uint32_t xid = (uint32_t)random();

	// Probe servers on this interface
	if(!send_dhcp_discover(dhcp_socket, xid, iface, mac))
		goto end_dhcp_discover_iface;

	// wait for a DHCPOFFER packet
	get_dhcp_offer(dhcp_socket, xid, iface, mac);

end_dhcp_discover_iface:
	// Close socket if we created one
	if(dhcp_socket > 0)
		close(dhcp_socket);

	pthread_exit(NULL);
}

int run_dhcp_discover(void)
{
	// Check if we are capable of binding to port 67 (DHCP)
	// DHCP uses normal UDP datagrams, so we cdon't need CAP_NET_RAW
	if(!check_capability(CAP_NET_BIND_SERVICE))
	{
		puts("Error: Insufficient permissions or capabilities (needs CAP_NET_BIND_SERVICE). Try running as root (sudo)");
		return EXIT_FAILURE;
	}

	// Disable terminal output during config config file parsing
	log_ctrl(false, false);
	// Process pihole-FTL.conf to get gravity.db
	readFTLconf(&config, false);
	// Only print to terminal, disable log file
	log_ctrl(false, true);

	printf("Scanning all your interfaces for DHCP servers\n");
	printf("Timeout: %d seconds\n", DHCPOFFER_TIMEOUT);

	// Get interface names for available interfaces on this machine
	// and launch a thread for each one
	pthread_t scanthread[MAXTHREADS];
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);

	// Create processing/printfing lock
	pthread_mutexattr_t lock_attr = {};
	// Initialize the lock attributes
	pthread_mutexattr_init(&lock_attr);
	// Initialize the lock
	pthread_mutex_init(&lock, &lock_attr);
	// Destroy the lock attributes since we're done with it
	pthread_mutexattr_destroy(&lock_attr);

	struct ifaddrs *addrs, *tmp;
	getifaddrs(&addrs);
	tmp = addrs;

	// Loop until there are no more interfaces available
	// or we reached the maximum number of threads
	int tid = 0;
	while(tmp != NULL && tid < MAXTHREADS)
	{
		// Create a thread for interfaces of type AF_INET (IPv4)
		if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
		{
			// Skip interface scan if ...
			// - interface is not up
			// - broadcast is not supported
			// - interface is loopback net
			if(!(tmp->ifa_flags & IFF_UP) ||
			   !(tmp->ifa_flags & IFF_BROADCAST) ||
			     tmp->ifa_flags & IFF_LOOPBACK)
			{
				tmp = tmp->ifa_next;
				continue;
			}

			// Create a probing thread for this interface
			if(pthread_create(&scanthread[tid], &attr, dhcp_discover_iface, tmp ) != 0)
			{
				printf_locked("Unable to launch thread for interface %s, skipping...",
				              tmp->ifa_name);
				tmp = tmp->ifa_next;
				continue;
			}

			// Increase thread ID
			tid++;
		}

		// Advance to the next interface
		tmp = tmp->ifa_next;
	}

	// Wait for all threads to join back with us
	for(tid--; tid > -1; tid--)
		pthread_join(scanthread[tid], NULL);

	// Free linked-list of interfaces on this client
	freeifaddrs(addrs);

	return EXIT_SUCCESS;
}
