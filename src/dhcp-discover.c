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
// logg(), format_time()
#include "log.h"
// read_FTLconf()
#include "config.h"

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
		logg("Error: Could not create socket for interface %s!", iname);
		return -1;
	}

#ifdef DEBUG
	logg("DHCP socket: %d", sock);
#endif
	// set the reuse address flag so we don't get errors when restarting
	if(setsockopt(sock,SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag))<0)
	{
		logg("Error: Could not set reuse address option on DHCP socket (%s)!", iname);
		close(sock);
		return -1;
	}

	// set the broadcast option - we need this to listen to DHCP broadcast messages
	if(setsockopt(sock, SOL_SOCKET,SO_BROADCAST, (char *)&flag, sizeof flag) < 0)
	{
		logg("Error: Could not set broadcast option on DHCP socket (%s)!", iname);
		close(sock);
		return -1;
	}

	// bind socket to interface
	strncpy(interface.ifr_ifrn.ifrn_name, iname, IFNAMSIZ-1);
	if(setsockopt(sock,SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0)
	{
		logg("Error: Could not bind socket to interface %s (%s)\n       ---> Check your privileges (run with sudo)!\n",
		     iname, strerror(errno));
		close(sock);
		return -1;
	}

	// bind the socket
	if(bind(sock, (struct sockaddr *)&dhcp_socket, sizeof(dhcp_socket)) < 0)
	{
		logg("Error: Could not bind to DHCP socket (interface %s, port %d, %s)\n       ---> Check your privileges (run with sudo)!\n",
		     iname, DHCP_CLIENT_PORT, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

// determines hardware address on client machine
static int get_hardware_address(const int sock, const char *iname, unsigned char *mac)
{
	struct ifreq ifr;
	strncpy((char *)&ifr.ifr_name, iname, sizeof(ifr.ifr_name)-1);

	// try and grab hardware address of requested interface
	int ret = 0;
	if((ret = ioctl(sock, SIOCGIFHWADDR, &ifr)) < 0){
		logg(" Error: Could not get hardware address of interface '%s' (socket %d, error: %s)", iname, sock, strerror(errno));
		return false;
	}
	memcpy(&mac[0], &ifr.ifr_hwaddr.sa_data, 6);
#ifdef DEBUG
	logg_sameline("Hardware address of this interface: ");
	for (uint8_t i = 0; i < 6; ++i)
		logg_sameline("%02x%s", mac[i], i < 5 ? ":" : "");
	logg(" ");
#endif
	return true;
}

typedef struct dhcp_packet_struct
{
	u_int8_t  op;                   // packet type
	u_int8_t  htype;                // type of hardware address for this machine (Ethernet, etc)
	u_int8_t  hlen;                 // length of hardware address (of this machine)
	u_int8_t  hops;                 // hops
	u_int32_t xid;                  // random transaction id number - chosen by this machine
	u_int16_t secs;                 // seconds used in timing
	u_int16_t flags;                // flags
	struct in_addr ciaddr;          // IP address of this machine (if we already have one)
	struct in_addr yiaddr;          // IP address of this machine (offered by the DHCP server)
	struct in_addr siaddr;          // IP address of DHCP server
	struct in_addr giaddr;          // IP address of DHCP relay
	unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      // hardware address of this machine
	char sname [MAX_DHCP_SNAME_LENGTH];    // name of DHCP server
	char file [MAX_DHCP_FILE_LENGTH];      // boot file name (used for diskless booting?)
	char options[MAX_DHCP_OPTIONS_LENGTH];  // options
} dhcp_packet_data;

#define BOOTREQUEST     1
#define BOOTREPLY       2

// sends a DHCPDISCOVER message to the specified in an attempt to find DHCP servers
static bool send_dhcp_discover(const int sock, const uint32_t xid, const char *iface, unsigned char *mac, const in_addr_t addr)
{
	dhcp_packet_data discover_packet;

	// clear the packet data structure
	memset(&discover_packet, 0, sizeof(discover_packet));

	// boot request flag (backward compatible with BOOTP servers)
	discover_packet.op = BOOTREQUEST;

	// hardware address type
	discover_packet.htype = 1; // ETHERNET_HARDWARE_ADDRESS;

	// length of our hardware address
	discover_packet.hlen = 6; // ETHERNET_HARDWARE_ADDRESS_LENGTH;
	discover_packet.hops = 0;

	// transaction id is supposed to be random
	discover_packet.xid = htonl(xid);
	ntohl(discover_packet.xid);
	discover_packet.secs = 0x00;

	// tell server it should broadcast its response
	discover_packet.flags = htons(32768); // DHCP_BROADCAST_FLAG

	// our hardware address
	memcpy(discover_packet.chaddr, mac, 6);

	// first four bytes of options field is magic cookie (as per RFC 2132)
	discover_packet.options[0] = '\x63';
	discover_packet.options[1] = '\x82';
	discover_packet.options[2] = '\x53';
	discover_packet.options[3] = '\x63';

	// DHCP message type is embedded in options field
	discover_packet.options[4] = 53;     // DHCP message type option identifier
	discover_packet.options[5] = '\x01'; // DHCP message option length in bytes
	discover_packet.options[6] = 1;      // DHCP message type code for DHCPDISCOVER

	// Place end option at the end of the options
	discover_packet.options[7] = 255;

	// send the DHCPDISCOVER packet to the specified address
	struct sockaddr_in target;
	target.sin_family = AF_INET;
	target.sin_port = htons(DHCP_SERVER_PORT);
	target.sin_addr.s_addr = addr;
	memset(&target.sin_zero, 0, sizeof(target.sin_zero));

#ifdef DEBUG
	logg("Sending DHCPDISCOVER on interface %s:%s ... ", iface, inet_ntoa(target.sin_addr));
	logg("DHCPDISCOVER XID: %lu (0x%X)", (unsigned long) ntohl(discover_packet.xid), ntohl(discover_packet.xid));
	logg("DHCDISCOVER ciaddr:  %s", inet_ntoa(discover_packet.ciaddr));
	logg("DHCDISCOVER yiaddr:  %s", inet_ntoa(discover_packet.yiaddr));
	logg("DHCDISCOVER siaddr:  %s", inet_ntoa(discover_packet.siaddr));
	logg("DHCDISCOVER giaddr:  %s", inet_ntoa(discover_packet.giaddr));
#endif
	// send the DHCPDISCOVER packet
	const int bytes = sendto(sock, (char *)&discover_packet, sizeof(discover_packet), 0, (struct sockaddr *)&target,sizeof(target));
#ifdef DEBUG
	logg("Sent %d bytes", bytes);
#endif

	return bytes > 0;
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
static void print_dhcp_offer(struct in_addr source, dhcp_packet_data *offer_packet)
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
			logg(" OVERFLOWING DHCP OPTION (invalid size)");
			break;
		}

		// get option type
		const uint8_t opttype = offer_packet->options[x++];

		// get option length
		const uint8_t optlen = offer_packet->options[x++];

		logg_sameline("   ");

		// Sanity check
		if(x + optlen > MAX_DHCP_OPTIONS_LENGTH)
		{
			logg(" OVERFLOWING DHCP OPTION (invalid size)");
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
						logg_sameline("   ");

					logg("%s: %s", opttab[i].name, inet_ntoa(addr_list));
				}

				// Special case: optlen == 0
				if(optlen == 0)
					logg("--- end of options ---");
			}
			else if(opttab[i].size & OT_NAME)
			{
				// We may need to escape this, buffer size: 4
				// chars per control character plus room for
				// possible "(empty)"
				char buffer[4*optlen + 9];
				binbuf_to_escaped_C_literal(&offer_packet->options[x], optlen, buffer, sizeof(buffer));
				logg("%s: \"%s\"", opttab[i].name, buffer);
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
					logg("%s: Infinite", optname);
				else
				{
					char buffer[42] = { 0 };
					format_time(buffer, time, 0.0);
					logg("%s: %lu (%s)", optname, (unsigned long)time, buffer);
				}
			}
			else if(opttab[i].size & OT_DEC)
			{
				if(opttype == 53) // DHCP MESSAGE TYPE
				{
					switch(offer_packet->options[x])
					{
						case 1:
							logg("Message type: DHCPDISCOVER (1)");
							break;
						case 2:
							logg("Message type: DHCPOFFER (2)");
							break;
						case 3:
							logg("Message type: DHCPREQUEST (3)");
							break;
						case 4:
							logg("Message type: DHCPDECLINE (4)");
							break;
						case 5:
							logg("Message type: DHCPACK (5)");
							break;
						case 6:
							logg("Message type: DHCPNAK (6)");
							break;
						case 7:
							logg("Message type: DHCPRELEASE (7)");
							break;
						case 8:
							logg("Message type: DHCPINFORM (8)");
							break;
						default:
							logg("Message type: UNKNOWN (%u)", offer_packet->options[x]);
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
						logg("%s: %u", opttab[i].name, number);
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
				char buffer[4*optlen + 9];
				binbuf_to_escaped_C_literal(&offer_packet->options[x], optlen, buffer, sizeof(buffer));
				logg("wpad-server: \"%s\"", buffer);
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
						logg_sameline("   ");

					logg("Port Control Protocol (PCP) server: %s", inet_ntoa(addr_list));
				}
			}
			else if((opttype == 121 || opttype == 249) && optlen > 4)
			{
				// RFC 3442 / Microsoft Classless Static Route Option
				// see
				// - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpe/f9c19c79-1c7f-4746-b555-0c0fc523f3f9
				// - https://datatracker.ietf.org/doc/html/rfc3442 (page 3)
				logg("%s Classless Static Route:", opttype == 121 ? "RFC 3442" : "Microsoft");
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
						logg("     %d: default via %d.%d.%d.%d", i,
						     router[0], router[1], router[2], router[3]);
					}
					else
					{
						// specific route
						logg("     %d: %d.%d.%d.%d/%d via %d.%d.%d.%d", i,
						     addr[0], addr[1], addr[2], addr[3], cidr,
						     router[0], router[1], router[2], router[3]);
					}
				}
			}
			else
			{
				logg_sameline("Unknown option %d:", opttype);
				// Print bytes
				for(unsigned i = 0; i < optlen; i++)
					logg_sameline(" %02X", (unsigned char)offer_packet->options[x+i]);
				// Add newline when done above
				logg(" (length %d)", optlen);
			}
		}

		// Advance option pointer index
		x += optlen;
	}

	// Add one empty line for readability
	logg(" ");
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

	logg("* Received %d bytes from %s:%s", recv_result, iface, inet_ntoa(address->sin_addr));
#ifdef DEBUG
	logg("  after waiting for %f seconds", difftime(time(NULL), start_time));
#endif
	// Return on error
	if(recv_result == -1){
		logg(" recvfrom() failed on %s, error: %s", iface, strerror(errno));
		return false;
	}

	return true;
}

// waits for a DHCPOFFER message from one or more DHCP servers
static bool get_dhcp_offer(const int sock, const uint32_t xid, const char *iface, unsigned char *mac)
{
	dhcp_packet_data offer_packet;
	struct sockaddr_in source;
#ifdef DEBUG
	unsigned int responses = 0;
#endif
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
#ifdef DEBUG
		else
			responses++;
#endif

		if(pthread_mutex_lock(&lock) != 0)
			return false;

#ifdef DEBUG
		logg(" DHCPOFFER XID: %lu (0x%X)", (unsigned long) ntohl(offer_packet.xid), ntohl(offer_packet.xid));
#endif

		// check packet xid to see if its the same as the one we used in the discover packet
		if(ntohl(offer_packet.xid) != xid)
		{
			logg("  DHCPOFFER XID (%lu) does not match our DHCPDISCOVER XID (%lu) - ignoring packet (not for us)\n",
			     (unsigned long) ntohl(offer_packet.xid), (unsigned long) xid);

			pthread_mutex_unlock(&lock);
			continue;
		}

		// check hardware address
		if(memcmp(offer_packet.chaddr, mac, 6) != 0)
		{
			logg("  DHCPOFFER hardware address did not match our own - ignoring packet (not for us)");

			logg_sameline("  DHCPREQUEST chaddr: ");
			for(uint8_t x = 0; x < 6; x++)
				logg_sameline("%02x%s", mac[x], x < 5 ? ":" : "");
			logg(" (our MAC address)");

			logg_sameline("  DHCPOFFER   chaddr: ");
			for(uint8_t x = 0; x < 6; x++)
				logg_sameline("%02x%s", offer_packet.chaddr[x], x < 5 ? ":" : "");
			logg(" (response MAC address)");

			pthread_mutex_unlock(&lock);
			continue;
		}

		logg_sameline("  Offered IP address: ");
		if(offer_packet.yiaddr.s_addr != 0)
			logg("%s", inet_ntoa(offer_packet.yiaddr));
		else
			logg("N/A");

		logg_sameline("  Server IP address: ");
		if(offer_packet.siaddr.s_addr != 0)
			logg("%s", inet_ntoa(offer_packet.siaddr));
		else
			logg("N/A");

		logg_sameline("  Relay-agent IP address: ");
		if(offer_packet.giaddr.s_addr != 0)
			logg("%s", inet_ntoa(offer_packet.giaddr));
		else
			logg("N/A");

		logg_sameline("  BOOTP server: ");
		if(offer_packet.sname[0] != 0)
		{
			size_t len = strlen(offer_packet.sname);
			char buffer[4*len + 9];
			binbuf_to_escaped_C_literal(offer_packet.sname, len, buffer, sizeof(buffer));
			logg("%s", buffer);
		}
		else
			logg("(empty)");

		logg_sameline("  BOOTP file: ");
		if(offer_packet.file[0] != 0)
		{
			size_t len = strlen(offer_packet.file);
			char buffer[4*len + 9];
			binbuf_to_escaped_C_literal(offer_packet.file, len, buffer, sizeof(buffer));
			logg("%s", buffer);
		}
		else
			logg("(empty)");

		logg("  DHCP options:");
		print_dhcp_offer(source.sin_addr, &offer_packet);
		pthread_mutex_unlock(&lock);

		valid_responses++;
	}
#ifdef DEBUG
	logg(" Responses seen while scanning:    %d", responses);
	logg(" Responses meant for this machine: %d\n", valid_responses);
#endif
	logg("DHCP packets received on interface %s: %u", iface, valid_responses);
	return true;
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
		pthread_exit(NULL);

	// get hardware address of client machine
	unsigned char mac[MAX_DHCP_CHADDR_LENGTH] = { 0 };
	get_hardware_address(dhcp_socket, iface, mac);

	// Generate pseudo-random transaction ID
	srand(time(NULL));
	const uint32_t xid = random();

	if(strcmp(iface, "lo") == 0)
	{
		// Probe a local server listening on this interface
		// Send DHCPDISCOVER packet to interface address
		struct sockaddr_in ifaddr = { 0 };
		memcpy(&ifaddr, ((struct ifaddrs*)args)->ifa_addr, sizeof(ifaddr));
		send_dhcp_discover(dhcp_socket, xid, iface, mac, ifaddr.sin_addr.s_addr);
	}
	else
	{
		// Probe distant servers
		// Send DHCPDISCOVER packet to broadcast address
		send_dhcp_discover(dhcp_socket, xid, iface, mac, INADDR_BROADCAST);
	}

	// wait for a DHCPOFFER packet
	get_dhcp_offer(dhcp_socket, xid, iface, mac);

	// close socket we created
	close(dhcp_socket);

	pthread_exit(NULL);
}

int run_dhcp_discover(void)
{
	// Disable terminal output during config config file parsing
	log_ctrl(false, false);
	// Process pihole-FTL.conf to get gravity.db
	read_FTLconf();
	// Only print to terminal, disable log file
	log_ctrl(false, true);

	logg("Scanning all your interfaces for DHCP servers");
	logg("Timeout: %d seconds\n", DHCPOFFER_TIMEOUT);

	// Get interface names for available interfaces on this machine
	// and launch a thread for each one
	pthread_t scanthread[MAXTHREADS];
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);

	// Create processing/logging lock
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
		// Create a thread for interfaces of type AF_PACKET
		if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
		{
			if(pthread_create(&scanthread[tid], &attr, dhcp_discover_iface, tmp ) != 0)
			{
				logg("Unable to launch thread for interface %s, skipping...",
				     tmp->ifa_name);
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
