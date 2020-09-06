/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DHCP discover routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "dhcp-discover.h"
// logg()
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
#define DHCPOFFER_TIMEOUT 5

// How many threads do we spawn at maximum?
// This is also the limit for interfaces
// we scan for DHCP activity.
#define MAXTHREADS 32

unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH]="";

// creates a socket for DHCP communication
static int create_dhcp_socket(const char *interface_name)
{
	struct sockaddr_in dhcp_socket;
	struct ifreq interface;
	int flag=1;

	// Set up the address we're going to bind to (we will listen on any address).
	memset(&dhcp_socket, 0, sizeof(dhcp_socket));
	dhcp_socket.sin_family = AF_INET;
	dhcp_socket.sin_port = htons(DHCP_CLIENT_PORT);
	dhcp_socket.sin_addr.s_addr = INADDR_ANY;

	// create a socket for DHCP communications
	const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0)
	{
		logg("Error: Could not create socket!");
		return -1;
	}

#ifdef DEBUG
	logg("DHCP socket: %d", sock);
#endif
	// set the reuse address flag so we don't get errors when restarting
	flag=1;
	if(setsockopt(sock,SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag))<0)
	{
		logg("Error: Could not set reuse address option on DHCP socket!");
		return -1;
	}

	// set the broadcast option - we need this to listen to DHCP broadcast messages
	if(setsockopt(sock, SOL_SOCKET,SO_BROADCAST, (char *)&flag, sizeof flag) < 0)
	{
		logg("Error: Could not set broadcast option on DHCP socket!");
		return -1;
	}

	// bind socket to interface
	strncpy(interface.ifr_ifrn.ifrn_name, interface_name, IFNAMSIZ-1);
	if(setsockopt(sock,SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0)
	{
		logg("Error: Could not bind socket to interface %s.\n       ---> Check your privileges (run with sudo)!\n", interface_name);
		return -1;
	}

	// bind the socket
	if(bind(sock, (struct sockaddr *)&dhcp_socket, sizeof(dhcp_socket)) < 0){
		logg("Error: Could not bind to DHCP socket (port %d)!\n       ---> Check your privileges (run with sudo)!\n", DHCP_CLIENT_PORT);
		return -1;
	}

	return sock;
}

// determines hardware address on client machine
static int get_hardware_address(const int sock, const char *interface_name)
{
	struct ifreq ifr;
	strncpy((char *)&ifr.ifr_name, interface_name, sizeof(ifr.ifr_name)-1);

	// try and grab hardware address of requested interface
	int ret = 0;
	if((ret = ioctl(sock, SIOCGIFHWADDR, &ifr)) < 0){
		logg(" Error: Could not get hardware address of interface '%s' (socket %d, error: %s)", interface_name, sock, strerror(errno));
		return false;
	}
	memcpy(&client_hardware_address[0], &ifr.ifr_hwaddr.sa_data, 6);
#ifdef DEBUG
	logg_sameline("Hardware address of this interface: ");
	for (uint8_t i = 0; i < 6; ++i)
		logg_sameline("%2.2x%s", client_hardware_address[i], i < 5 ? ":" : "");
	logg("");
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
} dhcp_packet;

unsigned int packet_xid;

#define BOOTREQUEST     1
#define BOOTREPLY       2

// sends a DHCPDISCOVER broadcast message in an attempt to find DHCP servers
static bool send_dhcp_discover(int sock, const char *iface)
{
	dhcp_packet discover_packet;
	struct sockaddr_in sockaddr_broadcast;

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
	srand(time(NULL));
	packet_xid = random();
	discover_packet.xid = htonl(packet_xid);
	ntohl(discover_packet.xid);
	discover_packet.secs = 0xFF;

	// tell server it should broadcast its response
	discover_packet.flags = htons(32768); // DHCP_BROADCAST_FLAG

	// our hardware address
	memcpy(discover_packet.chaddr,client_hardware_address, 6);

	// first four bytes of options field is magic cookie (as per RFC 2132)
	discover_packet.options[0] = '\x63';
	discover_packet.options[1] = '\x82';
	discover_packet.options[2] = '\x53';
	discover_packet.options[3] = '\x63';

	// DHCP message type is embedded in options field
	discover_packet.options[4] = 53;     // DHCP message type option identifier
	discover_packet.options[5] = '\x01'; // DHCP message option length in bytes
	discover_packet.options[6] = 1;

	// send the DHCPDISCOVER packet to broadcast address
	sockaddr_broadcast.sin_family = AF_INET;
	sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
	sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
	memset(&sockaddr_broadcast.sin_zero, 0, sizeof(sockaddr_broadcast.sin_zero));

	logg("Sending DHCPDISCOVER on interface %s ... ", iface);
#ifdef DEBUG
	logg("DHCPDISCOVER XID: %lu (0x%X)", (unsigned long) ntohl(discover_packet.xid), ntohl(discover_packet.xid));
	logg("DHCDISCOVER ciaddr:  %s", inet_ntoa(discover_packet.ciaddr));
	logg("DHCDISCOVER yiaddr:  %s", inet_ntoa(discover_packet.yiaddr));
	logg("DHCDISCOVER siaddr:  %s", inet_ntoa(discover_packet.siaddr));
	logg("DHCDISCOVER giaddr:  %s", inet_ntoa(discover_packet.giaddr));
#endif
	// send the DHCPDISCOVER packet out
	//send_dhcp_packet(&discover_packet,sizeof(discover_packet),sock,&sockaddr_broadcast);
	const int bytes = sendto(sock, (char *)&discover_packet, sizeof(discover_packet), 0, (struct sockaddr *)&sockaddr_broadcast,sizeof(sockaddr_broadcast));
#ifdef DEBUG
	logg("Sent %d bytes", bytes);
#endif

	return bytes > 0;
}

static void nice_time(char *buffer, unsigned long seconds)
{
	unsigned int days = seconds / (60 * 60 * 24);
	seconds -= days * (60 * 60 * 24);
	unsigned int hours = seconds / (60 * 60);
	seconds -= hours * (60 * 60);
	unsigned int minutes = seconds / 60;
	seconds %= 60;
	if(days > 0)
		sprintf(buffer, "%ud %uh %um %lus", days, hours, minutes, seconds);
	else if(hours > 0)
		sprintf(buffer, "%uh %um %lus", hours, minutes, seconds);
	else if(minutes > 0)
		sprintf(buffer, "%um %lus", minutes, seconds);
	else
		sprintf(buffer, "%lus", seconds);
}

// adds a DHCP OFFER to list in memory
static void print_dhcp_offer(struct in_addr source, dhcp_packet *offer_packet)
{
	if(offer_packet == NULL)
		return;

	// process all DHCP options present in the packet
	// We start from 4 as the first 32 bit are the DHCP magic coockie (verified before)
	for(unsigned long int x = 4; x < MAX_DHCP_OPTIONS_LENGTH;)
	{
		// End of options
		if(offer_packet->options[x] == 0)
			break;

		// get option type
		const uint8_t opttype = offer_packet->options[x++];

		// get option length
		const uint8_t optlen = offer_packet->options[x++];

		logg_sameline("   ");

		// Interpret option data, see RFC 1497 and RFC 2132, Section 3 for further details
		// A nice summary can be found in https://tools.ietf.org/html/rfc2132#section-3
		if(opttype == 1) // SUBNET_MASK
		{
			struct in_addr subnet;
			memcpy(&subnet.s_addr, &offer_packet->options[x], sizeof(subnet.s_addr));
			logg("Subnet mask: %s", inet_ntoa(subnet));
		}
		else if(opttype == 3) // ROUTER
		{
			for(unsigned int n = 0; n < optlen/4; n++)
			{
				struct in_addr router;
				memcpy(&router.s_addr, &offer_packet->options[x+n*4], sizeof(router.s_addr));
				logg("Router %u: %s", n+1, inet_ntoa(router));
			}
		}
		else if(opttype == 4) // TIME SERVER
		{
			for(unsigned int n = 0; n < optlen/4; n++)
			{
				struct in_addr time_server;
				memcpy(&time_server.s_addr, &offer_packet->options[x+n*4], sizeof(time_server.s_addr));
				logg("Time server %u: %s", n+1, inet_ntoa(time_server));
			}
		}
		else if(opttype == 5) // NAME SERVER
		{
			for(unsigned int n = 0; n < optlen/4; n++)
			{
				struct in_addr name_server;
				memcpy(&name_server.s_addr, &offer_packet->options[x+n*4], sizeof(name_server.s_addr));
				logg("Name server %u: %s", n+1, inet_ntoa(name_server));
			}
		}
		else if(opttype == 6) // DNS SERVER
		{
			for(unsigned int n = 0; n < optlen/4; n++)
			{
				struct in_addr dns_server;
				memcpy(&dns_server.s_addr, &offer_packet->options[x+n*4], sizeof(dns_server.s_addr));
				logg("DNS server %u: %s", n+1, inet_ntoa(dns_server));
			}
		}
		else if(opttype == 13) // HOST NAME
		{
			char host_name[optlen+1];
			memcpy(&host_name, &offer_packet->options[x], optlen);
			host_name[optlen] = '\0';
			logg("Host name: \"%s\"", host_name);
		}
		else if(opttype == 15) // DOMAIN NAME
		{
			char domain_name[optlen+1];
			memcpy(&domain_name, &offer_packet->options[x], optlen);
			domain_name[optlen] = '\0';
			logg("Domain name: \"%s\"", domain_name);
		}
		else if(opttype == 18) // EXTENSION PATH
		{
			char extension_path[optlen+1];
			memcpy(&extension_path, &offer_packet->options[x], optlen);
			extension_path[optlen] = '\0';
			logg("Extension path (TFTP): \"%s\"", extension_path);
		}
		else if(opttype == 28) // BROADCAST ADDRESS
		{
			struct in_addr bc_addr;
			memcpy(&bc_addr.s_addr, &offer_packet->options[x], sizeof(bc_addr.s_addr));
			logg("Broadcast address: %s", inet_ntoa(bc_addr));
		}
		else if(opttype == 51) // LEASE_TIME
		{
			uint32_t lease_time = 0;
			memcpy(&lease_time, &offer_packet->options[x], sizeof(lease_time));
			lease_time = ntohl(lease_time);
			logg_sameline("Lease time:");
			if(lease_time == 0xFFFFFFFF)
				logg("Infinite");
			else
			{
				char buffer[32] = { 0 };
				nice_time(buffer, lease_time);
				logg(" %lu (%s)", (unsigned long)lease_time, buffer);
			}
		}
		else if(opttype == 53) // DHCP MESSAGE TYPE
		{
			switch(offer_packet->options[x])
			{
				case 1:
					logg("Message type: DHCPDISCOVER");
					break;
				case 2:
					logg("Message type: DHCPOFFER");
					break;
				case 3:
					logg("Message type: DHCPREQUEST");
					break;
				case 4:
					logg("Message type: DHCPDECLINE");
					break;
				case 5:
					logg("Message type: DHCPACK");
					break;
				case 6:
					logg("Message type: DHCPNAK");
					break;
				case 7:
					logg("Message type: DHCPRELEASE");
					break;
				case 8:
					logg("Message type: DHCPINFORM");
					break;
				default:
					logg("Message type: UNKNOWN (%u)", offer_packet->options[x]);
					break;
			}
		}
		else if(opttype == 54) // SERVER IDENTIFICATION
		{
			struct in_addr server_id;
			memcpy(&server_id.s_addr, &offer_packet->options[x], sizeof(server_id.s_addr));
			logg("Server identification: %s", inet_ntoa(server_id));
		}
		else if(opttype == 58) // RENEWAL_TIME
		{
			uint32_t renewal_time = 0;
			memcpy(&renewal_time, &offer_packet->options[x], sizeof(renewal_time));
			renewal_time = ntohl(renewal_time);
			logg_sameline("Renewal time:");
			if(renewal_time == 0xFFFFFFFF)
				logg("Infinite");
			else
			{
				char buffer[32] = { 0 };
				nice_time(buffer, renewal_time);
				logg(" %lu (%s)", (unsigned long)renewal_time, buffer);
			}
		}
		else if(opttype == 59) // REBINDING_TIME
		{
			uint32_t rebinding_time = 0;
			memcpy(&rebinding_time, &offer_packet->options[x], sizeof(rebinding_time));
			rebinding_time = ntohl(rebinding_time);
			logg_sameline("Rebindung time:");
			if(rebinding_time == 0xFFFFFFFF)
				logg("Infinite");
			else
			{
				char buffer[32] = { 0 };
				nice_time(buffer, rebinding_time);
				logg(" %lu (%s)", (unsigned long)rebinding_time, buffer);
			}
		}
		else if(opttype == 255) // END OF OPTIONS
		{
			logg("--- end of options ---");
			break;
		}
		else
		{
			logg("Unknown option %d with length %d", opttype, optlen);
		}

		// Advance option pointer index
		x += optlen;
	}
}

// receives a DHCP packet
static bool receive_dhcp_packet(void *buffer, int buffer_size, int sock, int timeout, struct sockaddr_in *address)
{
	struct timeval tv;
	fd_set readfds;
	int recv_result;
	socklen_t address_size;
	struct sockaddr_in source_address;

	// Wait for data to arrive (up time timeout)
	tv.tv_sec=timeout;
	tv.tv_usec=0;
	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	select(sock+1, &readfds, NULL, NULL, &tv);

	// make sure some data has arrived
	if(!FD_ISSET(sock,&readfds))
		return false;

	memset(&source_address, 0, sizeof(source_address));
	address_size=sizeof(source_address);
	recv_result=recvfrom(sock, (char *)buffer, buffer_size, 0, (struct sockaddr *)&source_address, &address_size);
	logg(" Received %d bytes from %s", recv_result, inet_ntoa(source_address.sin_addr));

	if(recv_result == -1){
		logg(" recvfrom() failed, error: %s", strerror(errno));
		return false;
	}

	memcpy(address, &source_address, sizeof(source_address));
	return true;
}

static bool received_something;
// waits for a DHCPOFFER message from one or more DHCP servers
static bool get_dhcp_offer(int sock)
{
	dhcp_packet offer_packet;
	struct sockaddr_in source;
	bool result;
#ifdef DEBUG
	unsigned int responses = 0;
	unsigned int valid_responses = 0;
#endif
	time_t start_time;
	time_t current_time;

	time(&start_time);

	// receive as many responses as we can
	while(true)
	{

		time(&current_time);
		if((current_time-start_time) >= DHCPOFFER_TIMEOUT)
			break;

		memset(&source, 0, sizeof(source));
		memset(&offer_packet, 0, sizeof(offer_packet));

		if(!receive_dhcp_packet(&offer_packet, sizeof(offer_packet), sock, DHCPOFFER_TIMEOUT, &source))
		{
			if(!received_something)
				logg(" Nobody replied to our request on this interface\n");
			continue;
		}

		received_something = true;

#if DEBUG
		else
			responses++;
#endif

#if DEBUG
		logg(" DHCPOFFER XID: %lu (0x%X)", (unsigned long) ntohl(offer_packet.xid), ntohl(offer_packet.xid));
#endif

		// check packet xid to see if its the same as the one we used in the discover packet
		if(ntohl(offer_packet.xid) != packet_xid)
		{
			logg("  DHCPOFFER XID (%lu) does not match our DHCPDISCOVER XID (%lu) - ignoring packet (not for us)\n",
			     (unsigned long) ntohl(offer_packet.xid), (unsigned long) packet_xid);
			continue;
		}

		// check hardware address
		result = true;
#if DEBUG
		logg_sameline("  DHCPOFFER chaddr: ");
#endif
		for(uint8_t x = 0; x < 6; x++)
		{
#if DEBUG
			logg_sameline("%02X",(unsigned char)offer_packet.chaddr[x]);
#endif
			if(offer_packet.chaddr[x]!=client_hardware_address[x])
				result = false;
		}
#if DEBUG
		logg(" (client MAC address)");
#endif
		if(!result)
		{
			logg("  DHCPOFFER hardware address did not match our own - ignoring packet (not for us)\n");
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

		logg("  DHCP options:");
		print_dhcp_offer(source.sin_addr, &offer_packet);
#ifdef DEBUG
		valid_responses++;
#endif
	}
#ifdef DEBUG
	logg(" Responses seen while scanning:    %d", responses);
	logg(" Responses meant for this machine: %d\n", valid_responses);
#endif
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
	get_hardware_address(dhcp_socket, iface);

	// send DHCPDISCOVER packet
	send_dhcp_discover(dhcp_socket, iface);

	// wait for a DHCPOFFER packet
	received_something = false;
	get_dhcp_offer(dhcp_socket);

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

	// Get interface names for available interfaces on this machine
	// and launch a thread for each one
	pthread_t scanthread[MAXTHREADS];
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);

	struct ifaddrs *addrs, *tmp;
	getifaddrs(&addrs);
	tmp = addrs;

	// Loop until there are no more interfaces available
	// or we reached the maximum number of threads
	int tid = 0;
	while(tmp != NULL && tid < MAXTHREADS)
	{
		// Create a thread for interfaces of type AF_INET (IPv4 sockets)
		if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
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
