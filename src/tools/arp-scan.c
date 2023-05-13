/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  ARP scanning routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
// Inspired by https://stackoverflow.com/a/39287433 but heavily modified

#include "FTL.h"
#include "arp-scan.h"
#include "log.h"
// get_hardware_address()
#include "dhcp-discover.h"

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
//htons etc
#include <arpa/inet.h>

// How many threads do we spawn at maximum?
// This is also the limit for interfaces
// we scan for DHCP activity.
#define MAXTHREADS 32
#define MAX_MACS 3
#define NUM_SCANS 10
#define ARP_TIMEOUT 1

// Global lock used by all threads
static pthread_mutex_t lock;
static bool arp_verbose = false;
static bool arp_all = false;

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

#pragma pack(push, 1)

// ARP header struct
// See https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
struct arp_header {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_len;
	unsigned char protocol_len;
	unsigned short opcode;
	unsigned char sender_mac[MAC_LENGTH];
	unsigned char sender_ip[IPV4_LENGTH];
	unsigned char target_mac[MAC_LENGTH];
	unsigned char target_ip[IPV4_LENGTH];
};
#pragma pack(pop)

struct arp_result {
	unsigned int replied[NUM_SCANS];
	unsigned char mac[MAX_MACS][MAC_LENGTH];
};

// Sends multiple ARP who-has request on interface ifindex, using source mac src_mac and source ip src_ip.
// Interates over all IP addresses in the range of dst_ip/cidr.
static int send_arps(const int fd, const int ifindex, const char *iface, const unsigned char *src_mac,
                     struct in_addr *src_ip, struct in_addr dst_ip, const int dst_cidr)
{
	int err = -1;
	unsigned char buffer[BUF_SIZE];
	memset(buffer, 0, sizeof(buffer));

	// Construct the Ethernet header
	struct sockaddr_ll socket_address;
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_ARP);
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_hatype = htons(ARPHRD_ETHER);
	socket_address.sll_pkttype = PACKET_BROADCAST;
	socket_address.sll_halen = MAC_LENGTH;
	socket_address.sll_addr[6] = 0;
	socket_address.sll_addr[7] = 0;

	struct ethhdr *send_req = (struct ethhdr *) buffer;
	struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
	ssize_t ret;

	// Destination is the broadcast address
	memset(send_req->h_dest, 0xff, MAC_LENGTH);

	// Target MAC is zero (we don't know it)
	memset(arp_req->target_mac, 0x00, MAC_LENGTH);

	// Source MAC to our own MAC address
	memcpy(send_req->h_source, src_mac, MAC_LENGTH);
	memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
	memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

	// Protocol type is ARP
	send_req->h_proto = htons(ETH_P_ARP);

	// Create ARP request
	arp_req->hardware_type = htons(HW_TYPE);
	arp_req->protocol_type = htons(ETH_P_IP);
	arp_req->hardware_len = MAC_LENGTH;
	arp_req->protocol_len = IPV4_LENGTH;
	arp_req->opcode = htons(ARP_REQUEST);

	// Copy IP address to arp_req
	memcpy(arp_req->sender_ip, &src_ip->s_addr, sizeof(src_ip->s_addr));

	// Loop over all possible IP addresses in the range dst_ip/cidr
	// We start at 1 because the first IP address has already been set above
	for(unsigned int i = 0; i < (1u << (32 - dst_cidr)); i++)
	{
		// Fill in target IP address
		memcpy(arp_req->target_ip, &dst_ip.s_addr, sizeof(dst_ip.s_addr));

#ifdef DEBUG
		printf("Sending ARP request for %s@%s\n", inet_ntoa(*dst_ip), iface);
#endif

		// Send ARP request
		ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
		if (ret == -1)
		{
			if(errno != EPROTONOSUPPORT)
				printf("Unable to send ARP request for %s@%s: %s\n",
				       inet_ntoa(dst_ip), iface, strerror(errno));
			goto out;
		}

		// Increment IP address
		dst_ip.s_addr = htonl(ntohl(dst_ip.s_addr) + 1);
	}

	err = 0;
out:
	return err;
}

static int create_arp_socket(const int ifindex, const char *iface)
{
	// Create socket for ARP communications
	const int arp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(arp_socket < 0)
	{
		printf("Unable to create socket for ARP communications on interface %s: %s\n", iface, strerror(errno));
		return -1;
	}

	// Bind socket to interface
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	if (bind(arp_socket, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0)
	{
		printf("Unable to bind socket for ARP communications on interface %s: %s\n", iface, strerror(errno));
		close(arp_socket);
		return -1;
	}

	// Set timeout
	struct timeval tv;
	tv.tv_sec = ARP_TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(arp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		printf("Unable to set timeout for ARP communications on interface %s: %s\n", iface, strerror(errno));
		close(arp_socket);
		return -1;
	}

	return arp_socket;
}

// Read all ARP responses
static ssize_t read_arp(const int fd, const char *iface, struct in_addr *dst_ip,
                        struct arp_result *result, const size_t result_len, const unsigned int scan_id)
{
	ssize_t ret = 0;
	unsigned char buffer[BUF_SIZE];

	// Read ARP responses
	while(ret >= 0)
	{
		ret = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
		if (ret == -1)
		{
			if(errno == EAGAIN)
			{
				// Timeout
				ret = 0;
				break;
			}

			// Error
			printf("recvfrom(): %s", strerror(errno));
			break;
		}
		struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
		struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
		if (ntohs(rcv_resp->h_proto) != PROTO_ARP)
		{
#ifdef DEBUG
			printf("Not an ARP packet");
#endif
			continue;
		}
		if (ntohs(arp_resp->opcode) != ARP_REPLY)
		{
#ifdef DEBUG
			printf("Not an ARP reply");
#endif
			continue;
		}
#ifdef DEBUG
		printf("received ARP len=%ld", ret);
#endif
		struct in_addr sender_a;
		memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(sender_a.s_addr));

#ifdef DEBUG
		printf("%-16s %-20s\t%02x:%02x:%02x:%02x:%02x:%02x",
		     iface, inet_ntoa(sender_a),
		     arp_resp->sender_mac[0],
		     arp_resp->sender_mac[1],
		     arp_resp->sender_mac[2],
		     arp_resp->sender_mac[3],
		     arp_resp->sender_mac[4],
		     arp_resp->sender_mac[5]);
#endif

		// Check if we have already found this IP address
		uint32_t i = ntohl(sender_a.s_addr) - ntohl(dst_ip->s_addr);
		if(i >= result_len)
		{
			printf("Received IP address %s out of range\n", inet_ntoa(sender_a));
			continue;
		}

		// Memorize that we have received a reply for this IP address
		result[i].replied[scan_id]++;

		// Save MAC address
		for(unsigned int j = 0; j < MAX_MACS; j++)
		{
			// Check if received MAC is already stored in result[i].mac[j]
			if(memcmp(result[i].mac[j], arp_resp->sender_mac, MAC_LENGTH) == 0)
			{
				break;
			}
			// Check if result[i].mac[j] is all-zero
			if(memcmp(result[i].mac[j], "\x00\x00\x00\x00\x00\x00", MAC_LENGTH) == 0)
			{
				// Copy MAC address to result[i].mac[j]
				memcpy(result[i].mac[j], arp_resp->sender_mac, sizeof(arp_resp->sender_mac));
				break;
			}
		}
	}

	return ret;
}

// Convert netmask to CIDR
static int netmask_to_cidr(struct in_addr *addr)
{
	// Count the number of set bits in an unsigned integer
	return __builtin_popcount(addr->s_addr);
}

static void *arp_scan_iface(void *args)
{
	// Get interface details
	struct ifaddrs *ifa = (struct ifaddrs*)args;

	// Get interface name
	const char *iface = ifa->ifa_name;

	// Set interface name as thread name
	prctl(PR_SET_NAME, iface, 0, 0, 0);

	// Get interface IPv4 address
	struct sockaddr_in src_addr = { 0 };
	memcpy(&src_addr, ((struct ifaddrs*)args)->ifa_addr, sizeof(src_addr));
	char ipstr[INET_ADDRSTRLEN] = { 0 };
	inet_ntop(AF_INET, &src_addr.sin_addr, ipstr, INET_ADDRSTRLEN);

	// Get interface netmask
	struct sockaddr_in mask = { 0 };
	memcpy(&mask, ((struct ifaddrs*)args)->ifa_netmask, sizeof(mask));
	// char netmask[INET_ADDRSTRLEN] = { 0 };
	// inet_ntop(AF_INET, &mask.sin_addr, netmask, INET_ADDRSTRLEN);

	// Convert subnet to CIDR
	const int cidr = netmask_to_cidr(&mask.sin_addr);

	// Get interface index
	const int ifindex = if_nametoindex(iface);

	// Scan only interfaces with CIDR >= 24
	if(cidr < 24 && !arp_all)
	{
		printf("Skipped interface %s (%s/%i)\n", iface, ipstr, cidr);
		pthread_exit(NULL);
	}
	if(arp_verbose)
		printf("Scanning interface %s (%s/%i)...\n", iface, ipstr, cidr);

	// Create socket for ARP communications
	const int arp_socket = create_arp_socket(ifindex, iface);

	// Cannot create socket, likely a permission error
	if(arp_socket < 0)
		pthread_exit(NULL);

	// Get hardware address of client machine
	unsigned char mac[16] = { 0 };
	get_hardware_address(arp_socket, iface, mac);

	// Define destination IP address by masking source IP with netmask
	struct in_addr dst_addr = { 0 };
	dst_addr.s_addr = src_addr.sin_addr.s_addr & mask.sin_addr.s_addr;

	// Allocate memory for ARP response buffer
	const size_t arp_result_len = 1 << (32 - cidr);
	struct arp_result *result = calloc(arp_result_len, sizeof(struct arp_result));

	for(unsigned int scan_id = 0; scan_id < NUM_SCANS; scan_id++)
	{
#ifdef DEBUG
		printf("Scanning interface %s (%s/%i) for the %i. time\n", iface, ipstr, cidr, scan_id + 1);
#endif
		// Send ARP requests to all IPs in subnet
		if(send_arps(arp_socket, ifindex, iface, mac, &src_addr.sin_addr, dst_addr, cidr) != 0)
			break;

		// Read ARP responses
		if(read_arp(arp_socket, iface, &dst_addr, result, arp_result_len, scan_id) != 0)
			break;
	}

	// Check if there are any results
	unsigned int replies = 0;
	for(unsigned int i = 0; i < arp_result_len; i++)
		for(unsigned int j = 0; j < NUM_SCANS; j++)
			replies += result[i].replied[j];

	if(pthread_mutex_lock(&lock) != 0)
		return NULL;

	if(replies == 0)
	{
		printf("No devices found on interface %s (%s/%i)\n", iface, ipstr, cidr);
		goto arp_scan_iface_end;
	}

	// Print results
	printf("ARP scan on interface %s (%s/%i) finished\n", iface, ipstr, cidr);
	printf("%-20s %-16s %-17s  Reply matrix\n", "IP address", "Interface", "MAC address");
	for(unsigned int i = 0; i < arp_result_len; i++)
	{
		// Check if IP address replied
		bool replied = false, multiple_replies = false;
		for(unsigned int j = 0; j < NUM_SCANS; j++)
		{
			if(result[i].replied[j] > 0)
			{
				replied = true;
				multiple_replies |= result[i].replied[j] > 1;
			}
		}
		if(!replied)
			continue;

		// Convert IP address to string
		struct in_addr ip = { 0 };
		ip.s_addr = htonl(ntohl(dst_addr.s_addr) + i);
		inet_ntop(AF_INET, &ip, ipstr, INET_ADDRSTRLEN);

		// Print MAC addresses
		unsigned int j = 0;
		for(j = 0; j < MAX_MACS; j++)
		{
			// Check if result[i].mac[j] is all-zero
			if(memcmp(result[i].mac[j], "\x00\x00\x00\x00\x00\x00", 6) == 0)
				break;

			// Print MAC address
			printf("%-20s %-16s %02x:%02x:%02x:%02x:%02x:%02x ",
			       ipstr, iface,
			       result[i].mac[j][0],
			       result[i].mac[j][1],
			       result[i].mac[j][2],
			       result[i].mac[j][3],
			       result[i].mac[j][4],
			       result[i].mac[j][5]);

			for(unsigned int k = 0; k < NUM_SCANS; k++)
			{
				printf(" %s", result[i].replied[k] > 0 ? "X" : "-");
			}
			putc('\n', stdout);
		}

		// Print warning if multiple MAC addresses replied
		if(j > 1)
			printf("WARNING: Multiple MAC addresses replied as %s\n", ipstr);
		if(multiple_replies)
			printf("WARNING: Received multiple replies for %s\n", ipstr);
	}
	putc('\n', stdout);

arp_scan_iface_end:
	if(pthread_mutex_unlock(&lock) != 0)
		return NULL;

	// Close socket
	close(arp_socket);
	pthread_exit(NULL);
}

int run_arp_scan(const bool verbose, const bool scan_all)
{
	arp_verbose = verbose;
	arp_all = scan_all;
	puts("Discovering IPv4 hosts on the network using the Address Resolution Protocol (ARP)...\n");

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
		// Create a thread for interfaces of type AF_INET
		if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
		{
			if(pthread_create(&scanthread[tid], &attr, arp_scan_iface, tmp ) != 0)
			{
				printf("Unable to launch thread for interface %s, skipping...\n",
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
