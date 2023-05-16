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
// sleepms()
#include "timers.h"

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
//htons etc
#include <arpa/inet.h>

// How many threads do we spawn at maximum?
// This is also the limit for interfaces
// we scan for DHCP activity.
#define MAXTHREADS 32

// How many MAC addresses do we store per IP address?
#define MAX_MACS 3

// How many ARP requests do we send per IP address?
#define NUM_SCANS 10

// How long do we wait for ARP replies in each scan [seconds]?
#define ARP_TIMEOUT 1

// Global constant
static bool arp_all = false;

// Protocol definitions
#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

// ARP header struct
// See https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
#pragma pack(push, 1)
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
	struct device {
		unsigned int replied[NUM_SCANS];
		unsigned char mac[MAC_LENGTH];
	} device[MAX_MACS];
};

enum status {
	STATUS_INITIALIZING = 0,
	STATUS_SKIPPED_CIDR_MISMATCH,
	STATUS_SCANNING,
	STATUS_ERROR,
	STATUS_COMPLETE
};

struct thread_data {
	int dst_cidr;
	struct sockaddr_in src_addr;
	struct sockaddr_in dst_addr;
	struct sockaddr_in mask;
	struct ifaddrs *ifa;
	const char *iface;
	struct arp_result *result;
	size_t result_size;
	enum status status;
	char ipstr[INET_ADDRSTRLEN];
	unsigned char mac[16];
	unsigned int num_scans;
	uint32_t scanned_addresses;
	char *error;
};

// Sends multiple ARP who-has request on interface ifindex, using source mac src_mac and source ip src_ip.
// Iterates over all IP addresses in the range of dst_ip/cidr.
static int send_arps(const int fd, const int ifindex, const char *iface, const unsigned char *src_mac,
                     struct in_addr *src_ip, struct in_addr dst_ip, const int dst_cidr, uint32_t *scanned_addresses)
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

		(*scanned_addresses)++;
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

static void add_result(const char *iface, struct in_addr *rcv_ip, struct in_addr *dst_ip, unsigned char *sender_mac,
                       struct arp_result *result, const size_t result_len, const unsigned int scan_id)
{

	// Check if we have already found this IP address
	uint32_t i = ntohl(rcv_ip->s_addr) - ntohl(dst_ip->s_addr);
	if(i >= result_len)
	{
		printf("Received IP address %s out of range for interface %s (%u >= %zu)\n", inet_ntoa(*rcv_ip), iface, i, result_len);
		return;
	}

	// Save MAC address
	unsigned int j = 0;
	for(; j < MAX_MACS; j++)
	{
		// Check if received MAC is already stored in result[i].device[j].mac
		if(memcmp(result[i].device[j].mac, sender_mac, MAC_LENGTH) == 0)
		{
			break;
		}
		// Check if result[i].device[j].mac is all-zero
		if(memcmp(result[i].device[j].mac, "\x00\x00\x00\x00\x00\x00", MAC_LENGTH) == 0)
		{
			// Copy MAC address to result[i].device[j].mac
			memcpy(result[i].device[j].mac, sender_mac, MAC_LENGTH);
			break;
		}
	}

	// Memorize that we have received a reply for this IP address
	result[i].device[j].replied[scan_id]++;
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
		add_result(iface, &sender_a, dst_ip, arp_resp->sender_mac, result, result_len, scan_id);
	}

	return ret;
}

// Convert netmask to CIDR
static int netmask_to_cidr(struct in_addr *addr)
{
	// Count the number of set bits in an unsigned integer
	return __builtin_popcount(addr->s_addr);
}

static const char *get_hostname(const struct in_addr *addr)
{
	// Get hostname
	struct hostent *he = gethostbyaddr(&addr->s_addr, sizeof(addr->s_addr), AF_INET);
	if(he == NULL)
		return "N/A";

	// Allow at most 24 characters for the hostname
	static char hostname[25] = { 0 };
	strncpy(hostname, he->h_name, 24);

	// Return hostname
	return hostname;
}

static void *arp_scan_iface(void *args)
{
	// Get thread_data pointer
	struct thread_data *thread_data = (struct thread_data*)args;

	// Get interface details
	struct ifaddrs *ifa = thread_data->ifa;

	// Get interface name
	const char *iface = thread_data->iface;

	// Set interface name as thread name
	prctl(PR_SET_NAME, iface, 0, 0, 0);

	// Get interface netmask
	memcpy(&thread_data->mask, ifa->ifa_netmask, sizeof(thread_data->mask));

	// Convert subnet to CIDR
	thread_data->dst_cidr = netmask_to_cidr(&thread_data->mask.sin_addr);

	// Get interface index
	const int ifindex = if_nametoindex(iface);

	// Scan only interfaces with CIDR >= 24
	if(thread_data->dst_cidr < 24 && !arp_all)
	{
		thread_data->status = STATUS_SKIPPED_CIDR_MISMATCH;
		//printf("Skipped interface %s (%s/%i)\n", iface, thread_data->ipstr, thread_data->dst_cidr);
		pthread_exit(NULL);
	}
	//if(arp_verbose)
	//	printf("Scanning interface %s (%s/%i)...\n", iface, thread_data->ipstr, thread_data->dst_cidr);
	thread_data->status = STATUS_SCANNING;

	// Create socket for ARP communications
	const int arp_socket = create_arp_socket(ifindex, iface);

	// Cannot create socket, likely a permission error
	if(arp_socket < 0)
	{
		thread_data->status = STATUS_ERROR;
		pthread_exit(NULL);
	}

	// Get hardware address of client machine
	get_hardware_address(arp_socket, iface, thread_data->mac);

	// Define destination IP address by masking source IP with netmask
	thread_data->dst_addr.sin_addr.s_addr = thread_data->src_addr.sin_addr.s_addr & thread_data->mask.sin_addr.s_addr;

	// Allocate memory for ARP response buffer
	const size_t arp_result_len = 1 << (32 - thread_data->dst_cidr);
	thread_data->result_size = arp_result_len;
	struct arp_result *result = calloc(thread_data->result_size, sizeof(struct arp_result));
	thread_data->result = result;

	for(thread_data->num_scans = 0; thread_data->num_scans < NUM_SCANS; thread_data->num_scans++)
	{
		//if(arp_verbose)
		//	printf("Still scanning interface %s (%s/%i) %i%%...\n", iface, thread_data->ipstr, thread_data->dst_cidr, 100*scan_id/NUM_SCANS);

		// Send ARP requests to all IPs in subnet
		if(send_arps(arp_socket, ifindex, iface, thread_data->mac, &thread_data->src_addr.sin_addr,
		             thread_data->dst_addr.sin_addr, thread_data->dst_cidr, &thread_data->scanned_addresses) != 0)
		{
			thread_data->status = STATUS_ERROR;
			break;
		}

		// Read ARP responses
		if(read_arp(arp_socket, iface, &thread_data->dst_addr.sin_addr, thread_data->result, thread_data->result_size,
		            thread_data->num_scans) != 0)
		{
			thread_data->status = STATUS_ERROR;
			break;
		}
	}

	// Close socket
	if(close(arp_socket) != 0)
		thread_data->status = STATUS_ERROR;

	if(thread_data->status != STATUS_ERROR)
		thread_data->status = STATUS_COMPLETE;

	pthread_exit(NULL);
}

static void print_results(struct thread_data *thread_data)
{

	if(thread_data->status == STATUS_SKIPPED_CIDR_MISMATCH)
	{
		printf("Skipped interface %s (%s/%i) because of too large network (use -a to force scanning this interface)\n\n",
		       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr);
		return;
	}

	if(thread_data->status == STATUS_ERROR)
	{
		printf("Error scanning interface %s (%s/%i)\n\n",
		       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr);
		return;
	}

	// Check if there are any results
	unsigned int replies = 0;
	for(unsigned int i = 0; i < thread_data->result_size; i++)
		for(unsigned int j = 0; j < MAX_MACS; j++)
			for(unsigned int k = 0; k < NUM_SCANS; k++)
				replies += thread_data->result[i].device[j].replied[k];

	// Exit early if there are no results
	if(replies == 0)
	{
		printf("No devices replied on interface %s (%s/%i)\n\n",
		       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr);
		return;
	}

	// If there is at least one result, print header
	printf("ARP scan on interface %s (%s/%i) finished\n",
	       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr);
	printf("%-16s %-16s %-24s %-17s  Reply matrix\n",
	       "IP address", "Interface", "Hostname", "MAC address");

	// Add our own IP address to the results so IP conflicts can be detected
	// (our own IP address is not included in the ARP scan)
	for(unsigned int i = 0; i < NUM_SCANS; i++)
		add_result(thread_data->iface, &thread_data->src_addr.sin_addr, &thread_data->dst_addr.sin_addr, thread_data->mac, thread_data->result, thread_data->result_size, i);

	// Print results
	for(unsigned int i = 0; i < thread_data->result_size; i++)
	{
		unsigned int j = 0, replied_devices = 0;
		unsigned int multiple_replies = 0;

		// Print MAC addresses
		for(j = 0; j < MAX_MACS; j++)
		{
			// Check if IP address replied
			bool replied = false;
			for(unsigned int k = 0; k < NUM_SCANS; k++)
			{
				replied |= thread_data->result[i].device[j].replied[k] > 0;
				multiple_replies += thread_data->result[i].device[j].replied[k] > 1;
			}
			if(!replied)
				continue;

			// Check if IP address replied multiple times from different MAC address
			replied_devices++;

			// Convert IP address to string
			struct in_addr ip = { 0 };
			ip.s_addr = htonl(ntohl(thread_data->dst_addr.sin_addr.s_addr) + i);
			inet_ntop(AF_INET, &ip, thread_data->ipstr, INET_ADDRSTRLEN);
			// Check if result[i].mac[j] is all-zero
			if(memcmp(thread_data->result[i].device[j].mac, "\x00\x00\x00\x00\x00\x00", 6) == 0)
				break;

			// Print MAC address
			printf("%-16s %-16s %-24s %02x:%02x:%02x:%02x:%02x:%02x ",
			       thread_data->ipstr, thread_data->iface,
			       get_hostname(&ip),
			       thread_data->result[i].device[j].mac[0],
			       thread_data->result[i].device[j].mac[1],
			       thread_data->result[i].device[j].mac[2],
			       thread_data->result[i].device[j].mac[3],
			       thread_data->result[i].device[j].mac[4],
			       thread_data->result[i].device[j].mac[5]);

			for(unsigned int k = 0; k < NUM_SCANS; k++)
				printf(" %s", thread_data->result[i].device[j].replied[k] > 0 ? "X" : "-");

			putc('\n', stdout);
		}

		// Print warning if we received multiple replies
		if(replied_devices > 1)
			printf("WARNING: Received replies for %s from %i devices\n",
			       thread_data->ipstr, replied_devices);
		if(multiple_replies > 0)
			printf("WARNING: Received multiple replies for %s in %i scan%s\n",
			       thread_data->ipstr, multiple_replies, multiple_replies > 1 ? "s" : "");
	}
	putc('\n', stdout);
}

int run_arp_scan(const bool scan_all)
{
	arp_all = scan_all;
	puts("Discovering IPv4 hosts on the network using the Address Resolution Protocol (ARP)...\n");

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
	unsigned int tid = 0;

	struct thread_data thread_data[MAXTHREADS] = {0};

	while(tmp != NULL && tid < MAXTHREADS)
	{
		// Create a thread for interfaces of type AF_INET
		if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
		{
			thread_data[tid].ifa = tmp;
			thread_data[tid].iface = tmp->ifa_name;

			// Get interface IPv4 address
			memcpy(&thread_data[tid].src_addr, tmp->ifa_addr, sizeof(thread_data[tid].src_addr));
			inet_ntop(AF_INET, &thread_data[tid].src_addr.sin_addr, thread_data[tid].ipstr, INET_ADDRSTRLEN);

			// Always skip the loopback interface
			if(thread_data[tid].src_addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
			{
				// Create thread
				if(pthread_create(&scanthread[tid], &attr, arp_scan_iface, &thread_data[tid] ) != 0)
				{
					printf("Unable to launch thread for interface %s, skipping...\n",
						tmp->ifa_name);
				}

				// Increase thread ID
				tid++;
			}
		}

		// Advance to the next interface
		tmp = tmp->ifa_next;
	}

	// Wait for all threads to finish scanning
	bool all_done = false;
	unsigned int progress = 0;
	while(!all_done)
	{
		all_done = true;
		uint64_t num_scans = 0, total_scans = 0;
		for(unsigned int i = 0; i < tid; i++)
		{
			if(thread_data[i].status == STATUS_INITIALIZING ||
			   thread_data[i].status == STATUS_SCANNING)
			{
				// At least one thread is still scanning
				all_done = false;
			}
			if(thread_data[i].status == STATUS_SCANNING ||
			   thread_data[i].status == STATUS_COMPLETE)
			{
				// Also add up scans for completed threads
				num_scans += thread_data[i].scanned_addresses;
				total_scans +=  NUM_SCANS * thread_data[i].result_size;
			}
		}
		if(!all_done)
		{
			// Calculate progress (total number of scans / total number of addresses)
			// We add 1 to total_scans to avoid division by zero
			const unsigned int new_progress = 100 * num_scans / (total_scans + 1);
			if(new_progress > progress)
			{
				// Print progress
				printf(" %i%%", new_progress);

				// Update progress
				progress = new_progress;
			}

			putc('.', stdout);

			// Flush stdout
			fflush(stdout);

			// Sleep for 1 second
			sleepms(1000);
		}
	}
	puts("100%\n\n");

	// Wait for all threads to join back with us
	for(unsigned int i = 0; i < tid; i++)
		pthread_join(scanthread[i], NULL);

	// Destroy the thread attributes object, since we are done with it
	pthread_attr_destroy(&attr);

	// Free linked-list of interfaces on this client
	freeifaddrs(addrs);

	// Loop over thread results and print them
	for(unsigned int i = 0; i < tid; i++)
	{
		// Print results
		print_results(&thread_data[i]);

		// Free allocated memory
		if(thread_data[i].result != NULL)
			free(thread_data[i].result);
	}

	return EXIT_SUCCESS;
}
