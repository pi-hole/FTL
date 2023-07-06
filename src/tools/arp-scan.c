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
// check_capability()
#include "capabilities.h"
#include <linux/capability.h>

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
		unsigned char replied[NUM_SCANS];
		unsigned char mac[MAC_LENGTH];
	} device[MAX_MACS];
};

struct arp_result_extreme {
	struct device_extreme {
		// In extreme mode, we can scan up to 10x more often
		unsigned char replied[10*NUM_SCANS];
		unsigned char mac[MAC_LENGTH];
	} device[MAX_MACS];
};

enum status {
	STATUS_INITIALIZING = 0,
	STATUS_SKIPPED_CIDR_MISMATCH,
	STATUS_SCANNING,
	STATUS_ERROR,
	STATUS_COMPLETE
} __attribute__ ((packed));

struct thread_data {
	bool scan_all :1;
	bool extreme :1;
	char iface[IF_NAMESIZE + 1];
	char ipstr[INET_ADDRSTRLEN];
	unsigned char mac[MAC_LENGTH];
	enum status status;
	int dst_cidr;
	unsigned int num_scans;
	unsigned int total_scans;
	size_t result_size;
	uint32_t scanned_addresses;
	const char *error;
	struct ifaddrs *ifa;
	union {
		struct arp_result_extreme *result_extreme;
		struct arp_result *result;
	};
	struct sockaddr_in src_addr;
	struct sockaddr_in dst_addr;
	struct sockaddr_in mask;
};

// Sends multiple ARP who-has request on interface ifindex, using source mac src_mac and source ip src_ip.
// Iterates over all IP addresses in the range of dst_ip/cidr.
static int send_arps(const int fd, const int ifindex, struct thread_data *thread_data)
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
	memcpy(send_req->h_source, thread_data->mac, MAC_LENGTH);
	memcpy(arp_req->sender_mac, thread_data->mac, MAC_LENGTH);
	memcpy(socket_address.sll_addr, thread_data->mac, MAC_LENGTH);

	// Protocol type is ARP
	send_req->h_proto = htons(ETH_P_ARP);

	// Create ARP request
	arp_req->hardware_type = htons(HW_TYPE);
	arp_req->protocol_type = htons(ETH_P_IP);
	arp_req->hardware_len = MAC_LENGTH;
	arp_req->protocol_len = IPV4_LENGTH;
	arp_req->opcode = htons(ARP_REQUEST);

	// Copy IP address to arp_req
	memcpy(arp_req->sender_ip, &thread_data->src_addr.sin_addr.s_addr, sizeof(thread_data->src_addr.sin_addr.s_addr));

	// Loop over all possible IP addresses in the range dst_ip/cidr
	// We start at 1 because the first IP address has already been set above
	struct in_addr dst_ip = thread_data->dst_addr.sin_addr;
	for(unsigned int i = 0; i < (1u << (32 - thread_data->dst_cidr)); i++)
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
			err = errno;
			thread_data->error = strerror(err);
			goto out;
		}

		// Increment IP address
		dst_ip.s_addr = htonl(ntohl(dst_ip.s_addr) + 1);

		thread_data->scanned_addresses++;
	}

	err = 0;
out:
	return err;
}

static int create_arp_socket(const int ifindex, const char *iface, const char **error)
{
	// Create socket for ARP communications
	const int arp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(arp_socket < 0)
	{
		*error = strerror(errno);
#ifdef DEBUG
		printf("Unable to create socket for ARP communications on interface %s: %s\n", iface, *error);
#endif
		return -1;
	}

	// Bind socket to interface
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	if (bind(arp_socket, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0)
	{
		*error = strerror(errno);
#ifdef DEBUG
		printf("Unable to bind socket for ARP communications on interface %s: %s\n", iface, *error);
#endif
		close(arp_socket);
		return -1;
	}

	// Set timeout
	struct timeval tv;
	tv.tv_sec = ARP_TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(arp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		*error = strerror(errno);
#ifdef DEBUG
		printf("Unable to set timeout for ARP communications on interface %s: %s\n", iface, *error);
#endif
		close(arp_socket);
		return -1;
	}

	return arp_socket;
}

static void add_result(struct in_addr *rcv_ip, unsigned char *sender_mac,
                       struct thread_data *thread_data, const unsigned int scan_id)
{

	// Check if we have already found this IP address
	uint32_t i = ntohl(rcv_ip->s_addr) - ntohl(thread_data->dst_addr.sin_addr.s_addr);
	if(i >= thread_data->result_size)
	{
		printf("Received IP address %s out of range for interface %s (%u >= %zu)\n",
		       inet_ntoa(*rcv_ip), thread_data->iface, i, thread_data->result_size);
		return;
	}

	// Save MAC address
	unsigned int j = 0;
	for(; j < MAX_MACS; j++)
	{
		unsigned char *mac = thread_data->extreme ?
		                       thread_data->result_extreme[i].device[j].mac :
		                       thread_data->result[i].device[j].mac;
		// Check if received MAC is already stored in result[i].device[j].mac
		if(memcmp(mac, sender_mac, MAC_LENGTH) == 0)
		{
			break;
		}
		// Check if mac is all-zero
		if(memcmp(mac, "\x00\x00\x00\x00\x00\x00", MAC_LENGTH) == 0)
		{
			// Copy MAC address to mac
			memcpy(mac, sender_mac, MAC_LENGTH);
			break;
		}
	}

	// Memorize that we have received a reply for this IP address
	thread_data->extreme ?
	  thread_data->result_extreme[i].device[j].replied[scan_id]++ :
	  thread_data->result[i].device[j].replied[scan_id]++;
}

// Read all ARP responses
static ssize_t read_arp(const int fd, struct thread_data *thread_data)
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
			thread_data->error = strerror(errno);
			printf("recvfrom(): %s", thread_data->error);
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
		     thread_data->iface, inet_ntoa(sender_a),
		     arp_resp->sender_mac[0],
		     arp_resp->sender_mac[1],
		     arp_resp->sender_mac[2],
		     arp_resp->sender_mac[3],
		     arp_resp->sender_mac[4],
		     arp_resp->sender_mac[5]);
#endif
		add_result(&sender_a, arp_resp->sender_mac, thread_data, thread_data->num_scans);
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
	if(thread_data->dst_cidr < 24 && !thread_data->scan_all)
	{
		thread_data->status = STATUS_SKIPPED_CIDR_MISMATCH;
#ifdef DEBUG
		printf("Skipped interface %s (%s/%i)\n", iface, thread_data->ipstr, thread_data->dst_cidr);
#endif
		pthread_exit(NULL);
	}
#ifdef DEBUG
	printf("Scanning interface %s (%s/%i)...\n", iface, thread_data->ipstr, thread_data->dst_cidr);
#endif
	thread_data->status = STATUS_SCANNING;

	// Create socket for ARP communications
	const int arp_socket = create_arp_socket(ifindex, iface, &thread_data->error);

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
	if(thread_data->extreme)
	{
		// Allocate extreme memory for ARP response buffer
		struct arp_result_extreme *result = calloc(arp_result_len, sizeof(struct arp_result_extreme));
		if(result == NULL)
		{
			// Memory allocation failed due to insufficient memory being
			// available
			thread_data->status = STATUS_ERROR;
			thread_data->error = strerror(ENOMEM);
			pthread_exit(NULL);
		}
		thread_data->result_extreme = result;
	}
	else
	{
		// Allocate memory for ARP response buffer
		struct arp_result *result = calloc(arp_result_len, sizeof(struct arp_result));
		if(result == NULL)
		{
			// Memory allocation failed due to insufficient memory being
			// available
			thread_data->status = STATUS_ERROR;
			thread_data->error = strerror(ENOMEM);
			pthread_exit(NULL);
		}
		thread_data->result = result;
	}

	for(thread_data->num_scans = 0; thread_data->num_scans < thread_data->total_scans; thread_data->num_scans++)
	{
#ifdef DEBUG
		printf("Still scanning interface %s (%s/%i) %i%%...\n", iface, thread_data->ipstr, thread_data->dst_cidr, 100*scan_id/thread_data->total_scans);
#endif
		// Send ARP requests to all IPs in subnet
		if(send_arps(arp_socket, ifindex, thread_data) != 0)
		{
			thread_data->status = STATUS_ERROR;
			break;
		}

		// Read ARP responses
		if(read_arp(arp_socket, thread_data) != 0)
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
		printf("Skipped interface %s (%s/%i) because of too large network (use -a or -x to force scanning this interface)\n\n",
		       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr);
		return;
	}

	if(thread_data->status == STATUS_ERROR)
	{
		printf("Error scanning interface %s (%s/%i)%s%s\n\n",
		       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr,
		       thread_data->error ? ": " : "", thread_data->error ? thread_data->error : "");
		return;
	}

	// Check if there are any results
	bool any_replies = false;
	for(unsigned int i = 0; i < thread_data->result_size; i++)
		for(unsigned int j = 0; j < MAX_MACS; j++)
			for(unsigned int k = 0; k < thread_data->total_scans; k++)
				if(thread_data->extreme)
				{
					if(thread_data->result_extreme[i].device[j].replied[k])
					{
						any_replies = true;
						break;
					}
				}
				else
				{
					if(thread_data->result[i].device[j].replied[k])
					{
						any_replies = true;
						break;
					}
				}

	// Exit early if there are no results
	if(!any_replies)
	{
		printf("No devices replied on interface %s (%s/%i)\n\n",
		       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr);
		return;
	}

	// If there is at least one result, print header
	printf("ARP scan on interface %s (%s/%i) finished\n",
	       thread_data->iface, thread_data->ipstr, thread_data->dst_cidr);
	printf("%-16s %-16s %-24s %-17s  %s\n",
	       "IP address", "Interface", "Hostname", "MAC address", "Reply rate");

	// Add our own IP address to the results so IP conflicts can be detected
	// (our own IP address is not included in the ARP scan)
	for(unsigned int i = 0; i < thread_data->total_scans; i++)
		add_result(&thread_data->src_addr.sin_addr, thread_data->mac, thread_data, i);

	// Print results
	for(unsigned int i = 0; i < thread_data->result_size; i++)
	{
		unsigned int j = 0, replied_devices = 0;

		// Print MAC addresses
		for(j = 0; j < MAX_MACS; j++)
		{
			// Check if result[i].mac[j] is all-zero, if so, skip this entry
			unsigned char *mac = thread_data->extreme ?
			                       thread_data->result_extreme[i].device[j].mac :
			                       thread_data->result[i].device[j].mac;
			if(memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6) == 0)
				break;

			bool replied = false;
			unsigned char replies = 0u;
			unsigned char multiple_replies = 0;
			const unsigned char *rp = thread_data->extreme ?
							thread_data->result_extreme[i].device[j].replied :
							thread_data->result[i].device[j].replied;

			// Check if IP address replied
			for(unsigned int k = 0; k < thread_data->total_scans; k++)
			{
				replied |= rp[k] > 0;
				replies += rp[k] > 0 ? 1 : 0;
				multiple_replies += rp[k] > 1;
			}
			if(!replied)
				continue;

			// Check if IP address replied multiple times from different MAC address
			replied_devices++;

			// Convert IP address to string
			struct in_addr ip = { 0 };
			ip.s_addr = htonl(ntohl(thread_data->dst_addr.sin_addr.s_addr) + i);
			inet_ntop(AF_INET, &ip, thread_data->ipstr, INET_ADDRSTRLEN);

			// Print MAC address
			printf("%-16s %-16s %-24s %02x:%02x:%02x:%02x:%02x:%02x  %3u %%\n",
			       thread_data->ipstr, thread_data->iface,
			       get_hostname(&ip),
			       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
			       replies * 100 / thread_data->total_scans);

#ifdef DEBUG
			for(unsigned int k = 0; k < thread_data->total_scans; k++)
				printf(" %s", rp[k] > 0 ? "X" : "-");
#endif
		if(multiple_replies > 0)
			printf("INFO: Received multiple replies from %02x:%02x:%02x:%02x:%02x:%02x for %s in %i scan%s\n",
			       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
			       thread_data->ipstr, multiple_replies, multiple_replies > 1 ? "s" : "");
		}

		// Print warning if we received multiple replies
		if(replied_devices > 1)
			printf("WARNING: Received replies for %s from %u devices\n",
			       thread_data->ipstr, replied_devices);
	}
	putc('\n', stdout);
}

int run_arp_scan(const bool scan_all, const bool extreme_mode)
{
	// Check if we are capable of sending ARP packets
	if(!check_capability(CAP_NET_RAW))
	{
		puts("Error: Insufficient permissions or capabilities (needs CAP_NET_RAW). Try running as root (sudo)");
		return EXIT_FAILURE;
	}

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
			// Skip interface scan if ...
			// - interface is not up
			// - ARP is not supported
			// - interface is loopback net
			if(!(tmp->ifa_flags & IFF_UP) ||
			    (tmp->ifa_flags & IFF_NOARP) ||
			    (tmp->ifa_flags & IFF_LOOPBACK))
			{
				tmp = tmp->ifa_next;
				continue;
			}

			thread_data[tid].ifa = tmp;
			strncpy(thread_data[tid].iface, tmp->ifa_name, sizeof(thread_data[tid].iface) - 1);

			// Get interface IPv4 address
			memcpy(&thread_data[tid].src_addr, tmp->ifa_addr, sizeof(thread_data[tid].src_addr));
			inet_ntop(AF_INET, &thread_data[tid].src_addr.sin_addr, thread_data[tid].ipstr, INET_ADDRSTRLEN);

			thread_data[tid].extreme = extreme_mode;
			thread_data[tid].scan_all = scan_all || extreme_mode;
			thread_data[tid].total_scans = extreme_mode ? 10*NUM_SCANS : NUM_SCANS;

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
				total_scans +=  thread_data[i].total_scans * thread_data[i].result_size;
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
				printf(" %u%% ", new_progress);

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
	puts("100%\n");

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
