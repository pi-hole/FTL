/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DNS Client Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "resolve.h"
#include "shmem.h"
// struct config
#include "config/config.h"
// sleepms()
#include "timers.h"
// logging routines
#include "log.h"
// global variable killed
#include "signals.h"
// struct _res
#include <resolv.h>
// resolveNetworkTableNames()
#include "database/network-table.h"
// resolver_ready
#include "daemon.h"
// logg_hostname_warning()
#include "database/message-table.h"
// Eventqueue routines
#include "events.h"
// resolve_regex_cnames()
#include "regex_r.h"
// statis_assert()
#include <assert.h>

// Function Prototypes
static void name_toDNS(unsigned char *dns, const size_t dnslen, const char *host, const size_t hostlen) __attribute__((nonnull(1,3)));
static unsigned char *name_fromDNS(unsigned char *reader, unsigned char *buffer, uint16_t *count) __attribute__((malloc)) __attribute__((nonnull(1,2,3)));

// Avoid "error: packed attribute causes inefficient alignment for ..." on ARM32
// builds due to the use of __attribute__((packed)) in the following structs
// Their correct size is ensured for each by static_assert() below
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wattributes\"")

// DNS header structure
struct DNS_HEADER
{
	uint16_t id; // identification number

	bool rd :1; // recursion desired
	bool tc :1; // truncated message
	bool aa :1; // authoritative answer
	uint8_t opcode :4; // purpose of message
	bool qr :1; // query/response flag

	uint8_t rcode :4; // response code
	bool cd :1; // checking disabled
	bool ad :1; // authenticated data
	bool z :1; // its z! reserved
	bool ra :1; // recursion available

	uint16_t q_count; // number of question entries
	uint16_t ans_count; // number of answer entries
	uint16_t auth_count; // number of authority entries
	uint16_t add_count; // number of resource entries
} __attribute__((packed));
static_assert(sizeof(struct DNS_HEADER) == 12);

// Constant sized fields of query structure
struct QUESTION
{
	uint16_t qtype;
	uint16_t qclass;
};
static_assert(sizeof(struct QUESTION) == 4);

// Constant sized fields of the resource record structure
struct R_DATA
{
	uint16_t type;
	uint16_t class;
	uint32_t ttl; // RFC 1035 defines the TTL field as "positive values of a signed 32bit number"
	uint16_t data_len;
} __attribute__((packed));
static_assert(sizeof(struct R_DATA) == 10);
_Pragma("GCC diagnostic pop")

// Pointers to resource record contents
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	uint8_t *rdata;
};

// Validate given hostname
static bool valid_hostname(char* name, const char* clientip)
{
	// Check for validity of input
	if(name == NULL)
		return false;

	// Check for maximum length of hostname
	// Truncate if too long (MAXHOSTNAMELEN defaults to 64, see asm-generic/param.h)
	if(strlen(name) > MAXHOSTNAMELEN)
	{
		log_warn("Hostname of client %s too long, truncating to %d chars!",
		         clientip, MAXHOSTNAMELEN);
		// We can modify the string in-place as the target is
		// shorter than the source
		name[MAXHOSTNAMELEN] = '\0';
	}

	// Iterate over characters in hostname
	// to check for legal char: A-Z a-z 0-9 - _ .
	unsigned int len = strlen(name);
	for (unsigned int i = 0; i < len; i++)
	{
		const char c = name[i];
		if ((c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') ||
			 c == '-' ||
			 c == '_' ||
			 c == '.' )
			continue;

		// Invalid character found, log and return hostname being invalid
		logg_hostname_warning(clientip, name, i);
		return false;
	}

	// No invalid characters found
	return true;
}

// Return if we want to resolve address to names at all
// (may be disabled due to config settings)
bool __attribute__((pure)) resolve_names(void)
{
	if(!config.resolver.resolveIPv4.v.b && !config.resolver.resolveIPv6.v.b)
		return false;
	return true;
}

// Return if we want to resolve this type of address to a name
bool __attribute__((pure)) resolve_this_name(const char *ipaddr)
{
	if(!config.resolver.resolveIPv4.v.b ||
	  (!config.resolver.resolveIPv6.v.b && strstr(ipaddr,":") != NULL))
		return false;
	return true;
}

// Perform a name lookup by sending a packet to ourselves
static char *__attribute__((malloc)) ngethostbyname(const char *host, const char *ipaddr)
{
	uint8_t buf[1024] = { 0 };
	uint8_t *qname = NULL, *reader = NULL;
	struct RES_RECORD answers[20] = { 0 }; // buffer for DNS replies
	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	// Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;
	dns->id = (unsigned short) htons(random()); // random query ID
	dns->qr = 0; // This is a query
	dns->opcode = 0; // This is a standard query
	dns->aa = 0; // Not Authoritative
	dns->tc = 0; // This message is not truncated
	dns->rd = 1; // Recursion Desired
	dns->ra = 0; // Recursion not available!
	dns->z = 0; // Reserved
	dns->ad = 0; // This is not an authenticated answer
	dns->cd = 0; // Checking Disabled
	dns->rcode = 0; // Response code
	dns->q_count = htons(1); // 1 question
	dns->ans_count = 0; // No answers
	dns->auth_count = 0; // No authority
	dns->add_count = 0; // No additional

	// Point to the query portion
	qname = &buf[sizeof(struct DNS_HEADER)];

	// Make a copy of the hostname with two extra bytes for the length and
	// the final dot, copy the hostname into it and convert to convert to
	// DNS format
	const size_t hnamelen = strlen(host) + 2;
	char *hname = calloc(hnamelen, sizeof(char));
	if(hname == NULL)
	{
		log_err("Unable to allocate memory for hname");
		return strdup("");
	}
	strncpy(hname, host, hnamelen);
	strncat(hname, ".", hnamelen - strlen(hname));
	hname[hnamelen - 1] = '\0';

	name_toDNS(qname, sizeof(buf) - sizeof(struct DNS_HEADER), hname, hnamelen);
	free(hname);
	qinfo = (void*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];

	qinfo->qtype = htons(T_PTR); // Type of the query, A, MX, CNAME, NS etc
	qinfo->qclass = htons(1); // IN

	// UDP packet for DNS queries
	const int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in dest = { 0 };
	dest.sin_family = AF_INET; // IPv4
	dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
	dest.sin_port = htons(config.dns.port.v.u16); // Configured DNS port

	const size_t questionlen = sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION);
	if(sendto(s, buf, questionlen, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
	{
		perror("sendto failed");
		close(s);
		return strdup("");
	}

	// Receive the answer
	socklen_t addrlen = sizeof(dest);
	if(recvfrom (s, buf, sizeof(buf), 0, (struct sockaddr*)&dest, &addrlen) < 0)
	{
		perror("recvfrom failed");
		close(s);
		return strdup("");
	}

	// Close socket
	close(s);

	// Parse the reply
	dns = (struct DNS_HEADER*) buf;
	// Move ahead of the dns header and the query field
	reader = &buf[questionlen];

	// Start reading answers
	uint16_t stop = 0;
	char *name = NULL;
	for(uint16_t i = 0; i < ntohs(dns->ans_count); i++)
	{
		answers[i].name = name_fromDNS(reader, buf, &stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		// We only care about PTR answers and ignore all others
		if(ntohs(answers[i].resource->type) != T_PTR)
			continue;

		// Read the answer and convert from network to host representation
		answers[i].rdata = name_fromDNS(reader, buf, &stop);
		reader = reader + stop;

		name = (char *)answers[i].rdata;
		log_debug(DEBUG_RESOLVER, "Resolving %s (PTR \"%s\"): %u = \"%s\"",
		          ipaddr, answers[i].name, i, answers[i].rdata);

		// We break out of the loop if this is a valid hostname
		if(strlen(name) > 0 && valid_hostname(name, ipaddr))
		{
			break;
		}
		else
		{
			// Discard this answer: free memory and set name to NULL
			free(name);
			name = NULL;
		}
	}

	if(name != NULL)
	{
		// We have a valid hostname, return it
		// This is allocated memory
		return name;
	}
	else
	{
		// No valid hostname found, return empty string
		return strdup("");
	}
}

// Convert hostname from network to host representation
// This routine supports DNS compression pointers
// 3www6google3com -> www.google.com
static u_char * __attribute__((malloc)) __attribute__((nonnull(1,2,3))) name_fromDNS(unsigned char *reader, unsigned char *buffer, uint16_t *count)
{
	unsigned char *name = calloc(MAXHOSTNAMELEN, sizeof(char));
	unsigned int p = 0, jumped = 0;

	// Initialize count
	*count = 1;

	// Parse DNS label string encoding (e.g, 3www6google3com)
	//
	// In its text format, a domain name is a sequence of dot-separated
	// "labels". The dot separators are not used in binary DNS messages.
	// Instead, each label is preceded by a byte containing its length, and
	// the name is terminated by a zero-length label representing the root
	// zone.
	while(*reader != 0)
	{
		if(*reader >= 0xC0)
		{
			// RFC 1035, Section 4.1.4: Message compression
			//
			// A label can be up to 63 bytes long; if the length
			// byte is 64 (0x40) or greater, it has a special
			// meaning. Values between 0x40 and 0xBF have no purpose
			// except to cause painful memories for those involved
			// in DNS extensions in the late 1990s.
			//
			// However, if the length byte is 0xC0 or greater, the
			// length byte and the next byte form a "compression
			// pointer". A DNS name compression pointer allows DNS
			// messages to reuse parent domains. The lower 14 bits
			// are an offset into the DNS message where the
			// remaining suffix of the name previously occurred.
			//
			//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			//  | 1  1|                OFFSET                   |
			//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			//
			// The first two bits are ones.  This allows a pointer
			// to be distinguished from a label, since the label
			// must begin with two zero bits because labels are
			// restricted to 63 octets or less. See the referenced
			// RFC for more details.
			const unsigned int offset = ((*reader - 0xC0) << 8) + *(reader + 1);
			reader = buffer + offset - 1;
			jumped = 1; // We have jumped to another location so counting won't go up
		}
		else
			// Copy character to name
			name[p++] = *reader;

		// Increment read pointer
		reader = reader + 1;

		if(jumped == 0)
			*count = *count + 1; // If we haven't jumped to another location then we can count up
	}

	// Terminate string
	name[p] = '\0';

	// Number of steps we actually moved forward in the packet
	if(jumped == 1)
		*count += 1;

	// Now convert 3www6google3com0 to www.google.com
	unsigned int i = 0;
	for(; i < strlen((const char*)name); i++)
	{
		p = name[i];
		for(unsigned j = 0; j < p; j++)
		{
			name[i] = name[i + 1];
			i = i + 1;
		}
		name[i] = '.';
	}

	// Strip off the trailing dot
	name[i-1] = '\0';
	return name;
}

// Convert hostname from host to network representation
// www.google.com -> 3www6google3com
// We do not use DNS compression pointers here as we do not know if the DNS
// server we are talking to supports them
static void __attribute__((nonnull(1,3))) name_toDNS(unsigned char *dns, const size_t dnslen, const char *host, const size_t hostlen)
{
	unsigned int lock = 0;

	// Iterate over hostname characters
	for(unsigned int i = 0 ; i < strlen((char*)host); i++)
	{
		// If we encounter a dot, write the number of characters since the last dot
		// and then write the characters themselves
		if(host[i] == '.')
		{
			*dns++ = i - lock;
			for(;lock < i; lock++)
				*dns++ = host[lock];
			lock++;
		}
	}

	// Terminate the string at the end
	*dns++='\0';
}

char *__attribute__((malloc)) resolveHostname(const char *addr, const bool force)
{
	// Get host name
	char *hostn = NULL;

	// Check if we want to resolve host names
	if(!force && !resolve_this_name(addr))
	{
		log_debug(DEBUG_RESOLVER, "Configured to not resolve host name for %s", addr);

		// Return an empty host name
		return strdup("");
	}

	log_debug(DEBUG_RESOLVER, "Trying to resolve %s", addr);

	// Check if this is a hidden client
	// if so, return "hidden" as hostname
	if(strcmp(addr, "0.0.0.0") == 0)
	{
		hostn = strdup("hidden");
		log_debug(DEBUG_RESOLVER, "---> \"%s\" (privacy settings)", hostn);
		return hostn;
	}

	// Check if this is the internal client
	// if so, return "hidden" as hostname
	if(strcmp(addr, "::") == 0)
	{
		hostn = strdup("pi.hole");
		log_debug(DEBUG_RESOLVER, "---> \"%s\" (special)", hostn);
		return hostn;
	}

	// Test if we want to resolve an IPv6 address
	bool IPv6 = false;
	if(strstr(addr,":") != NULL)
		IPv6 = true;

	// Convert address into binary form
	struct sockaddr_storage ss = { 0 };
	char *inaddr = NULL;
	if(IPv6)
	{
		// Get binary form of IPv6 address
		ss.ss_family = AF_INET6;
		if(!inet_pton(ss.ss_family, addr, &(((struct sockaddr_in6 *)&ss)->sin6_addr)))
		{
			log_warn("Invalid IPv6 address when trying to resolve hostname: %s", addr);
			return strdup("");
		}

		// Need extra space for ".ip6.arpa" suffix
		// The 1.2.3.4... string is 63 + terminating \0 = 64 bytes long
		inaddr = calloc(64 + 10, sizeof(char));
		if(inaddr == NULL)
		{
			log_err("Unable to allocate memory for reverse lookup");
			return strdup("");
		}

		// Convert IPv6 address to reverse lookup format
		//                       b a 9 8 7 6 5   4       |<--       ::      -->| 0       1 2 3 4
		// 4321:0::4:567:89ab -> b.a.9.8.7.6.5.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.2.3.4
		for(int i = 0; i < 32; i++)
		{
			// Get current nibble
			uint8_t nibble = ((uint8_t *)&(((struct sockaddr_in6 *)&ss)->sin6_addr))[i/2];

			// Get lower nibble for even i, upper nibble for odd i
			if(i % 2 == 0)
				nibble = nibble >> 4;

			// Mask out upper nibble
			nibble = nibble & 0x0F;

			// Convert to ASCII
			char c = '0' + nibble;
			if(c > '9')
				c = 'a' + nibble - 10;

			// Prepend to string
			inaddr[62-2*i] = c;

			// Add dot after (actually: before) every nibble except
			// the last one
			if(i != 31)
				inaddr[62-2*i-1] = '.';
		}

		// Add suffix
		strcat(inaddr, ".ip6.arpa");
	}
	else
	{
		// Get binary form of IPv4 address
		ss.ss_family = AF_INET;
		if(!inet_pton(ss.ss_family, addr, &(((struct sockaddr_in *)&ss)->sin_addr)))
		{
			log_warn("Invalid IPv4 address when trying to resolve hostname: %s", addr);
			return strdup("");
		}

		// Need extra space for ".in-addr.arpa" suffix
		inaddr = calloc(INET_ADDRSTRLEN + 14, sizeof(char));
		if(inaddr == NULL)
		{
			log_err("Unable to allocate memory for reverse lookup");
			return strdup("");
		}

		// Convert IPv4 address to reverse lookup format
		// 12.34.56.78 -> 78.56.34.12.in-addr.arpa
		snprintf(inaddr, INET_ADDRSTRLEN + 14, "%d.%d.%d.%d.in-addr.arpa",
		        (int)((uint8_t *)&(((struct sockaddr_in *)&ss)->sin_addr))[3],
		        (int)((uint8_t *)&(((struct sockaddr_in *)&ss)->sin_addr))[2],
		        (int)((uint8_t *)&(((struct sockaddr_in *)&ss)->sin_addr))[1],
		        (int)((uint8_t *)&(((struct sockaddr_in *)&ss)->sin_addr))[0]);
	}

	// Get host name by making a reverse lookup to ourselves (server at 127.0.0.1 with port 53)
	// We implement a minimalistic resolver here as we cannot rely on the system resolver using whatever
	// nameserver we configured in /etc/resolv.conf
	return ngethostbyname(inaddr, addr);
}

// Resolve upstream destination host names
static size_t resolveAndAddHostname(size_t ippos, size_t oldnamepos)
{
	// Get IP and host name strings. They are cloned in case shared memory is
	// resized before the next lock
	lock_shm();
	char *ipaddr = strdup(getstr(ippos));
	char *oldname = strdup(getstr(oldnamepos));
	unlock_shm();

	// Test if we want to resolve host names, otherwise all calls to resolveHostname()
	// and getNameFromIP() can be skipped as they will all return empty names (= no records)
	if(!resolve_this_name(ipaddr))
	{
		log_debug(DEBUG_RESOLVER, " ---> \"\" (configured to not resolve host name)");

		// Free allocated memory
		free(ipaddr);
		free(oldname);

		// Return fixed position of empty string
		return 0;
	}

	// Important: Don't hold a lock while resolving as the main thread
	// (dnsmasq) needs to be operable during the call to resolveHostname()
	char *newname = resolveHostname(ipaddr, false);

	// If no hostname was found, try to obtain hostname from the network table
	// This may be disabled due to a user setting
	if(strlen(newname) == 0 && config.resolver.networkNames.v.b)
	{
		free(newname);
		newname = getNameFromIP(NULL, ipaddr);
		if(newname != NULL)
			log_debug(DEBUG_RESOLVER, " ---> \"%s\" (provided by database)", newname);
	}

	// Only store new newname if it is valid and differs from oldname
	// We do not need to check for oldname == NULL as names are
	// always initialized with an empty string at position 0
	if(newname != NULL && strcmp(oldname, newname) != 0)
	{
		lock_shm();
		size_t newnamepos = addstr(newname);
		// newname has already been checked against NULL
		// so we can safely free it
		free(newname);
		free(ipaddr);
		free(oldname);
		unlock_shm();
		return newnamepos;
	}
	else
	{
		// Debugging output
		log_debug(DEBUG_SHMEM, "Not adding \"%s\" to buffer (unchanged)", oldname);
	}

	if(newname != NULL)
		free(newname);
	free(ipaddr);
	free(oldname);

	// Not changed, return old namepos
	return oldnamepos;
}

// Resolve client host names
static void resolveClients(const bool onlynew, const bool force_refreshing)
{
	const time_t now = time(NULL);
	// Lock counter access here, we use a copy in the following loop
	lock_shm();
	int clientscount = counters->clients;
	unlock_shm();

	int skipped = 0;
	for(int clientID = 0; clientID < clientscount; clientID++)
	{
		// Memory access needs to get locked
		lock_shm();
		// Get client pointer for the first time (reading data)
		clientsData* client = getClient(clientID, true);
		if(client == NULL)
		{
			// Client has been recycled, skip it
			unlock_shm();
			skipped++;
			continue;
		}

		// Skip alias-clients
		if(client->flags.aliasclient)
		{
			unlock_shm();
			skipped++;
			continue;
		}

		bool newflag = client->flags.new;
		size_t ippos = client->ippos;
		size_t oldnamepos = client->namepos;

		// Only try to resolve host names of clients which were recently active if we are re-resolving
		// Limit for a "recently active" client is two hours ago
		if(!force_refreshing && !onlynew && client->lastQuery < now - 2*60*60)
		{
			log_debug(DEBUG_RESOLVER, "Skipping client %s (%s) because it was inactive for %i seconds",
			          getstr(ippos), getstr(oldnamepos), (int)(now - client->lastQuery));

			unlock_shm();
			skipped++;
			continue;
		}

		// If onlynew flag is set, we will only resolve new clients
		// If not, we will try to re-resolve all known clients
		if(!force_refreshing && onlynew && !newflag)
		{
			log_debug(DEBUG_RESOLVER, "Skipping client %s (%s) because it is not new",
			          getstr(ippos), getstr(oldnamepos));

			unlock_shm();
			skipped++;
			continue;
		}

		unlock_shm();

		// Check if we want to resolve an IPv6 address
		bool IPv6 = false;
		const char *ipaddr = NULL;
		if((ipaddr = getstr(ippos)) != NULL && strstr(ipaddr,":") != NULL)
			IPv6 = true;

		// If we're in refreshing mode (onlynew == false), we skip clients if
		// 1. We should not refresh any hostnames
		// 2. We should only refresh IPv4 client, but this client is IPv6
		// 3. We should only refresh unknown hostnames, but leave
		//    existing ones as they are
		if(onlynew == false &&
		   (config.resolver.refreshNames.v.refresh_hostnames == REFRESH_NONE ||
		   (config.resolver.refreshNames.v.refresh_hostnames == REFRESH_IPV4_ONLY && IPv6) ||
		   (config.resolver.refreshNames.v.refresh_hostnames == REFRESH_UNKNOWN && oldnamepos != 0)))
		{
			if(config.debug.resolver.v.b)
			{
				const char *reason = "N/A";
				if(config.resolver.refreshNames.v.refresh_hostnames == REFRESH_NONE)
					reason = "Not refreshing any hostnames";
				else if(config.resolver.refreshNames.v.refresh_hostnames == REFRESH_IPV4_ONLY)
					reason = "Only refreshing IPv4 names";
				else if(config.resolver.refreshNames.v.refresh_hostnames == REFRESH_UNKNOWN)
					reason = "Looking only for unknown hostnames";

				lock_shm();
				log_debug(DEBUG_RESOLVER, "Skipping client %s (%s) because it should not be refreshed: %s",
				          getstr(ippos), getstr(oldnamepos), reason);
				unlock_shm();
			}
			skipped++;
			continue;
		}

		// Obtain/update hostname of this client
		size_t newnamepos = resolveAndAddHostname(ippos, oldnamepos);

		lock_shm();
		// Get client pointer for the second time (writing data)
		// We cannot use the same pointer again as we released
		// the lock in between so we cannot know if something
		// happened to the shared memory object (resize event)
		client = getClient(clientID, true);
		if(client == NULL)
		{
			log_warn("Unable to get client pointer (2) with ID %i in resolveClients(), skipping...", clientID);
			skipped++;
			unlock_shm();
			continue;
		}

		// Store obtained host name (may be unchanged)
		client->namepos = newnamepos;
		// Mark entry as not new
		client->flags.new = false;

		log_debug(DEBUG_RESOLVER, "Client %s -> \"%s\" is new", getstr(ippos), getstr(newnamepos));

		unlock_shm();
	}

	log_debug(DEBUG_RESOLVER, "%i / %i client host names resolved",
	          clientscount-skipped, clientscount);
}

// Resolve upstream destination host names
static void resolveUpstreams(const bool onlynew)
{
	const time_t now = time(NULL);
	// Lock counter access here, we use a copy in the following loop
	lock_shm();
	int upstreams = counters->upstreams;
	unlock_shm();

	int skipped = 0;
	for(int upstreamID = 0; upstreamID < upstreams; upstreamID++)
	{
		// Memory access needs to get locked
		lock_shm();
		// Get upstream pointer for the first time (reading data)
		upstreamsData* upstream = getUpstream(upstreamID, true);
		if(upstream == NULL)
		{
			// This is not a fatal error, as the upstream may have been recycled
			skipped++;
			unlock_shm();
			continue;
		}

		bool newflag = upstream->flags.new;
		size_t ippos = upstream->ippos;
		size_t oldnamepos = upstream->namepos;

		// Only try to resolve host names of upstream servers which were recently active
		// Limit for a "recently active" upstream server is two hours ago
		if(upstream->lastQuery < now - 2*60*60)
		{
			log_debug(DEBUG_RESOLVER, "Skipping upstream %s (%s) because it was inactive for %i seconds",
			          getstr(ippos), getstr(oldnamepos), (int)(now - upstream->lastQuery));

			unlock_shm();
			continue;
		}
		unlock_shm();

		// If onlynew flag is set, we will only resolve new upstream destinations
		// If not, we will try to re-resolve all known upstream destinations
		if(onlynew && !newflag)
		{
			skipped++;
			if(config.debug.resolver.v.b)
			{
				lock_shm();
				log_debug(DEBUG_RESOLVER, "Upstream %s -> \"%s\" already known", getstr(ippos), getstr(oldnamepos));
				unlock_shm();
			}
			continue;
		}

		// Obtain/update hostname of this client
		size_t newnamepos = resolveAndAddHostname(ippos, oldnamepos);

		lock_shm();
		// Get upstream pointer for the second time (writing data)
		// We cannot use the same pointer again as we released
		// the lock in between so we cannot know if something
		// happened to the shared memory object (resize event)
		upstream = getUpstream(upstreamID, true);
		if(upstream == NULL)
		{
			log_warn("Unable to get upstream pointer (2) with ID %i in resolveUpstreams(), skipping...", upstreamID);
			skipped++;
			unlock_shm();
			continue;
		}

		// Store obtained host name (may be unchanged)
		upstream->namepos = newnamepos;
		// Mark entry as not new
		upstream->flags.new = false;

		log_debug(DEBUG_RESOLVER, "Upstream %s -> \"%s\" is new", getstr(ippos), getstr(newnamepos));

		unlock_shm();
	}

	log_debug(DEBUG_RESOLVER, "%i / %i upstream server host names resolved",
	          upstreams-skipped, upstreams);
}

void *DNSclient_thread(void *val)
{
	// Set thread name
	thread_names[DNSclient] = "DNS client";
	thread_running[DNSclient] = true;
	prctl(PR_SET_NAME, thread_names[DNSclient], 0, 0, 0);

	// Initial delay until we first try to resolve anything
	thread_sleepms(DNSclient, 2000);

	// Run as long as this thread is not canceled
	while(!killed)
	{
		// Run whenever necessary to resolve only new clients and
		// upstream servers
		if(resolver_ready && get_and_clear_event(RESOLVE_NEW_HOSTNAMES))
		{
			// Try to resolve new client host names
			// (onlynew=true)
			// We're not forcing refreshing here
			resolveClients(true, false);
			// Try to resolve new upstream destination host names
			// (onlynew=true)
			resolveUpstreams(true);

			// Try to resolve regex CNAMEs (if any)
			resolve_regex_cnames();
		}

		// Intermediate cancellation-point
		if(killed)
			break;

		// Run every hour to update possibly changed client host names
		if(resolver_ready && (time(NULL) % RERESOLVE_INTERVAL == 0))
		{
			set_event(RERESOLVE_HOSTNAMES);      // done below
		}

		bool force_refreshing = false;
		if(get_and_clear_event(RERESOLVE_HOSTNAMES_FORCE))
		{
			set_event(RERESOLVE_HOSTNAMES);      // done below
			force_refreshing = true;
		}

		// Process resolver related event queue elements
		if(get_and_clear_event(RERESOLVE_HOSTNAMES))
		{
			// Try to resolve all client host names
			// (onlynew=false)
			resolveClients(false, force_refreshing);

			// Intermediate cancellation-point
			if(killed)
				break;

			// Try to resolve all upstream destination host names
			// (onlynew=false)
			resolveUpstreams(false);
		}

		// Idle for 1 sec
		thread_sleepms(DNSclient, 1000);
	}

	log_info("Terminating resolver thread");
	thread_running[DNSclient] = false;
	return NULL;
}
