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

static bool res_initialized = false;

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

#define NUM_NS4 (sizeof(_res.nsaddr_list) / sizeof(_res.nsaddr_list[0]))
#define NUM_NS6 (sizeof(_res._u._ext.nsaddrs) / sizeof(_res._u._ext.nsaddrs[0]))

static void print_used_resolvers(const char *message)
{
	// Print details only when debugging
	if(!(config.debug.resolver.v.b))
		return;

	log_debug(DEBUG_RESOLVER, "%s", message);
	for(unsigned int i = 0u; i < NUM_NS4 + NUM_NS6; i++)
	{
		int family;
		in_port_t port;
		void *addr = NULL;
		if(i < NUM_NS4)
		{
			// Regular name servers (IPv4)
			const unsigned int j = i;
			// Some of the entries may not be configured
			if(_res.nsaddr_list[j].sin_family != AF_INET)
			{
				log_debug(DEBUG_RESOLVER, "Skipping unused NS4 %u => %i", i, _res.nsaddr_list[j].sin_family);
				continue;
			}

			// IPv4 name servers
			addr = &_res.nsaddr_list[j].sin_addr;
			port = ntohs(_res.nsaddr_list[j].sin_port);
			family = _res.nsaddr_list[j].sin_family;
		}
		else
		{
			// Extension name servers (IPv6)
			const unsigned int j = i - NUM_NS4;
			// Some of the entries may not be configured
			if(_res._u._ext.nsaddrs[j] == NULL ||
			   _res._u._ext.nsaddrs[j]->sin6_family != AF_INET6)
			{
				log_debug(DEBUG_RESOLVER, "Skipping unused NS6 %u => %i", i, _res.nsaddr_list[j].sin_family);
				continue;
			}
			addr = &_res._u._ext.nsaddrs[j]->sin6_addr;
			port = ntohs(_res._u._ext.nsaddrs[j]->sin6_port);
			family = _res._u._ext.nsaddrs[j]->sin6_family;
		}

		// Convert nameserver information to human-readable form
		char nsname[INET6_ADDRSTRLEN];
		inet_ntop(family, addr, nsname, INET6_ADDRSTRLEN);

		log_debug(DEBUG_RESOLVER, " %s %u: %s:%hu (IPv%u)", i < MAXNS ? "   " : "EXT",
		          i, nsname, port, family == AF_INET ? 4u : 6u);
	}
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

char *resolveHostname(const char *addr)
{
	// Get host name
	char *hostname = NULL;

	// Check if we want to resolve host names
	if(!resolve_this_name(addr))
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
		hostname = strdup("hidden");
		log_debug(DEBUG_RESOLVER, "---> \"%s\" (privacy settings)", hostname);
		return hostname;
	}

	// Check if this is the internal client
	// if so, return "hidden" as hostname
	if(strcmp(addr, "::") == 0)
	{
		hostname = strdup("pi.hole");
		log_debug(DEBUG_RESOLVER, "---> \"%s\" (special)", hostname);
		return hostname;
	}

	// Check if we want to resolve host names
	if(!resolve_this_name(addr))
	{
		log_debug(DEBUG_RESOLVER, "Configured to not resolve host name for %s", addr);

		// Return an empty host name
		return strdup("");
	}

	// Test if we want to resolve an IPv6 address
	bool IPv6 = false;
	if(strstr(addr,":") != NULL)
		IPv6 = true;

	// Convert address into binary form
	struct sockaddr_storage ss = { 0 };
	if(IPv6)
	{
		// Get binary form of IPv6 address
		ss.ss_family = AF_INET6;
		if(!inet_pton(ss.ss_family, addr, &(((struct sockaddr_in6 *)&ss)->sin6_addr)))
		{
			log_warn("Invalid IPv6 address when trying to resolve hostname: %s", addr);
			return strdup("");
		}
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
	}

	// Initialize resolver subroutines if trying to resolve for the first time
	// res_init() reads resolv.conf to get the default domain name and name server
	// address(es). If no server is given, the local host is tried. If no domain
	// is given, that associated with the local host is used.
	if(!res_initialized)
	{
		res_init();
		res_initialized = true;
	}

	// INADDR_LOOPBACK is in host byte order, however, in_addr has to be in
	// network byte order, convert it here if necessary
	struct in_addr FTLaddr = { htonl(INADDR_LOOPBACK) };
	in_port_t FTLport = htons(config.dns.port.v.u16);

	// Warn if no system resolvers are configured
	if(_res.nscount == 0 && _res._u._ext.nscount6 == 0)
	{
		log_warn("No system resolvers found, trying to use FTL at %s#%hu as resolver",
		         inet_ntoa(FTLaddr), FTLport);
	}

	// Temporarily set FTL as system resolver

	// Backup configured name servers and invalidate them (IPv4)
	struct in_addr ns_addr_bck[MAXNS];
	in_port_t ns_port_bck[MAXNS];
	sa_family_t ns_family_bck[MAXNS];
	int bck_nscount = _res.nscount;
	for(unsigned int i = 0u; i < NUM_NS4; i++)
	{
		ns_addr_bck[i] = _res.nsaddr_list[i].sin_addr;
		ns_port_bck[i] = _res.nsaddr_list[i].sin_port;
		ns_family_bck[i] = _res.nsaddr_list[i].sin_family;
		_res.nsaddr_list[i].sin_addr.s_addr = 0; // 0.0.0.0
	}

	// Set FTL at 127.0.0.1 as the only resolver
	_res.nsaddr_list[0].sin_addr.s_addr = FTLaddr.s_addr;
	// Set resolver port
	_res.nsaddr_list[0].sin_port = FTLport;
	// Explicitly set the address family to IPv4
	_res.nsaddr_list[0].sin_family = AF_INET;
	// Configure resolver to use only one resolver
	_res.nscount = 1;

	// Backup configured name server and invalidate them (IPv6)
	struct in6_addr ns6_addr_bck[MAXNS];
	in_port_t ns6_port_bck[MAXNS];
	sa_family_t ns6_family_bck[MAXNS];
	int bck_nscount6 = _res._u._ext.nscount6;
	for(unsigned int i = 0u; i < NUM_NS6; i++)
	{
		if(_res._u._ext.nsaddrs[i] == NULL)
			continue;
		memcpy(&ns6_addr_bck[i], &_res._u._ext.nsaddrs[i]->sin6_addr, sizeof(struct in6_addr));
		ns6_port_bck[i] = _res._u._ext.nsaddrs[i]->sin6_port;
		memcpy(&_res._u._ext.nsaddrs[i]->sin6_addr, &in6addr_any, sizeof(struct in6_addr));
		ns6_family_bck[i] = _res._u._ext.nsaddrs[i]->sin6_family;
	}

	// Set FTL as the only resolver only when IPv6 is enabled
	if(bck_nscount6 > 0)
	{
		// Set FTL at ::1 as the only resolver
		memcpy(&_res._u._ext.nsaddrs[0]->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr));
		// Set resolver port
		_res._u._ext.nsaddrs[0]->sin6_port = FTLport;
		// Explicitly set the address family to IPv6
		_res._u._ext.nsaddrs[0]->sin6_family = AF_INET6;
		// Configure resolver to use only one resolver
		_res._u._ext.nscount6 = 1;
	}

	if(config.debug.resolver.v.b)
		print_used_resolvers("Set nameservers to:");

	// Try to resolve address
	char host[NI_MAXHOST] = { 0 };
	int ret = getnameinfo((struct sockaddr*)&ss, sizeof(ss), host, sizeof(host), NULL, 0, NI_NAMEREQD);

	// Check if getnameinfo() returned a host name
	if(ret == 0)
	{
		if(valid_hostname(host, addr))
		{
			// Return hostname copied to new memory location
			hostname = strdup(host);
		}
		else
		{
			hostname = strdup("[invalid host name]");
		}

		log_debug(DEBUG_RESOLVER, " ---> \"%s\" (found internally)", hostname);
	}
	else
		log_debug(DEBUG_RESOLVER, " ---> \"\" (not found internally: %s", gai_strerror(ret));

	// Restore IPv4 resolvers
	for(unsigned int i = 0u; i < NUM_NS4; i++)
	{
		_res.nsaddr_list[i].sin_addr = ns_addr_bck[i];
		_res.nsaddr_list[i].sin_port = ns_port_bck[i];
		_res.nsaddr_list[i].sin_family = ns_family_bck[i];
	}
	_res.nscount = bck_nscount;

	// Restore IPv6 resolvers
	for(unsigned int i = 0u; i < NUM_NS6; i++)
	{
		if(_res._u._ext.nsaddrs[i] == NULL)
			continue;
		memcpy(&_res._u._ext.nsaddrs[i]->sin6_addr, &ns6_addr_bck[i], sizeof(struct in6_addr));
		_res._u._ext.nsaddrs[i]->sin6_port = ns6_port_bck[i];
		_res._u._ext.nsaddrs[i]->sin6_family = ns6_family_bck[i];
	}
	_res._u._ext.nscount6 = bck_nscount6;

	if(config.debug.resolver.v.b)
		print_used_resolvers("Restored nameservers to:");

	// If no host name was found before, try again with system-configured
	// resolvers (necessary for docker and friends)
	if(hostname == NULL)
	{
		// Try to resolve address
		ret = getnameinfo((struct sockaddr*)&ss, sizeof(ss), host, sizeof(host), NULL, 0, NI_NAMEREQD);

		// Check if getnameinfo() returned a host name this time
		// First check for he not being NULL before trying to dereference it
		if(ret == 0)
		{
			if(valid_hostname(host, addr))
			{
				// Return hostname copied to new memory location
				hostname = strdup(host);
			}
			else
			{
				hostname = strdup("[invalid host name]");
			}

			log_debug(DEBUG_RESOLVER, " ---> \"%s\" (found externally)", hostname);
		}
		else
		{
			// No hostname found (empty PTR)
			hostname = strdup("");

			if(config.debug.resolver.v.b)
			log_debug(DEBUG_RESOLVER, " ---> \"\" (not found externally: %s)", gai_strerror(ret));
		}
	}

	// Return result
	return hostname;
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
	char *newname = resolveHostname(ipaddr);

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
