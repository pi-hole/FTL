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
#include "shmem.h"

static char *resolveHostname(const char *addr)
{
	// Get host name
	struct hostent *he = NULL;
	char *hostname = NULL;;
	bool IPv6 = false;

	// Check if this is a hidden client
	// if so, return "hidden" as hostname
	if(strcmp(addr, "0.0.0.0") == 0)
	{
		hostname = strdup("hidden");
		//if(hostname == NULL) return NULL;
		return hostname;
	}

	// Test if we want to resolve an IPv6 address
	if(strstr(addr,":") != NULL)
	{
		IPv6 = true;
	}

	if(IPv6 && config.resolveIPv6) // Resolve IPv6 address only if requested
	{
		struct in6_addr ipaddr;
		inet_pton(AF_INET6, addr, &ipaddr);
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET6);
	}
	else if(!IPv6 && config.resolveIPv4) // Resolve IPv4 address only if requested
	{
		struct in_addr ipaddr;
		inet_pton(AF_INET, addr, &ipaddr);
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET);
	}

	if(he == NULL)
	{
		// No hostname found
		hostname = strdup("");
		//if(hostname == NULL) return NULL;
	}
	else
	{
		// Return hostname copied to new memory location
		hostname = strdup(he->h_name);
		if(hostname == NULL) return NULL;
		// Convert hostname to lower case
		strtolower(hostname);
	}
	return hostname;
}

// Resolve upstream destination host names
static size_t resolveAndAddHostname(size_t ippos, size_t oldnamepos)
{
	// Get IP and host name strings
	lock_shm();
	const char* ipaddr = getstr(ippos);
	const char* oldname = getstr(oldnamepos);
	unlock_shm();

	// Important: Don't hold a lock while resolving as the main thread
	// (dnsmasq) needs to be operable during the call to resolveHostname()
	char* newname = resolveHostname(ipaddr);

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
		unlock_shm();
		return newnamepos;
	}
	else if(config.debug & DEBUG_SHMEM)
	{
		// Debugging output
		logg("Not adding \"%s\" to buffer (unchanged)", oldname);
	}

	// Not changed, return old namepos
	return oldnamepos;
}

// Resolve client host names
void resolveClients(bool onlynew)
{
	int clientID;
	for(clientID = 0; clientID < counters->clients; clientID++)
	{
		// Memory validation
		validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);

		// If onlynew flag is set, we will only resolve new clients
		// If not, we will try to re-resolve all known clients
		if(onlynew && !clients[clientID].new)
			continue;

		// Obtain/update hostname of this client
		size_t oldnamepos = clients[clientID].namepos;
		size_t newnamepos = resolveAndAddHostname(clients[clientID].ippos, oldnamepos);

		if(newnamepos != oldnamepos)
		{
			// Need lock when storing obtained hostname
			lock_shm();
			clients[clientID].namepos = newnamepos;
			unlock_shm();
		}

		// Mark entry as not new
		clients[clientID].new = false;
	}
}

// Resolve upstream destination host names
void resolveForwardDestinations(bool onlynew)
{
	int forwardID;
	for(forwardID = 0; forwardID < counters->forwarded; forwardID++)
	{
		// Memory validation
		validate_access("forwarded", forwardID, true, __LINE__, __FUNCTION__, __FILE__);

		// If onlynew flag is set, we will only resolve new upstream destinations
		// If not, we will try to re-resolve all known upstream destinations
		if(onlynew && !forwarded[forwardID].new)
			continue;

		// Obtain/update hostname of this client
		size_t oldnamepos = forwarded[forwardID].namepos;
		size_t newnamepos = resolveAndAddHostname(forwarded[forwardID].ippos, oldnamepos);

		if(newnamepos != oldnamepos)
		{
			// Need lock when storing obtained hostname
			lock_shm();
			forwarded[forwardID].namepos = newnamepos;
			unlock_shm();
		}

		// Mark entry as not new
		forwarded[forwardID].new = false;
	}
}

void *DNSclient_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME, "DNS client", 0, 0, 0);

	while(!killed)
	{
		// Run every minute to resolve only new clients and upstream servers
		if(time(NULL) % RESOLVE_INTERVAL == 0)
		{
			// Try to resolve new client host names (onlynew=true)
			resolveClients(true);
			// Try to resolve new upstream destination host names (onlynew=true)
			resolveForwardDestinations(true);
			// Prevent immediate re-run of this routine
			sleepms(500);
		}

		// Run every hour to update possibly changed client host names
		if(time(NULL) % RERESOLVE_INTERVAL == 0)
		{
			// Try to resolve all client host names (onlynew=false)
			resolveClients(false);
			// Try to resolve all upstream destination host names (onlynew=false)
			resolveForwardDestinations(false);
			// Prevent immediate re-run of this routine
			sleepms(500);
		}

		// Idle for 0.5 sec before checking again the time criteria
		sleepms(500);
	}

	return NULL;
}
