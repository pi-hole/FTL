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
#include "shmem_r.h"
#include "memory.h"
#include "datastructure.h"
#include "resolve.h"
#include "daemon.h"
#include "log.h"

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
	// Get IP and host name strings. They are cloned in case shared memory is
	// resized before the next lock
	lock_shm();
	char* ipaddr = strdup(getstr(ippos));
	char* oldname = strdup(getstr(oldnamepos));
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
		free(ipaddr);
		free(oldname);
		unlock_shm();
		return newnamepos;
	}
	else if(config.debug & DEBUG_SHMEM)
	{
		// Debugging output
		logg("Not adding \"%s\" to buffer (unchanged)", oldname);
	}

	free(ipaddr);
	free(oldname);

	// Not changed, return old namepos
	return oldnamepos;
}

// Resolve client host names
void resolveClients(const bool onlynew)
{
	// Lock counter access here, we use a copy in the following loop
	lock_shm();
	int clientscount = counters->clients;
	unlock_shm();
	for(int clientID = 0; clientID < clientscount; clientID++)
	{
		// Get client pointer
		clientsData* client = getClient(clientID, true);

		// Memory access needs to get locked
		lock_shm();
		bool newflag = client->new;
		size_t ippos = client->ippos;
		size_t oldnamepos = client->namepos;
		unlock_shm();

		// If onlynew flag is set, we will only resolve new clients
		// If not, we will try to re-resolve all known clients
		if(onlynew && !newflag)
			continue;

		// Obtain/update hostname of this client
		size_t newnamepos = resolveAndAddHostname(ippos, oldnamepos);

		lock_shm();
		// Store obtained host name (may be unchanged)
		client->namepos = newnamepos;
		// Mark entry as not new
		client->new = false;
		unlock_shm();
	}
}

// Resolve upstream destination host names
void resolveForwardDestinations(const bool onlynew)
{
	// Lock counter access here, we use a copy in the following loop
	lock_shm();
	int forwardedcount = counters->forwarded;
	unlock_shm();
	for(int forwardID = 0; forwardID < forwardedcount; forwardID++)
	{
		// Get forward pointer
		forwardedData* forward = getForward(forwardID, true);

		// Memory access needs to get locked
		lock_shm();
		bool newflag = forward->new;
		size_t ippos = forward->ippos;
		size_t oldnamepos = forward->namepos;
		unlock_shm();

		// If onlynew flag is set, we will only resolve new upstream destinations
		// If not, we will try to re-resolve all known upstream destinations
		if(onlynew && !newflag)
			continue;

		// Obtain/update hostname of this client
		size_t newnamepos = resolveAndAddHostname(ippos, oldnamepos);

		lock_shm();
		// Store obtained host name (may be unchanged)
		forward->namepos = newnamepos;
		// Mark entry as not new
		forward->new = false;
		unlock_shm();
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
