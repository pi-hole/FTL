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

// Resolve new client and upstream server host names
// once every minute
#define RESOLVE_INTERVAL 60

// Re-resolve client names
// once every hour
#define RERESOLVE_INTERVAL 3600

char *resolveHostname(const char *addr)
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

// Resolve client host names
void resolveClients(bool onlynew)
{
	int i;
	for(i = 0; i < counters.clients; i++)
	{
		// Memory validation
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);

		// If onlynew flag is set, we will only resolve new clients
		// If not, we will try to re-resolve all known clients
		if(onlynew && clients[i].new)
		{
			char *hostname = resolveHostname(clients[i].ip);

			enable_thread_lock();

			if(clients[i].name != NULL)
				free(clients[i].name);

			clients[i].name = hostname;
			clients[i].new = false;

			disable_thread_lock();
		}
	}
}

// Resolve upstream destination host names
void resolveForwardDestinations(bool onlynew)
{
	int i;
	for(i = 0; i < counters.forwarded; i++)
	{
		// Memory validation
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);

		// If onlynew flag is set, we will only resolve new upstream destinations
		// If not, we will try to re-resolve all known upstream destinations
		if(onlynew && forwarded[i].new)
		{
			char *hostname = resolveHostname(forwarded[i].ip);

			enable_thread_lock();

			if(forwarded[i].name != NULL)
				free(forwarded[i].name);

			forwarded[i].name = hostname;
			forwarded[i].new = false;

			disable_thread_lock();
		}
	}
}

pthread_t resolverthread;
void *resolver_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME,"resolver",0,0,0);

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
			// Prevent immediate re-run of this routine
			sleepms(500);
		}

		// Idle for 0.5 sec before checking again the time criteria
		sleepms(500);
	}

	return NULL;
}
