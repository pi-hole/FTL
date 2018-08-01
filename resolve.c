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

// This routine is run *after* garbage cleaning (default interval is once per hour)
// to account for possibly updated hostnames
void reresolveHostnames(void)
{
	int clientID;
	for(clientID = 0; clientID < counters.clients; clientID++)
	{
		// Memory validation
		validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);

		// Process this client only if it has at least one active query in the log
		if(clients[clientID].count < 1)
			continue;

		// Get client hostname
		char *oldhostname = getstr(clients[clientID].namepos);
		char *newhostname = resolveHostname(getstr(clients[clientID].ippos));
		if(strlen(newhostname) > 0 && strcmp(newhostname,oldhostname) != 0)
		{
			// Store client hostname
			clients[clientID].namepos = addstr(newhostname);
		}
		free(newhostname);
	}
}

// This routine is run *before* saving to the database (default interval is once per minute)
// to account for new clients (and forward destinations)
void resolveNewClients(void)
{
	int i;
	for(i = 0; i < counters.clients; i++)
	{
		// Memory validation
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);

		// Only try to resolve new clients
		// Note that it can happen that we are not able to find hostnames but we don't
		// want to try to resolve them every minute in this case.
		if(clients[i].new)
		{
			clients[i].namepos = addstr(resolveHostname(getstr(clients[i].ippos)));
			clients[i].new = false;
		}
	}
	for(i = 0; i < counters.forwarded; i++)
	{
		// Memory validation
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);

		// Only try to resolve new forward destinations
		if(forwarded[i].new)
		{
			char *ipaddr = getstr(forwarded[i].ippos);
			char *hostname = resolveHostname(ipaddr);
			forwarded[i].namepos = addstr(hostname);
			free(hostname);
			forwarded[i].new = false;
		}
	}
}
