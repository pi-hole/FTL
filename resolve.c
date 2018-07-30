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
		char *clientip = getClientIP(clientID);
		char *hostname = resolveHostname(clientip);
		if(strlen(hostname) > 0)
		{
			// Delete possibly already existing hostname pointer before storing new data
			if(clients[clientID].name != NULL)
			{
				free(clients[clientID].name);
				clients[clientID].name = NULL;
			}

			// Store client hostname
			clients[clientID].name = strdup(hostname);
		}
		free(clientip);
		free(hostname);
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
		char* clientip = getClientIP(i);
		if(clients[i].new)
		{
			clients[i].name = resolveHostname(clientip);
			clients[i].new = false;
		}
		free(clientip);
	}
	for(i = 0; i < counters.forwarded; i++)
	{
		// Memory validation
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);

		// Only try to resolve new forward destinations
		if(forwarded[i].new)
		{
			forwarded[i].name = resolveHostname(forwarded[i].ip);
			forwarded[i].new = false;
		}
	}
}
