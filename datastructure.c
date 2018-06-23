/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query processing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

// converts upper to lower case, and leaves other characters unchanged
void strtolower(char *str)
{
	int i = 0;
	while(str[i]){ str[i] = tolower(str[i]); i++; }
}

void gettimestamp(int *querytimestamp, int *overTimetimestamp)
{
	// Get current time
	*querytimestamp = (int)time(NULL);

	// Floor timestamp to the beginning of 10 minutes interval
	// and add 5 minutes to center it in the interval
	*overTimetimestamp = *querytimestamp-(*querytimestamp%600)+300;
}

int findOverTimeID(int overTimetimestamp)
{
	int timeidx = -1, i;
	// Check struct size
	memory_check(OVERTIME);
	if(counters.overTime > 0)
		validate_access("overTime", counters.overTime-1, true, __LINE__, __FUNCTION__, __FILE__);
	for(i=0; i < counters.overTime; i++)
	{
		if(overTime[i].timestamp == overTimetimestamp)
			return i;
	}
	// We loop over this to fill potential data holes with zeros
	int nexttimestamp = 0;
	if(counters.overTime != 0)
	{
		validate_access("overTime", counters.overTime-1, false, __LINE__, __FUNCTION__, __FILE__);
		nexttimestamp = overTime[counters.overTime-1].timestamp + 600;
	}
	else
	{
		nexttimestamp = overTimetimestamp;
	}

	// Fill potential holes in the overTime struct (may happen
	// if there haven't been any queries within a time interval)
	while(overTimetimestamp >= nexttimestamp)
	{
		// Check struct size
		memory_check(OVERTIME);
		timeidx = counters.overTime;
		validate_access("overTime", timeidx, false, __LINE__, __FUNCTION__, __FILE__);
		// Set magic byte
		overTime[timeidx].magic = MAGICBYTE;
		overTime[timeidx].timestamp = nexttimestamp;
		overTime[timeidx].total = 0;
		overTime[timeidx].blocked = 0;
		overTime[timeidx].cached = 0;
		// overTime[timeidx].querytypedata is static
		overTime[timeidx].clientnum = 0;
		overTime[timeidx].clientdata = NULL;
		counters.overTime++;

		// Update time stamp for next loop interation
		if(counters.overTime != 0)
		{
			validate_access("overTime", counters.overTime-1, false, __LINE__, __FUNCTION__, __FILE__);
			nexttimestamp = overTime[counters.overTime-1].timestamp + 600;
		}
	}
	return timeidx;
}

int findForwardID(const char * forward, bool count)
{
	int i, forwardID = -1;
	if(counters.forwarded > 0)
		validate_access("forwarded", counters.forwarded-1, true, __LINE__, __FUNCTION__, __FILE__);
	// Go through already knows forward servers and see if we used one of those
	for(i=0; i < counters.forwarded; i++)
	{
		if(strcmp(forwarded[i].ip, forward) == 0)
		{
			forwardID = i;
			if(count) forwarded[forwardID].count++;
			return forwardID;
		}
	}
	// This forward server is not known
	// Store ID
	forwardID = counters.forwarded;
	logg("New forward server: %s (%i/%u)", forward, forwardID, counters.forwarded_MAX);

	// Check struct size
	memory_check(FORWARDED);

	validate_access("forwarded", forwardID, false, __LINE__, __FUNCTION__, __FILE__);
	// Set magic byte
	forwarded[forwardID].magic = MAGICBYTE;
	// Initialize its counter
	if(count)
		forwarded[forwardID].count = 1;
	else
		forwarded[forwardID].count = 0;
	// Save forward destination IP address
	forwarded[forwardID].ip = strdup(forward);
	forwarded[forwardID].failed = 0;
	// Initialize forward hostname
	// Due to the nature of us being the resolver,
	// the actual resolving of the host name has
	// to be done separately to be non-blocking
	forwarded[forwardID].new = true;
	forwarded[forwardID].name = NULL;
	// Increase counter by one
	counters.forwarded++;

	return forwardID;
}

int findDomainID(const char *domain)
{
	int i;
	if(counters.domains > 0)
		validate_access("domains", counters.domains-1, true, __LINE__, __FUNCTION__, __FILE__);
	for(i=0; i < counters.domains; i++)
	{
		// Quick test: Does the domain start with the same character?
		if(domains[i].domain[0] != domain[0])
			continue;

		// If so, compare the full domain using strcmp
		if(strcmp(domains[i].domain, domain) == 0)
		{
			domains[i].count++;
			return i;
		}
	}

	// If we did not return until here, then this domain is not known
	// Store ID
	int domainID = counters.domains;

	// Check struct size
	memory_check(DOMAINS);

	validate_access("domains", domainID, false, __LINE__, __FUNCTION__, __FILE__);
	// Set magic byte
	domains[domainID].magic = MAGICBYTE;
	// Set its counter to 1
	domains[domainID].count = 1;
	// Set blocked counter to zero
	domains[domainID].blockedcount = 0;
	// Store domain name - no need to check for NULL here as it doesn't harm
	domains[domainID].domain = strdup(domain);
	// RegEx needs to be evaluated for this new domain
	domains[domainID].regexmatch = REGEX_UNKNOWN;
	// Increase counter by one
	counters.domains++;

	return domainID;
}

int findClientID(const char *client)
{
	int i;
	// Compare content of client against known client IP addresses
	if(counters.clients > 0)
		validate_access("clients", counters.clients-1, true, __LINE__, __FUNCTION__, __FILE__);
	for(i=0; i < counters.clients; i++)
	{
		// Quick test: Does the clients IP start with the same character?
		if(clients[i].ip[0] != client[0])
			continue;

		// If so, compare the full IP using strcmp
		if(strcmp(clients[i].ip, client) == 0)
		{
			clients[i].count++;
			return i;
		}
	}

	// If we did not return until here, then this client is definitely new
	// Store ID
	int clientID = counters.clients;

	// Check struct size
	memory_check(CLIENTS);

	validate_access("clients", clientID, false, __LINE__, __FUNCTION__, __FILE__);
	// Set magic byte
	clients[clientID].magic = MAGICBYTE;
	// Set its counter to 1
	clients[clientID].count = 1;
	// Initialize blocked count to zero
	clients[clientID].blockedcount = 0;
	// Store client IP - no need to check for NULL here as it doesn't harm
	clients[clientID].ip = strdup(client);
	// Initialize client hostname
	// Due to the nature of us being the resolver,
	// the actual resolving of the host name has
	// to be done separately to be non-blocking
	clients[clientID].new = true;
	clients[clientID].name = NULL;
	// Increase counter by one
	counters.clients++;

	return clientID;
}

bool isValidIPv4(const char *addr)
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, addr, &(sa.sin_addr)) != 0;
}

bool isValidIPv6(const char *addr)
{
	struct sockaddr_in6 sa;
	return inet_pton(AF_INET6, addr, &(sa.sin6_addr)) != 0;
}
