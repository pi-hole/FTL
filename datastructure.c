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

// Macro comparing the first 4 bytes (the first byte is assumed to have already been checked)
#define COMP4(a,b) (a[1] == b[1] && a[2] == b[2] && a[3] == b[3])
// Macro comparing 16 bytes (for IPv6 addresses)
#define COMP16(a,b) (a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && \
                     a[4] == b[4] && a[5] == b[5] && a[6] == b[6] && \
                     a[7] == b[7] && a[8] == b[8] && a[9] == b[9] && \
                     a[10] == b[10] && a[11] == b[11] && a[12] == b[12] && \
                     a[13] == b[13] && a[14] == b[14] && a[15] == b[15])

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
	int ret, proto = !(strstr(forward,":") != NULL) ? AF_INET : AF_INET6;
	char addrbuf[16];
	if((ret = inet_pton(proto, forward, addrbuf)) != 1)
		logg("ERROR: inet_pton(%i, \"%s\", %p) failed with code %i (findForwardID)", proto, forward, addrbuf, ret);
	if(counters.forwarded > 0)
		validate_access("forwarded", counters.forwarded-1, true, __LINE__, __FUNCTION__, __FILE__);
	// Go through already knows forward servers and see if we used one of those
	for(i=0; i < counters.forwarded; i++)
	{
		// Quick test: Does the forwarded IP start with octet?
		if(forwarded[i].addr[0] != addrbuf[0])
			continue;

		// If so, compare the rest of the address
		if(proto == AF_INET && COMP4(forwarded[i].addr, addrbuf))
		{
			forwarded[i].count++;
			return i;
		}

		// If so, compare the rest of the address
		if(proto == AF_INET6 && COMP16(forwarded[i].addr, addrbuf))
		{
			forwarded[i].count++;
			return i;
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
	// Store client IP
	saveForwardIP(i, forward);
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
	int ret, proto = !(strstr(client,":") != NULL) ? AF_INET : AF_INET6;
	char addrbuf[16];
	if((ret = inet_pton(proto, client, addrbuf)) != 1)
		logg("ERROR: inet_pton(%i, \"%s\", %p) failed with code %i (findClientID)", proto, client, addrbuf, ret);

	// Compare content of client against known client IP addresses
	if(counters.clients > 0)
		validate_access("clients", counters.clients-1, true, __LINE__, __FUNCTION__, __FILE__);
	for(i=0; i < counters.clients; i++)
	{
		// Quick test: Does the clients IP start with octet?
		if(clients[i].addr[0] != addrbuf[0])
			continue;

		// If so, compare the rest of the address
		if(proto == AF_INET && COMP4(clients[i].addr, addrbuf))
		{
			clients[i].count++;
			return i;
		}

		// If so, compare the rest of the address
		if(proto == AF_INET6 && COMP16(clients[i].addr, addrbuf))
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
	// Store client IP
	saveClientIP(i, client);
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

void saveClientIP(int i, const char *ipaddr)
{
	clients[i].IPv4 = !(strstr(ipaddr,":") != NULL);
	int ret, proto = clients[i].IPv4 ? AF_INET : AF_INET6;
	if((ret = inet_pton(proto, ipaddr, clients[i].addr)) != 1)
		logg("ERROR: inet_pton(%i, %s, %p) failed with %i", proto, ipaddr, clients[i].addr, ret);
}

char* getClientIP(int i)
{
	char *buffer = calloc(INET6_ADDRSTRLEN, sizeof(char));
	int proto = clients[i].IPv4 ? AF_INET : AF_INET6;
	inet_ntop(proto, clients[i].addr, buffer, INET6_ADDRSTRLEN);
	return buffer;
}

void saveForwardIP(int i, const char *ipaddr)
{
	forwarded[i].IPv4 = !(strstr(ipaddr,":") != NULL);
	int ret, proto = forwarded[i].IPv4 ? AF_INET : AF_INET6;
	if((ret = inet_pton(proto, ipaddr, forwarded[i].addr)) != 1)
		logg("ERROR: inet_pton(%i, %s, %p) failed with %i", proto, ipaddr, forwarded[i].addr, ret);
}

char* getForwardIP(int i)
{
	char *buffer = calloc(INET6_ADDRSTRLEN, sizeof(char));
	int proto = forwarded[i].IPv4 ? AF_INET : AF_INET6;
	inet_ntop(proto, forwarded[i].addr, buffer, INET6_ADDRSTRLEN);
	return buffer;
}
