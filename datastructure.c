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

int findForwardID(const char * forwardString, bool count)
{
	int forwardID = -1;
	// Go through already knows forward servers and see if we used one of those
	for(int i=0; i < counters->forwarded; i++)
	{
		// Get forward pointer
		forwardedData* forward = getForward(i, true);

		if(strcmp(getstr(forward->ippos), forwardString) == 0)
		{
			if(count) forward->count++;
			return i;
		}
	}
	// This forward server is not known
	// Store ID
	forwardID = counters->forwarded;
	logg("New forward server: %s (%i/%u)", forwardString, forwardID, counters->forwarded_MAX);

	// Check struct size
	memory_check(FORWARDED);

	// Get forward pointer
	forwardedData* forward = getForward(forwardID, false);

	// Set magic byte
	forward->magic = MAGICBYTE;
	// Initialize its counter
	if(count)
		forward->count = 1;
	else
		forward->count = 0;
	// Save forward destination IP address
	forward->ippos = addstr(forwardString);
	forward->failed = 0;
	// Initialize forward hostname
	// Due to the nature of us being the resolver,
	// the actual resolving of the host name has
	// to be done separately to be non-blocking
	forward->new = true;
	forward->namepos = 0; // 0 -> string with length zero
	// Increase counter by one
	counters->forwarded++;

	return forwardID;
}

int findDomainID(const char *domainString)
{
	for(int i=0; i < counters->domains; i++)
	{
		// Get domain pointer
		domainsData* domain = getDomain(i, true);

		// Quick test: Does the domain start with the same character?
		if(getstr(domain->domainpos)[0] != domainString[0])
			continue;

		// If so, compare the full domain using strcmp
		if(strcmp(getstr(domain->domainpos), domainString) == 0)
		{
			domain->count++;
			return i;
		}
	}

	// If we did not return until here, then this domain is not known
	// Store ID
	int domainID = counters->domains;

	// Check struct size
	memory_check(DOMAINS);

	// Get domain pointer
	domainsData* domain = getDomain(domainID, false);

	// Set magic byte
	domain->magic = MAGICBYTE;
	// Set its counter to 1
	domain->count = 1;
	// Set blocked counter to zero
	domain->blockedcount = 0;
	// Store domain name - no need to check for NULL here as it doesn't harm
	domain->domainpos = addstr(domainString);
	// RegEx needs to be evaluated for this new domain
	domain->regexmatch = REGEX_UNKNOWN;
	// Increase counter by one
	counters->domains++;

	return domainID;
}

int findClientID(const char *clientIP, bool count)
{
	// Compare content of client against known client IP addresses
	for(int i=0; i < counters->clients; i++)
	{
		// Get client pointer
		clientsData* client = getClient(i, true);

		// Quick test: Does the clients IP start with the same character?
		if(getstr(client->ippos)[0] != clientIP[0])
			continue;

		// If so, compare the full IP using strcmp
		if(strcmp(getstr(client->ippos), clientIP) == 0)
		{
			// Add one if count == true (do not add one, e.g., during ARP table processing)
			if(count) client->count++;
			return i;
		}
	}

	// Return -1 (= not found) if count is false ...
	if(!count)
		return -1;
	// ... otherwise proceed with adding a new client entry

	// If we did not return until here, then this client is definitely new
	// Store ID
	int clientID = counters->clients;

	// Check struct size
	memory_check(CLIENTS);

	// Get client pointer
	clientsData* client = getClient(clientID, false);

	// Set magic byte
	client->magic = MAGICBYTE;
	// Set its counter to 1
	client->count = 1;
	// Initialize blocked count to zero
	client->blockedcount = 0;
	// Store client IP - no need to check for NULL here as it doesn't harm
	client->ippos = addstr(clientIP);
	// Initialize client hostname
	// Due to the nature of us being the resolver,
	// the actual resolving of the host name has
	// to be done separately to be non-blocking
	client->new = true;
	client->namepos = 0;
	// No query seen so far
	client->lastQuery = 0;
	client->numQueriesARP = 0;

	// Initialize client-specific overTime data
	for(int i = 0; i < OVERTIME_SLOTS; i++)
		client->overTime[i] = 0;

	// Increase counter by one
	counters->clients++;

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

// Privacy-level sensitive subroutine that returns the domain name
// only when appropriate for the requested query
char *getDomainString(int queryID)
{
	const queriesData* query = getQuery(queryID, true);
	if(query->privacylevel < PRIVACY_HIDE_DOMAINS)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(query->domainID, true);

		// Return string
		return getstr(domain->domainpos);
	}
	else
		return HIDDEN_DOMAIN;
}

// Privacy-level sensitive subroutine that returns the client IP
// only when appropriate for the requested query
char *getClientIPString(int queryID)
{
	const queriesData* query = getQuery(queryID, false);
	if(query->privacylevel < PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		// Get client pointer
		const clientsData* client = getClient(query->clientID, false);

		// Return string
		return getstr(client->ippos);
	}
	else
		return HIDDEN_CLIENT;
}

// Privacy-level sensitive subroutine that returns the client host name
// only when appropriate for the requested query
char *getClientNameString(int queryID)
{
	const queriesData* query = getQuery(queryID, true);
	if(query->privacylevel < PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		// Get client pointer
		const clientsData* client = getClient(query->clientID, true);

		// Return string
		return getstr(client->namepos);
	}
	else
		return HIDDEN_CLIENT;
}
