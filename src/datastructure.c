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
#include "datastructure.h"
#include "memory.h"
#include "shmem.h"
#include "log.h"
// enum REGEX
#include "regex_r.h"
#include "database/gravity-db.h"

// converts upper to lower case, and leaves other characters unchanged
void strtolower(char *str)
{
	int i = 0;
	while(str[i]){ str[i] = tolower(str[i]); i++; }
}

int findForwardID(const char * forwardString, const bool count)
{
	// Go through already knows forward servers and see if we used one of those
	for(int forwardID=0; forwardID < counters->forwarded; forwardID++)
	{
		// Get forward pointer
		forwardedData* forward = getForward(forwardID, true);

		// Check if the returned pointer is valid before trying to access it
		if(forward == NULL)
			continue;

		if(strcmp(getstr(forward->ippos), forwardString) == 0)
		{
			if(count) forward->count++;
			return forwardID;
		}
	}
	// This forward server is not known
	// Store ID
	const int forwardID = counters->forwarded;
	logg("New forward server: %s (%i/%u)", forwardString, forwardID, counters->forwarded_MAX);

	// Check struct size
	memory_check(FORWARDED);

	// Get forward pointer
	forwardedData* forward = getForward(forwardID, false);
	if(forward == NULL)
	{
		logg("ERROR: Encountered serious memory error in findForwardID()");
		return -1;
	}

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
	for(int domainID = 0; domainID < counters->domains; domainID++)
	{
		// Get domain pointer
		domainsData* domain = getDomain(domainID, true);

		// Check if the returned pointer is valid before trying to access it
		if(domain == NULL)
			continue;

		// Quick test: Does the domain start with the same character?
		if(getstr(domain->domainpos)[0] != domainString[0])
			continue;

		// If so, compare the full domain using strcmp
		if(strcmp(getstr(domain->domainpos), domainString) == 0)
		{
			domain->count++;
			return domainID;
		}
	}

	// If we did not return until here, then this domain is not known
	// Store ID
	const int domainID = counters->domains;

	// Check struct size
	memory_check(DOMAINS);

	// Get domain pointer
	domainsData* domain = getDomain(domainID, false);
	if(domain == NULL)
	{
		logg("ERROR: Encountered serious memory error in findDomainID()");
		return -1;
	}

	// Set magic byte
	domain->magic = MAGICBYTE;
	// Set its counter to 1
	domain->count = 1;
	// Set blocked counter to zero
	domain->blockedcount = 0;
	// Store domain name - no need to check for NULL here as it doesn't harm
	domain->domainpos = addstr(domainString);
	// Storage for individual client blocking status
	domain->clientstatus = new_ucharvec(counters->clients);
	// Increase counter by one
	counters->domains++;

	return domainID;
}

int findClientID(const char *clientIP, const bool count)
{
	// Compare content of client against known client IP addresses
	for(int clientID=0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		clientsData* client = getClient(clientID, true);

		// Check if the returned pointer is valid before trying to access it
		if(client == NULL)
			continue;

		// Quick test: Does the clients IP start with the same character?
		if(getstr(client->ippos)[0] != clientIP[0])
			continue;

		// If so, compare the full IP using strcmp
		if(strcmp(getstr(client->ippos), clientIP) == 0)
		{
			// Add one if count == true (do not add one, e.g., during ARP table processing)
			if(count) client->count++;
			return clientID;
		}
	}

	// Return -1 (= not found) if count is false ...
	if(!count)
		return -1;
	// ... otherwise proceed with adding a new client entry

	// If we did not return until here, then this client is definitely new
	// Store ID
	const int clientID = counters->clients;

	// Check struct size
	memory_check(CLIENTS);

	// Get client pointer
	clientsData* client = getClient(clientID, false);
	if(client == NULL)
	{
		logg("ERROR: Encountered serious memory error in findClientID()");
		return -1;
	}

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

	// Initialize client-specific domain data
	for(int domainID = 0; domainID < counters->domains; domainID++)
	{
		domainsData *domain = getDomain(domainID, true);
		domain->clientstatus->append(domain->clientstatus, UNKNOWN_BLOCKED);
	}

	// Allocate regex substructure
	allocate_regex_client_enabled(client);

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
const char *getDomainString(const int queryID)
{
	const queriesData* query = getQuery(queryID, true);

	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

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
const char *getClientIPString(const int queryID)
{
	const queriesData* query = getQuery(queryID, false);

	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

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
const char *getClientNameString(const int queryID)
{
	const queriesData* query = getQuery(queryID, true);

	// Check if the returned pointer is valid before trying to access it
	if(query == NULL)
		return "";

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
