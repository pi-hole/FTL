/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "new_query.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// overTime struct
#include "../overTime.h"
// struct queriesData, etc.
#include "../datastructure.h"
// gravityDB_reload_groups()
#include "../database/gravity-db.h"
// converttimeval()
#include "../timers.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// query_to_database()
#include "../database/query-table.h"
// struct nxtiface next_iface
#include "iface.h"
// force_next_DNS_reply
#include "blocking_metadata.h"
// FTL_check_blocking
#include "check_blocking.h"

bool _FTL_new_query(const unsigned int flags, const char *name,
                    const char **blockingreason, union mysockaddr *addr,
                    const char *types, const unsigned short qtype, const int id,
                    const ednsData *edns, const enum protocol proto,
                    const char* file, const int line)
{
	// Create new query in data structure

	// Get timestamp
	const double querytimestamp = double_time();

	// Save request time
	struct timeval request;
	gettimeofday(&request, 0);

	// Determine query type
	enum query_type querytype;
	switch(qtype)
	{
		case T_A:
			querytype = TYPE_A;
			break;
		case T_AAAA:
			querytype = TYPE_AAAA;
			break;
		case T_ANY:
			querytype = TYPE_ANY;
			break;
		case T_SRV:
			querytype = TYPE_SRV;
			break;
		case T_SOA:
			querytype = TYPE_SOA;
			break;
		case T_PTR:
			querytype = TYPE_PTR;
			break;
		case T_TXT:
			querytype = TYPE_TXT;
			break;
		case T_NAPTR:
			querytype = TYPE_NAPTR;
			break;
		case T_MX:
			querytype = TYPE_MX;
			break;
		case T_DS:
			querytype = TYPE_DS;
			break;
		case T_RRSIG:
			querytype = TYPE_RRSIG;
			break;
		case T_DNSKEY:
			querytype = TYPE_DNSKEY;
			break;
		case T_NS:
			querytype = TYPE_NS;
			break;
		case 64: // Scn. 2 of https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
			querytype = TYPE_SVCB;
			break;
		case 65: // Scn. 2 of https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
			querytype = TYPE_HTTPS;
			break;
		default:
			querytype = TYPE_OTHER;
			break;
	}

	// Skip AAAA queries if user doesn't want to have them analyzed
	if(!config.analyze_AAAA && querytype == TYPE_AAAA)
	{
		log_debug(DEBUG_QUERIES, "Not analyzing AAAA query");
		return false;
	}

	// If domain is "pi.hole" we skip this query
	if(strcasecmp(name, "pi.hole") == 0)
		return false;

	// Convert domain to lower case
	char *domainString = strdup(name);
	strtolower(domainString);

	// Get client IP address
	// The requestor's IP address can be rewritten using EDNS(0) client
	// subnet (ECS) data), however, we do not rewrite the IPs ::1 and
	// 127.0.0.1 to avoid queries originating from localhost of the
	// *distant* machine as queries coming from the *local* machine
	const sa_family_t family = addr->sa.sa_family;
	char clientIP[ADDRSTRLEN+1] = { 0 };
	if(config.edns0_ecs && edns->client_set)
	{
		// Use ECS provided client
		strncpy(clientIP, edns->client, ADDRSTRLEN);
		clientIP[ADDRSTRLEN] = '\0';
	}
	else
	{
		// Use original requestor
		inet_ntop(family,
		          family == AF_INET ?
		             (union mysockaddr*)&addr->in.sin_addr :
		             (union mysockaddr*)&addr->in6.sin6_addr,
		          clientIP, ADDRSTRLEN);
	}

	// Check if user wants to skip queries coming from localhost
	if(config.ignore_localhost &&
	   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
	{
		free(domainString);
		return false;
	}

	// Lock shared memory
	lock_shm();
	const int queryID = counters->queries;

	// Find client IP
	const int clientID = findClientID(clientIP, true, false);

	// Get client pointer
	clientsData* client = getClient(clientID, true);
	if(client == NULL)
	{
		// Encountered memory error, skip query
		// Free allocated memory
		free(domainString);
		// Release thread lock
		unlock_shm();
		return false;
	}

	// Check rate-limit for this client
	if(config.rate_limit.count > 0 &&
	   ++client->rate_limit > config.rate_limit.count)
	{
		log_debug(DEBUG_QUERIES, "Rate-limiting %s %s query \"%s\" from %s:%s",
		          proto == TCP ? "TCP" : "UDP",
		          types, domainString, next_iface.name, clientIP);

		// Block this query
		force_next_DNS_reply = REFUSED;

		// Do not further process this query, Pi-hole has never seen it
		unlock_shm();
		return true;
	}

	// Log new query if in debug mode
	log_debug(DEBUG_QUERIES, "**** new %s %s query \"%s\" from %s:%s (ID %i, FTL %i, %s:%i)",
	          proto == TCP ? "TCP" : "UDP",
	          types, domainString, next_iface.name, clientIP, id, queryID, file, line);

	// Update counters
	counters->querytype[querytype]++;

	// Update overTime
	const unsigned int timeidx = getOverTimeID(querytimestamp);

	// Skip rest of the analysis if this query is not of type A or AAAA
	// but user wants to see only A and AAAA queries (pre-v4.1 behavior)
	if(config.analyze_only_A_AAAA && querytype != TYPE_A && querytype != TYPE_AAAA)
	{
		// Don't process this query further here, we already counted it
		log_debug(DEBUG_QUERIES, "Skipping new query: %s (%i)", types, id);
		free(domainString);
		unlock_shm();
		return false;
	}

	// Go through already knows domains and see if it is one of them
	const int domainID = findDomainID(domainString, true);

	// Save everything
	queriesData* query = getQuery(queryID, false);
	if(query == NULL)
	{
		// Encountered memory error, skip query
		log_err("No memory available, skipping query analysis");
		// Free allocated memory
		free(domainString);
		// Release thread lock
		unlock_shm();
		return false;
	}

	// Fill query object with available data
	query->magic = MAGICBYTE;
	query->timestamp = querytimestamp;
	query->type = querytype;
	query->qtype = qtype;
	query->id = id; // Has to be set before calling query_set_status()

	// This query is unknown as long as no reply has been found and analyzed
	counters->status[STATUS_UNKNOWN]++;
	query_set_status(query, STATUS_UNKNOWN);
	query->domainID = domainID;
	query->clientID = clientID;
	query->timeidx = timeidx;
	// Initialize database rowID, will be set later
	query->db = -1;
	query->flags.complete = false;
	query->response = 0.0;
	// Initialize reply type
	query->reply = REPLY_UNKNOWN;
	// Store DNSSEC result for this domain
	query->dnssec = DNSSEC_UNKNOWN;
	query->CNAME_domainID = -1;
	// This query is not yet known ad forwarded or blocked
	query->flags.blocked = false;
	query->flags.allowed = false;

	// Indicator that this query was not forwarded so far
	query->upstreamID = -1;

	// Check and apply possible privacy level rules
	// The currently set privacy level (at the time the query is
	// generated) is stored in the queries structure
	query->privacylevel = config.privacylevel;

	// Increase DNS queries counter
	counters->queries++;

	// Update overTime data
	overTime[timeidx].total++;

	// Update overTime data structure with the new client
	change_clientcount(client, 0, 0, timeidx, 1);

	// Set lastQuery timer and add one query for network table
	client->lastQuery = querytimestamp;
	client->numQueriesARP++;

	// Process interface information of client (if available)
	// Skip interface name length 1 to skip "-". No real interface should
	// have a name with a length of 1...
	if(strlen(next_iface.name) > 1)
	{
		if(client->ifacepos == 0u)
		{
			// Store in the client data if unknown so far
			client->ifacepos = addstr(next_iface.name);
		}
		else
		{
			// Check if this is still the same interface or
			// if the client moved to another interface
			// (may require group re-processing)
			const char *oldiface = getstr(client->ifacepos);
			if(strcasecmp(oldiface, next_iface.name) != 0)
			{
				if(config.debug & DEBUG_CLIENTS)
				{
					const char *clientName = getstr(client->namepos);
					log_debug(DEBUG_CLIENTS, "Client %s (%s) changed interface: %s -> %s",
					          clientIP, clientName, oldiface, next_iface.name);
				}

				gravityDB_reload_groups(client);
			}
		}
	}

	// Set client MAC address from EDNS(0) information (if available)
	if(config.edns0_ecs && edns->mac_set)
	{
		memcpy(client->hwaddr, edns->mac_byte, 6);
		client->hwlen = 6;
	}

	// Try to obtain MAC address from dnsmasq's cache (also asks the kernel)
	if(client->hwlen < 1)
	{
		client->hwlen = find_mac(addr, client->hwaddr, 1, time(NULL));
		if(client->hwlen == 6)
			log_debug(DEBUG_ARP, "find_mac(\"%s\") returned hardware address "
			          "%02X:%02X:%02X:%02X:%02X:%02X", clientIP,
			          client->hwaddr[0], client->hwaddr[1], client->hwaddr[2],
			          client->hwaddr[3], client->hwaddr[4], client->hwaddr[5]);
		else
			log_debug(DEBUG_ARP, "find_mac(\"%s\") returned %i bytes of data",
			          clientIP, client->hwlen);
	}

	bool blockDomain = FTL_check_blocking(queryID, domainID, clientID, blockingreason);

	// Store query in database
	query_to_database(query);

	// Free allocated memory
	free(domainString);

	// Release thread lock
	unlock_shm();

	return blockDomain;
}