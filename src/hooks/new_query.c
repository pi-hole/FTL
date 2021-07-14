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
// FTL_check_blocking
#include "check_blocking.h"
// force_next_DNS_reply
#include "make_answer.h"
// hostname()
#include "../daemon.h"
// mysockaddr_extract_ip_port()
#include "mysockaddr_extract_ip_port.h"
// pihole_PTR()
#include "pihole_PTR.h"
// short_path()
#include "../files.h"

bool _FTL_new_query(const unsigned int flags, const char *name,
                    union mysockaddr *addr, const char *types,
                    const unsigned short qtype, const int id,
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

	// If domain is "pi.hole" or the local hostname we skip analyzing this query
	// and, instead, immediately reply with the IP address - these queries are not further analyzed
	if(strcasecmp(name, "pi.hole") == 0 || strcasecmp(name, hostname()) == 0)
	{
		if(querytype == TYPE_A || querytype == TYPE_AAAA || querytype == TYPE_ANY)
		{
			// "Block" this query by sending the interface IP address
			force_next_DNS_reply = REPLY_IP;
			blockingreason = "internal";
			log_debug(DEBUG_QUERIES, "Replying to %s with interface-local IP address", name);
			return true;
		}
		else
		{
			// Don't block this query
			return false;
		}
	}

	// Check if this is a PTR request for a local interface.
	// If so, we inject a "pi.hole" reply here
	if(querytype == TYPE_PTR && config.pihole_ptr)
		pihole_PTR((char*)name);

	// Skip AAAA queries if user doesn't want to have them analyzed
	if(!config.analyze_AAAA && querytype == TYPE_AAAA)
	{
		log_debug(DEBUG_QUERIES, "Not analyzing AAAA query");
		return false;
	}

	// Convert domain to lower case
	char *domainString = strdup(name);
	strtolower(domainString);

	// Get client IP address
	// The requestor's IP address can be rewritten using EDNS(0) client
	// subnet (ECS) data), however, we do not rewrite the IPs ::1 and
	// 127.0.0.1 to avoid queries originating from localhost of the
	// *distant* machine as queries coming from the *local* machine
	const sa_family_t family = addr ? addr->sa.sa_family : AF_INET;
	in_port_t clientPort = daemon->port;
	bool internal_query = false;
	char clientIP[ADDRSTRLEN+1] = { 0 };
	if(config.edns0_ecs && edns && edns->client_set)
	{
		// Use ECS provided client
		strncpy(clientIP, edns->client, ADDRSTRLEN);
		clientIP[ADDRSTRLEN] = '\0';
	}
	else if(addr)
	{
		// Use original requestor
		mysockaddr_extract_ip_port(addr, clientIP, &clientPort);
	}
	else
	{
		// No client address available, this is an automatically generated (e.g.
		// DNSSEC) query
		internal_query = true;
		strcpy(clientIP, "::");
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

	// Interface name is only available for regular queries, not for
	// automatically generated DNSSEC queries
	const char *interface = internal_query ? "-" : next_iface.name;

	// Check rate-limit for this client
	if(!internal_query && config.rate_limit.count > 0 &&
	   ++client->rate_limit > config.rate_limit.count)
	{
		log_debug(DEBUG_QUERIES, "Rate-limiting %sIPv%d %s query \"%s\" from %s:%s#%d",
		          proto == TCP ? "TCP " : proto == UDP ? "UDP " : "",
		          family == AF_INET ? 4 : 6, types, domainString, interface,
		          clientIP, clientPort);

		// Block this query
		force_next_DNS_reply = REPLY_REFUSED;

		// Do not further process this query, Pi-hole has never seen it
		unlock_shm();
		return true;
	}

	// Log new query if in debug mode
	if(config.debug & DEBUG_QUERIES)
	{
		log_debug(DEBUG_QUERIES, "**** new %sIPv%d %s query \"%s\" from %s:%s#%d (ID %i, FTL %i, %s:%i)",
		          proto == TCP ? "TCP " : proto == UDP ? "UDP " : "",
		          family == AF_INET ? 4 : 6, types, domainString, interface,
		          internal_query ? "<internal>" : clientIP, clientPort,
		          id, queryID, short_path(file), line);
	}

	// Update counters
	counters->querytype[querytype-1]++;

	// Update overTime
	const unsigned int timeidx = getOverTimeID(querytimestamp);

	// Skip rest of the analysis if this query is not of type A or AAAA
	// but user wants to see only A and AAAA queries (pre-v4.1 behavior)
	if(config.analyze_only_A_AAAA && querytype != TYPE_A && querytype != TYPE_AAAA)
	{
		// Don't process this query further here, we already counted it
		log_debug(DEBUG_QUERIES, "Notice: Skipping new query: %s (%i)", types, id);
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
	counters->status[QUERY_UNKNOWN]++;
	query_set_status(query, QUERY_UNKNOWN);
	query->domainID = domainID;
	query->clientID = clientID;
	// Initialize database field, will be set when the query is stored in the long-term DB
	query->flags.database = false;
	query->flags.complete = false;
	query->response = converttimeval(request);
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

	// Query extended DNS error
	query->ede = EDE_UNSET;

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
	if(!internal_query && strlen(interface) > 1)
	{
		if(client->ifacepos == 0u)
		{
			// Store in the client data if unknown so far
			client->ifacepos = addstr(interface);
		}
		else
		{
			// Check if this is still the same interface or
			// if the client moved to another interface
			// (may require group re-processing)
			const char *oldiface = getstr(client->ifacepos);
			if(strcasecmp(oldiface, interface) != 0)
			{
				if(config.debug & DEBUG_CLIENTS)
				{
					const char *clientName = getstr(client->namepos);
					log_debug(DEBUG_CLIENTS, "Client %s (%s) changed interface: %s -> %s",
					          clientIP, clientName, oldiface, interface);
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
		if(config.debug & DEBUG_ARP)
		{
			if(client->hwlen == 6)
				log_debug(DEBUG_ARP, "find_mac(\"%s\") returned hardware address "
				          "%02X:%02X:%02X:%02X:%02X:%02X", clientIP,
				          client->hwaddr[0], client->hwaddr[1], client->hwaddr[2],
				          client->hwaddr[3], client->hwaddr[4], client->hwaddr[5]);
			else
				log_debug(DEBUG_ARP, "find_mac(\"%s\") returned %i bytes of data",
				          clientIP, client->hwlen);
		}
	}

	bool blockDomain = false;
	// Check if this should be blocked only for active queries
	// (skipped for internally generated ones, e.g., DNSSEC)
	if(!internal_query)
		blockDomain = FTL_check_blocking(queryID, domainID, clientID);

	// Free allocated memory
	free(domainString);

	// Release thread lock
	unlock_shm();

	return blockDomain;
}