/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "dnsmasq_interface.h"

void print_flags(unsigned int flags);
void save_reply_type(unsigned int flags, int queryID, struct timeval response);
unsigned long converttimeval(struct timeval time);
static void block_single_domain(char *domain);

char flagnames[28][12] = {"F_IMMORTAL ", "F_NAMEP ", "F_REVERSE ", "F_FORWARD ", "F_DHCP ", "F_NEG ", "F_HOSTS ", "F_IPV4 ", "F_IPV6 ", "F_BIGNAME ", "F_NXDOMAIN ", "F_CNAME ", "F_DNSKEY ", "F_CONFIG ", "F_DS ", "F_DNSSECOK ", "F_UPSTREAM ", "F_RRNAME ", "F_SERVER ", "F_QUERY ", "F_NOERR ", "F_AUTH ", "F_DNSSEC ", "F_KEYTAG ", "F_SECSTAT ", "F_NO_RR ", "F_IPSET ", "F_NOEXTRA "};

void FTL_new_query(unsigned int flags, char *name, struct all_addr *addr, char *types, int id, char type)
{
	// Create new query in data structure
	enable_thread_lock();
	// Get timestamp
	int querytimestamp, overTimetimestamp;
	gettimestamp(&querytimestamp, &overTimetimestamp);

	// Save request time
	struct timeval request;
	gettimeofday(&request, 0);

	// Skip AAAA queries if user doesn't want to have them analyzed
	if(!config.analyze_AAAA && strcmp(types,"query[AAAA]") == 0)
	{
		if(debug) logg("Not analyzing AAAA query");
		disable_thread_lock();
		return;
	}

	// Ensure we have enough space in the queries struct
	memory_check(QUERIES);
	int queryID = counters.queries;

	// Convert domain to lower case
	char *domain = strdup(name);
	strtolower(domain);

	// If domain is "pi.hole" we skip this query
	if(strcmp(domain, "pi.hole") == 0)
	{
		// free memory already allocated here
		free(domain);
		disable_thread_lock();
		return;
	}

	// Check and apply possible privacy level rules
	// We do this immediately on the raw data to avoid any possible leaking
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
	{
		free(domain);
		domain = strdup("hidden");
	}

	// Get client IP address
	char dest[ADDRSTRLEN];
	inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	char *client = strdup(dest);
	strtolower(client);

	// Check if user wants to skip queries coming from localhost
	if(config.ignore_localhost &&
	   (strcmp(client, "127.0.0.1") == 0 || strcmp(client, "::1") == 0))
	{
		free(domain);
		free(client);
		disable_thread_lock();
		return;
	}

	// Check and apply possible privacy level rules
	// We do this immediately on the raw data to avoid any possible leaking
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
	{
		free(client);
		client = strdup("0.0.0.0");
	}

	// Log new query if in debug mode
	char *proto = (type == UDP) ? "UDP" : "TCP";
	if(debug) logg("**** new %s %s \"%s\" from %s (ID %i)", proto, types, domain, client, id);

	// Determine query type
	unsigned char querytype = 0;
	if(strcmp(types,"query[A]") == 0)
		querytype = TYPE_A;
	else if(strcmp(types,"query[AAAA]") == 0)
		querytype = TYPE_AAAA;
	else if(strcmp(types,"query[ANY]") == 0)
		querytype = TYPE_ANY;
	else if(strcmp(types,"query[SRV]") == 0)
		querytype = TYPE_SRV;
	else if(strcmp(types,"query[SOA]") == 0)
		querytype = TYPE_SOA;
	else if(strcmp(types,"query[PTR]") == 0)
		querytype = TYPE_PTR;
	else if(strcmp(types,"query[TXT]") == 0)
		querytype = TYPE_TXT;
	else
	{
		// Return early to avoid accessing querytypedata out of bounds
		if(debug) logg("Notice: Skipping unknown query type: %s (%i)", types, id);
		free(domain);
		free(client);
		disable_thread_lock();
		return;
	}

	// Update counters
	int timeidx = findOverTimeID(overTimetimestamp);
	validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
	overTime[timeidx].querytypedata[querytype-1]++;
	counters.querytype[querytype-1]++;

	// Skip rest of the analyis if this query is not of type A or AAAA
	if(querytype != TYPE_A && querytype != TYPE_AAAA)
	{
		// Don't process this query further here, we already counted it
		if(debug) logg("Notice: Skipping new query: %s (%i)", types, id);
		free(domain);
		free(client);
		disable_thread_lock();
		return;
	}

	// Go through already knows domains and see if it is one of them
	int domainID = findDomainID(domain);

	// Go through already knows clients and see if it is one of them
	int clientID = findClientID(client);

	// Save everything
	validate_access("queries", queryID, false, __LINE__, __FUNCTION__, __FILE__);
	queries[queryID].magic = MAGICBYTE;
	queries[queryID].timestamp = querytimestamp;
	queries[queryID].type = querytype;
	queries[queryID].status = QUERY_UNKNOWN;
	queries[queryID].domainID = domainID;
	queries[queryID].clientID = clientID;
	queries[queryID].timeidx = timeidx;
	queries[queryID].db = false;
	queries[queryID].id = id;
	queries[queryID].complete = false;
	queries[queryID].private = (config.privacylevel == PRIVACY_MAXIMUM);
	queries[queryID].response = converttimeval(request);
	// Initialize reply type
	queries[queryID].reply = REPLY_UNKNOWN;
	// Store DNSSEC result for this domain
	queries[queryID].dnssec = DNSSEC_UNSPECIFIED;

	// Increase DNS queries counter
	counters.queries++;
	// Count this query as unknown as long as no reply has
	// been found and analyzed
	counters.unknown++;

	// Update overTime data
	validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
	overTime[timeidx].total++;

	// Update overTime data structure with the new client
	validate_access_oTcl(timeidx, clientID, __LINE__, __FUNCTION__, __FILE__);
	overTime[timeidx].clientdata[clientID]++;

	// Try blocking regex if configured
	validate_access("domains", domainID, false, __LINE__, __FUNCTION__, __FILE__);
	if(config.blockingregex && domains[domainID].regexmatch == REGEX_UNKNOWN)
	{
		// For minimal performance impact, we test the regex only when
		// - regex checking is enabled, and
		// - this domain has not already been validated against the regex.
		// This effectively prevents multiple evaluations of the same domain
		if(match_regex(domain))
		{
			// We have to block this domain if not already done
			if(debug) logg("Blocking %s due to RegEx match", domain);
			block_single_domain(domain);
			domains[domainID].regexmatch = REGEX_BLOCKED;
		}
		else
		{
			// Explicitly mark as not blocked to skip regex test
			// next time we see this domain
			domains[domainID].regexmatch = REGEX_NOTBLOCKED;
		}
	}

	// Free allocated memory
	free(client);
	free(domain);

	// Release thread lock
	disable_thread_lock();
}

void FTL_forwarded(unsigned int flags, char *name, struct all_addr *addr, int id)
{
	// Save that this query got forwarded to an upstream server
	enable_thread_lock();

	// Get forward destination IP address
	char dest[ADDRSTRLEN];
	inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	// Convert forward to lower case
	char *forward = strdup(dest);
	strtolower(forward);

	// Debug logging
	if(debug) logg("**** forwarded %s to %s (ID %i)", name, forward, id);

	// Save status and forwardID in corresponding query identified by dnsmasq's ID
	bool found = false;
	int i;
	// Loop through all queries - this is an expensive loop, however, there is no
	// good alternative as we will loose the relation between dnsmasq's id and our
	// id due to garbage collection, hence, it may be that a query that with an ID
	// of dnsmasq of 123.456 is our query with ID 567 when the other queries have
	// already been removed due to their age. This is the price ofour very memory
	// efficient datastructure which, however, allows us to have FTL run non-stop.
	// Previously, FTL had to flush its internal data structure at midnight and re-
	// parse the history from the pihole.log.1 file. Something like this is not
	// needed anymore. We only have to get historic information from the database
	// once on startup but then never again.

	// Validate access only once for the maximum index (all lower will work)
	validate_access("queries", counters.queries-1, false, __LINE__, __FUNCTION__, __FILE__);
	for(i=0; i<counters.queries; i++)
	{
		// Check UUID of this query
		if(queries[i].id == id)
		{
			queries[i].status = QUERY_FORWARDED;
			found = true;
			break;
		}
	}
	if(!found)
	{
		// This may happen e.g. if the original query was a PTR query or "pi.hole"
		// as we ignore them altogether
		free(forward);
		disable_thread_lock();
		return;
	}

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destionations are coimg in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	if(queries[i].complete && queries[i].status != QUERY_CACHE)
	{
		free(forward);
		disable_thread_lock();
		return;
	}

	// Get ID of forward destination, create new forward destination record
	// if not found in current data structure
	int forwardID = findForwardID(forward, true);
	queries[i].forwardID = forwardID;

	if(!queries[i].complete)
	{
		int j = queries[i].timeidx;
		validate_access("overTime", j, true, __LINE__, __FUNCTION__, __FILE__);

		if(queries[i].status == QUERY_CACHE)
		{
			// Detect if we cached the <CNAME> but need to ask the upstream
			// servers for the actual IPs now, we remove this query from the
			// counters for cache replied queries as we had to forward a
			// request for it. Example:
			// Assume a domain a.com is a CNAME which is cached and has a very
			// long TTL. It point to another domain server.a.com which has an
			// A record but this has a much lower TTL.
			// If you now query a.com and then again after some time, you end
			// up in a situation where dnsmasq can answer the first level of
			// the DNS result (the CNAME) from cache, hence the status of this
			// query is marked as "answered from cache" in FTLDNS. However, for
			// server.a.com wit the much shorter TTL, we still have to forward
			// something and ask the upstream server for the final IP address.
			// This code section acknowledges this by removing one entry from
			// the cached counters as we will re-brand this query as having been
			// forwarded in the following.
			counters.cached--;
			// Also correct overTime data
			overTime[j].cached--;

			// Correct reply timer
			struct timeval response;
			gettimeofday(&response, 0);
			// Reset timer, shift slightly into the past to acknowledge the time
			// FTLDNS needed to look up the CNAME in its cache
			queries[i].response = converttimeval(response) - queries[i].response;
		}
		else
		{
			// Normal cache reply
			// Query is no longer unknown
			counters.unknown--;
			// Hereby, this query is now fully determined
			queries[i].complete = true;
		}
		// Update overTime data
		overTime[j].forwarded++;

		// Update couter for forwarded queries
		counters.forwardedqueries++;
	}

	// Release allocated memory
	free(forward);
	disable_thread_lock();
}

void FTL_dnsmasq_reload(void)
{
	// Called when dnsmasq re-reads its config and hosts files
	// Reset number of blocked domains and re-read list of wildcard domains
	counters.gravity = 0;
	readGravityFiles();
}

void FTL_reply(unsigned short flags, char *name, struct all_addr *addr, int id)
{
	// Interpret hosts files that have been read by dnsmasq
	enable_thread_lock();
	// Determine returned result if available
	char dest[ADDRSTRLEN]; dest[0] = '\0';
	if(addr)
	{
		inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	}

	if(debug)
	{
		char *answer = dest;
		if(flags & F_CNAME)
			answer = "(CNAME)";
		else if((flags & F_NEG) && (flags & F_NXDOMAIN))
			answer = "(NXDOMAIN)";
		else if(flags & F_NEG)
			answer = "(NODATA)";

		logg("**** got reply %s is %s (ID %i)", name, answer, id);
		print_flags(flags);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	if(flags & F_CONFIG)
	{
		// Answered from local configuration, might be a wildcard or user-provided
		// Save status in corresponding query indentified by dnsmasq's ID
		bool found = false;
		int i;

		// Validate access only once for the maximum index (all lower will work)
		// See comments in FTL_forwarded() for further details on computational costs
		validate_access("queries", counters.queries-1, false, __LINE__, __FUNCTION__, __FILE__);
		for(i=0; i<counters.queries; i++)
		{
			// Check UUID of this query
			if(queries[i].id == id)
			{
				queries[i].status = detectStatus(domains[queries[i].domainID].domain);
				found = true;
				break;
			}
		}

		// Determine if this is a cached reply and NXDOMAIN
		// if so -> blocked via server=/.../ rule
		if(queries[i].status == QUERY_CACHE && (flags & F_NEG) && (flags & F_NXDOMAIN))
			queries[i].status = QUERY_GRAVITY;

		if(!found)
		{
			// This may happen e.g. if the original query was a PTR query or "pi.hole"
			// as we ignore them altogether
			disable_thread_lock();
			return;
		}

		if(!queries[i].complete)
		{
			// This query is no longer unknown
			counters.unknown--;

			// Get time index
			int querytimestamp, overTimetimestamp;
			gettimestamp(&querytimestamp, &overTimetimestamp);
			int timeidx = findOverTimeID(overTimetimestamp);
			validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);

			int domainID = queries[i].domainID;
			validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);

			int clientID = queries[i].clientID;
			validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);

			// Decide what to do depening on the result of detectStatus()
			if(queries[i].status == QUERY_WILDCARD)
			{
				// Blocked due to a matching wildcard rule
				counters.wildcardblocked++;
				overTime[timeidx].blocked++;
				domains[domainID].blockedcount++;
				domains[domainID].wildcard = true;
				clients[clientID].blockedcount++;
			}
			else if(queries[i].status == QUERY_CACHE)
			{
				// Answered from a custom (user provided) cache file
				counters.cached++;
				overTime[timeidx].cached++;
			}
			else if(queries[i].status == QUERY_GRAVITY)
			{
				// Blocked using server=/.../ rule
				counters.blocked++;
				overTime[timeidx].blocked++;
				domains[domainID].blockedcount++;
				clients[clientID].blockedcount++;
			}

			// Save reply type and update individual reply counters
			save_reply_type(flags, i, response);

			// Hereby, this query is now fully determined
			queries[i].complete = true;
		}

		// We are done here
		disable_thread_lock();
		return;
	}
	else if(flags & F_FORWARD)
	{
		// Search for corresponding query indentified by dnsmasq's ID
		bool found = false;
		int i;

		// Validate access only once for the maximum index (all lower will work)
		// See comments in FTL_forwarded() for further details on computational costs
		validate_access("queries", counters.queries-1, false, __LINE__, __FUNCTION__, __FILE__);
		for(i=0; i<counters.queries; i++)
		{
			// Check UUID of this query
			if(queries[i].id == id)
			{
				found = true;
				break;
			}
		}

		if(!found)
		{
			// This may happen e.g. if the original query was a PTR query or "pi.hole"
			// as we ignore them altogether
			disable_thread_lock();
			return;
		}

		int domainID = queries[i].domainID;
		validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
		if(strcmp(domains[domainID].domain, name) == 0)
		{
			// Save reply type and update individual reply counters
			save_reply_type(flags, i, response);
		}
	}
	else if(flags & F_REVERSE)
	{
		if(debug) logg("Skipping result of PTR query");
	}
	else
	{
		logg("*************************** unknown REPLY ***************************");
		print_flags(flags);
	}

	disable_thread_lock();
}

void FTL_cache(unsigned int flags, char *name, struct all_addr *addr, char *arg, int id)
{
	// Save that this query got answered from cache
	enable_thread_lock();
	char dest[ADDRSTRLEN]; dest[0] = '\0';
	if(addr)
	{
		inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
	}

	// Convert domain to lower case
	char *domain = strdup(name);
	strtolower(domain);

	// If domain is "pi.hole", we skip this query
	if(strcmp(domain, "pi.hole") == 0)
	{
		// free memory already allocated here
		free(domain);
		disable_thread_lock();
		return;
	}
	free(domain);

	// Debug logging
	if(debug) logg("**** got cache answer for %s / %s / %s (ID %i)", name, dest, arg, id);
	if(debug) print_flags(flags);

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	if(((flags & F_HOSTS) && (flags & F_IMMORTAL)) || ((flags & F_NAMEP) && (flags & F_DHCP)) || (flags & F_FORWARD))
	{
		// List data: /etc/pihole/gravity.list, /etc/pihole/black.list, /etc/pihole/local.list, etc.
		// or
		// DHCP server reply
		// or
		// cached answer to previously forwarded request

		// Determine requesttype
		unsigned char requesttype = 0;
		if(flags & F_HOSTS)
		{
			if(arg != NULL && strstr(arg, "/gravity.list") != NULL)
				requesttype = QUERY_GRAVITY;
			else if(arg != NULL && strstr(arg, "/black.list") != NULL)
				requesttype = QUERY_BLACKLIST;
			else // local.list, hostname.list, /etc/hosts and others
				requesttype = QUERY_CACHE;
		}
		else if((flags & F_NAMEP) && (flags & F_DHCP)) // DHCP server reply
			requesttype = QUERY_CACHE;
		else if(flags & F_FORWARD) // cached answer to previously forwarded request
			requesttype = QUERY_CACHE;
		else
		{
			logg("*************************** unknown CACHE reply (1) ***************************");
			print_flags(flags);
		}

		bool found = false;
		int i;
		// Validate access only once for the maximum index (all lower will work)
		// See comments in FTL_forwarded() for further details on computational costs
		validate_access("queries", counters.queries-1, false, __LINE__, __FUNCTION__, __FILE__);
		for(i=0; i<counters.queries; i++)
		{
			// Check UUID of this query
			if(queries[i].id == id)
			{
				queries[i].status = requesttype;
				found = true;
				break;
			}
		}
		if(!found)
		{
			// This may happen e.g. if the original query was a PTR query or "pi.hole"
			// as we ignore them altogether
			disable_thread_lock();
			return;
		}

		if(!queries[i].complete)
		{
			// This query is no longer unknown
			counters.unknown--;

			// Get time index
			int querytimestamp, overTimetimestamp;
			gettimestamp(&querytimestamp, &overTimetimestamp);
			int timeidx = findOverTimeID(overTimetimestamp);
			validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);

			int domainID = queries[i].domainID;
			validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);

			int clientID = queries[i].clientID;
			validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);

			// Handle counters accordingly
			switch(requesttype)
			{
				case QUERY_GRAVITY: // gravity.list
				case QUERY_BLACKLIST: // black.list
					counters.blocked++;
					overTime[timeidx].blocked++;
					domains[domainID].blockedcount++;
					clients[clientID].blockedcount++;
					break;
				case QUERY_CACHE: // cached from one of the lists
					counters.cached++;
					overTime[timeidx].cached++;
					break;
			}

			// Save reply type and update individual reply counters
			save_reply_type(flags, i, response);

			// Hereby, this query is now fully determined
			queries[i].complete = true;
		}
	}
	else
	{
		logg("*************************** unknown CACHE reply (2) ***************************");
		print_flags(flags);
	}
	disable_thread_lock();
}

void FTL_dnssec(int status, int id)
{
	// Process DNSSEC result for a domain
	enable_thread_lock();
	// Search for corresponding query indentified by ID
	bool found = false;
	int i;
	// Validate access only once for the maximum index (all lower will work)
	// See comments in FTL_forwarded() for further details on computational costs
	validate_access("queries", counters.queries-1, false, __LINE__, __FUNCTION__, __FILE__);
	for(i=0; i<counters.queries; i++)
	{
		// Check both UUID and generation of this query
		if(queries[i].id == id)
		{
			found = true;
			break;
		}
	}

	if(!found)
	{
		// This may happen e.g. if the original query was an unhandled query type
		disable_thread_lock();
		return;
	}

	// Debug logging
	if(debug)
	{
		int domainID = queries[i].domainID;
		validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
		logg("**** got DNSSEC details for %s: %i (ID %i)", domains[domainID].domain, status, id);
	}

	// Iterate through possible values
	if(status == STAT_SECURE)
		queries[i].dnssec = DNSSEC_SECURE;
	else if(status == STAT_INSECURE)
		queries[i].dnssec = DNSSEC_INSECURE;
	else
		queries[i].dnssec = DNSSEC_BOGUS;

	disable_thread_lock();
}

void print_flags(unsigned int flags)
{
	// Debug function, listing resolver flags in clear text
	// e.g. "Flags: F_FORWARD F_NEG F_IPV6"
	unsigned int i;
	char *flagstr = calloc(256,sizeof(char));
	for(i = 0; i < sizeof(flags)*8; i++)
		if(flags & (1 << i))
			strcat(flagstr, flagnames[i]);
	logg("     Flags: %s", flagstr);
	free(flagstr);
}

void save_reply_type(unsigned int flags, int queryID, struct timeval response)
{
	// Iterate through possible values
	validate_access("queries", queryID, false, __LINE__, __FUNCTION__, __FILE__);
	if(flags & F_NEG)
	{
		if(flags & F_NXDOMAIN)
		{
			// NXDOMAIN
			queries[queryID].reply = REPLY_NXDOMAIN;
			counters.reply_NXDOMAIN++;
		}
		else
		{
			// NODATA(-IPv6)
			queries[queryID].reply = REPLY_NODATA;
			counters.reply_NODATA++;
		}
	}
	else if(flags & F_CNAME)
	{
		// <CNAME>
		queries[queryID].reply = REPLY_CNAME;
		counters.reply_CNAME++;
	}
	else
	{
		// Valid IP
		queries[queryID].reply = REPLY_IP;
		counters.reply_IP++;
	}

	// Save response time (relative time)
	queries[queryID].response = converttimeval(response) -
	                            queries[queryID].response;
}

pthread_t telnet_listenthreadv4;
pthread_t telnet_listenthreadv6;
pthread_t socket_listenthread;
pthread_t DBthread;
pthread_t GCthread;

void FTL_fork_and_bind_sockets(void)
{
	if(!debug && daemonmode)
		go_daemon();
	else
		savepid();

	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Bind to sockets
	bind_sockets();

	// Start TELNET IPv4 thread
	if(ipv4telnet && pthread_create( &telnet_listenthreadv4, &attr, telnet_listening_thread_IPv4, NULL ) != 0)
	{
		logg("Unable to open IPv4 telnet listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start TELNET IPv6 thread
	if(ipv6telnet &&  pthread_create( &telnet_listenthreadv6, &attr, telnet_listening_thread_IPv6, NULL ) != 0)
	{
		logg("Unable to open IPv6 telnet listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start SOCKET thread
	if(pthread_create( &socket_listenthread, &attr, socket_listening_thread, NULL ) != 0)
	{
		logg("Unable to open Unix socket listening thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start database thread if database is used
	if(database && pthread_create( &DBthread, &attr, DB_thread, NULL ) != 0)
	{
		logg("Unable to open database thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until garbage collection needs to be done
	if(pthread_create( &GCthread, &attr, GC_thread, NULL ) != 0)
	{
		logg("Unable to open GC thread. Exiting...");
		exit(EXIT_FAILURE);
	}
}

// int cache_inserted, cache_live_freed are defined in dnsmasq/cache.c
extern int cache_inserted, cache_live_freed;
void getCacheInformation(int *sock)
{
	ssend(*sock,"cache-size: %i\ncache-live-freed: %i\ncache-inserted: %i\n",
	            daemon->cachesize, cache_live_freed, cache_inserted);
	// cache-size is obvious
	// It means the resolver handled <cache-inserted> names lookups that needed to be sent to
	// upstream severes and that <cache-live-freed> was thrown out of the cache
	// before reaching the end of its time-to-live, to make room for a newer name.
	// For <cache-live-freed>, smaller is better.
	// New queries are always cached. If the cache is full with entries
	// which haven't reached the end of their time-to-live, then the entry
	// which hasn't been looked up for the longest time is evicted.
}

void FTL_forwarding_failed(struct server *server)
{
	// Save that this query got forwarded to an upstream server
	enable_thread_lock();
	char dest[ADDRSTRLEN];
	if(server->addr.sa.sa_family == AF_INET)
		inet_ntop(AF_INET, &server->addr.in.sin_addr, dest, ADDRSTRLEN);
	else
		inet_ntop(AF_INET6, &server->addr.in6.sin6_addr, dest, ADDRSTRLEN);

	// Convert forward to lower case
	char *forward = strdup(dest);
	strtolower(forward);
	int forwardID = findForwardID(forward, false);

	if(debug) logg("**** forwarding to %s (ID %i) failed", dest, forwardID);

	forwarded[forwardID].failed++;

	free(forward);
	disable_thread_lock();
	return;
}

unsigned long converttimeval(struct timeval time)
{
	// Convert time from struct timeval into units
	// of 10*milliseconds
	return time.tv_sec*10000 + time.tv_usec/100;
}

// Routine that handles simple lists format for both gravity.list and black.list
void add_hosts_entry(struct crec *cache, struct all_addr *addr, int addrlen, unsigned int index, struct crec **rhash, int hashsz);
void rehash(int size);
int FTL_listsfile(char* filename, unsigned int index, FILE *f, int cache_size, struct crec **rhash, int hashsz)
{
	int name_count = cache_size;
	int added = 0;
	size_t size = 0;
	char *buffer = NULL, *a = NULL;
	struct all_addr addr4, addr6;
	bool has_IPv4 = false, has_IPv6 = false;

	// Handle only gravity.list and black.list
	// Skip all other files (they are interpreted in the usual format)
	if(strcmp(filename, files.gravity) != 0 &&
	   strcmp(filename, files.blacklist) != 0)
		return cache_size;

	// Start timer for list analysis
	timer_start(LISTS_TIMER);

	// Read IPv4 address for host entries from setupVars.conf
	char *IPv4addr = read_setupVarsconf("IPV4_ADDRESS");
	if(IPv4addr != NULL)
	{
		// Strip off everything at the end of the IP (CIDR might be there)
		a=IPv4addr; for(;*a;a++) if(*a == '/') *a = 0;
		// Prepare IPv4 address for records
		if(inet_pton(AF_INET, IPv4addr, &addr4) > 0)
			has_IPv4 = true;
	}
	clearSetupVarsArray(); // will free/invalidate IPv4addr

	// Read IPv6 address for host entries from setupVars.conf
	char *IPv6addr = read_setupVarsconf("IPV6_ADDRESS");
	if(IPv6addr != NULL)
	{
		// Strip off everything at the end of the IP (CIDR might be there)
		a=IPv6addr; for(;*a;a++) if(*a == '/') *a = 0;
		// Prepare IPv6 address for records
		if(inet_pton(AF_INET6, IPv6addr, &addr6) > 0)
			has_IPv6 = true;
	}
	clearSetupVarsArray(); // will free/invalidate IPv6addr

	// If no IPv4 address was found but user wants us to server NXDOMAIN
	// we have to mock an IP record (which won't do anything in the end)
	if(!has_IPv4 && config.blockingmode == MODE_NX)
	{
		if(inet_pton(AF_INET, "127.0.0.1", &addr4) > 0)
			has_IPv4 = true;
	}

	// If we have neither a valid IPv4 nor a valid IPv6, then we cannot add any entries here
	if(!has_IPv4 && !has_IPv6)
	{
		logg("ERROR: found neither a valid IPV4_ADDRESS nor IPV6_ADDRESS in setupVars.conf");
		return cache_size;
	}

	// Walk file line by line
	bool firstline = true;
	while(getline(&buffer, &size, f) != -1)
	{
		char *domain = buffer;
		// Skip hashed out lines
		while (*domain == '#')
			continue;

		// Filter leading dots or spaces
		while (*domain == '.' || *domain == ' ') domain++;

		// Check for spaces or tabs
		// If found, then this list is still in HOSTS format and we
		// don't analyze it here.
		if(firstline &&
		   (strstr(domain, " ") != NULL || strstr(domain, "\t") != NULL))
		{
			// Reset file pointer back to beginning of the list
			rewind(f);
			logg("File %s is in HOSTS format, please run pihole -g!", filename);
			return name_count;
		}
		firstline = false;

		// Skip empty lines
		if(strlen(domain) == 0)
			continue;

		// Strip newline character at the end of line we just read
		if(domain[strlen(domain)-1] == '\n')
			domain[strlen(domain)-1] = '\0';

		// As of here we assume the entry to be valid
		// Rehash every 1000 valid names
		if(rhash && ((name_count - cache_size) > 1000))
		{
			rehash(name_count);
			cache_size = name_count;
		}

		struct crec *cache4,*cache6;
		// Add IPv4 record
		if(has_IPv4 &&
		   (cache4 = malloc(sizeof(struct crec) + strlen(domain)+1-SMALLDNAME)))
		{
			strcpy(cache4->name.sname, domain);
			cache4->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV4;
			// If we block in NXDOMAIN mode, we add the NXDOMAIN flag and make this host record
			// also valid for AAAA requests
			if(config.blockingmode == MODE_NX) cache4->flags |= F_IPV6 | F_NEG | F_NXDOMAIN;
			cache4->ttd = daemon->local_ttl;
			add_hosts_entry(cache4, &addr4, INADDRSZ, index, rhash, hashsz);
			name_count++;
		}
		// Add IPv6 record only if we respond with an IP address to blocked domains
		if(has_IPv6 && config.blockingmode == MODE_IP &&
		   (cache6 = malloc(sizeof(struct crec) + strlen(domain)+1-SMALLDNAME)))
		{
			strcpy(cache6->name.sname, domain);
			cache6->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV6;
			cache6->ttd = daemon->local_ttl;
			add_hosts_entry(cache6, &addr6, IN6ADDRSZ, index, rhash, hashsz);
			name_count++;
		}
		// Count added domain
		added++;
	}

	// Free allocated memory
	if(buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
	}

	logg("%s: parsed %i domains (took %.1f ms)", filename, added, timer_elapsed_msec(LISTS_TIMER));
	counters.gravity += added;
	return name_count;
}

static void block_single_domain(char *domain)
{
	struct all_addr addr4;
	if(inet_pton(AF_INET, "127.0.0.1", &addr4) <= 0)
	{
		logg("inet_pton failed in block_single_domain(%s)!",domain);
		return;
	}

	struct crec *cache4;
	if((cache4 = malloc(sizeof(struct crec) + strlen(domain)+1-SMALLDNAME)))
	{
		strcpy(cache4->name.sname, domain);
		cache4->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV4 | F_NEG | F_NXDOMAIN;
		cache4->ttd = daemon->local_ttl;
		add_hosts_entry(cache4, &addr4, INADDRSZ, 0, NULL, 0);
	}
	else
	{
		logg("malloc failed in block_single_domain(%s)!",domain);
		return;
	}
}
