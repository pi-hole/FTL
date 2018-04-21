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

char flagnames[28][12] = {"F_IMMORTAL ", "F_NAMEP ", "F_REVERSE ", "F_FORWARD ", "F_DHCP ", "F_NEG ", "F_HOSTS ", "F_IPV4 ", "F_IPV6 ", "F_BIGNAME ", "F_NXDOMAIN ", "F_CNAME ", "F_DNSKEY ", "F_CONFIG ", "F_DS ", "F_DNSSECOK ", "F_UPSTREAM ", "F_RRNAME ", "F_SERVER ", "F_QUERY ", "F_NOERR ", "F_AUTH ", "F_DNSSEC ", "F_KEYTAG ", "F_SECSTAT ", "F_NO_RR ", "F_IPSET ", "F_NOEXTRA "};

void FTL_new_query(unsigned int flags, char *name, struct all_addr *addr, char *types, int id)
{
	// Create new query in data structure
	enable_thread_lock();
	// Get timestamp
	int querytimestamp, overTimetimestamp;
	gettimestamp(&querytimestamp, &overTimetimestamp);

	// Save request time
	struct timeval request;
	gettimeofday(&request, 0);

	if(!config.analyze_AAAA && strcmp(types,"query[AAAA]") == 0)
	{
		if(debug) logg("Not analyzing AAAA query");
		disable_thread_lock();
		return;
	}

	// Ensure we have enough space in the queries struct
	memory_check(QUERIES);
	int queryID = counters.queries;
	int timeidx = findOverTimeID(overTimetimestamp);

	// Convert domain to lower case
	char *domain = strdup(name);
	strtolower(domain);

	if(strcmp(domain, "pi.hole") == 0)
	{
		// domain is "pi.hole", skip this query
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

	if(debug) logg("**** new query %s %s %s (ID %i)", types, domain, client, id);

	unsigned char querytype = 0;
	validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
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
	overTime[timeidx].querytypedata[querytype-1]++;
	counters.querytype[querytype-1]++;

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
	// Check struct size
	memory_check(DOMAINS);
	int domainID = findDomainID(domain);

	// Go through already knows clients and see if it is one of them
	// Check struct size
	memory_check(CLIENTS);
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

	// Free allocated memory
	free(client);
	free(domain);
	disable_thread_lock();
}

void FTL_forwarded(unsigned int flags, char *name, struct all_addr *addr, int id)
{
	// Save that this query got forwarded to an updtream server
	enable_thread_lock();
	char dest[ADDRSTRLEN];
	inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);

	if(debug) logg("**** forwarded %s to %s (ID %i)", name, dest, id);

	// Convert forward to lower case
	char *forward = strdup(dest);
	strtolower(forward);

	// Save status and forwardID in corresponding query indentified by dnsmasq's ID
	bool found = false;
	int i;
	for(i=0; i<counters.queries; i++)
	{
		validate_access("queries", i, false, __LINE__, __FUNCTION__, __FILE__);
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
		for(i=0; i<counters.queries; i++)
		{
			validate_access("queries", i, false, __LINE__, __FUNCTION__, __FILE__);
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

			int domainID = queries[i].domainID;
			validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);

			// Decide what to do depening on the result of detectStatus()
			if(queries[i].status == QUERY_WILDCARD)
			{
				// Blocked due to a matching wildcard rule
				counters.wildcardblocked++;

				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].blocked++;
				domains[domainID].blockedcount++;
				domains[domainID].wildcard = true;
			}
			else if(queries[i].status == QUERY_CACHE)
			{
				// Answered from a custom (user provided) cache file
				counters.cached++;

				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].cached++;
			}
			else if(queries[i].status == QUERY_GRAVITY)
			{
				// Blocked using server=/.../ rule
				counters.blocked++;

				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].blocked++;
				domains[domainID].blockedcount++;
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
		for(i=0; i<counters.queries; i++)
		{
			validate_access("queries", i, false, __LINE__, __FUNCTION__, __FILE__);
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
	if(strcmp(domain, "pi.hole") == 0)
	{
		// domain is "pi.hole", skip this query
		// free memory already allocated here
		free(domain);
		disable_thread_lock();
		return;
	}
	free(domain);

	if(debug) logg("**** got cache answer for %s / %s / %s (ID %i)", name, dest, arg, id);
	if(debug) print_flags(flags);

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	if(((flags & F_HOSTS) && (flags & F_IMMORTAL)) || ((flags & F_NAMEP) && (flags & F_DHCP)) || (flags & F_FORWARD))
	{
		// Hosts data: /etc/pihole/gravity.list, /etc/pihole/black.list, /etc/pihole/local.list, etc.
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
		for(i=0; i<counters.queries; i++)
		{
			validate_access("queries", i, false, __LINE__, __FUNCTION__, __FILE__);
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

		int domainID = queries[i].domainID;
		validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
		if(!queries[i].complete)
		{
			// This query is no longer unknown
			counters.unknown--;

			// Get time index
			int querytimestamp, overTimetimestamp;
			gettimestamp(&querytimestamp, &overTimetimestamp);
			int timeidx = findOverTimeID(overTimetimestamp);
			validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);

			// Handle counters accordingly
			switch(requesttype)
			{
				case QUERY_GRAVITY: // gravity.list
				case QUERY_BLACKLIST: // black.list
					counters.blocked++;
					overTime[timeidx].blocked++;
					domains[domainID].blockedcount++;
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
	validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
	if(debug) logg("**** got DNSSEC details for %s: %i (ID %i)", domains[queries[i].domainID].domain, status, id);

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

void FTL_hostsfile(unsigned short *flags, char *filename)
{
	if(!config.serve_nxdomain)
		return;

	if(strcmp(filename,files.gravity) == 0 ||
	   strcmp(filename,files.blacklist) == 0)
		*flags |= F_NEG | F_NXDOMAIN;
}
