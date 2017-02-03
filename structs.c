/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global variable definitions and memory reallocation handling
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

FTLFileNamesStruct FTLfiles = {
	"/etc/pihole/pihole-FTL.log",
	"/etc/pihole/pihole-FTL.pid",
	"/etc/pihole/pihole-FTL.port"
	// "/var/log/pihole-FTL.log",
	// "/var/run/pihole-FTL.pid",
	// "/var/run/pihole-FTL.port"
};

logFileNamesStruct files = {
	"/var/log/pihole.log",
	"/etc/pihole/list.preEventHorizon",
	"/etc/pihole/whitelist.txt",
	"/etc/pihole/blacklist.txt",
	"/etc/pihole/setupVars.conf"
};

countersStruct counters = { 0 };

overTimeDataStruct overTime[600] = {{ 0, 0 }};

void memory_check(int which)
{
	switch(which)
	{
		case QUERIES:
			if(counters.queries >= counters.queries_MAX)
			{
				// Have to reallocate memory
				logg_struct_resize("queries",counters.queries_MAX,counters.queries_MAX+QUERIESALLOCSTEP);
				counters.queries_MAX += QUERIESALLOCSTEP;
				queries = realloc(queries, counters.queries_MAX*sizeof(*queries));
				if(queries == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					free(queries);
					exit(EXIT_FAILURE);
				}
			}
		break;
		case FORWARDED:
			if(counters.forwarded >= counters.forwarded_MAX)
			{
				// Have to reallocate memory
				logg_struct_resize("forwarded",counters.forwarded_MAX,counters.forwarded_MAX+FORWARDEDALLOCSTEP);
				counters.forwarded_MAX += FORWARDEDALLOCSTEP;
				forwarded = realloc(forwarded, counters.forwarded_MAX*sizeof(*forwarded));
				if(forwarded == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					free(forwarded);
					exit(EXIT_FAILURE);
				}
			}
		break;
		case CLIENTS:
			if(counters.clients >= counters.clients_MAX)
			{
				// Have to reallocate memory
				logg_struct_resize("clients",counters.clients_MAX,counters.clients_MAX+CLIENTSALLOCSTEP);
				counters.clients_MAX += CLIENTSALLOCSTEP;
				clients = realloc(clients, counters.clients_MAX*sizeof(*clients));
				if(clients == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					free(clients);
					exit(EXIT_FAILURE);
				}
			}
		break;
		case DOMAINS:
			if(counters.domains >= counters.domains_MAX)
			{
				// Have to reallocate memory
				logg_struct_resize("domains",counters.domains_MAX,counters.domains_MAX+DOMAINSALLOCSTEP);
				counters.domains_MAX += DOMAINSALLOCSTEP;
				domains = realloc(domains, counters.domains_MAX*sizeof(*domains));
				if(domains == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					free(domains);
					exit(EXIT_FAILURE);
				}
			}
		break;
		default:
			/* That cannot happen */
		break;
	}
}
