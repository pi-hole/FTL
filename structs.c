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
	"/etc/pihole/pihole-FTL.conf",
	"/var/log/pihole-FTL.log",
	"/var/run/pihole-FTL.pid",
	"/var/run/pihole-FTL.port",
	"/etc/pihole/pihole-FTL.db"
};

logFileNamesStruct files = {
	"/var/log/pihole.log",
	"/var/log/pihole.log.1",
	"/etc/pihole/list.preEventHorizon",
	"/etc/pihole/whitelist.txt",
	"/etc/pihole/blacklist.txt",
	"/etc/pihole/setupVars.conf",
	"/etc/dnsmasq.d/01-pihole.conf",
	"/etc/dnsmasq.d/03-pihole-wildcard.conf",
	"/etc/pihole/auditlog.list"
};

countersStruct counters = { 0 };

void memory_check(int which)
{
	switch(which)
	{
		case QUERIES:
			if(counters.queries >= counters.queries_MAX)
			{
				// Have to reallocate memory
				counters.queries_MAX += QUERIESALLOCSTEP;
				logg_struct_resize("queries",counters.queries_MAX,QUERIESALLOCSTEP);
				queries = realloc(queries, counters.queries_MAX*sizeof(queriesDataStruct));
				if(queries == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					exit(EXIT_FAILURE);
				}
			}
		break;
		case FORWARDED:
			if(counters.forwarded >= counters.forwarded_MAX)
			{
				// Have to reallocate memory
				counters.forwarded_MAX += FORWARDEDALLOCSTEP;
				logg_struct_resize("forwarded",counters.forwarded_MAX,FORWARDEDALLOCSTEP);
				forwarded = realloc(forwarded, counters.forwarded_MAX*sizeof(forwardedDataStruct));
				if(forwarded == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					exit(EXIT_FAILURE);
				}
			}
		break;
		case CLIENTS:
			if(counters.clients >= counters.clients_MAX)
			{
				// Have to reallocate memory
				counters.clients_MAX += CLIENTSALLOCSTEP;
				logg_struct_resize("clients",counters.clients_MAX,CLIENTSALLOCSTEP);
				clients = realloc(clients, counters.clients_MAX*sizeof(clientsDataStruct));
				if(clients == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					exit(EXIT_FAILURE);
				}
			}
		break;
		case DOMAINS:
			if(counters.domains >= counters.domains_MAX)
			{
				// Have to reallocate memory
				counters.domains_MAX += DOMAINSALLOCSTEP;
				logg_struct_resize("domains",counters.domains_MAX,DOMAINSALLOCSTEP);
				domains = realloc(domains, counters.domains_MAX*sizeof(domainsDataStruct));
				if(domains == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					exit(EXIT_FAILURE);
				}
			}
		break;
		case OVERTIME:
			if(counters.overTime >= counters.overTime_MAX)
			{
				// Have to reallocate memory
				counters.overTime_MAX += OVERTIMEALLOCSTEP;
				logg_struct_resize("overTime",counters.overTime_MAX,OVERTIMEALLOCSTEP);
				overTime = realloc(overTime, counters.overTime_MAX*sizeof(overTimeDataStruct));
				if(overTime == NULL)
				{
					logg("FATAL: Memory allocation failed! Exiting");
					exit(EXIT_FAILURE);
				}
			}
		break;
		case WILDCARD:
			// Definitely enlarge wildcard entry
			// Enlarge wildcarddomains pointer array
			logg_struct_resize("wildcards", (counters.wildcarddomains+1), 1);
			wildcarddomains = realloc(wildcarddomains, (counters.wildcarddomains+1)*sizeof(*wildcarddomains));
			if(wildcarddomains == NULL)
			{
				logg("FATAL: Memory allocation failed! Exiting");
				exit(EXIT_FAILURE);
			}
		break;
		default:
			/* That cannot happen */
		break;
	}
}
