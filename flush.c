/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Log flush handling routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

void pihole_log_flushed(bool message)
{
	if(message)
	{
		logg("NOTICE: pihole.log has been flushed");
		logg("  Resetting internal data structure");
		logg("  Queries in memory before flushing: %i",counters.queries);
	}

	int i;

	// Free memory on allocated data structure
	// queries struct: No allocated entries
	free(queries);
	queries = NULL;

	// forwarded struct: Free allocated substructure
	for(i=0;i<counters.forwarded;i++)
	{
		free(forwarded[i].name);
		free(forwarded[i].ip);
	}
	free(forwarded);
	forwarded = NULL;

	// clients struct: Free allocated substructure
	for(i=0;i<counters.clients;i++)
	{
		free(clients[i].name);
		free(clients[i].ip);
	}
	free(clients);
	clients = NULL;

	// domains struct: Free allocated substructure
	for(i=0;i<counters.domains;i++)
	{
		free(domains[i].domain);
	}
	free(domains);
	domains = NULL;
	memory.domainnames = 0;

	// wildcarddomains struct: Free allocated substructure
	for(i=0;i<counters.wildcarddomains;i++)
	{
		free(wildcarddomains[i]);
	}
	free(wildcarddomains);
	wildcarddomains = NULL;
	memory.wildcarddomains = 0;

	// overTime struct: Free allocated substructure
	for(i=0;i<counters.overTime;i++)
	{
		if(overTime[i].forwarddata != NULL )
			free(overTime[i].forwarddata);
		free(overTime[i].querytypedata);
	}
	free(overTime);
	overTime = NULL;
	memory.forwarddata = 0;
	memory.querytypedata = 0;

	// Reset DB index counter so that new queries will be stored in the DB
	lastdbindex = 0;

	// Reset all counters to zero
	memset(&counters, 0, sizeof(countersStruct));

	// Recount entries in gravity files
	read_gravity_files();

	// Try to import queries from long-term database if available
	if(database)
		read_data_from_DB();
}
