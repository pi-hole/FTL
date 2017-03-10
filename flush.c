/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Logflush handling routines
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
	}

	int i;

	// Free memory on allocated data structure
	// queries struct: No allocated entries
	free(queries);
	queries = NULL;

	// forwarded struct: Keep forward destinations, but reset their counters
	for(i=0;i<counters.forwarded;i++)
	{
		forwarded[i].count = 0;
	}

	// clients struct: Keep clients, but reset their counters
	for(i=0;i<counters.clients;i++)
	{
		clients[i].count = 0;
	}

	// domains struct: Free allocated substructure
	for(i=0;i<counters.domains;i++)
	{
		free(domains[i].domain);
	}
	free(domains);
	domains = NULL;

	// wildcarddomains struct: Free allocated substructure
	for(i=0;i<counters.wildcarddomains;i++)
	{
		free(wildcarddomains[i]);
	}
	free(wildcarddomains);
	wildcarddomains = NULL;

	// Free memory on allocated data structure
	// overTime struct: No allocated entries
	free(overTime);
	overTime = NULL;

	// Reset all counters (except clients and forwards, because they need PTRs) to zero
	int counters_bck  = counters.clients;
	int forwarded_bck = counters.forwarded;
	memset(&counters, 0, sizeof(countersStruct));
	counters.clients = counters_bck;
	counters.forwarded = forwarded_bck;

	// Update file pointer position to beginning of file
	dnsmasqlogpos = 0;
	fseek(dnsmasqlog, dnsmasqlogpos, SEEK_SET);

	// Recount entries in gravity files
	read_gravity_files();
}
