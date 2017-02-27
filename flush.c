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

void pihole_log_flushed(void)
{
	logg("NOTICE: pihole.log has been flushed");
	logg("  Resetting internal data structure");

	int i;

	// Free memory on allocated data structure
	// queries struct: No allocated entries
	free(queries);
	queries = NULL;

	// forwarded struct: Free allocated substructure
	for(i=0;i<counters.forwarded;i++)
	{
		free(forwarded[i].ip);
		free(forwarded[i].name);
	}
	free(forwarded);
	forwarded = NULL;

	// clients struct: Free allocated substructure
	for(i=0;i<counters.clients;i++)
	{
		free(clients[i].ip);
		free(clients[i].name);
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

	// wildcarddomains struct: Free allocated substructure
	for(i=0;i<counters.wildcarddomains;i++)
	{
		free(wildcarddomains[i]);
	}
	free(wildcarddomains);
	wildcarddomains = NULL;

	// Reset all counters to zero
	memset(&counters, 0, sizeof(countersStruct));
	// Reset over Time data
	memset(&overTime, 0, 600*sizeof(overTimeDataStruct));

	// Update file pointer position
	dnsmasqlogpos = ftell(dnsmasqlog);

	// Recount entries in gravity files
	read_gravity_files();
}
