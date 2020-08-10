/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Super-client processing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "superclients.h"
// global counters variable
#include "shmem.h"

static int get_superclient_ID(const clientsData *client)
{
	for(int superclientID = 0; superclientID < counters->clients; superclientID++)
	{
		// Get pointer to super client candidate
		const clientsData *super_client = getClient(superclientID, true);

		// Skip clients that are not super-clients
		if(super_client->super_client_id != -2)
			continue;

		// Compare MAC address of the current client to the
		// super client candidate's MAC address
		if(memcmp(client->hwaddr, super_client->hwaddr, client->hwlen) == 0)
			return superclientID;
	}

	// Not found
	return -1;
}

static void recompute_superclient(const int superclientID)
{
	clientsData *superclient = getClient(superclientID, true);

	// Reset counts of this super-client
	superclient->count = 0;
	superclient->blockedcount = 0;
	memset(superclient->overTime, 0, sizeof(superclient->overTime));

	// Loop over all existing clients to find which clients are associated to this one
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get pointer to client candidate
		const clientsData *client = getClient(clientID, true);

		// Skip clients that are not managed by this superclient
		if(client->super_client_id != superclientID)
			continue;

		// Add counts of this client to the super-client
		superclient->count += client->count;
		superclient->blockedcount += client->blockedcount;
		for(int idx = 0; idx < OVERTIME_SLOTS; idx++)
			superclient->overTime[idx] += client->overTime[idx];
	}
}

void reset_superclient(clientsData *client)
{
	// Only process clients with valid MAC addresses
	if(client->hwlen != 6)
		return;

	// Skip super-clients themselves
	if(client->super_client_id == -2)
		return;

	// Find corresponding super-client (if any)
	client->super_client_id = get_superclient_ID(client);

	// Skip if there is no responsible super-client (nothing found above)
	if(client->super_client_id == -1)
		return;
	
	// Recompute all values for this super-client
	recompute_superclient(client->super_client_id);
}