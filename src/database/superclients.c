/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Super client table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "superclients.h"
#include "common.h"
// global counters variable
#include "../shmem.h"
// global config variable
#include "../config.h"
// logg()
#include "../log.h"

bool create_superclients_table(void)
{
	// Create network table in the database
	SQL_bool("CREATE TABLE superclients (id INTEGER PRIMARY KEY NOT NULL, " \
	                                    "hwaddr TEXT NOT NULL, " \
	                                    "name TEXT NOT NULL, " \
	                                    "comment TEXT);");

	// Update database version to 9
	if(!db_set_FTL_property(DB_VERSION, 9))
	{
		logg("create_superclients_table(): Failed to update database version!");
		return false;
	}

	return true;
}


// Store hostname of device identified by dbID
bool import_superclients(void)
{
	sqlite3_stmt *stmt = NULL;
	const char querystr[] = "SELECT id,hwaddr,name FROM superclients";

	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("import_superclients() - SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Loop until no further data is available
	int imported = 0;
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE)
	{
		// Check if we ran into an error
		if(rc != SQLITE_ROW)
		{
			logg("import_superclients() - SQL error step: %s", sqlite3_errstr(rc));
			break;
		}

		// Get hardware address from database and store it as IP + MAC address of this client
		const char *hwaddr = (char*)sqlite3_column_text(stmt, 1);

		// MAC address parsing
		unsigned char data[6];
		const int n = sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
								&data[0], &data[1], &data[2],
								&data[3], &data[4], &data[5]);

		// Set hwlen only if we got data
		if(n != 6)
		{
			logg("Skipping invalid super-client with ID %d", sqlite3_column_int(stmt, 0));
			continue;
		}

		// Create a new (super-)client
		const int clientID = findClientID(hwaddr, true);
		clientsData *client = getClient(clientID, true);
		client->new = false;

		// Reset counter
		client->count = 0;

		// Store MAC address
		memcpy(client->hwaddr, data, sizeof(data));
		client->hwlen = sizeof(data);

		// Store intended name
		const char *name = (char*)sqlite3_column_text(stmt, 2);
		client->namepos = addstr(name);

		// This is a superclient
		client->super_client_id = -2;

		// Debug logging
		if(config.debug & DEBUG_SUPERCLIENTS)
		{
			logg("Added super-client \"%s\" (%s)",
				getstr(client->namepos), getstr(client->ippos));
		}

		imported++;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(stmt)) != SQLITE_OK)
	{
		logg("import_superclients() - SQL error finalize: %s", sqlite3_errstr(rc));
		return false;
	}

	logg("Imported %d super-client%s", imported, (imported != 1) ? "s":"");

	return true;
}

static int get_superclient_ID(const clientsData *client)
{
	if(config.debug & DEBUG_SUPERCLIENTS)
	{
		logg("Looking for the super-client for client \"%s\" (%s)...",
		     getstr(client->namepos), getstr(client->ippos));
	}

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
		{
			if(config.debug & DEBUG_SUPERCLIENTS)
			{
				logg("... FOUND \"%s\" (%s)",
				     getstr(super_client->namepos),
				     getstr(super_client->ippos));
			}

			return superclientID;
		}
	}

	if(config.debug & DEBUG_SUPERCLIENTS)
	{
		logg("... not found");
	}


	// Not found
	return -1;
}

static void recompute_superclient(const int superclientID)
{
	clientsData *superclient = getClient(superclientID, true);

	if(config.debug & DEBUG_SUPERCLIENTS)
	{
		logg("Recomputing super-client \"%s\" (%s)...",
		     getstr(superclient->namepos), getstr(superclient->ippos));
	}

	// Reset this super-client
	superclient->count = 0;
	superclient->blockedcount = 0;
	memset(superclient->overTime, 0, sizeof(superclient->overTime));

	// Loop over all existing clients to find which clients are associated to this one
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get pointer to client candidate
		const clientsData *client = getClient(clientID, true);
		if(client == NULL)
			continue;

		// Skip clients that are not managed by this superclient
		if(client->super_client_id != superclientID)
		{
			if(config.debug & DEBUG_SUPERCLIENTS)
			{
				logg("Client \"%s\" (%s) NOT managed by this super-client, skipping",
				     getstr(superclient->namepos), getstr(superclient->ippos));
			}
			continue;
		}

		// Debug logging
		if(config.debug & DEBUG_SUPERCLIENTS)
		{
			logg("Client \"%s\" (%s) IS managed by this super-client, adding counts",
					getstr(superclient->namepos), getstr(superclient->ippos));
		}

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
	// and skip super-clients themselves
	if(client->hwlen != 6 || client->super_client_id == -2)
		return;

	// Find corresponding super-client (if any)
	client->super_client_id = get_superclient_ID(client);

	// Skip if there are no responsible super-clients
	if(client->super_client_id == -1)
		return;
	
	// Recompute all values for this super-client
	recompute_superclient(client->super_client_id);
}
