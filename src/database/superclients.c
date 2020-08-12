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
// calloc()
#include "../memory.h"
// getSuperclientIDfromIP()
#include "network-table.h"

bool create_superclients_table(void)
{
	// Create superclient table in the database
	SQL_bool("CREATE TABLE superclient (id INTEGER PRIMARY KEY NOT NULL, " \
	                                   "name TEXT NOT NULL, " \
	                                   "comment TEXT);");

	// Add superclient_id to network table
	SQL_bool("ALTER TABLE network ADD COLUMN superclient_id INTEGER;");

	// Update database version to 9
	if(!db_set_FTL_property(DB_VERSION, 9))
	{
		logg("create_superclients_table(): Failed to update database version!");
		return false;
	}

	return true;
}

// Recompute the super-client's values
// We shouldn't do this too often as it iterates over all existing clients
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
		// Skip invalid clients and super-clients
		if(client == NULL || client->superclient)
			continue;

		// Skip clients that are not managed by this superclient
		if(client->superclient_id != superclientID)
		{
			if(config.debug & DEBUG_SUPERCLIENTS)
			{
				logg("Client \"%s\" (%s) NOT managed by this super-client, skipping",
				     getstr(client->namepos), getstr(client->ippos));
			}
			continue;
		}

		// Debug logging
		if(config.debug & DEBUG_SUPERCLIENTS)
		{
			logg("Client \"%s\" (%s) IS  managed by this super-client, adding counts",
					getstr(client->namepos), getstr(client->ippos));
		}

		// Add counts of this client to the super-client
		superclient->count += client->count;
		superclient->blockedcount += client->blockedcount;
		for(int idx = 0; idx < OVERTIME_SLOTS; idx++)
			superclient->overTime[idx] += client->overTime[idx];
	}
}

// Store hostname of device identified by dbID
bool import_superclients(void)
{
	sqlite3_stmt *stmt = NULL;
	const char querystr[] = "SELECT id,name FROM superclient";

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
		const int superclient_id = sqlite3_column_int(stmt, 0);

		// Create a new (super-)client
		char *superclient_str = NULL;
		if(asprintf(&superclient_str, "superclient-%i", superclient_id) < 10)
		{
			logg("Memory error in import_superclients()");
			return false;
		}

		// Try to open existing client
		const int clientID = findClientID(superclient_str, false, true);

		clientsData *client = getClient(clientID, true);
		client->new = false;

		// Reset counter
		client->count = 0;

		// Store intended name
		const char *name = (char*)sqlite3_column_text(stmt, 1);
		client->namepos = addstr(name);

		// This is a superclient
		client->superclient = true;
		client->superclient_id = superclient_id;

		// Debug logging
		if(config.debug & DEBUG_SUPERCLIENTS)
		{
			logg("Added super-client \"%s\" (%s) with FTL ID %i", name, superclient_str, clientID);
		}

		free(superclient_str);
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
	// Skip super-clients themselves
	if(client->superclient)
		return -1;

	const char *clientIP = getstr(client->ippos);
	if(config.debug & DEBUG_SUPERCLIENTS)
	{
		logg("   Looking for the super-client for client %s...",
		     clientIP);
	}

	// Get superclient ID from database (DB index)
	const int superclient_DBid = getSuperclientIDfromIP(clientIP);

	// Compare DB index for all super-clients stored in FTL
	int superclientID = 0;
	for(; superclientID < counters->clients; superclientID++)
	{
		// Get pointer to super client candidate
		const clientsData *super_client = getClient(superclientID, true);

		// Skip clients that are not super-clients
		if(!super_client->superclient)
			continue;

		// Compare MAC address of the current client to the
		// super client candidate's MAC address
		if(super_client->superclient_id == superclient_DBid)
		{
			if(config.debug & DEBUG_SUPERCLIENTS)
			{
				logg("   -> \"%s\" (%s)",
				     getstr(super_client->namepos),
				     getstr(super_client->ippos));
			}

			return superclientID;
		}
	}

	if(config.debug & DEBUG_SUPERCLIENTS && superclientID == counters->clients)
	{
		logg("   -> not found");
	}

	// Not found
	return -1;
}

void reset_superclient(clientsData *client)
{
	// Skip super-clients themselves
	if(client->superclient)
		return;

	// Find corresponding super-client (if any)
	client->superclient_id = get_superclient_ID(client);

	// Skip if there is no responsible super-client
	if(client->superclient_id == -1)
		return;

	// Recompute all values for this super-client
	recompute_superclient(client->superclient_id);
}

// Return a list of clients linked to the current super-client
// The first element contains the number of following IDs
int *get_superclient_list(const int superclientID)
{
	int count = 0;
	// Loop over all existing clients to count associated clients
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get pointer to client candidate
		const clientsData *client = getClient(clientID, true);
		// Skip invalid clients and those that are not managed by this superclient
		if(client == NULL || client->superclient_id != superclientID)
			continue;

		count++;
	}

	int *list = calloc(count + 1, sizeof(int));
	list[0] = count;

	// Loop over all existing clients to fill list of clients
	count = 0;
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get pointer to client candidate
		const clientsData *client = getClient(clientID, true);
		// Skip invalid clients and those that are not managed by this superclient
		if(client == NULL || client->superclient_id != superclientID)
			continue;

		list[++count] = clientID;
	}

	return list;
}

// Reimport super-clients from database
// Note that this will always only change or add new clients. Super-clients are
// removed by nulling them before importing new clients
void reimport_superclients(void)
{
	lock_shm();

	// Open pihole-FTL.db database file if needed
	const bool db_already_open = FTL_DB_avail();
	if(!db_already_open && !dbopen())
	{
		logg("reimport_superclients() - Failed to open DB");
		return;
	}
	// Loop over all existing super-clients and set their counters to zero
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get pointer to client candidate
		clientsData *client = getClient(clientID, true);
		// Skip invalid and non-super-clients
		if(client == NULL || !client->superclient)
			continue;

		// Reset this super-client
		client->count = 0;
		client->blockedcount = 0;
		memset(client->overTime, 0, sizeof(client->overTime));
	}

	// Import superclients from database table
	import_superclients();

	if(!db_already_open)
		dbclose();

	// Recompute all super-clients
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get pointer to client candidate
		clientsData *client = getClient(clientID, true);
		// Skip invalid and super-clients
		if(client == NULL || client->superclient)
			continue;

		reset_superclient(client);
	}

	unlock_shm();
}