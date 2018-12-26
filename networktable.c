/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Network table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "shmem.h"
#define ARPCACHE "/proc/net/arp"

bool create_network_table(void)
{
	bool ret;
	// Create FTL table in the database (holds properties like database version, etc.)
	ret = dbquery("CREATE TABLE network ( id INTEGER PRIMARY KEY NOT NULL, " \
	                                     "ip TEXT NOT NULL, " \
	                                     "hwaddr TEXT NOT NULL, " \
	                                     "interface TEXT NOT NULL, " \
	                                     "name TEXT, " \
	                                     "firstSeen INTEGER NOT NULL, " \
	                                     "lastQuery INTEGER NOT NULL);");
	if(!ret){ dbclose(); return false; }

	// Update database version to 3
	ret = db_set_FTL_property(DB_VERSION, 3);
	if(!ret){ dbclose(); return false; }

	return true;
}

// Read kernel's ARP cache using procfs
void parse_arp_cache(void)
{
	FILE* arpfp = NULL;
	// Try to access the kernel's ARP cache
	if((arpfp = fopen(ARPCACHE, "r")) == NULL)
	{
		logg("WARN: Opening of %s failed!", ARPCACHE);
		logg("      Message: %s", strerror(errno));
		return;
	}

	// Open database file
	if(!dbopen())
	{
		logg("read_arp_cache() - Failed to open DB");
		return;
	}

	// Start ARP timer
	if(debug) timer_start(ARP_TIMER);

	// Prepare buffers
	char * linebuffer = NULL;
	size_t linebuffersize = 0;
	char ip[100], mask[100], hwaddr[100], iface[100];
	int type, flags, entries = 0;
	time_t now = time(NULL);

	// Start collecting database commands
	dbquery("BEGIN TRANSACTION");

	// Read ARP cache line by line
	while(getline(&linebuffer, &linebuffersize, arpfp) != -1)
	{
		int num = sscanf(linebuffer, "%99s 0x%x 0x%x %99s %99s %99s\n",
		                 ip, &type, &flags, hwaddr, mask, iface);

		// Skip header and empty lines
		if (num < 4)
			continue;

		// Skip incomplete entires, i.e., entries without C (complete) flag
		if(!(flags & 0x02))
			continue;

		// Get ID of this device in our network database. If it cannot be found, then this is a new device
		// We match both IP *and* MAC address
		// Same MAC, two IPs: Non-deterministic DHCP server, treat as two entries
		// Same IP, two MACs: Either non-deterministic DHCP server or (almost) full DHCP address pool
		// We can run this SELECT inside the currently active transaction as only the
		// changed to the database are collected for latter commitment. Read-only access
		// such as this SELECT command will be executed immediately on the database.
		char* querystr = NULL;
		int ret = asprintf(&querystr, "SELECT id FROM network WHERE ip = \"%s\" AND hwaddr = \"%s\";", ip, hwaddr);
		if(querystr == NULL || ret < 0)
		{
			logg("Memory allocation failed in parse_arp_cache (%i)", ret);
			break;
		}

		// Perform SQL query
		int dbID = db_query_int(querystr);
		free(querystr);

		if(dbID == -2)
		{
			// SQLite error
			break;
		}

		// If we reach this point, we can check if this client
		// is known to pihole-FTL
		// false = do not create a new record if the client is
		//         unknown (only DNS requesting clients do this)
		lock_shm();
		int clientID = findClientID(ip, false);
		unlock_shm();

		// This client is known (by its IP address) to pihole-FTL if
		// findClientID() returned a non-negative index
		bool clientKnown = clientID >= 0;

		// Get hostname of this client if the client is known
		char *hostname = NULL;
		if(clientKnown)
		{
			validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);
			hostname = getstr(clients[clientID].namepos);
		}

		// Device not in database, add new entry
		if(dbID == -1)
		{
			dbquery("INSERT INTO network "\
			        "(ip,hwaddr,interface,firstSeen,lastQuery,name) "\
			        "VALUES (\"%s\",\"%s\",\"%s\",%lu, %ld, \"%s\");",\
			        ip, hwaddr, iface, now,
			        clientKnown ? clients[clientID].lastQuery : 0L,
			        hostname == NULL ? "" : hostname);
		}
		// Device in database AND client known to Pi-hole
		else if(clientKnown)
		{
			// Update lastQuery, only use new value if larger
			// clients[clientID].lastQuery may be zero if this
			// client is only known from a database entry but has
			// not been seen since then
			dbquery("UPDATE network "\
			        "SET lastQuery = MAX(lastQuery, %ld) "\
			        "WHERE id = %i;",\
			        clients[clientID].lastQuery, dbID);

			// Store hostname if available
			if(hostname != NULL && strlen(hostname) > 0)
			{
				// Store host name
				dbquery("UPDATE network "\
				        "SET name = \"%s\" "\
				        "WHERE id = %i;",\
				        hostname, dbID);
			}
		}
		// else:
		// Device in database but not known to Pi-hole: No action required

		// Count number of processed ARP cache entries
		entries++;
	}

	// Actually update the database
	dbquery("COMMIT");

	// Debug logging
	if(debug) logg("ARP table processing (%i entries) took %.1f ms", entries, timer_elapsed_msec(ARP_TIMER));

	// Close file handle
	fclose(arpfp);

	// Close database connection
	dbclose();
}
