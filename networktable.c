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
	                                     "lastSeen INTEGER NOT NULL, " \
	                                     "usesPihole BOOLEAN NOT NULL );");
	if(!ret){ dbclose(); return false; }

	// Update database version to 3
	ret = db_set_FTL_property(DB_VERSION, 3);
	if(!ret){ dbclose(); return false; }

	return true;
}

// Read kernel's ARP cache using procfs
void read_arp_cache(void)
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

	// Prepare buffers
	char * linebuffer = NULL;
	size_t linebuffersize = 0;
	char ip[100], mask[100], hwaddr[100], iface[100];
	int type, flags, entries = 0;
	time_t now = time(NULL);

	// Read ARP cache line by line
	while(getline(&linebuffer, &linebuffersize, arpfp) != -1)
	{
		int num = sscanf(linebuffer, "%99s 0x%x 0x%x %99s %99s %99s\n",
		                 ip, &type, &flags, hwaddr, mask, iface);

		// Skip header and empty lines
		if (num < 4)
			continue;

		entries++;
		if(debug) logg("ARP (%i): %i %i %s %s %s <-> %s", num, type, flags, mask, iface, hwaddr, ip);

		// Get ID of this device in our network database. If it cannot be found, then this is a new device
		char querystr[256];
		sprintf(querystr, "SELECT id FROM network WHERE ip = \"%s\" AND hwaddr = \"%s\";", ip, hwaddr);
		int dbID = db_query_int(querystr);

		if(dbID == -2)
		{
			// SQLite error
			break;
		}

		// If we reach this point, we can check if this client
		// is known to pihole-FTL
		// false = do not create a new record if the client is
		//         unknown (only DNS requesting clients do this)
		int clientID = findClientID(ip, false);
		bool clientKnown = clientID >= 0;

		if(dbID == -1)
		{
			// Device not in database, add new entry
			dbquery("INSERT INTO network "\
			        "(ip,hwaddr,interface,firstSeen,lastSeen,usesPihole) "\
			        "VALUES "\
			        "(\"%s\",\"%s\",\"%s\",%lu,%lu,%s);",\
			        ip, hwaddr, iface, now, now,
			        clientKnown ? "true" : "false");
		}
		else
		{
			// Device already in database, update lastSeen
			dbquery("UPDATE network "\
			        "SET lastSeen = %lu "\
			        "WHERE id = %i;",\
			        now, dbID);

			// Store if device uses Pi-hole
			if(clientKnown)
			{
				// Device uses Pi-hole, update record
				dbquery("UPDATE network "\
				        "SET usesPihole = true "\
				        "WHERE id = %i;",\
				        dbID);
			}
		}

		char *hostname = NULL;
		if(clientKnown)
			hostname = getstr(clients[clientID].namepos);
		if(hostname != NULL && strlen(hostname) > 0)
		{
			// Store host name
			dbquery("UPDATE network "\
			        "SET name = \"%s\" "\
			        "WHERE id = %i;",\
			        hostname, dbID);
		}

	}

	// Close file handle
	fclose(arpfp);

	// Close database connection
	dbclose();
}
