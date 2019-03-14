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
#include "sqlite3.h"
#define ARPCACHE "/proc/net/arp"

// Private prototypes
static char* getMACVendor(const char* hwaddr);

bool create_network_table(void)
{
	bool ret;
	// Create network table in the database
	ret = dbquery("CREATE TABLE network ( id INTEGER PRIMARY KEY NOT NULL, " \
	                                     "ip TEXT NOT NULL, " \
	                                     "hwaddr TEXT NOT NULL, " \
	                                     "interface TEXT NOT NULL, " \
	                                     "name TEXT, " \
	                                     "firstSeen INTEGER NOT NULL, " \
	                                     "lastQuery INTEGER NOT NULL, " \
	                                     "numQueries INTEGER NOT NULL," \
	                                     "macVendor TEXT);");
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
		fclose(arpfp);
		return;
	}

	// Start ARP timer
	if(config.debug & DEBUG_ARP) timer_start(ARP_TIMER);

	// Prepare buffers
	char * linebuffer = NULL;
	size_t linebuffersize = 0;
	char ip[100], mask[100], hwaddr[100], iface[100];
	int type, flags, entries = 0;
	time_t now = time(NULL);

	// Start collecting database commands
	lock_shm();
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
		int ret = asprintf(&querystr, "SELECT id FROM network WHERE ip = \'%s\' AND hwaddr = \'%s\';", ip, hwaddr);
		if(querystr == NULL || ret < 0)
		{
			logg("Memory allocation failed in parse_arp_cache (%i)", ret);
			break;
		}

		// Perform SQL query
		int dbID = db_query_int(querystr);
		free(querystr);

		if(dbID == DB_FAILED)
		{
			// SQLite error
			break;
		}

		// If we reach this point, we can check if this client
		// is known to pihole-FTL
		// false = do not create a new record if the client is
		//         unknown (only DNS requesting clients do this)
		int clientID = findClientID(ip, false);

		// Get hostname of this client if the client is known
		const char *hostname = "";
		// Get client pointer
		clientsData* client = NULL;

		if(clientID >= 0)
		{
			client = getClient(clientID, true);
			hostname = getstr(client->namepos);
		}

		// Device not in database, add new entry
		if(dbID == DB_NODATA)
		{
			char* macVendor = getMACVendor(hwaddr);
			dbquery("INSERT INTO network "\
			        "(ip,hwaddr,interface,firstSeen,lastQuery,numQueries,name,macVendor) "\
			        "VALUES (\'%s\',\'%s\',\'%s\',%lu, %ld, %u, \'%s\', \'%s\');",\
			        ip, hwaddr, iface, now,
			        client != NULL ? client->lastQuery : 0L,
			        client != NULL ? client->numQueriesARP : 0u,
			        hostname,
			        macVendor);
			free(macVendor);
		}
		// Device in database AND client known to Pi-hole
		else if(client != NULL)
		{
			// Update lastQuery. Only use new value if larger
			// client->lastQuery may be zero if this
			// client is only known from a database entry but has
			// not been seen since then
			dbquery("UPDATE network "\
			        "SET lastQuery = MAX(lastQuery, %ld) "\
			        "WHERE id = %i;",\
			        client->lastQuery, dbID);

			// Update numQueries. Add queries seen since last update
			// and reset counter afterwards
			dbquery("UPDATE network "\
			        "SET numQueries = numQueries + %u "\
			        "WHERE id = %i;",\
			        client->numQueriesARP, dbID);
			client->numQueriesARP = 0;

			// Store hostname if available
			if(strlen(hostname) > 0)
			{
				// Store host name
				dbquery("UPDATE network "\
				        "SET name = \'%s\' "\
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
	unlock_shm();

	// Debug logging
	if(config.debug & DEBUG_ARP) logg("ARP table processing (%i entries) took %.1f ms", entries, timer_elapsed_msec(ARP_TIMER));

	// Close file handle
	fclose(arpfp);

	// Close database connection
	dbclose();
}

static char* getMACVendor(const char* hwaddr)
{
	struct stat st;
	if(stat(FTLfiles.macvendordb, &st) != 0)
	{
		// File does not exist
		if(config.debug & DEBUG_ARP) logg("getMACVenor(%s): %s does not exist", hwaddr, FTLfiles.macvendordb);
		return strdup("");
	}
	else if(strlen(hwaddr) != 17)
	{
		// MAC address is incomplete
		if(config.debug & DEBUG_ARP) logg("getMACVenor(%s): MAC invalid (length %zu)", hwaddr, strlen(hwaddr));
		return strdup("");
	}

	sqlite3 *macdb;
	int rc = sqlite3_open_v2(FTLfiles.macvendordb, &macdb, SQLITE_OPEN_READONLY, NULL);
	if( rc ){
		logg("getMACVendor(%s) - SQL error (%i): %s", hwaddr, rc, sqlite3_errmsg(macdb));
		sqlite3_close(macdb);
		return strdup("");
	}

	char *querystr = NULL;
	// Only keep "XX:YY:ZZ" (8 characters)
	char * hwaddrshort = strdup(hwaddr);
	hwaddrshort[8] = '\0';
	rc = asprintf(&querystr, "SELECT vendor FROM macvendor WHERE mac LIKE \'%s\';", hwaddrshort);
	if(rc < 1)
	{
		logg("getMACVendor(%s) - Allocation error (%i)", hwaddr, rc);
		sqlite3_close(macdb);
		return strdup("");
	}
	free(hwaddrshort);

	sqlite3_stmt* stmt;
	rc = sqlite3_prepare_v2(macdb, querystr, -1, &stmt, NULL);
	if( rc ){
		logg("getMACVendor(%s) - SQL error prepare (%s, %i): %s", hwaddr, querystr, rc, sqlite3_errmsg(macdb));
		sqlite3_close(macdb);
		return strdup("");
	}
	free(querystr);

	char *vendor = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		vendor = strdup((char*)sqlite3_column_text(stmt, 0));
	}
	else
	{
		// Not found
		vendor = strdup("");
	}

	if(rc != SQLITE_DONE && rc != SQLITE_ROW)
	{
		// Error
		logg("getMACVendor(%s) - SQL error step (%i): %s", hwaddr, rc, sqlite3_errmsg(macdb));
	}

	sqlite3_finalize(stmt);
	sqlite3_close(macdb);

	return vendor;
}

void updateMACVendorRecords()
{
	struct stat st;
	if(stat(FTLfiles.macvendordb, &st) != 0)
	{
		// File does not exist
		if(config.debug & DEBUG_ARP) logg("updateMACVendorRecords(): %s does not exist", FTLfiles.macvendordb);
		return;
	}

	sqlite3 *db;
	int rc = sqlite3_open_v2(FTLfiles.db, &db, SQLITE_OPEN_READWRITE, NULL);
	if( rc ){
		logg("updateMACVendorRecords() - SQL error (%i): %s", rc, sqlite3_errmsg(db));
		sqlite3_close(db);
		return;
	}

	sqlite3_stmt* stmt;
	const char* selectstr = "SELECT id,hwaddr FROM network;";
	rc = sqlite3_prepare_v2(db, selectstr, -1, &stmt, NULL);
	if( rc ){
		logg("updateMACVendorRecords() - SQL error prepare (%s, %i): %s", selectstr, rc, sqlite3_errmsg(db));
		sqlite3_close(db);
		return;
	}

	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const int id = sqlite3_column_int(stmt, 0);
		char* hwaddr = strdup((char*)sqlite3_column_text(stmt, 1));

		// Get vendor for MAC
		char* vendor = getMACVendor(hwaddr);
		free(hwaddr);
		hwaddr = NULL;

		// Prepare UPDATE statement
		char *updatestr = NULL;
		if(asprintf(&updatestr, "UPDATE network SET macVendor = \'%s\' WHERE id = %i", vendor, id) < 1)
		{
			logg("updateMACVendorRecords() - Allocation error 2");
			free(vendor);
			break;
		}

		// Execute prepared statement
		char *zErrMsg = NULL;
		rc = sqlite3_exec(db, updatestr, NULL, NULL, &zErrMsg);
		if( rc != SQLITE_OK ){
			logg("updateMACVendorRecords() - SQL exec error: %s (%i): %s", updatestr, rc, zErrMsg);
			sqlite3_free(zErrMsg);
			free(updatestr);
			free(vendor);
			break;
		}

		// Free allocated memory
		free(updatestr);
		free(vendor);
	}
	if(rc != SQLITE_DONE)
	{
		// Error
		logg("updateMACVendorRecords() - SQL error step (%i): %s", rc, sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
}
