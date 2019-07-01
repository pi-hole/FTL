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
#include "networktable.h"
#include "memory.h"
#include "database.h"
#include "log.h"
#include "timers.h"
#include "datastructure.h"
#define ARPCACHE "/proc/net/arp"

// Private prototypes
static char* getMACVendor(const char* hwaddr);
bool unify_hwaddr(sqlite3 *db);

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
	unsigned int type, flags, entries = 0;
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

		// Get ID of this device in our network database. If it cannot be
		// found, then this is a new device. We only use the hardware address
		// to uniquely identify clients and only use the first returned ID.
		//
		// Same MAC, two IPs: Non-deterministic (sequential) DHCP server, we
		// update the IP address to the last seen one.
		//
		// We can run this SELECT inside the currently active transaction as
		// only the changed to the database are collected for latter
		// commitment. Read-only access such as this SELECT command will be
		// executed immediately on the database.
		char* querystr = NULL;
		int ret = asprintf(&querystr, "SELECT id FROM network WHERE hwaddr = \'%s\';", hwaddr);
		if(querystr == NULL || ret < 0)
		{
			logg("Memory allocation failed in parse_arp_cache (%i)", ret);
			break;
		}

		// Perform SQL query
		const int dbID = db_query_int(querystr);
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

		// This client is known (by its IP address) to pihole-FTL if
		// findClientID() returned a non-negative index
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

			// Update IP address in case it changed. This might happen with
			// sequential DHCP servers as found in many commercial routers
			dbquery("UPDATE network "\
			        "SET ip = \'%s\' "\
			        "WHERE id = %i;",\
			        ip, dbID);

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
	if(config.debug & DEBUG_ARP)
		logg("ARP table processing (%i entries) took %.1f ms", entries, timer_elapsed_msec(ARP_TIMER));

	// Close file handle
	fclose(arpfp);

	// Close database connection
	dbclose();
}

// Loop over all entries in network table and unify entries by their hwaddr
// If we find duplicates, we keep the most recent entry, while
// - we replace the first-seen date by the earliest across all rows
// - we sum up the number of queries of all clients with the same hwaddr
bool unify_hwaddr(sqlite3 *db)
{
	// We request sets of (id,hwaddr). They are GROUPed BY hwaddr to make
	// the set unique in hwaddr.
	// The grouping is constrained by the HAVING clause which is
	// evaluated once across all rows of a group to ensure the returned
	// set represents the most recent entry for a given hwaddr
	char* querystr = NULL;
	int ret = asprintf(&querystr, "SELECT id,hwaddr FROM network GROUP BY hwaddr HAVING MAX(lastQuery)");
	if(querystr == NULL || ret < 0)
	{
		logg("Memory allocation failed in unify_hwaddr (%i)", ret);
		dbclose();
		return false;
	}

	// Perform SQL query
	sqlite3_stmt* stmt;
	ret = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( ret ){
		logg("unify_hwaddr(%s) - SQL error prepare (%i): %s", querystr, ret, sqlite3_errmsg(db));
		dbclose();
		return false;
	}

	// Loop until no further (id,hwaddr) sets are available
	while((ret = sqlite3_step(stmt)) != SQLITE_DONE)
	{
		// Check if we ran into an error
		if(ret != SQLITE_ROW)
		{
			logg("unify_hwaddr(%s) - SQL error step (%i): %s", querystr, ret, sqlite3_errmsg(db));
			dbclose();
			return false;
		}

		// Obtain id and hwaddr of the most recent entry for this particular client
		const int id = sqlite3_column_int(stmt, 0);
		const char *hwaddr = (const char *)sqlite3_column_text(stmt, 1);

		// Update firstSeen with lowest value across all rows with the same hwaddr
		dbquery("UPDATE network "\
		        "SET firstSeen = (SELECT MIN(firstSeen) FROM network WHERE hwaddr = \'%s\') "\
		        "WHERE id = %i;",\
		        hwaddr, id);

		// Update numQueries with sum of all rows with the same hwaddr
		dbquery("UPDATE network "\
		        "SET numQueries = (SELECT SUM(numQueries) FROM network WHERE hwaddr = \'%s\') "\
		        "WHERE id = %i;",\
		        hwaddr, id);

		// Remove all other lines with the same hwaddr but a different id
		dbquery("DELETE FROM network "\
		        "WHERE hwaddr = \'%s\' "\
		        "AND id != %i;",\
		        hwaddr, id);
	}

	// Finalize statement and free query string
	sqlite3_finalize(stmt);
	free(querystr);

	// Ensure hwaddr is a unique field
	// Unfortunately, SQLite's ALTER TABLE does not support adding
	// constraints to existing tables. However, we can add a unique
	// index for the table to achieve the same effect.
	//
	// See https://www.sqlite.org/lang_createtable.html#constraints:
	// >>> In most cases, UNIQUE and PRIMARY KEY constraints are
	// >>> implemented by creating a unique index in the database.
	dbquery("CREATE UNIQUE INDEX network_hwaddr_idx ON network(hwaddr)");

	// Update database version to 4
	if(!db_set_FTL_property(DB_VERSION, 4))
	{
		dbclose();
		return false;
	}

	return true;
}

static char* getMACVendor(const char* hwaddr)
{
	struct stat st;
	if(stat(FTLfiles.macvendordb, &st) != 0)
	{
		// File does not exist
		if(config.debug & DEBUG_ARP)
			logg("getMACVenor(%s): %s does not exist", hwaddr, FTLfiles.macvendordb);
		return strdup("");
	}
	else if(strlen(hwaddr) != 17)
	{
		// MAC address is incomplete
		if(config.debug & DEBUG_ARP)
			logg("getMACVenor(%s): MAC invalid (length %zu)", hwaddr, strlen(hwaddr));
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
		if(config.debug & DEBUG_ARP)
			logg("updateMACVendorRecords(): %s does not exist", FTLfiles.macvendordb);
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
