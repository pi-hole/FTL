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
#include "network-table.h"
#include "common.h"
#include "shmem.h"
#include "sqlite3.h"
#include "memory.h"
#include "log.h"
#include "timers.h"
#include "config.h"
#include "datastructure.h"

// Private prototypes
static char* getMACVendor(const char* hwaddr);

bool create_network_table(void)
{
	// Create network table in the database
	SQL_bool("CREATE TABLE network ( id INTEGER PRIMARY KEY NOT NULL, " \
	                                "ip TEXT NOT NULL, " \
	                                "hwaddr TEXT NOT NULL, " \
	                                "interface TEXT NOT NULL, " \
	                                "name TEXT, " \
	                                "firstSeen INTEGER NOT NULL, " \
	                                "lastQuery INTEGER NOT NULL, " \
	                                "numQueries INTEGER NOT NULL," \
	                                "macVendor TEXT);");

	// Update database version to 3
	if(!db_set_FTL_property(DB_VERSION, 3))
	{
		logg("create_network_table(): Failed to update database version!");
		return false;
	}

	return true;
}

bool create_network_addresses_table(void)
{
	// Disable foreign key enforcement for this transaction
	// Otherwise, dropping the network table would not be allowed
	SQL_bool("PRAGMA foreign_keys=OFF");

	// Begin new transaction
	SQL_bool("BEGIN TRANSACTION");

	// Create network_addresses table in the database
	SQL_bool("CREATE TABLE network_addresses ( network_id INTEGER NOT NULL, "\
	                                          "ip TEXT NOT NULL, "\
	                                          "lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%%s', 'now') as int)), "\
	                                          "UNIQUE(network_id,ip), "\
	                                          "FOREIGN KEY(network_id) REFERENCES network(id));");

	// Create a network_addresses row for each entry in the network table
	SQL_bool("INSERT INTO network_addresses (network_id,ip) SELECT id,ip FROM network;");

	// Remove IP column from network table.
	// As ALTER TABLE is severely limit, we have to do the column deletion manually.
	// Step 1: We create a new table without the ip column
	SQL_bool("CREATE TABLE network_bck ( id INTEGER PRIMARY KEY NOT NULL, " \
	                                    "hwaddr TEXT UNIQUE NOT NULL, " \
	                                    "interface TEXT NOT NULL, " \
	                                    "name TEXT, " \
	                                    "firstSeen INTEGER NOT NULL, " \
	                                    "lastQuery INTEGER NOT NULL, " \
	                                    "numQueries INTEGER NOT NULL, " \
	                                    "macVendor TEXT);");

	// Step 2: Copy data (except ip column) from network into network_back
	SQL_bool("INSERT INTO network_bck "\
	         "SELECT id, hwaddr, interface, name, firstSeen, "\
	                "lastQuery, numQueries, macVendor "\
	                "FROM network;");

	// Step 3: Drop the network table, the unique index will be automatically dropped
	SQL_bool("DROP TABLE network;");

	// Step 4: Rename network_bck table to network table as last step
	SQL_bool("ALTER TABLE network_bck RENAME TO network;");

	// Update database version to 5
	if(!db_set_FTL_property(DB_VERSION, 5))
	{
		logg("create_network_addresses_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool("COMMIT");

	// Re-enable foreign key enforcement
	SQL_bool("PRAGMA foreign_keys=ON");

	return true;
}

// Parse kernel's neighbor cache
void parse_neighbor_cache(void)
{
	// Open database file
	if(!dbopen())
	{
		logg("parse_neighbor_cache() - Failed to open DB");
		return;
	}

	// Try to access the kernel's neighbor cache
	// We are only interested in entries which are in either STALE or REACHABLE state
	FILE* arpfp = NULL;
	if((arpfp = popen("ip neigh show nud stale nud reachable", "r")) == NULL)
	{
		logg("WARN: Command \"ip neigh show nud stale nud reachable\" failed!");
		logg("      Message: %s", strerror(errno));
		dbclose();
		return;
	}

	// Start ARP timer
	if(config.debug & DEBUG_ARP) timer_start(ARP_TIMER);

	// Prepare buffers
	char * linebuffer = NULL;
	size_t linebuffersize = 0;
	char ip[100], hwaddr[100], iface[100];
	unsigned int entries = 0;
	time_t now = time(NULL);

	// Start collecting database commands
	lock_shm();
	SQL_void("BEGIN TRANSACTION");

	// Read ARP cache line by line
	while(getline(&linebuffer, &linebuffersize, arpfp) != -1)
	{
		int num = sscanf(linebuffer, "%99s dev %99s lladdr %99s",
		                 ip, iface, hwaddr);

		// Check if we want to process the line we just read
		if(num != 3)
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
			logg("Memory allocation failed in parse_arp_cache(): %i", ret);
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
			        "(hwaddr,interface,firstSeen,lastQuery,numQueries,name,macVendor) "\
			        "VALUES (\'%s\',\'%s\',%lu, %ld, %u, \'%s\', \'%s\');",\
			        hwaddr, iface, now,
			        client != NULL ? client->lastQuery : 0L,
			        client != NULL ? client->numQueriesARP : 0u,
			        hostname,
			        macVendor);
			free(macVendor);

			// Obtain ID which was given to this new entry
			dbID = get_lastID();
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

		// Add unique pair of ID (corresponds to one particular hardware
		// address) and IP address if it does not exist (INSERT). In case
		// this pair already exists, the UNIQUE(network_id,ip) trigger
		// becomes active and the line is instead REPLACEd, causing the
		// lastQuery timestamp to be updated
		dbquery("INSERT OR REPLACE INTO network_addresses "\
		        "(network_id,ip) VALUES(%i,\'%s\');", dbID, ip);

		// Count number of processed ARP cache entries
		entries++;
	}

	// Actually update the database
	SQL_void("COMMIT");
	unlock_shm();

	// Debug logging
	if(config.debug & DEBUG_ARP)
		logg("ARP table processing (%i entries) took %.1f ms", entries, timer_elapsed_msec(ARP_TIMER));

	// Close file handle
	pclose(arpfp);

	// Close database connection
	dbclose();
}

// Loop over all entries in network table and unify entries by their hwaddr
// If we find duplicates, we keep the most recent entry, while
// - we replace the first-seen date by the earliest across all rows
// - we sum up the number of queries of all clients with the same hwaddr
bool unify_hwaddr(void)
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
	ret = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( ret != SQLITE_OK ){
		logg("unify_hwaddr(%s) - SQL error prepare (%i): %s", querystr, ret, sqlite3_errmsg(FTL_db));
		check_database(ret);
		return false;
	}

	// Loop until no further (id,hwaddr) sets are available
	while((ret = sqlite3_step(stmt)) != SQLITE_DONE)
	{
		// Check if we ran into an error
		if(ret != SQLITE_ROW)
		{
			logg("unify_hwaddr(%s) - SQL error step (%i): %s", querystr, ret, sqlite3_errmsg(FTL_db));
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
	SQL_bool("CREATE UNIQUE INDEX network_hwaddr_idx ON network(hwaddr)");

	// Update database version to 4
	if(!db_set_FTL_property(DB_VERSION, 4))
		return false;

	return true;
}

static char* getMACVendor(const char* hwaddr)
{
	struct stat st;
	if(stat(FTLfiles.macvendor_db, &st) != 0)
	{
		// File does not exist
		if(config.debug & DEBUG_ARP)
			logg("getMACVenor(%s): %s does not exist", hwaddr, FTLfiles.macvendor_db);
		return strdup("");
	}
	else if(strlen(hwaddr) != 17)
	{
		// MAC address is incomplete
		if(config.debug & DEBUG_ARP)
			logg("getMACVenor(%s): MAC invalid (length %zu)", hwaddr, strlen(hwaddr));
		return strdup("");
	}

	sqlite3 *macvendor_db = NULL;
	int rc = sqlite3_open_v2(FTLfiles.macvendor_db, &macvendor_db, SQLITE_OPEN_READONLY, NULL);
	if( rc != SQLITE_OK  ){
		logg("getMACVendor(%s) - SQL error (%i): %s", hwaddr, rc, sqlite3_errmsg(macvendor_db));
		sqlite3_close(macvendor_db);
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
		sqlite3_close(macvendor_db);
		return strdup("");
	}
	free(hwaddrshort);

	sqlite3_stmt* stmt = NULL;
	rc = sqlite3_prepare_v2(macvendor_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getMACVendor(%s) - SQL error prepare (%s, %i): %s", hwaddr, querystr, rc, sqlite3_errmsg(macvendor_db));
		sqlite3_close(macvendor_db);
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
		logg("getMACVendor(%s) - SQL error step (%i): %s", hwaddr, rc, sqlite3_errmsg(macvendor_db));
	}

	sqlite3_finalize(stmt);
	sqlite3_close(macvendor_db);

	return vendor;
}

void updateMACVendorRecords(void)
{
	struct stat st;
	if(stat(FTLfiles.macvendor_db, &st) != 0)
	{
		// File does not exist
		if(config.debug & DEBUG_ARP)
			logg("updateMACVendorRecords(): \"%s\" does not exist", FTLfiles.macvendor_db);
		return;
	}

	// Open database connection
	dbopen();

	sqlite3_stmt* stmt;
	const char* selectstr = "SELECT id,hwaddr FROM network;";
	int rc = sqlite3_prepare_v2(FTL_db, selectstr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("updateMACVendorRecords() - SQL error prepare (%s, %i): %s", selectstr, rc, sqlite3_errmsg(FTL_db));
		dbclose();
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
		rc = sqlite3_exec(FTL_db, updatestr, NULL, NULL, &zErrMsg);
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
		logg("updateMACVendorRecords() - SQL error step (%i): %s", rc, sqlite3_errmsg(FTL_db));
	}

	sqlite3_finalize(stmt);
	dbclose();
}
