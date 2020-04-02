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
#include "database/network-table.h"
#include "database/common.h"
#include "shmem.h"
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
	                                "numQueries INTEGER NOT NULL, " \
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
	// Ignore possible duplicates as they are harmless and can be skipped
	SQL_bool("INSERT OR IGNORE INTO network_addresses (network_id,ip) SELECT id,ip FROM network;");

	// Remove IP column from network table.
	// As ALTER TABLE is severely limited, we have to do the column deletion manually.
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
	//         The unique constraint on hwaddr is satisfied by grouping results
	//         by this field where we chose to take only the most recent entry
	SQL_bool("INSERT INTO network_bck "\
	         "SELECT id, hwaddr, interface, name, firstSeen, "\
	                "lastQuery, numQueries, macVendor "\
	                "FROM network GROUP BY hwaddr HAVING max(lastQuery);");

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

// Try to find device by recent usage of this IP address
static int find_device_by_recent_ip(const char *ipaddr)
{
	char *querystr = NULL;
	int ret = asprintf(&querystr,
	                   "SELECT network_id FROM network_addresses "
	                   "WHERE ip = \'%s\' AND "
	                   "lastSeen > (cast(strftime('%%s', 'now') as int)-86400) "
	                   "ORDER BY lastSeen DESC LIMIT 1;",
	                   ipaddr);
	if(querystr == NULL || ret < 0)
	{
		logg("Memory allocation failed in find_device_by_recent_ip(\"%s\"): %i",
		     ipaddr, ret);
		return -1;
	}

	// Perform SQL query
	int network_id = db_query_int(querystr);
	free(querystr);

	if(network_id == DB_FAILED)
	{
		// SQLite error
		return -1;
	}
	else if(network_id == DB_NODATA)
	{
		// No result found
		return -1;
	}

	if(config.debug & DEBUG_ARP)
		logg("APR: Identified device %s using most recently used IP address", ipaddr);

	// Found network_id
	return network_id;
}

// Try to find device by mock hardware address (generated from IP address)
static int find_device_by_mock_hwaddr(const char *ipaddr)
{
	char *querystr = NULL;
	int ret = asprintf(&querystr, "SELECT id FROM network WHERE hwaddr = \'ip-%s\';", ipaddr);
	if(querystr == NULL || ret < 0)
	{
		logg("Memory allocation failed in find_device_by_mock_hwaddr(\"%s\"): %i",
		     ipaddr, ret);
		return -1;
	}

	// Perform SQL query
	int network_id = db_query_int(querystr);
	free(querystr);

	return network_id;
}

// Try to find device by RECENT mock hardware address (generated from IP address)
static int find_recent_device_by_mock_hwaddr(const char *ipaddr)
{
	char *querystr = NULL;
	int ret = asprintf(&querystr,
	                   "SELECT id FROM network WHERE "
	                   "hwaddr = \'ip-%s\' AND "
	                   "firstSeen > (cast(strftime('%%s', 'now') as int)-3600);",
	                   ipaddr);
	if(querystr == NULL || ret < 0)
	{
		logg("Memory allocation failed in find_device_by_recent_mock_hwaddr(\"%s\"): %i",
		     ipaddr, ret);
		return -1;
	}

	// Perform SQL query
	int network_id = db_query_int(querystr);
	free(querystr);

	return network_id;
}

// Store hostname of device identified by dbID
static int update_netDB_hostname(const int dbID, const char *hostname)
{
	// Skip if hostname is NULL or an empty string (= no result)
	if(hostname == NULL || strlen(hostname) < 1)
		return SQLITE_OK;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network SET name = ? WHERE id = ?;";

	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("update_netDB_hostname(%i, \"%s\") - SQL error prepare (%i): %s",
		dbID, hostname, rc, sqlite3_errmsg(FTL_db));
		return rc;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\" with arguments 1 = \"%s\" and 2 = %i", querystr, hostname, dbID);
	}

	// Bind hostname to prepared statement (1st argument)
	// SQLITE_STATIC: Use the string without first duplicating it internally.
	// We can do this as hostname has dynamic scope that exceeds that of the binding.
	if((rc = sqlite3_bind_text(query_stmt, 1, hostname, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("update_netDB_hostname(%i, \"%s\"): Failed to bind hostname (error %d): %s",
		     dbID, hostname, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Bind dbID to prepared statement (2nd argument)
	if((rc = sqlite3_bind_int(query_stmt, 2, dbID)) != SQLITE_OK)
	{
		logg("update_netDB_hostname(%i, \"%s\"): Failed to bind dbID (error %d): %s",
		     dbID, hostname, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	sqlite3_step(query_stmt);
	sqlite3_finalize(query_stmt);

	return SQLITE_OK;
}

// Updates lastQuery. Only use new value if larger than zero.
// client->lastQuery may be zero if this client is only known
// from a database entry but has not been seen since then (skip in this case)
static int update_netDB_lastQuery(const int dbID, const clientsData* client)
{
	// Return early if there is nothing to update
	if(client->lastQuery < 1)
		return SQLITE_OK;

	return dbquery("UPDATE network "\
	               "SET lastQuery = MAX(lastQuery, %ld) "\
	               "WHERE id = %i;",
	               client->lastQuery, dbID);
}


// Update numQueries.
// Add queries seen since last update and reset counter afterwards
static int update_netDB_numQueries(const int dbID, clientsData* client)
{
	// Return early if there is nothing to update
	if(client->numQueriesARP < 1)
		return SQLITE_OK;

	int numQueries = client->numQueriesARP;
	client->numQueriesARP = 0;

	return dbquery("UPDATE network "\
	              "SET numQueries = numQueries + %u "\
	              "WHERE id = %i;",
	              numQueries, dbID);
}


// Add unique pair of ID (corresponds to one particular hardware
// address) and IP address if it does not exist (INSERT). In case
// this pair already exists, the UNIQUE(network_id,ip) trigger
// becomes active and the line is instead REPLACEd, causing the
// lastQuery timestamp to be updated
static int add_netDB_network_address(const int dbID, const char* ipaddr)
{
	return dbquery("INSERT OR REPLACE INTO network_addresses "\
	               "(network_id,ip,lastSeen) VALUES (%i,\'%s\',(cast(strftime('%%s', 'now') as int)));",
	               dbID, ipaddr);
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
	FILE *arpfp = NULL;
	const char neigh_command[] = "ip neigh show";
	if((arpfp = popen(neigh_command, "r")) == NULL)
	{
		logg("WARN: Command \"%s\" failed!", neigh_command);
		logg("      Message: %s", strerror(errno));
		dbclose();
		return;
	}

	// Start ARP timer
	if(config.debug & DEBUG_ARP)
		timer_start(ARP_TIMER);

	// Prepare buffers
	char *linebuffer = NULL;
	size_t linebuffersize = 0u;
	char ip[100], hwaddr[100], iface[100];
	unsigned int entries = 0u, additional_entries = 0u;
	time_t now = time(NULL);

	const char sql[] = "BEGIN TRANSACTION IMMEDIATE";
	int rc = dbquery(sql);
	if( rc != SQLITE_OK )
	{
		const char *text;
		if( rc == SQLITE_BUSY )
		{
			text = "WARNING";
		}
		else
		{
			text = "ERROR";
			// We shall not use the database any longer
			database = false;
		}

		// dbquery() above already logs the reson for why the query failed
		logg("%s: Storing devices in network table (\"%s\") failed", text, sql);
		dbclose();
		return;
	}

	// Start collecting database commands
	lock_shm();

	// Initialize array of status for individual clients used to
	// remember the status of a client already seen in the neigh cache
	enum arp_status { CLIENT_NOT_HANDLED, CLIENT_ARP_COMPLETE, CLIENT_ARP_INCOMPLETE };
	enum arp_status client_status[counters->clients];
	for(int i = 0; i < counters->clients; i++)
	{
		client_status[i] = CLIENT_NOT_HANDLED;
	}

	// Read ARP cache line by line
	while(getline(&linebuffer, &linebuffersize, arpfp) != -1)
	{
		// Skip if line buffer is invalid
		if(linebuffer == NULL)
			continue;

		int num = sscanf(linebuffer, "%99s dev %99s lladdr %99s",
		                 ip, iface, hwaddr);

		// Check if we want to process the line we just read
		if(num != 3)
		{
			if(num == 2)
			{
				// This line is incomplete, remember this to skip
				// mock-device creation after ARP processing
				int clientID = findClientID(ip, false);
				if(clientID >= 0)
					client_status[clientID] = CLIENT_ARP_INCOMPLETE;
			}

			// Skip to the next row in the neigh cache rather when
			// marking as incomplete client
			continue;
		}

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
		rc = asprintf(&querystr, "SELECT id FROM network WHERE hwaddr = \'%s\';", hwaddr);
		if(querystr == NULL || rc < 0)
		{
			logg("Memory allocation failed in parse_arp_cache(): %i", rc);
			break;
		}

		// Perform SQL query
		int dbID = db_query_int(querystr);
		free(querystr);

		if(dbID == DB_FAILED)
		{
			// Get SQLite error code and return early from loop
			rc = sqlite3_errcode(FTL_db);
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
			client_status[clientID] = CLIENT_ARP_COMPLETE;
			client = getClient(clientID, true);
			hostname = getstr(client->namepos);
		}

		// Device not in database, add new entry
		if(dbID == DB_NODATA)
		{
			// Check if we recently added a mock-device with the same IP address
			// and the ARP entry just came a bit delayed (reported by at least one user)
			dbID = find_recent_device_by_mock_hwaddr(ip);

			char* macVendor = getMACVendor(hwaddr);
			if(dbID == DB_NODATA)
			{
				// Device not known AND no recent mock-device found ---> create new device record
				if(config.debug & DEBUG_ARP)
				{
					logg("Device with IP %s not known and "
					     "no recent mock-device found ---> creating new record", ip);
				}

				// Create new record (INSERT)
				dbquery("INSERT INTO network "
				        "(hwaddr,interface,firstSeen,lastQuery,numQueries,name,macVendor) "
				        "VALUES (\'%s\',\'%s\',%lu, %ld, %u, \'%s\', \'%s\');",
				        hwaddr, iface, now,
				        client != NULL ? client->lastQuery : 0L,
				        client != NULL ? client->numQueriesARP : 0u,
				        hostname,
				        macVendor);

				// Reset client ARP counter (we stored the entry in the database)
				if(client != NULL)
				{
					client->numQueriesARP = 0;
				}

				// Obtain ID which was given to this new entry
				dbID = get_lastID();
			}
			else
			{
				// Device is ALREADY KNOWN ---> convert mock-device to a "real" one
				if(config.debug & DEBUG_ARP)
				{
					logg("Device with IP %s already known (mock-device) "
					     "---> converting mock-record to real record", ip);
				}

				// Update/replace important device properties
				dbquery("UPDATE network SET "
				        "hwaddr = '%s', "
				        "interface = '%s', "
				        "macVendor = '%s' "
				        "WHERE id = %i;",
				        hwaddr, iface, macVendor, dbID);
				// Host name, count and last query timestamp will be set in the next
				// loop interation for the sake of simplicity
			}

			// Free allocated mememory
			free(macVendor);
		}
		// Device in database AND client known to Pi-hole
		else if(client != NULL)
		{
			// Update timestamp of last query if applicable
			rc = update_netDB_lastQuery(dbID, client);
			if(rc != SQLITE_OK)
				break;

			// Update number of queries if applicable
			rc = update_netDB_numQueries(dbID, client);
			if(rc != SQLITE_OK)
				break;

			// Update hostname if available
			rc = update_netDB_hostname(dbID, hostname);
			if(rc != SQLITE_OK)
				break;
		}
		// else:
		// Device in database but not known to Pi-hole: No action required

		// Add unique IP address / mock-MAC pair to network_addresses table
		rc = add_netDB_network_address(dbID, ip);
		if(rc != SQLITE_OK)
			break;

		// Count number of processed ARP cache entries
		entries++;
	}

	// Close pipe handle and free allocated memory
	pclose(arpfp);
	if(linebuffer != NULL)
		free(linebuffer);

	// Finally, loop over all clients known to FTL and ensure we add them
	// all to the database
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{

		// Get client pointer
		clientsData* client = getClient(clientID, true);
		if(client == NULL)
		{
			if(config.debug & DEBUG_ARP)
				logg("Network table: Client %d returned NULL pointer", clientID);
			continue;
		}

		// Get hostname and IP address of this client
		const char *hostname, *ipaddr;
		ipaddr = getstr(client->ippos);
		hostname = getstr(client->namepos);

		// Skip if this client was inactive (last query may be older than 24 hours)
		// This also reduces database I/O when nothing would change anyways
		if(client->count < 1 || client->numQueriesARP < 1)
		{
			if(config.debug & DEBUG_ARP)
				logg("Network table: Client %s has zero new queries (count: %d, ARPcount: %d)",
				     ipaddr, client->count, client->numQueriesARP);
			continue;
		}
		// Skip if already handled above (first check against clients_array_size as we might have added
		// more clients to FTL's memory herein (those known only from the database))
		else if(client_status[clientID] != CLIENT_NOT_HANDLED)
		{
			if(config.debug & DEBUG_ARP)
				logg("Network table: Client %s known through ARP/neigh cache",
				     ipaddr);
			continue;
		}
		else if(config.debug & DEBUG_ARP)
		{
			logg("Network table: %s NOT known through ARP/neigh cache", ipaddr);
		}

		//
		// Variant 1: Try to find a device using the same IP address within the last 24 hours
		//
		int dbID = find_device_by_recent_ip(ipaddr);

		//
		// Variant 2: Try to find a device with mock IP address
		//
		if(dbID < 0)
			dbID = find_device_by_mock_hwaddr(ipaddr);

		if(dbID == DB_FAILED)
		{
			// SQLite error
			break;
		}
		// Device not in database, add new entry
		else if(dbID == DB_NODATA)
		{
			dbquery("INSERT INTO network "\
			        "(hwaddr,interface,firstSeen,lastQuery,numQueries,name,macVendor) "\
			        "VALUES (\'ip-%s\',\'N/A\',%lu, %ld, %u, \'%s\', \'\');",\
			        ipaddr, now, client->lastQuery, client->numQueriesARP, hostname);
			client->numQueriesARP = 0;

			if(rc != SQLITE_OK)
				break;

			// Obtain ID which was given to this new entry
			dbID = get_lastID();
		}
		// Device already in database
		else
		{
			// Update timestamp of last query if applicable
			rc = update_netDB_lastQuery(dbID, client);
			if(rc != SQLITE_OK)
				break;

			// Update number of queries if applicable
			rc = update_netDB_numQueries(dbID, client);
			if(rc != SQLITE_OK)
				break;

			// Update hostname if available
			rc = update_netDB_hostname(dbID, hostname);
			if(rc != SQLITE_OK)
				break;
		}

		// Add unique IP address / mock-MAC pair to network_addresses table
		rc = add_netDB_network_address(dbID, ipaddr);
		if(rc != SQLITE_OK)
			break;

		// Add to number of processed ARP cache entries
		additional_entries++;
	}

	// Check for possible error in loop
	if(rc != SQLITE_OK)
	{
		const char *text;
		if( rc == SQLITE_BUSY )
		{
			text = "WARNING";
		}
		else
		{
			text = "ERROR";
			// We shall not use the database any longer
			database = false;
		}

		logg("%s: Storing devices in network table failed: %s", text, sqlite3_errstr(rc));
		unlock_shm();
		dbclose();
		return;
	}

	// Actually update the database
	if((rc = dbquery("END TRANSACTION")) != SQLITE_OK) {
		const char *text;
		if( rc == SQLITE_BUSY )
		{
			text = "WARNING";
		}
		else
		{
			text = "ERROR";
			// We shall not use the database any longer
			database = false;
		}

		logg("%s: Storing devices in network table failed: %s", text, sqlite3_errstr(rc));
		unlock_shm();
		dbclose();
		return;
	}

	// Close database connection
	// We opened the connection in this function
	dbclose();

	unlock_shm();

	// Debug logging
	if(config.debug & DEBUG_ARP)
	{
		logg("ARP table processing (%i entries from ARP, %i from FTL's cache) took %.1f ms",
		     entries, additional_entries, timer_elapsed_msec(ARP_TIMER));
	}
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
	// Get only duplicated hwaddrs here (HAVING cnt > 1).
	const char* querystr = "SELECT id,hwaddr,COUNT(*) AS cnt FROM network GROUP BY hwaddr HAVING MAX(lastQuery) AND cnt > 1;";

	// Perform SQL query
	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("unify_hwaddr(\"%s\") - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		return false;
	}

	// Loop until no further (id,hwaddr) sets are available
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE)
	{
		// Check if we ran into an error
		if(rc != SQLITE_ROW)
		{
			logg("unify_hwaddr(\"%s\") - SQL error step: %s", querystr, sqlite3_errstr(rc));
			dbclose();
			return false;
		}

		// Obtain id and hwaddr of the most recent entry for this particular client
		const int id = sqlite3_column_int(stmt, 0);
		char *hwaddr = strdup((char*)sqlite3_column_text(stmt, 1));

		// Reset statement
		sqlite3_reset(stmt);

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

		free(hwaddr);
	}

	// Finalize statement
	sqlite3_finalize(stmt);

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
			logg("getMACVenor(\"%s\"): %s does not exist", hwaddr, FTLfiles.macvendor_db);
		return strdup("");
	}
	else if(strlen(hwaddr) != 17 || strstr(hwaddr, "ip-") != NULL)
	{
		// MAC address is incomplete or mock address (for distant clients)
		if(config.debug & DEBUG_ARP)
			logg("getMACVenor(\"%s\"): MAC invalid (length %zu)", hwaddr, strlen(hwaddr));
		return strdup("");
	}

	sqlite3 *macvendor_db = NULL;
	int rc = sqlite3_open_v2(FTLfiles.macvendor_db, &macvendor_db, SQLITE_OPEN_READONLY, NULL);
	if( rc != SQLITE_OK ){
		logg("getMACVendor(\"%s\") - SQL error: %s", hwaddr, sqlite3_errstr(rc));
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
		logg("getMACVendor(\"%s\") - Allocation error (%i)", hwaddr, rc);
		sqlite3_close(macvendor_db);
		return strdup("");
	}
	free(hwaddrshort);

	sqlite3_stmt* stmt = NULL;
	rc = sqlite3_prepare_v2(macvendor_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getMACVendor(\"%s\") - SQL error prepare \"%s\": %s", hwaddr, querystr, sqlite3_errstr(rc));
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
		logg("getMACVendor(\"%s\") - SQL error step: %s", hwaddr, sqlite3_errstr(rc));
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
		logg("updateMACVendorRecords() - SQL error prepare \"%s\": %s", selectstr, sqlite3_errstr(rc));
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
			logg("updateMACVendorRecords() - Allocation error");
			free(vendor);
			break;
		}

		// Execute prepared statement
		char *zErrMsg = NULL;
		rc = sqlite3_exec(FTL_db, updatestr, NULL, NULL, &zErrMsg);
		if( rc != SQLITE_OK ){
			logg("updateMACVendorRecords() - SQL exec error: \"%s\": %s", updatestr, zErrMsg);
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
		logg("updateMACVendorRecords() - SQL error step: %s", sqlite3_errstr(rc));
	}

	sqlite3_finalize(stmt);
	dbclose();
}

char* __attribute__((malloc)) getDatabaseHostname(const char* ipaddr)
{
	// Open pihole-FTL.db database file
	if(!dbopen())
	{
		logg("getDatabaseHostname(\"%s\") - Failed to open DB", ipaddr);
		return strdup("");
	}

	// Prepare SQLite statement
	sqlite3_stmt* stmt = NULL;
	const char *querystr = "SELECT name FROM network WHERE id = (SELECT network_id FROM network_addresses WHERE ip = ?);";
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getDatabaseHostname(\"%s\") - SQL error prepare: %s",
		     ipaddr, sqlite3_errstr(rc));
		return strdup("");
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("getDatabaseHostname(\"%s\"): Failed to bind domain: %s",
		     ipaddr, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return strdup("");
	}

	char *hostname = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		hostname = strdup((char*)sqlite3_column_text(stmt, 0));
	}
	else
	{
		// Not found or error (will be logged automatically through our SQLite3 hook)
		hostname = strdup("");
	}

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);
	dbclose();

	return hostname;
}
