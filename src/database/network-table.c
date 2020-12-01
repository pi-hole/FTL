/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Network table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "network-table.h"
#include "common.h"
#include "../shmem.h"
// strdup()
#include "../memory.h"
#include "../log.h"
// timer_elapsed_msec()
#include "../timers.h"
// struct config
#include "../config.h"
//#include "../datastructure.h"
// resolveHostname()
#include "../resolve.h"

// Private prototypes
static char *getMACVendor(const char *hwaddr);
enum arp_status { CLIENT_NOT_HANDLED, CLIENT_ARP_COMPLETE, CLIENT_ARP_INCOMPLETE };

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

bool create_network_addresses_with_names_table(void)
{
	// Disable foreign key enforcement for this transaction
	// Otherwise, dropping the network table would not be allowed
	SQL_bool("PRAGMA foreign_keys=OFF");

	// Begin new transaction
	SQL_bool("BEGIN TRANSACTION");

	// Step 1: Create network_addresses table in the database
	SQL_bool("CREATE TABLE network_addresses_bck ( network_id INTEGER NOT NULL, "
	                                              "ip TEXT UNIQUE NOT NULL, "
	                                              "lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%%s', 'now') as int)), "
	                                              "name TEXT, "
	                                              "nameUpdated INTEGER, "
	                                              "FOREIGN KEY(network_id) REFERENCES network(id));");

	// Step 2: Copy data from network_addresses into network_addresses_bck
	//         name and nameUpdated are NULL at this point
	SQL_bool("REPLACE INTO network_addresses_bck "
	         "(network_id,ip,lastSeen) "
	         "SELECT network_id,ip,lastSeen "
	                "FROM network_addresses;");

	// Step 3: Drop the network_addresses table
	SQL_bool("DROP TABLE network_addresses;");

	// Step 4: Drop the network_names table (if exists due to a previous v7 database update)
	SQL_bool("DROP TABLE IF EXISTS network_names;");

	// Step 5: Rename network_addresses_bck table to network_addresses table as last step
	SQL_bool("ALTER TABLE network_addresses_bck RENAME TO network_addresses;");

	// Remove name column from network table.
	// As ALTER TABLE is severely limited, we have to do the column deletion manually.
	// Step 1: We create a new table without the name column
	SQL_bool("CREATE TABLE network_bck ( id INTEGER PRIMARY KEY NOT NULL, " \
	                                    "hwaddr TEXT UNIQUE NOT NULL, " \
	                                    "interface TEXT NOT NULL, " \
	                                    "firstSeen INTEGER NOT NULL, " \
	                                    "lastQuery INTEGER NOT NULL, " \
	                                    "numQueries INTEGER NOT NULL, " \
	                                    "macVendor TEXT);");

	// Step 2: Copy data (except name column) from network into network_back
	SQL_bool("INSERT INTO network_bck "\
	         "SELECT id, hwaddr, interface, firstSeen, "\
	                "lastQuery, numQueries, macVendor "\
	                "FROM network;");

	// Step 3: Drop the network table, the unique index will be automatically dropped
	SQL_bool("DROP TABLE network;");

	// Step 4: Rename network_bck table to network table as last step
	SQL_bool("ALTER TABLE network_bck RENAME TO network;");

	// Update database version to 8
	if(!db_set_FTL_property(DB_VERSION, 8))
	{
		logg("create_network_addresses_with_names_table(): Failed to update database version!");
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

// Try to find device by hardware address
static int find_device_by_hwaddr(const char hwaddr[])
{
	char *querystr = NULL;
	int ret = asprintf(&querystr, "SELECT id FROM network WHERE hwaddr = \'%s\' COLLATE NOCASE;", hwaddr);
	if(querystr == NULL || ret < 0)
	{
		logg("Memory allocation failed in find_device_by_hwaddr(\"%s\"): %i",
		     hwaddr, ret);
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
static int update_netDB_name(const char *ip, const char *name)
{
	// Skip if hostname is NULL or an empty string (= no result)
	if(name == NULL || strlen(name) < 1)
		return SQLITE_OK;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network_addresses SET name = ?1, "
	                               "nameUpdated = (cast(strftime('%s', 'now') as int)) "
	                               "WHERE ip = ?2";

	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("update_netDB_name(%s, \"%s\") - SQL error prepare (%i): %s",
		     ip, name, rc, sqlite3_errmsg(FTL_db));
		return rc;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\" with arguments 1 = \"%s\" and 2 = \"%s\"",
		     querystr, name, ip);
	}

	// Bind name to prepared statement (1st argument)
	// SQLITE_STATIC: Use the string without first duplicating it internally.
	// We can do this as name has dynamic scope that exceeds that of the binding.
	if((rc = sqlite3_bind_text(query_stmt, 1, name, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("update_netDB_name(%s, \"%s\"): Failed to bind ip (error %d): %s",
		     ip, name, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}
	// Bind ip (unique key) to prepared statement (2nd argument)
	// SQLITE_STATIC: Use the string without first duplicating it internally.
	// We can do this as name has dynamic scope that exceeds that of the binding.
	if((rc = sqlite3_bind_text(query_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("update_netDB_name(%s, \"%s\"): Failed to bind name (error %d): %s",
		     ip, name, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		logg("update_netDB_name(%s, \"%s\"): Failed to step (error %d): %s",
		     ip, name, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		logg("update_netDB_name(%s, \"%s\"): Failed to finalize (error %d): %s",
		     ip, name, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	return SQLITE_OK;
}

// Updates lastQuery. Only use new value if larger than zero.
// client->lastQuery may be zero if this client is only known
// from a database entry but has not been seen since then (skip in this case)
static int update_netDB_lastQuery(const int network_id, const clientsData *client)
{
	// Return early if there is nothing to update
	if(client->lastQuery < 1)
		return SQLITE_OK;

	return dbquery("UPDATE network "\
	               "SET lastQuery = MAX(lastQuery, %ld) "\
	               "WHERE id = %i;",
	               client->lastQuery, network_id);
}


// Update numQueries.
// Add queries seen since last update and reset counter afterwards
static int update_netDB_numQueries(const int dbID, clientsData *client)
{
	// Return early if there is nothing to update
	if(client->numQueriesARP < 1)
		return SQLITE_OK;

	int numQueries = client->numQueriesARP;
	client->numQueriesARP = 0;

	return dbquery("UPDATE network "
	               "SET numQueries = numQueries + %u "
	               "WHERE id = %i;",
	               numQueries, dbID);
}

// Add IP address record if it does not exist (INSERT). If it already exists,
// the UNIQUE(ip) trigger becomes active and the line is instead REPLACEd.
// We preserve a possibly existing IP -> host name association here
static int add_netDB_network_address(const int network_id, const char *ip)
{
	// Return early if there is nothing to be done in here
	if(ip == NULL || strlen(ip) == 0)
		return SQLITE_OK;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "INSERT OR REPLACE INTO network_addresses "
	                        "(network_id,ip,lastSeen,name,nameUpdated) VALUES "
	                        "(?1,?2,(cast(strftime('%s', 'now') as int)),"
	                        "(SELECT name FROM network_addresses "
	                                "WHERE ip = ?2),"
	                        "(SELECT nameUpdated FROM network_addresses "
	                                "WHERE ip = ?2));";

	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("add_netDB_network_address(%i, \"%s\") - SQL error prepare (%i): %s",
		     network_id, ip, rc, sqlite3_errmsg(FTL_db));
		return rc;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\" with arguments ?1 = %i and ?2 = \"%s\"",
		     querystr, network_id, ip);
	}

	// Bind network_id to prepared statement (1st argument)
	if((rc = sqlite3_bind_int(query_stmt, 1, network_id)) != SQLITE_OK)
	{
		logg("add_netDB_network_address(%i, \"%s\"): Failed to bind network_id (error %d): %s",
		     network_id, ip, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}
	// Bind ip to prepared statement (2nd argument)
	if((rc = sqlite3_bind_text(query_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("add_netDB_network_address(%i, \"%s\"): Failed to bind name (error %d): %s",
		     network_id, ip, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		logg("add_netDB_network_address(%i, \"%s\"): Failed to step (error %d): %s",
		     network_id, ip, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		logg("add_netDB_network_address(%i, \"%s\"): Failed to finalize (error %d): %s",
		     network_id, ip, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	return SQLITE_OK;
}

// Insert a new record into the network table
static int insert_netDB_device(const char *hwaddr, time_t now, time_t lastQuery,
                               unsigned int numQueriesARP, const char *macVendor)
{
	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "INSERT INTO network "\
	                        "(hwaddr,interface,firstSeen,lastQuery,numQueries,macVendor) "\
	                        "VALUES (?1,\'N/A\',?2,?3,?4,?5);";

	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\") - SQL error prepare (%i): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		return rc;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\" with arguments ?1-?5 = (\"%s\",%lu,%lu,%u,\"%s\")",
		     querystr, hwaddr, now, lastQuery, numQueriesARP, macVendor);
	}

	// Bind hwaddr to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind hwaddr (error %d): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Bind now to prepared statement (2nd argument)
	if((rc = sqlite3_bind_int(query_stmt, 2, now)) != SQLITE_OK)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind now (error %d): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Bind lastQuery to prepared statement (3rd argument)
	if((rc = sqlite3_bind_int(query_stmt, 3, lastQuery)) != SQLITE_OK)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind lastQuery (error %d): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Bind numQueriesARP to prepared statement (4th argument)
	if((rc = sqlite3_bind_int(query_stmt, 4, numQueriesARP)) != SQLITE_OK)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind numQueriesARP (error %d): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Bind macVendor to prepared statement (5th argument) - the macVendor can be NULL here
	if((rc = sqlite3_bind_text(query_stmt, 5, macVendor, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind macVendor (error %d): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to step (error %d): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		logg("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to finalize (error %d): %s",
		     hwaddr, now, lastQuery, numQueriesARP, macVendor, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	return SQLITE_OK;
}

// Convert mock-device into a real one by changing the hardware address (and possibly adding a vendor string)
static int unmock_netDB_device(const char *hwaddr, const char *macVendor, const int dbID)
{
	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network SET "\
	                        "hwaddr = ?1, macVendor=?2 WHERE id = ?3;";

	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("unmock_netDB_device(\"%s\", \"%s\", %i) - SQL error prepare (%i): %s",
		     hwaddr, macVendor, dbID, rc, sqlite3_errmsg(FTL_db));
		return rc;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\" with arguments ?1 = \"%s\", ?2 = \"%s\", ?3 = %i",
		     querystr, hwaddr, macVendor, dbID);
	}

	// Bind hwaddr to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind hwaddr (error %d): %s",
		     hwaddr, macVendor, dbID, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Bind macVendor to prepared statement (2nd argument) - the macVendor can be NULL here
	if((rc = sqlite3_bind_text(query_stmt, 2, macVendor, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind macVendor (error %d): %s",
		     hwaddr, macVendor, dbID, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Bind now to prepared statement (3rd argument)
	if((rc = sqlite3_bind_int(query_stmt, 3, dbID)) != SQLITE_OK)
	{
		logg("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind now (error %d): %s",
		     hwaddr, macVendor, dbID, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		logg("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to step (error %d): %s",
		     hwaddr, macVendor, dbID, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		logg("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to finalize (error %d): %s",
		     hwaddr, macVendor, dbID, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	return SQLITE_OK;
}

// Update interface of device
static int update_netDB_interface(const int network_id, const char *iface)
{
	// Return early if there is nothing to be done in here
	if(iface == NULL || strlen(iface) == 0)
		return SQLITE_OK;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network SET interface = ?1 WHERE id = ?2";

	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("update_netDB_interface(%i, \"%s\") - SQL error prepare (%i): %s",
		     network_id, iface, rc, sqlite3_errmsg(FTL_db));
		return rc;
	}

	if(config.debug & DEBUG_DATABASE)
	{
		logg("dbquery: \"%s\" with arguments ?1 = \"%s\" and ?2 = %i",
		     querystr, iface, network_id);
	}

	// Bind iface to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, iface, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("update_netDB_interface(%i, \"%s\"): Failed to bind iface (error %d): %s",
		     network_id, iface, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}
	// Bind network_id to prepared statement (2nd argument)
	if((rc = sqlite3_bind_int(query_stmt, 2, network_id)) != SQLITE_OK)
	{
		logg("update_netDB_interface(%i, \"%s\"): Failed to bind name (error %d): %s",
		     network_id, iface, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		logg("update_netDB_interface(%i, \"%s\"): Failed to step (error %d): %s",
		     network_id, iface, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		logg("update_netDB_interface(%i, \"%s\"): Failed to finalize (error %d): %s",
		     network_id, iface, rc, sqlite3_errmsg(FTL_db));
		sqlite3_reset(query_stmt);
		return rc;
	}

	return SQLITE_OK;
}

// Loop over all clients known to FTL and ensure we add them all to the database
static bool add_FTL_clients_to_network_table(enum arp_status *client_status, time_t now, unsigned int *additional_entries)
{
	int rc = SQLITE_OK;
	char hwaddr[128];
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		clientsData *client = getClient(clientID, true);
		if(client == NULL)
		{
			if(config.debug & DEBUG_ARP)
				logg("Network table: Client %d returned NULL pointer", clientID);
			continue;
		}

		// Silently skip alias-clients - they do not really exist
		if(client->aliasclient)
			continue;

		// Get hostname and IP address of this client
		const char *hostname, *ipaddr, *interface;
		ipaddr = getstr(client->ippos);
		hostname = getstr(client->namepos);
		interface = getstr(client->ifacepos);

		// Skip if already handled above (first check against clients_array_size as we might have added
		// more clients to FTL's memory herein (those known only from the database))
		if(client_status[clientID] != CLIENT_NOT_HANDLED)
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
		// Variant 1: Try to find a device with an EDNS(0)-provided hardware address
		//
		int dbID = DB_NODATA;
		if(client->hwlen == 6)
		{
			snprintf(hwaddr, sizeof(hwaddr), "%02X:%02X:%02X:%02X:%02X:%02X",
			         client->hwaddr[0], client->hwaddr[1],
			         client->hwaddr[2], client->hwaddr[3],
			         client->hwaddr[4], client->hwaddr[5]);
			hwaddr[6*2+5] = '\0';
			dbID = find_device_by_hwaddr(hwaddr);

			if(config.debug & DEBUG_ARP && dbID >= 0)
				logg("Network table: Client with MAC %s is network ID %i", hwaddr, dbID);
		}
		else
		{
			//
			// Variant 2: Try to find a device using the same IP address within the last 24 hours
			// Only try this when there is no EDNS(0) MAC address available
			//
			if(dbID < 0)
			{
				dbID = find_device_by_recent_ip(ipaddr);
				if(config.debug & DEBUG_ARP && dbID >= 0)
					logg("Network table: Client with IP %s has no MAC info but was recently be seen for network ID %i",
					     ipaddr, dbID);
			}

			//
			// Variant 3: Try to find a device with mock IP address
			// Only try this when there is no EDNS(0) MAC address available
			//
			if(dbID < 0)
			{
				dbID = find_device_by_mock_hwaddr(ipaddr);
				if(config.debug & DEBUG_ARP && dbID >= 0)
					logg("Network table: Client with IP %s has no MAC info but is known as mock-hwaddr client with network ID %i",
					     ipaddr, dbID);
			}

			// Create mock hardware address in the style of "ip-<IP address>", like "ip-127.0.0.1"
			strcpy(hwaddr, "ip-");
			strncpy(hwaddr+3, ipaddr, sizeof(hwaddr)-4);
			hwaddr[sizeof(hwaddr)-1] = '\0';
		}

		if(dbID == DB_FAILED)
		{
			// SQLite error
			break;
		}
		// Device not in database, add new entry
		else if(dbID == DB_NODATA)
		{
			char *macVendor = NULL;
			if(client->hwlen == 6)
			{
				// Normal client, MAC was likely obtained from EDNS(0) data
				macVendor = getMACVendor(hwaddr);
			}

			if(config.debug & DEBUG_ARP)
			{
				logg("Network table: Creating new FTL device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\", interface = \"%s\"",
					hwaddr, ipaddr, hostname, macVendor, interface);
			}

			// Add new device to database
			insert_netDB_device(hwaddr, now, client->lastQuery,
			                    client->numQueriesARP, macVendor);
			client->numQueriesARP = 0;

			//Free allocated memory
			if(macVendor != NULL)
			{
				free(macVendor);
				macVendor = NULL;
			}

			// Obtain ID which was given to this new entry
			dbID = get_lastID();
		}
		else	// Device already in database
		{
			if(config.debug & DEBUG_ARP)
			{
				logg("Network table: Updating existing FTL device MAC = %s, IP = %s, hostname = \"%s\", interface = \"%s\"",
				     hwaddr, ipaddr, hostname, interface);
			}

			// Update timestamp of last query if applicable
			rc = update_netDB_lastQuery(dbID, client);
			if(rc != SQLITE_OK)
				break;

			// Update number of queries if applicable
			rc = update_netDB_numQueries(dbID, client);
			if(rc != SQLITE_OK)
				break;
		}

		// Add unique IP address / mock-MAC pair to network_addresses table
		rc = add_netDB_network_address(dbID, ipaddr);
		if(rc != SQLITE_OK)
			break;

		// Update hostname if available
		rc = update_netDB_name(ipaddr, hostname);
		if(rc != SQLITE_OK)
			break;

		// Update interface if available
		rc = update_netDB_interface(dbID, interface);
		if(rc != SQLITE_OK)
			break;

		// Add to number of processed ARP cache entries
		(*additional_entries)++;
	}

	// Check for possible error in loop
	if(rc != SQLITE_OK)
	{
		const char *text;
		if( rc == SQLITE_BUSY )
			text = "WARNING";
		else
		{
			text = "ERROR";
			dbclose();
		}

		logg("%s: Storing devices in network table failed: %s", text, sqlite3_errstr(rc));
		unlock_shm();
		return false;
	}

	return true;
}

static bool add_local_interfaces_to_network_table(time_t now, unsigned int *additional_entries)
{
	// Try to access the kernel's Internet protocol address management
	FILE *ip_pipe = NULL;
	const char ip_command[] = "ip address show";
	if((ip_pipe = popen(ip_command, "r")) == NULL)
	{
		logg("WARN: Command \"%s\" failed!", ip_command);
		logg("      Message: %s", strerror(errno));
		dbclose();
		return false;
	}

	// Buffers
	char *linebuffer = NULL;
	size_t linebuffersize = 0u;
	int iface_no, rc;
	bool has_iface = false, has_hwaddr = false;
	char ipaddr[128], hwaddr[128], iface[128];

	// Read response line by line
	while(getline(&linebuffer, &linebuffersize, ip_pipe) != -1)
	{
		// Skip if line buffer is invalid
		if(linebuffer == NULL)
			continue;

		if(sscanf(linebuffer, "%i: %99[^:]", &iface_no, iface) == 2)
		{
			// Obtained an interface, continue to the next line
			has_iface = true;
			has_hwaddr = false;
			iface[sizeof(iface)-1] = '\0';
			continue;
		}

		// Do not try to read IP addresses when the information above is incomplete
		if(!has_iface)
			continue;

		// Try to read hardware address
		// We skip lines with "link/none" (virtual, e.g., wireguard interfaces)
		if(sscanf(linebuffer, "    link/ether %99s", hwaddr) == 1)
		{
			// Obtained an Ethernet hardware address, continue to the next line
			has_hwaddr = true;
			hwaddr[sizeof(hwaddr)-1] = '\0';
			continue;
		}
		else if(sscanf(linebuffer, "    link/loopback %99s", hwaddr) == 1)
		{
			// Obtained a loopback hardware address, continue to the next line
			has_hwaddr = true;
			hwaddr[sizeof(hwaddr)-1] = '\0';
			continue;
		}

		// Do not try to read IP addresses when the information above is incomplete
		if(!has_hwaddr)
			continue;

		// Try to read IPv4 address
		// We need a special rule here to avoid "inet6 ..." being accepted as IPv4 address
		if(sscanf(linebuffer, "    inet%*[ ]%[0-9.] brd", ipaddr) == 1)
		{
			// Obtained an IPv4 address
			ipaddr[sizeof(ipaddr)-1] = '\0';
		}
		else
		{
			// Try to read IPv6 address
			if(sscanf(linebuffer, "    inet6%*[ ]%[0-9a-fA-F:] scope", ipaddr) == 1)
			{
				// Obtained an IPv6 address
				ipaddr[sizeof(ipaddr)-1] = '\0';
			}
			else
			{
				// No address data, continue to next line
				continue;
			}
		}

		if(config.debug & DEBUG_ARP)
		{
			logg("Network table: read interface details for interface %s (%s) with address %s",
			     iface, hwaddr, ipaddr);
		}

		// Try to find the device we parsed above
		int dbID = find_device_by_hwaddr(hwaddr);
		if(config.debug & DEBUG_ARP && dbID >= 0)
		{
			logg("Network table (ip a): Client with MAC %s was recently be seen for network ID %i",
			     hwaddr, dbID);
		}

		// Break on SQLite error
		if(dbID == DB_FAILED)
		{
			// SQLite error
			break;
		}

		// Get vendor
		char *macVendor = NULL;
		// Special rule to catch and handle the loopback interface correctly
		if(strcasecmp(hwaddr, "00:00:00:00:00:00") == 0)
			macVendor = strdup("virtual interface");
		else
			macVendor = getMACVendor(hwaddr);

		// Device not in database, add new entry
		if(dbID == DB_NODATA)
		{

			if(config.debug & DEBUG_ARP)
			{
				logg("Network table: Creating new ip a device MAC = %s, IP = %s, vendor = \"%s\", interface = \"%s\"",
					hwaddr, ipaddr, macVendor, iface);
			}


			// Try to import query data from a possibly previously existing mock-device
			int mockID = find_device_by_mock_hwaddr(ipaddr);
			int lastQuery = 0, firstSeen = now, numQueries = 0;
			if(mockID >= 0)
			{
				char *querystr = NULL;
				if(asprintf(&querystr, "SELECT lastQuery from network where id = %i", mockID) < 10)
					return false;
				lastQuery = db_query_int(querystr);
				free(querystr);

				if(asprintf(&querystr, "SELECT firstSeen from network where id = %i", mockID) < 10)
					return false;
				firstSeen = db_query_int(querystr);
				free(querystr);

				if(asprintf(&querystr, "SELECT numQueries from network where id = %i", mockID) < 10)
					return false;
				numQueries = db_query_int(querystr);
				free(querystr);
			}

			// Add new device to database
			insert_netDB_device(hwaddr, firstSeen, lastQuery, numQueries, macVendor);

			// Obtain ID which was given to this new entry
			dbID = get_lastID();
		}
		else	// Device already in database
		{
			if(config.debug & DEBUG_ARP)
			{
				logg("Network table: Updating existing ip a device MAC = %s, IP = %s, interface = \"%s\"",
				     hwaddr, ipaddr, iface);
			}
		}

		//Free allocated memory
		if(macVendor != NULL)
		{
			free(macVendor);
			macVendor = NULL;
		}

		// Add unique IP address / mock-MAC pair to network_addresses table
		rc = add_netDB_network_address(dbID, ipaddr);
		if(rc != SQLITE_OK)
			break;

		// Update interface if available
		rc = update_netDB_interface(dbID, iface);
		if(rc != SQLITE_OK)
			break;

		// Add to number of processed ARP cache entries
		(*additional_entries)++;
	}

	// Close pipe handle and free allocated memory
	pclose(ip_pipe);
	if(linebuffer != NULL)
		free(linebuffer);

	return true;
}

// Parse kernel's neighbor cache
void parse_neighbor_cache(void)
{
	// Open database file
	if(!FTL_DB_avail())
	{
		logg("parse_neighbor_cache() - Database is not available");
		return;
	}

	// Try to access the kernel's neighbor cache
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
	char ip[128], hwaddr[128], iface[128];
	unsigned int entries = 0u, additional_entries = 0u;
	time_t now = time(NULL);

	const char sql[] = "BEGIN TRANSACTION IMMEDIATE";
	int rc = dbquery(sql);
	if( rc != SQLITE_OK )
	{
		const char *text;
		if( rc == SQLITE_BUSY )
			text = "WARNING";
		else
		{
			text = "ERROR";
			dbclose();
		}

		// dbquery() above already logs the reson for why the query failed
		logg("%s: Storing devices in network table (\"%s\") failed", text, sql);
		return;
	}

	// Remove all but the most recent IP addresses not seen for more than a certain time
	if(config.network_expire > 0u)
	{
		const time_t limit = time(NULL)-24*3600*config.network_expire;
		dbquery("DELETE FROM network_addresses "
		               "WHERE lastSeen < %u;", limit);
		dbquery("UPDATE network_addresses SET name = NULL "
		               "WHERE nameUpdated < %u;", limit);
	}

	// Start collecting database commands
	lock_shm();

	// Initialize array of status for individual clients used to
	// remember the status of a client already seen in the neigh cache
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

		// Ensure strings are null-terminated in case we hit the max.
		// length limitation
		ip[sizeof(ip)-1] = '\0';
		iface[sizeof(iface)-1] = '\0';
		hwaddr[sizeof(hwaddr)-1] = '\0';

		// Check if we want to process the line we just read
		if(num != 3)
		{
			if(num == 2)
			{
				// This line is incomplete, remember this to skip
				// mock-device creation after ARP processing
				int clientID = findClientID(ip, false, false);
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
		int dbID = find_device_by_hwaddr(hwaddr);

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
		int clientID = findClientID(ip, false, false);

		// Get hostname of this client if the client is known
		const char *hostname = "";
		// Get client pointer
		clientsData *client = NULL;

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

			char *macVendor = getMACVendor(hwaddr);
			if(dbID == DB_NODATA)
			{
				// Device not known AND no recent mock-device found ---> create new device record
				if(config.debug & DEBUG_ARP)
				{
					logg("Network table: Creating new ARP device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\"",
					     hwaddr, ip, hostname, macVendor);
				}

				// Create new record (INSERT)
				insert_netDB_device(hwaddr, now, client != NULL ? client->lastQuery : 0L,
				                    client != NULL ? client->numQueriesARP : 0u, macVendor);

				// Reset client ARP counter (we stored the entry in the database)
				if(client != NULL)
					client->numQueriesARP = 0;

				// Obtain ID which was given to this new entry
				dbID = get_lastID();

				// Try to determine host names if this is a new device we don't know a hostname for...
				unlock_shm();
				if(strlen(hostname) == 0)
					hostname = resolveHostname(ip);
				lock_shm();
				// ... and store it in the appropriate network_address record
				rc = update_netDB_name(ip, hostname);
				if(rc != SQLITE_OK)
					break;
			}
			else
			{
				// Device is ALREADY KNOWN ---> convert mock-device to a "real" one
				if(config.debug & DEBUG_ARP)
				{
					logg("Network table: Un-mocking ARP device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\"",
					     hwaddr, ip, hostname, macVendor);
				}

				// Update/replace important device properties
				unmock_netDB_device(hwaddr, macVendor, dbID);

				// Host name, count and last query timestamp will be set in the next
				// loop interation for the sake of simplicity
			}

			// Free allocated mememory
			free(macVendor);
		}
		// Device in database AND client known to Pi-hole
		else if(client != NULL)
		{
			if(config.debug & DEBUG_ARP)
			{
				logg("Network table: Updating existing ARP device MAC = %s, IP = %s, hostname = \"%s\"",
				     hwaddr, ip, hostname);
			}

			// Update timestamp of last query if applicable
			rc = update_netDB_lastQuery(dbID, client);
			if(rc != SQLITE_OK)
				break;

			// Update number of queries if applicable
			rc = update_netDB_numQueries(dbID, client);
			if(rc != SQLITE_OK)
				break;

			// Update hostname if available
			rc = update_netDB_name(ip, hostname);
			if(rc != SQLITE_OK)
				break;
		}
		// else: Device in database but not known to Pi-hole

		// Store interface if available
		rc = update_netDB_interface(dbID, iface);
		if(rc != SQLITE_OK)
			break;

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

	// Loop over all clients known to FTL and ensure we add them all to the
	// database
	if(!add_FTL_clients_to_network_table(client_status, now, &additional_entries))
		return;

	// Finally, loop over the available interfaces to ensure we list the
	// IP addresses correctly (local addresses are NOT contained in the
	// ARP/neighor cache).
	if(!add_local_interfaces_to_network_table(now, &additional_entries))
		return;

	// Ensure mock-devices which are not assigned to any addresses any more
	// (they have been converted to "real" devices), are removed at this point
	dbquery("DELETE FROM network WHERE id NOT IN "
	                                  "(SELECT network_id from network_addresses) "
	                              "AND hwaddr LIKE 'ip-%%';");

	// Actually update the database
	if((rc = dbquery("END TRANSACTION")) != SQLITE_OK) {
		const char *text;
		if( rc == SQLITE_BUSY )
			text = "WARNING";
		else
		{
			text = "ERROR";
			dbclose();
		}

		logg("%s: Storing devices in network table failed: %s", text, sqlite3_errstr(rc));
		unlock_shm();

		// Return okay if the database is busy
		return;
	}

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
	const char querystr[] = "SELECT id,hwaddr,COUNT(*) cnt "
	                        "FROM network "
	                        "GROUP BY hwaddr "
	                        "HAVING MAX(lastQuery) "
	                        "AND cnt > 1;";

	// Perform SQL query
	sqlite3_stmt *stmt = NULL;
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
		        "SET firstSeen = (SELECT MIN(firstSeen) FROM network WHERE hwaddr = \'%s\' COLLATE NOCASE) "\
		        "WHERE id = %i;",\
		        hwaddr, id);

		// Update numQueries with sum of all rows with the same hwaddr
		dbquery("UPDATE network "\
		        "SET numQueries = (SELECT SUM(numQueries) FROM network WHERE hwaddr = \'%s\' COLLATE NOCASE) "\
		        "WHERE id = %i;",\
		        hwaddr, id);

		// Remove all other lines with the same hwaddr but a different id
		dbquery("DELETE FROM network "\
		        "WHERE hwaddr = \'%s\' COLLATE NOCASE "\
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

static char *getMACVendor(const char *hwaddr)
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

	// Only keep "XX:YY:ZZ" (8 characters)
	char hwaddrshort[9];
	strncpy(hwaddrshort, hwaddr, 8);
	hwaddrshort[8] = '\0';
	const char querystr[] = "SELECT vendor FROM macvendor WHERE mac LIKE ?;";

	sqlite3_stmt *stmt = NULL;
	rc = sqlite3_prepare_v2(macvendor_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getMACVendor(\"%s\") - SQL error prepare \"%s\": %s", hwaddr, querystr, sqlite3_errstr(rc));
		sqlite3_close(macvendor_db);
		return strdup("");
	}

	// Bind hwaddrshort to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, hwaddrshort, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("getMACVendor(\"%s\" -> \"%s\"): Failed to bind hwaddrshort: %s",
		     hwaddr, hwaddrshort, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		sqlite3_close(macvendor_db);
		return strdup("");
	}

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

	if(config.debug & DEBUG_DATABASE)
		logg("DEBUG: MAC Vendor lookup for %s returned \"%s\"", hwaddr, vendor);

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

	if(!FTL_DB_avail())
	{
		logg("updateMACVendorRecords() - Database not available");
		return;
	}

	sqlite3_stmt *stmt = NULL;
	const char *selectstr = "SELECT id,hwaddr FROM network;";
	int rc = sqlite3_prepare_v2(FTL_db, selectstr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("updateMACVendorRecords() - SQL error prepare \"%s\": %s", selectstr, sqlite3_errstr(rc));
		return;
	}

	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const int id = sqlite3_column_int(stmt, 0);
		char *hwaddr = strdup((char*)sqlite3_column_text(stmt, 1));

		// Get vendor for MAC
		char *vendor = getMACVendor(hwaddr);
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
}

// Get hardware address of device identified by IP address
char *__attribute__((malloc)) getMACfromIP(const char *ipaddr)
{
	if(!FTL_DB_avail())
	{
		logg("getMACfromIP(\"%s\") - Database not available", ipaddr);
		return NULL;
	}

	// Prepare SQLite statement
	// We request the most recent IP entry in case there an IP appears
	// multiple times in the network_addresses table
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT hwaddr FROM network WHERE id = "
	                       "(SELECT network_id FROM network_addresses "
	                       "WHERE ip = ? GROUP BY ip HAVING max(lastSeen));";
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getMACfromIP(\"%s\") - SQL error prepare: %s",
		     ipaddr, sqlite3_errstr(rc));
		return NULL;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("getMACfromIP(\"%s\"): Failed to bind ip: %s",
		     ipaddr, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return NULL;
	}

	char *hwaddr = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		hwaddr = strdup((char*)sqlite3_column_text(stmt, 0));
	}
	else
	{
		// Not found or error (will be logged automatically through our SQLite3 hook)
		hwaddr = NULL;
	}

	if(config.debug & DEBUG_DATABASE && hwaddr != NULL)
		logg("Found database hardware address %s -> %s", ipaddr, hwaddr);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return hwaddr;
}

// Get aliasclient ID of device identified by IP address (if available)
int getAliasclientIDfromIP(const char *ipaddr)
{
	// Open pihole-FTL.db database file if needed
	const bool db_already_open = FTL_DB_avail();
	if(!db_already_open && !dbopen())
	{
		logg("getAliasclientIDfromIP(\"%s\") - Failed to open DB", ipaddr);
		return -1;
	}

	// Prepare SQLite statement
	// We request the most recent IP entry in case there an IP appears
	// multiple times in the network_addresses table
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT aliasclient_id FROM network WHERE id = "
	                       "(SELECT network_id FROM network_addresses "
	                       "WHERE ip = ? "
	                             "AND aliasclient_id IS NOT NULL "
	                       "GROUP BY ip HAVING max(lastSeen));";
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getAliasclientIDfromIP(\"%s\") - SQL error prepare: %s",
		     ipaddr, sqlite3_errstr(rc));
		if(!db_already_open)
			dbclose();
		return -1;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("getAliasclientIDfromIP(\"%s\"): Failed to bind ip: %s",
		     ipaddr, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		if(!db_already_open)
			dbclose();
		return -1;
	}

	int aliasclient_id = -1;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found
		aliasclient_id = sqlite3_column_int(stmt, 0);
	}

	if(config.debug & DEBUG_ALIASCLIENTS)
		logg("   Aliasclient ID %s -> %i%s", ipaddr, aliasclient_id,
		     (aliasclient_id == -1) ? " (NOT FOUND)" : "");

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);
	if(!db_already_open)
		dbclose();

	return aliasclient_id;
}

// Get host name of device identified by IP address
char *__attribute__((malloc)) getNameFromIP(const char *ipaddr)
{
	if(!FTL_DB_avail())
	{
		logg("getNameFromIP(\"%s\") - Database not available", ipaddr);
		return NULL;
	}

	// Check if we want to resolve host names
	if(!resolve_this_name(ipaddr))
	{
		if(config.debug & DEBUG_DATABASE)
			logg("getNameFromIP(\"%s\") - configured to not resolve host name", ipaddr);
		
		return NULL;
	}

	// Check for a host name associated with the same IP address
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT name FROM network_addresses WHERE name IS NOT NULL AND ip = ?;";
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getNameFromIP(\"%s\") - SQL error prepare: %s",
		     ipaddr, sqlite3_errstr(rc));
		return NULL;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("getNameFromIP(\"%s\"): Failed to bind ip: %s",
		     ipaddr, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return NULL;
	}

	char *name = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		name = strdup((char*)sqlite3_column_text(stmt, 0));

		if(config.debug & DEBUG_DATABASE)
			logg("Found database host name (same address) %s -> %s", ipaddr, name);
	}
	else
	{
		// Not found or error (will be logged automatically through our SQLite3 hook)
	}

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Return here if we found the name
	if(name != NULL)
		return name;

	// Nothing found for the exact IP address
	// Check for a host name associated with the same device (but another IP address)
	querystr = "SELECT name FROM network_addresses "
	                       "WHERE name IS NOT NULL AND "
	                             "network_id = (SELECT network_id FROM network_addresses "
	                                                             "WHERE ip = ?) "
	                       "ORDER BY lastSeen DESC LIMIT 1";
	rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getNameFromIP(\"%s\") - SQL error prepare: %s",
		ipaddr, sqlite3_errstr(rc));
		return NULL;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("getNameFromIP(\"%s\"): Failed to bind ip: %s",
		ipaddr, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return NULL;
	}

	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		name = strdup((char*)sqlite3_column_text(stmt, 0));

		if(config.debug & (DEBUG_DATABASE | DEBUG_RESOLVER))
			logg("Found database host name (same device) %s -> %s", ipaddr, name);
	}
	else
	{
		// Not found or error (will be logged automatically through our SQLite3 hook)
		name = NULL;

		if(config.debug & (DEBUG_DATABASE | DEBUG_RESOLVER))
			logg(" ---> not found");
	}
	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return name;
}

// Get interface of device identified by IP address
char *__attribute__((malloc)) getIfaceFromIP(const char *ipaddr)
{
	if(!FTL_DB_avail())
	{
		logg("getIfaceFromIP(\"%s\") - Database not available", ipaddr);
		return NULL;
	}

	// Prepare SQLite statement
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT interface FROM network "
	                               "JOIN network_addresses "
	                                    "ON network_addresses.network_id = network.id "
	                               "WHERE network_addresses.ip = ? AND "
	                                     "interface != 'N/A' AND "
	                                     "interface IS NOT NULL;";
	int rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		logg("getIfaceFromIP(\"%s\") - SQL error prepare: %s",
		     ipaddr, sqlite3_errstr(rc));
		return NULL;
	}

	if(config.debug & (DEBUG_DATABASE | DEBUG_RESOLVER))
	{
		logg("getDatabaseHostname(): \"%s\" with ? = \"%s\"",
		     querystr, ipaddr);
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("getIfaceFromIP(\"%s\"): Failed to bind ip: %s",
		     ipaddr, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return NULL;
	}

	char *iface = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		iface = strdup((char*)sqlite3_column_text(stmt, 0));
	}
	else
	{
		// Not found or error (will be logged automatically through our SQLite3 hook)
		iface = NULL;
	}

	if(config.debug & DEBUG_DATABASE && iface != NULL)
		logg("Found database interface %s -> %s", ipaddr, iface);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return iface;
}

// Resolve unknown names of recently seen IP addresses in network table
void resolveNetworkTableNames(void)
{
	if(!FTL_DB_avail())
	{
		logg("resolveNetworkTableNames() - Database not available");
		return;
	}

	// Check if we want to resolve host names
	if(!resolve_names())
	{
		if(config.debug & DEBUG_DATABASE)
			logg("resolveNetworkTableNames() - configured to not resolve host names");
		return;
	}

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
		}

		// dbquery() above already logs the reson for why the query failed
		logg("%s: Trying to resolve unknown network table host names (\"%s\") failed", text, sql);

		return;
	}

	// Get IP addresses seen within the last 24 hours with empty or NULL host names
	const char querystr[] = "SELECT ip FROM network_addresses "
	                               "WHERE lastSeen > cast(strftime('%%s', 'now') as int)-86400;";

	// Prepare query
	sqlite3_stmt *table_stmt = NULL;
	rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("resolveNetworkTableNames() - SQL error prepare: %s",
		     sqlite3_errstr(rc));
		sqlite3_finalize(table_stmt);
		return;
	}

	// Get data
	while((rc = sqlite3_step(table_stmt)) == SQLITE_ROW)
	{
		// Get IP address from database
		const char *ip = (const char*)sqlite3_column_text(table_stmt, 0);

		if(config.debug & DEBUG_DATABASE)
			logg("Resolving database IP %s", ip);

		// Try to obtain host name
		char *newname = resolveHostname(ip);

		if(config.debug & DEBUG_DATABASE)
			logg("---> \"%s\"", newname);

		// Store new host name in database if not empty
		if(newname != NULL && strlen(newname) > 0)
		{
			const char updatestr[] = "UPDATE network_addresses "
			                                "SET name = ?1,"
			                                    "nameUpdated = cast(strftime('%s', 'now') as int) "
			                                "WHERE ip = ?2;";
			sqlite3_stmt *update_stmt = NULL;
			int rc2 = sqlite3_prepare_v2(FTL_db, updatestr, -1, &update_stmt, NULL);
			if(rc2 != SQLITE_OK){
				logg("resolveNetworkTableNames(%s -> \"%s\") - SQL error prepare: %s",
					ip, newname, sqlite3_errstr(rc2));
				sqlite3_finalize(update_stmt);
				break;
			}

			// Bind newname to prepared statement
			if((rc2 = sqlite3_bind_text(update_stmt, 1, newname, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				logg("resolveNetworkTableNames(%s -> \"%s\"): Failed to bind newname: %s",
					ip, newname, sqlite3_errstr(rc2));
				sqlite3_finalize(update_stmt);
				break;
			}

			// Bind ip to prepared statement
			if((rc2 = sqlite3_bind_text(update_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				logg("resolveNetworkTableNames(%s -> \"%s\"): Failed to bind ip: %s",
					ip, newname, sqlite3_errstr(rc2));
				sqlite3_finalize(update_stmt);
				break;
			}

			if(config.debug & DEBUG_DATABASE)
				logg("dbquery: \"%s\" with ?1 = \"%s\" and ?2 = \"%s\"", updatestr, newname, ip);

			rc2 = sqlite3_step(update_stmt);
			if(rc2 != SQLITE_BUSY && rc2 != SQLITE_DONE)
			{
				// Any return code that is neither SQLITE_BUSY not SQLITE_ROW
				// is a real error we should log
				logg("resolveNetworkTableNames(%s -> \"%s\"): Failed to perform step: %s",
				     ip, newname, sqlite3_errstr(rc2));
				sqlite3_finalize(update_stmt);
				break;
			}

			// Finalize host name update statement
			sqlite3_finalize(update_stmt);
		}
		free(newname);
	}

	// Possible error handling and reporting
	if(rc != SQLITE_DONE)
	{
		logg("resolveNetworkTableNames() - SQL error step: %s",
		     sqlite3_errstr(rc));
		sqlite3_finalize(table_stmt);
		return;
	}

	// Close and unlock database connection
	sqlite3_finalize(table_stmt);

	dbquery("COMMIT");
}
