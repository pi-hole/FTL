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
#include "log.h"
// timer_elapsed_msec()
#include "timers.h"
#include "config/config.h"
#include "datastructure.h"
// struct config
#include "config/config.h"
// resolve_this_name()
#include "resolve.h"
// killed
#include "signals.h"
// nlneigh(), nllinks()
#include "tools/netlink.h"
// DHCPLEASESFILE
#include "config/dnsmasq_config.h"

#define MAXVENDORLEN 128
static bool getMACVendor(const char *hwaddr, char vendor[MAXVENDORLEN]);
enum arp_status { CLIENT_NOT_HANDLED, CLIENT_ARP_COMPLETE, CLIENT_ARP_INCOMPLETE } __attribute__ ((packed));

bool create_network_table(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Start transaction
	SQL_bool(db, "BEGIN TRANSACTION");

	// Create network table in the database
	SQL_bool(db, "CREATE TABLE network ( id INTEGER PRIMARY KEY NOT NULL, " \
	                                    "ip TEXT NOT NULL, " \
	                                    "hwaddr TEXT NOT NULL, " \
	                                    "interface TEXT NOT NULL, " \
	                                    "name TEXT, " \
	                                    "firstSeen INTEGER NOT NULL, " \
	                                    "lastQuery INTEGER NOT NULL, " \
	                                    "numQueries INTEGER NOT NULL, " \
	                                    "macVendor TEXT);");

	// Update database version to 3
	if(!db_set_FTL_property(db, DB_VERSION, 3))
	{
		log_warn("create_network_table(): Failed to update database version!");
		return false;
	}

	// End transaction
	SQL_bool(db, "COMMIT");

	return true;
}

bool create_network_addresses_table(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Disable foreign key enforcement for this transaction
	// Otherwise, dropping the network table would not be allowed
	SQL_bool(db, "PRAGMA foreign_keys=OFF");

	// Begin new transaction
	SQL_bool(db, "BEGIN TRANSACTION");

	// Create network_addresses table in the database
	SQL_bool(db, "CREATE TABLE network_addresses ( network_id INTEGER NOT NULL, "\
	                                              "ip TEXT NOT NULL, "\
	                                              "lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%%s', 'now') as int)), "\
	                                              "UNIQUE(network_id,ip), "\
	                                              "FOREIGN KEY(network_id) REFERENCES network(id));");

	// Create a network_addresses row for each entry in the network table
	// Ignore possible duplicates as they are harmless and can be skipped
	SQL_bool(db, "INSERT OR IGNORE INTO network_addresses (network_id,ip) SELECT id,ip FROM network;");

	// Remove IP column from network table.
	// As ALTER TABLE is severely limited, we have to do the column deletion manually.
	// Step 1: We create a new table without the ip column
	SQL_bool(db, "CREATE TABLE network_bck ( id INTEGER PRIMARY KEY NOT NULL, " \
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
	SQL_bool(db, "INSERT INTO network_bck "\
	         "SELECT id, hwaddr, interface, name, firstSeen, "\
	                "lastQuery, numQueries, macVendor "\
	                "FROM network GROUP BY hwaddr HAVING max(lastQuery);");

	// Step 3: Drop the network table, the unique index will be automatically dropped
	SQL_bool(db, "DROP TABLE network;");

	// Step 4: Rename network_bck table to network table as last step
	SQL_bool(db, "ALTER TABLE network_bck RENAME TO network;");

	// Update database version to 5
	if(!db_set_FTL_property(db, DB_VERSION, 5))
	{
		log_warn("create_network_addresses_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "COMMIT");

	// Re-enable foreign key enforcement
	SQL_bool(db, "PRAGMA foreign_keys=ON");

	return true;
}

bool create_network_addresses_with_names_table(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Disable foreign key enforcement for this transaction
	// Otherwise, dropping the network table would not be allowed
	SQL_bool(db, "PRAGMA foreign_keys=OFF");

	// Begin new transaction
	SQL_bool(db, "BEGIN TRANSACTION");

	// Step 1: Create network_addresses table in the database
	SQL_bool(db, "CREATE TABLE network_addresses_bck ( network_id INTEGER NOT NULL, "
	                                                  "ip TEXT UNIQUE NOT NULL, "
	                                                  "lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%%s', 'now') as int)), "
	                                                  "name TEXT, "
	                                                  "nameUpdated INTEGER, "
	                                                  "FOREIGN KEY(network_id) REFERENCES network(id));");

	// Step 2: Copy data from network_addresses into network_addresses_bck
	//         name and nameUpdated are NULL at this point
	SQL_bool(db, "REPLACE INTO network_addresses_bck "
	             "(network_id,ip,lastSeen) "
	             "SELECT network_id,ip,lastSeen "
	                    "FROM network_addresses;");

	// Step 3: Drop the network_addresses table
	SQL_bool(db, "DROP TABLE network_addresses;");

	// Step 4: Drop the network_names table (if exists due to a previous v7 database update)
	SQL_bool(db, "DROP TABLE IF EXISTS network_names;");

	// Step 5: Rename network_addresses_bck table to network_addresses table as last step
	SQL_bool(db, "ALTER TABLE network_addresses_bck RENAME TO network_addresses;");

	// Remove name column from network table.
	// As ALTER TABLE is severely limited, we have to do the column deletion manually.
	// Step 1: We create a new table without the name column
	SQL_bool(db, "CREATE TABLE network_bck ( id INTEGER PRIMARY KEY NOT NULL, " \
	                                        "hwaddr TEXT UNIQUE NOT NULL, " \
	                                        "interface TEXT NOT NULL, " \
	                                        "firstSeen INTEGER NOT NULL, " \
	                                        "lastQuery INTEGER NOT NULL, " \
	                                        "numQueries INTEGER NOT NULL, " \
	                                        "macVendor TEXT);");

	// Step 2: Copy data (except name column) from network into network_back
	SQL_bool(db, "INSERT INTO network_bck "\
	             "SELECT id, hwaddr, interface, firstSeen, "\
	                    "lastQuery, numQueries, macVendor "\
	                    "FROM network;");

	// Step 3: Drop the network table, the unique index will be automatically dropped
	SQL_bool(db, "DROP TABLE network;");

	// Step 4: Rename network_bck table to network table as last step
	SQL_bool(db, "ALTER TABLE network_bck RENAME TO network;");

	// Update database version to 8
	if(!db_set_FTL_property(db, DB_VERSION, 8))
	{
		log_warn("create_network_addresses_with_names_table(): Failed to update database version!");
		return false;
	}

	// Finish transaction
	SQL_bool(db, "COMMIT");

	// Re-enable foreign key enforcement
	SQL_bool(db, "PRAGMA foreign_keys=ON");

	return true;
}

bool create_network_addresses_network_id_index(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Create index on network_id column in network_addresses table
	SQL_bool(db, "CREATE INDEX IF NOT EXISTS network_addresses_network_id_index ON network_addresses (network_id);");

	// Update database version to 20
	if(!db_set_FTL_property(db, DB_VERSION, 20))
	{
		log_warn("create_network_addresses_with_names_table(): Failed to update database version!");
		return false;
	}

	return true;
}

// Try to find device by recent usage of this IP address
static int find_device_by_recent_ip(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return -1;

	const char *querystr = "SELECT network_id FROM network_addresses "
	                       "WHERE ip = ?1 AND "
	                       "lastSeen > (cast(strftime('%%s', 'now') as int)-86400) "
	                       "ORDER BY lastSeen DESC LIMIT 1;";

	// Perform SQL query
	int network_id = db_query_int_str(db, querystr, ipaddr);

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

	log_debug(DEBUG_ARP, "APR: Identified device %s using most recently used IP address", ipaddr);

	// Found network_id
	return network_id;
}

// Try to find device by mock hardware address (generated from IP address)
static int find_device_by_mock_hwaddr(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	const char *querystr = "SELECT id FROM network WHERE hwaddr = concat('ip-',?1)";

	// Perform SQL query
	return db_query_int_str(db, querystr, ipaddr);
}

// Try to find device by hardware address
static int find_device_by_hwaddr(sqlite3 *db, const char hwaddr[])
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	log_debug(DEBUG_ARP, "find_device_by_hwaddr(%s)", hwaddr);

	const char *querystr = "SELECT id FROM network WHERE hwaddr = ?1 COLLATE NOCASE;";

	// Perform SQL query
	return db_query_int_str(db, querystr, hwaddr);
}

// Try to find device by RECENT mock hardware address (generated from IP address)
static int find_recent_device_by_mock_hwaddr(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	log_debug(DEBUG_ARP, "find_recent_device_by_mock_hwaddr(%s)", ipaddr);

	const char *querystr = "SELECT id FROM network WHERE "
	                       "hwaddr = concat('ip-',?1) AND "
	                       "firstSeen > (cast(strftime('%%s', 'now') as int)-3600)";

	// Perform SQL query
	return db_query_int_str(db, querystr, ipaddr);
}

/**
 * @brief Updates the name associated with a given IP address in the network database.
 *
 * @param db A pointer to the SQLite database connection.
 * @param ip The IP address whose associated name is to be updated.
 * @param name The new name to associate with the given IP address.
 * @return true if the operation was successful, false otherwise.
 */
static bool update_netDB_name(sqlite3 *db, const char *ip, const char *name)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Skip if hostname is NULL or an empty string (= no result)
	if(name == NULL || strlen(name) < 1)
		return true;

	log_debug(DEBUG_ARP, "update_netDB_name(%s, \"%s\")", ip, name);

	bool success = false;
	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network_addresses SET name = ?1, "
	                               "nameUpdated = (cast(strftime('%s', 'now') as int)) "
	                               "WHERE ip = ?2";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("update_netDB_name(%s, \"%s\") - SQL error prepare (%i): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		goto update_netDB_name_end;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments 1 = \"%s\" and 2 = \"%s\"",
	          querystr, name, ip);


	// Bind name to prepared statement (1st argument)
	// We can do this as name has dynamic scope that exceeds that of the binding.
	if((rc = sqlite3_bind_text(query_stmt, 1, name, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("update_netDB_name(%s, \"%s\"): Failed to bind ip (error %d): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		goto update_netDB_name_end;
	}
	// Bind ip (unique key) to prepared statement (2nd argument)
	// We can do this as name has dynamic scope that exceeds that of the binding.
	if((rc = sqlite3_bind_text(query_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("update_netDB_name(%s, \"%s\"): Failed to bind name (error %d): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		goto update_netDB_name_end;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("update_netDB_name(%s, \"%s\"): Failed to step (error %d): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		goto update_netDB_name_end;
	}

	success = true;

update_netDB_name_end:
	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement
	sqlite3_reset(query_stmt);
	sqlite3_finalize(query_stmt);

	return success;
}

/**
 * @brief Updates the last query time for a specific network in the database.
 *
 * This function updates the `lastQuery` field for a network identified by `network_id`
 * in the database. It ensures that the `lastQuery` field is set to the maximum of its
 * current value and the provided `lastQuery` value.
 *
 * @param db Pointer to the SQLite database connection.
 * @param network_id The ID of the network to update.
 * @param lastQuery The new last query time to set.
 * @return true if the operation was successful, false otherwise.
 */
static bool update_netDB_lastQuery(sqlite3 *db, const int network_id, const time_t lastQuery)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Check for invalid network ID
	if(network_id < 0)
		return false;

	// Return early if there is nothing to update
	if(lastQuery < 1)
		return true;

	log_debug(DEBUG_ARP, "update_netDB_lastQuery(%i, %lu)", network_id, (unsigned long)lastQuery);

	const int ret = dbquery(db, "UPDATE network "\
	                            "SET lastQuery = MAX(lastQuery, %lu) "\
	                            "WHERE id = %i;",
	                            (unsigned long)lastQuery, network_id);

	return ret == SQLITE_OK;
}

/**
 * @brief Updates the number of queries for a specific network entry in the database.
 *
 * @param db Pointer to the SQLite database connection.
 * @param dbID The ID of the network entry to update.
 * @param numQueries The number of queries to add to the current count.
 * @return true if the operation was successful, false otherwise.
 */
static bool update_netDB_numQueries(sqlite3 *db, const int dbID, const int numQueries)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Return early if there is nothing to update
	if(numQueries < 1)
		return true;

	log_debug(DEBUG_ARP, "update_netDB_numQueries(%i, %i)", dbID, numQueries);

	const int ret = dbquery(db, "UPDATE network "
	                            "SET numQueries = numQueries + %i "
	                            "WHERE id = %i;",
	                            numQueries, dbID);

	return ret == SQLITE_OK;
}

/**
 * @brief Adds or updates a network address in the database.
 *
 * @param db Pointer to the SQLite database connection.
 * @param network_id The ID of the network to which the IP address belongs.
 * @param ip The IP address to be added or updated in the database.
 * @return true if the operation was successful or if there was nothing to be done, false otherwise.
 */
static bool add_netDB_network_address(sqlite3 *db, const int network_id, const char *ip)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Check for invalid network ID
	if(network_id < 0)
		return false;

	// Return early if there is nothing to be done in here
	if(ip == NULL || strlen(ip) == 0)
		return true;

	log_debug(DEBUG_ARP, "add_netDB_network_address(%i, \"%s\")", network_id, ip);

	bool success = false;
	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "INSERT OR REPLACE INTO network_addresses "
	                        "(network_id,ip,lastSeen,name,nameUpdated) VALUES "
	                        "(?1,?2,(cast(strftime('%s', 'now') as int)),"
	                        "(SELECT name FROM network_addresses "
	                                "WHERE ip = ?2),"
	                        "(SELECT nameUpdated FROM network_addresses "
	                                "WHERE ip = ?2));";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("add_netDB_network_address(%i, \"%s\") - SQL error prepare (%i): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		goto add_netDB_network_address_end;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1 = %i and ?2 = \"%s\"",
		     querystr, network_id, ip);

	// Bind network_id to prepared statement (1st argument)
	if((rc = sqlite3_bind_int(query_stmt, 1, network_id)) != SQLITE_OK)
	{
		log_err("add_netDB_network_address(%i, \"%s\"): Failed to bind network_id (error %d): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		goto add_netDB_network_address_end;
	}
	// Bind ip to prepared statement (2nd argument)
	if((rc = sqlite3_bind_text(query_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_netDB_network_address(%i, \"%s\"): Failed to bind name (error %d): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		goto add_netDB_network_address_end;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("add_netDB_network_address(%i, \"%s\"): Failed to step (error %d): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		goto add_netDB_network_address_end;
	}

	success = true;

add_netDB_network_address_end:
	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement
	sqlite3_reset(query_stmt);
	sqlite3_finalize(query_stmt);

	return success;
}

/**
 * @brief Inserts a network device record into the database.
 *
 * @param db Pointer to the SQLite database connection.
 * @param hwaddr Hardware address (MAC address) of the network device.
 * @param firstSeen Timestamp of when the device was first seen.
 * @param lastQuery Timestamp of the last query made to the device.
 * @param numQueriesARP Number of ARP queries made to the device.
 * @param macVendor Vendor of the MAC address.
 * @param new_id Pointer to store the new ID of the inserted device.
 * @return true if the insertion was successful, false otherwise.
 */
static bool insert_netDB_device(sqlite3 *db, const char *hwaddr, const time_t firstSeen, const time_t lastQuery,
                               const unsigned int numQueriesARP, const char *macVendor, int *new_id)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	log_debug(DEBUG_ARP, "insert_netDB_device(\"%s\", %lu, %lu, %u, \"%s\")",
		      hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor);

	bool success = false;
	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "INSERT INTO network "\
	                        "(hwaddr,interface,firstSeen,lastQuery,numQueries,macVendor) "\
	                        "VALUES (?1,\'N/A\',?2,?3,?4,?5);";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\", %lu, %lu, %u, \"%s\") - SQL error prepare (%i): %s",
		        hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		goto insert_netDB_device_end;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1-?5 = (\"%s\", %lu, %lu, %u, \"%s\")",
		      querystr, hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor);

	// Bind hwaddr to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\", %lu, %lu, %u, \"%s\"): Failed to bind hwaddr (error %d): %s",
		        hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		goto insert_netDB_device_end;
	}

	// Bind firstSeen to prepared statement (2nd argument)
	if((rc = sqlite3_bind_int(query_stmt, 2, firstSeen)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind firstSeen (error %d): %s",
		        hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		goto insert_netDB_device_end;
	}

	// Bind lastQuery to prepared statement (3rd argument)
	if((rc = sqlite3_bind_int(query_stmt, 3, lastQuery)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind lastQuery (error %d): %s",
		        hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		goto insert_netDB_device_end;
	}

	// Bind numQueriesARP to prepared statement (4th argument)
	if((rc = sqlite3_bind_int(query_stmt, 4, numQueriesARP)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind numQueriesARP (error %d): %s",
		        hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		goto insert_netDB_device_end;
	}

	// Bind macVendor to prepared statement (5th argument) - the macVendor can be NULL here
	if((rc = sqlite3_bind_text(query_stmt, 5, macVendor, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind macVendor (error %d): %s",
		        hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		goto insert_netDB_device_end;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to step (error %d): %s",
		        hwaddr, (unsigned long)firstSeen, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		goto insert_netDB_device_end;
	}

	// Get the ID of the newly inserted row
	*new_id = sqlite3_last_insert_rowid(db);

	success = true;

insert_netDB_device_end:
	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement
	sqlite3_reset(query_stmt);
	sqlite3_finalize(query_stmt);

	return success;
}

/**
 * @brief Updates the network table in the database with the provided hardware address and MAC vendor.
 *
 * @param db A pointer to the SQLite database.
 * @param hwaddr The hardware address to update in the network table.
 * @param macVendor The MAC vendor to update in the network table. This can be NULL.
 * @param dbID The database ID of the entry to update.
 * @return true if the update is successful, false otherwise.
 */
static bool unmock_netDB_device(sqlite3 *db, const char *hwaddr, const char *macVendor, const int dbID)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Check for invalid network ID
	if(dbID < 0)
		return false;

	log_debug(DEBUG_ARP, "unmock_netDB_device(\"%s\", \"%s\", %i)", hwaddr, macVendor, dbID);

	bool success = false;
	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network SET "\
	                        "hwaddr = ?1, macVendor=?2 WHERE id = ?3;";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i) - SQL error prepare (%i): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		goto unmock_netDB_device_end;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1 = \"%s\", ?2 = \"%s\", ?3 = %i",
		     querystr, hwaddr, macVendor, dbID);

	// Bind hwaddr to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind hwaddr (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		goto unmock_netDB_device_end;
	}

	// Bind macVendor to prepared statement (2nd argument) - the macVendor can be NULL here
	if((rc = sqlite3_bind_text(query_stmt, 2, macVendor, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind macVendor (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		goto unmock_netDB_device_end;
	}

	// Bind now to prepared statement (3rd argument)
	if((rc = sqlite3_bind_int(query_stmt, 3, dbID)) != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind now (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		goto unmock_netDB_device_end;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to step (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		goto unmock_netDB_device_end;
	}

	success = true;

unmock_netDB_device_end:
	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement
	sqlite3_reset(query_stmt);
	sqlite3_finalize(query_stmt);

	return success;
}

/**
 * @brief Updates the network interface in the database for a given network ID.
 *
 * @param db Pointer to the SQLite database connection.
 * @param network_id The ID of the network to update.
 * @param iface The new interface value to set.
 * @return true if the update was successful, false otherwise.
 */
static bool update_netDB_interface(sqlite3 *db, const int network_id, const char *iface)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Check for invalid network ID
	if(network_id < 0)
		return false;

	// Return early if there is nothing to be done in here
	if(iface == NULL || strlen(iface) == 0)
		return true;

	log_debug(DEBUG_ARP, "update_netDB_interface(%i, \"%s\")", network_id, iface);

	bool success = false;
	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network SET interface = ?1 WHERE id = ?2";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("update_netDB_interface(%i, \"%s\") - SQL error prepare (%i): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		goto update_netDB_interface_end;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1 = \"%s\" and ?2 = %i",
		     querystr, iface, network_id);

	// Bind iface to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, iface, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("update_netDB_interface(%i, \"%s\"): Failed to bind iface (error %d): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		goto update_netDB_interface_end;
	}
	// Bind network_id to prepared statement (2nd argument)
	if((rc = sqlite3_bind_int(query_stmt, 2, network_id)) != SQLITE_OK)
	{
		log_err("update_netDB_interface(%i, \"%s\"): Failed to bind name (error %d): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		goto update_netDB_interface_end;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("update_netDB_interface(%i, \"%s\"): Failed to step (error %d): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		goto update_netDB_interface_end;
	}

	success = true;

update_netDB_interface_end:
	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement
	sqlite3_reset(query_stmt);
	sqlite3_finalize(query_stmt);

	return true;
}

// Loop over all clients known to FTL and ensure we add them all to the database
static bool add_FTL_clients_to_network_table(sqlite3 *db, const enum arp_status *client_status,
                                             const unsigned int clients, const time_t now, unsigned int *additional_entries)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	log_debug(DEBUG_ARP, "Network table: Adding up to %u FTL clients to network table", clients);

	int rc = SQLITE_OK;
	char hwaddr[128];
	for(unsigned int clientID = 0; clientID < clients; clientID++)
	{
		// Check thread cancellation
		if(killed)
			break;

		// Get client pointer
		lock_shm();
		clientsData *client = getClient(clientID, true);
		if(client == NULL)
		{
			log_debug(DEBUG_ARP, "Network table: Client %u returned NULL pointer", clientID);
			unlock_shm();
			continue;
		}

		// Silently skip alias-clients - they do not really exist
		if(client->flags.aliasclient)
		{
			unlock_shm();
			continue;
		}

		// Get hostname and IP address of this client
		char hostname[MAXHOSTNAMELEN], ipaddr[INET6_ADDRSTRLEN], interface[MAXIFACESTRLEN];
		strncpy(ipaddr, getstr(client->ippos), sizeof(ipaddr));
		strncpy(hostname, getstr(client->namepos), sizeof(hostname));
		strncpy(interface, getstr(client->ifacepos), sizeof(interface));

		// Skip if already handled above (first check against clients_array_size as we might have added
		// more clients to FTL's memory herein (those known only from the database))
		if(client_status[clientID] != CLIENT_NOT_HANDLED)
		{
			log_debug(DEBUG_ARP, "Network table: Client %s known through ARP/neigh cache",
			          ipaddr);
			unlock_shm();
			continue;
		}
		else
			log_debug(DEBUG_ARP, "Network table: %s NOT known through ARP/neigh cache", ipaddr);

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

			unlock_shm();
			dbID = find_device_by_hwaddr(db, hwaddr);
			lock_shm();

			// Reacquire client pointer (if may have changed when unlocking above)
			client = getClient(clientID, true);

			if(dbID >= 0)
				log_debug(DEBUG_ARP, "Network table: Client with MAC %s is network ID %i", hwaddr, dbID);
		}
		if (dbID == DB_NODATA)
		{
			//
			// Variant 2: Try to find a device using the same IP address within the last 24 hours
			// Only try this when there is no EDNS(0) MAC address available
			//
			unlock_shm();
			dbID = find_device_by_recent_ip(db, ipaddr);
			lock_shm();

			// Reacquire client pointer (if may have changed when unlocking above)
			client = getClient(clientID, true);

			if(dbID > DB_NODATA)
			{
				log_debug(DEBUG_ARP, "Network table: Client with IP %s has no MAC info but was recently be seen for network ID %i",
				          ipaddr, dbID);
			}
		}

		//
		// Variant 3: Try to find MAC address from DHCP leases file
		// if DHCP server is enabled
		//
		bool dhcp_lease = false;
		if (dbID == DB_NODATA && config.dhcp.active.v.b)
		{
			log_debug(DEBUG_ARP, "Network table: DHCP server enabled, checking leases for IP %s", ipaddr);
			FILE *fp = fopen(DHCPLEASESFILE, "r");
			if(fp != NULL)
			{
				char *line = NULL;
				size_t line_len = 0;
				ssize_t read;

				while((read = getline(&line, &line_len, fp)) != -1 && !dhcp_lease)
				{
					// Skip empty lines
					if(read == 0)
						continue;
					// Skip duid line
					if(strncmp(line, "duid", 4) == 0)
						continue;

					// Parse line
					unsigned long expires = 0;
					char lease_hwaddr[48] = { 0 };
					char lease_ip[INET6_ADDRSTRLEN] = { 0 };
					char lease_name[65] = { 0 };
					const int ret = sscanf(line, "%lu %47s %45s %64s",
			                       &expires, lease_hwaddr, lease_ip, lease_name);
					// Skip invalid lines
					if(ret != 4)
						continue;

					// Check if this lease matches our client's IP address
					if(strcmp(lease_ip, ipaddr) == 0)
					{
						// Found matching lease, use its MAC address
						strncpy(hwaddr, lease_hwaddr, sizeof(hwaddr) - 1);
						hwaddr[sizeof(hwaddr) - 1] = '\0';

						// Check if lease has a hostname recorded
						if(strcmp(lease_name, "*") != 0) {
							strncpy(hostname, lease_name, sizeof(hostname) -1);
						hostname[sizeof(hostname) -1] = '\0';}

						log_debug(DEBUG_ARP, "Network table: Found MAC %s for IP %s in DHCP leases file",
						          hwaddr, ipaddr);

						unlock_shm();
						dbID = find_device_by_hwaddr(db, hwaddr);
						lock_shm();

						// Reacquire client pointer (it may have changed when unlocking above)
						client = getClient(clientID, true);

						if(dbID >= 0)
							log_debug(DEBUG_ARP, "Network table: Client with MAC %s is network ID %i", hwaddr, dbID);
						dhcp_lease = true;
					}
				}
				free(line);
				fclose(fp);
			}
			else
			log_debug(DEBUG_ARP, "Network table: Unable to open dhcp.leases");
		}

		//
		// Variant 4: Try to find a device with mock IP address
		// Only try this when there is no EDNS(0) MAC address available
		// nor a corresponding DHCP lease
		//
		if (dbID < 0 && dhcp_lease == false)
		{
			unlock_shm();
			dbID = find_device_by_mock_hwaddr(db, ipaddr);
			lock_shm();

			// Reacquire client pointer (if may have changed when unlocking above)
			client = getClient(clientID, true);

			if(dbID > DB_NODATA)
			{
				log_debug(DEBUG_ARP, "Network table: Client with IP %s has no MAC info but is known as mock-hwaddr client with network ID %i",
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
			char macVendor[MAXVENDORLEN] = { 0 };
			if(client->hwlen == 6 || dhcp_lease)
			{
				// Normal client, MAC was likely obtained from EDNS(0) data
				// or from dhcp lease
				unlock_shm();
				getMACVendor(hwaddr, macVendor);
				lock_shm();

				// Reacquire client pointer (if may have changed when unlocking above)
				client = getClient(clientID, true);
			}

			log_debug(DEBUG_ARP, "Network table: Creating new FTL device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\", interface = \"%s\"",
			          hwaddr, ipaddr, hostname, macVendor, interface);

			// Add new device to database
			const time_t lastQuery = client->lastQuery;
			const time_t firstSeen = client->firstSeen;
			const unsigned int numQueries = client->count;
			unlock_shm();
			if(!insert_netDB_device(db, hwaddr, firstSeen, lastQuery, numQueries, macVendor, &dbID))
				break;

			lock_shm();

			// Reacquire client pointer (if may have changed when unlocking above)
			client = getClient(clientID, true);

			// Reset client counter
			client->numQueriesARP = 0;
		}
		else	// Device already in database
		{
			log_debug(DEBUG_ARP, "Network table: Updating existing FTL device MAC = %s, IP = %s, hostname = \"%s\", interface = \"%s\"",
			          hwaddr, ipaddr, hostname, interface);

			// Update timestamp of last query if applicable
			const time_t lastQuery = client->lastQuery;
			const unsigned int numQueriesARP = client->numQueriesARP;
			unlock_shm();
			if(!update_netDB_lastQuery(db, dbID, lastQuery))
				break;

			// Update number of queries if applicable
			if(!update_netDB_numQueries(db, dbID, numQueriesARP))
				break;

			lock_shm();
			// Reacquire client pointer (if may have changed when unlocking above)
			client = getClient(clientID, true);
			client->numQueriesARP = 0;
		}

		unlock_shm();

		// Break early if we failed to add the new device to the
		// database above, continuing is not possible anymore
		if(dbID < 0)
			break;

		// Add unique IP address / mock-MAC pair to network_addresses table
		// ipaddr is a local copy
		if(!add_netDB_network_address(db, dbID, ipaddr))
			break;

		// Update hostname if available
		// hostname is a local copy
		if(!update_netDB_name(db, ipaddr, hostname))
			break;

		// Update interface if available
		// interface is a local copy
		if(!update_netDB_interface(db, dbID, interface))
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
			text = "ERROR";

		log_err("%s: Storing devices in network table failed: %s", text, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return false;
	}

	return true;
}

static bool add_local_interfaces_to_network_table(sqlite3 *db, time_t now, unsigned int *additional_entries)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	log_debug(DEBUG_ARP, "Network table: Adding local interfaces to network table");
	cJSON *links = cJSON_CreateArray();
	if(!nllinks(links, false))
	{
		log_err("Failed to get links, cannot update network table");
		cJSON_Delete(links);
		return false;
	}
	log_debug(DEBUG_ARP, "Network table: Successfully read links with %i entries",
	          cJSON_GetArraySize(links));

	// Parse link information
	cJSON *link = NULL;
	cJSON_ArrayForEach(link, links)
	{
		// Skip if entry is invalid
		if(link == NULL)
			continue;

		char *iface = cJSON_GetStringValue(cJSON_GetObjectItem(link, "ifname"));
		char *hwaddr = cJSON_GetStringValue(cJSON_GetObjectItem(link, "mac"));

		// Do not try to read IP addresses when the information above is incomplete
		if(iface == NULL || strlen(iface) == 0 ||
		   hwaddr == NULL || strlen(hwaddr) == 0)
			continue;

		cJSON *addr = NULL;
		cJSON_ArrayForEach(addr, cJSON_GetObjectItem(link, "addresses"))
		{
			// Skip if entry is invalid
			if(addr == NULL)
				continue;

			char *ipaddr = cJSON_GetStringValue(cJSON_GetObjectItem(addr, "address"));
			if(ipaddr == NULL || strlen(ipaddr) == 0)
				continue;

			log_debug(DEBUG_ARP, "Network table: read interface details for interface %s (%s) with address %s",
			          iface, hwaddr, ipaddr);

			// Try to find the device we parsed above
			int dbID = find_device_by_hwaddr(db, hwaddr);
			if(dbID >= 0)
			{
				log_debug(DEBUG_ARP, "Network table (ip a): Client with MAC %s was recently be seen for network ID %i",
				          hwaddr, dbID);
			}

			// Break on SQLite error
			if(dbID == DB_FAILED)
			{
				// SQLite error
				break;
			}

			// Get vendor
			char macVendor[MAXVENDORLEN] = { 0 };
			getMACVendor(hwaddr, macVendor);

			// Device not in database, add new entry
			if(dbID == DB_NODATA)
			{

				log_debug(DEBUG_ARP, "Network table: Creating new ip a device MAC = %s, IP = %s, vendor = \"%s\", interface = \"%s\"",
				          hwaddr, ipaddr, macVendor, iface);

				// Try to import query data from a possibly previously existing mock-device
				int mockID = find_device_by_mock_hwaddr(db, ipaddr);
				int lastQuery = 0, firstSeen = now, numQueries = 0;
				if(mockID >= 0)
				{
					lastQuery = db_query_int_int(db, "SELECT lastQuery from network where id = ?1", mockID);
					firstSeen = db_query_int_int(db, "SELECT firstSeen from network where id = ?1", mockID);
					numQueries = db_query_int_int(db, "SELECT numQueries from network where id = ?1", mockID);
				}

				// Add new device to database
				if(!insert_netDB_device(db, hwaddr, firstSeen, lastQuery, numQueries, macVendor, &dbID))
					break;
			}
			else
			{
				// Device already in database
				log_debug(DEBUG_ARP, "Network table: Updating existing ip a device MAC = %s, IP = %s, interface = \"%s\"",
				          hwaddr, ipaddr, iface);
			}

			// Add unique IP address / mock-MAC pair to network_addresses table
			if(!add_netDB_network_address(db, dbID, ipaddr))
				break;

			// Update interface if available
			if(!update_netDB_interface(db, dbID, iface))
				break;

			// Add to number of processed ARP cache entries
			(*additional_entries)++;
		}
	}

	// Free allocated memory
	cJSON_Delete(links);

	return true;
}

/**
 * @brief Cleans the network table in the database by removing outdated entries.
 *
 * This function performs two main tasks:
 * 1. Deletes IP addresses that have not been seen for more than a specified time.
 * 2. Sets the name field to NULL for entries where the name was last updated before a specified time.
 *
 * The time limit for these operations is determined by the configuration setting
 * `config.database.network.expire.v.ui`. If this setting is zero, the function
 * will not perform any cleaning and will return true immediately.
 *
 * @param db A pointer to the SQLite database connection.
 * @return true if the cleaning operations were successful or if cleaning is disabled.
 * @return false if any of the cleaning operations failed.
 */
static bool clean_network_table(sqlite3 *db)
{
	// Do not clean if disabled
	if(config.database.network.expire.v.ui == 0)
		return true;

	log_debug(DEBUG_ARP, "Cleaning network table");

	// Remove all but the most recent IP addresses not seen for more than a certain time
	const time_t limit = time(NULL)-24*3600*config.database.network.expire.v.ui;
	int rc = dbquery(db, "DELETE FROM network_addresses "
	                     "WHERE lastSeen < %lu;", (unsigned long)limit);
	if(rc != SQLITE_OK)
		return false;

	rc = dbquery(db, "UPDATE network_addresses SET name = NULL "
	                 "WHERE nameUpdated < %lu;", (unsigned long)limit);

	return rc == SQLITE_OK;
}

/**
 * @brief Flushes the network table by removing all IP addresses and devices.
 *
 * This function opens the database, deletes all entries from the
 * `network_addresses` and `network` tables, and then closes the database.
 *
 * @return true if the operation was successful, false otherwise.
 */
bool flush_network_table(void)
{
	sqlite3 *db = dbopen(false, false);
	if(db == NULL)
		return false;

	// Remove all IP addresses
	if(dbquery(db, "DELETE FROM network_addresses;") != SQLITE_OK)
		return false;

	// Remove all devices
	if(dbquery(db, "DELETE FROM network;") != SQLITE_OK)
		return false;

	// Close database
	dbclose(&db);

	return true;
}

// Parse kernel's neighbor cache
void parse_neighbor_cache(sqlite3 *db)
{
	// Prepare buffers
	int rc = SQLITE_OK;
	unsigned int entries = 0u, additional_entries = 0u;
	const time_t now = time(NULL);

	log_debug(DEBUG_ARP, "Parsing kernel's neighbor cache");

	// Start ARP timer
	if(config.debug.arp.v.b)
		timer_start(ARP_TIMER);

	// Start transaction to speed up database queries, to avoid that the
	// database is locked by other processes and to allow for a rollback in
	// case of an error
	if(dbquery(db, "BEGIN TRANSACTION") != SQLITE_OK)
	{
		// dbquery() above already logs the reason for why the query failed
		log_warn("Starting first transaction failed during ARP parsing");
		return;
	}

	// Delete old entries from network table
	if(!clean_network_table(db))
		return;

	// Initialize array of status for individual clients used to
	// remember the status of a client already seen in the neigh cache
	lock_shm();
	const int clients = counters->clients;
	unlock_shm();
	enum arp_status *client_status = calloc(clients, sizeof(enum arp_status));
	for(int i = 0; i < clients; i++)
		client_status[i] = CLIENT_NOT_HANDLED;

	// Try to access the kernel's neighbor cache
	if(config.database.network.parseARPcache.v.b)
	{
		// Parse ARP cache and add new entries to network table
		log_debug(DEBUG_ARP, "Network table: Calling Netlink to get ARP cache entries");
		cJSON *json = cJSON_CreateArray();
		if(!nlneigh(json))
		{
			log_err("Failed to read ARP cache, cannot update network table");
			cJSON_Delete(json);
			free(client_status);
			return;
		}
		log_debug(DEBUG_ARP, "Network table: Successfully read ARP cache with %i entries",
		          cJSON_GetArraySize(json));

		// Read ARP cache line by line
		cJSON *entry = NULL;
		cJSON_ArrayForEach(entry, json)
		{
			// Skip if entry is invalid
			if(entry == NULL)
				continue;

			// Check thread cancellation
			if(killed)
				break;

			if(config.debug.arp.v.b)
			{
				// Get line from JSON object
				char *line = cJSON_Print(entry);
				if(line == NULL)
				{
					log_err("Failed to print ARP cache entry");
					continue;
				}

				log_debug(DEBUG_ARP, "Network table: Parsing ARP cache line: %s", line);
				free(line);
			}

			// Extract IP address, interface, and hardware address from JSON object
			char *ip = NULL, *iface = NULL, *hwaddr = NULL;
			if((ip = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "ip"))) == NULL ||
			   (iface = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "iface"))) == NULL ||
			   (hwaddr = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "mac"))) == NULL)
			{
				log_err("Failed to extract ARP cache entry data");
				continue;
			}

			// Check if we want to process the line we just read
			if(strlen(hwaddr) != 17 ||	// MAC address must be 17 characters long
			   ip[0] == '\0' ||		// IP address must not be empty
			   iface[0] == '\0')		// Interface must not be empty
			{
				log_debug(DEBUG_ARP, "Network table: Skipping incomplete ARP cache entry: %s",
				          hwaddr[0] == '\0' ? "no MAC address" : "incomplete");
				if(hwaddr[0] == '\0')
				{
					// This line is incomplete, remember this to skip
					// mock-device creation after ARP processing
					// both false = do not create a new record if the client
					//              is unknown (only DNS requesting clients
					//              do this), the now value is ignored
					lock_shm();
					int clientID = findClientID(ip, false, false, 0.0);
					unlock_shm();
					if(clientID >= 0 && clientID < clients)
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
			int dbID = find_device_by_hwaddr(db, hwaddr);

			if(dbID == DB_FAILED)
			{
				// Get SQLite error code and return early from loop
				rc = sqlite3_errcode(db);
				break;
			}

			// If we reach this point, we can check if this client
			// is known to pihole-FTL
			// both false = do not create a new record if the client
			//              is unknown (only DNS requesting clients
			//              do this), the now value is ignored
			lock_shm();
			const int clientID = findClientID(ip, false, false, 0.0);

			// Set default values for a new device, may be updated
			// below if the client is known to pihole-FTL
			char hostname[MAXHOSTNAMELEN] = { 0 };
			bool client_valid = false;
			time_t lastQuery = 0;
			time_t firstSeen = now;
			unsigned int numQueries = 0, totalQueries = 0;

			// This client is known (by its IP address) to pihole-FTL if
			// findClientID() returned a non-negative index
			if(clientID >= 0 && clientID < clients)
			{
				clientsData *client = getClient(clientID, true);
				if(!client)
					continue;

				// Client is known to Pi-hole, update properties
				// with their real values
				client_valid = true;
				strncpy(hostname, getstr(client->namepos), sizeof(hostname) - 1);
				hostname[sizeof(hostname) - 1] = '\0';
				firstSeen = client->firstSeen;
				lastQuery = client->lastQuery;
				numQueries = client->numQueriesARP;
				totalQueries = client->count;
				client_status[clientID] = CLIENT_ARP_COMPLETE;
			}
			// else
			// {
				// Client is not known to Pi-hole, create a
				// mock-device with the default values set above
				// and an empty hostname
			// }
			unlock_shm();

			// Device not in database, add new entry
			if(client_valid && dbID == DB_NODATA)
			{
				// Try to obtain vendor from MAC database
				char macVendor[MAXVENDORLEN] = { 0 };
				getMACVendor(hwaddr, macVendor);

				// Check if we recently added a mock-device with the same IP address
				// and the ARP entry just came a bit delayed (reported by at least one user)
				dbID = find_recent_device_by_mock_hwaddr(db, ip);

				// Exception for the case where the device is
				// not yet in the database: Use total count of
				// queries as the number of queries for the new
				// device instead of the special ARP cache
				// counter to add also the number of queries in
				// the DNS history imported from the long-term
				// database
				numQueries = totalQueries;

				if(dbID == DB_NODATA)
				{
					// Device not known AND no recent mock-device found ---> create new device record
					log_debug(DEBUG_ARP, "Network table: Creating new ARP device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\"",
					          hwaddr, ip, hostname, macVendor);

					// Create new record (INSERT)
					if(!insert_netDB_device(db, hwaddr, firstSeen, lastQuery, numQueries, macVendor, &dbID))
						break;

					lock_shm();
					clientsData *client = getClient(clientID, true);
					if(client != NULL)
					{
						// Reset client ARP counter (we stored the entry in the database)
						client->numQueriesARP = 0;
					}
					unlock_shm();

					// Store hostname in the appropriate network_address record (if available)
					if(hostname[0] != '\0')
					{
						if(!update_netDB_name(db, ip, hostname))
							break;
					}
				}
				else
				{
					// Device is ALREADY KNOWN ---> convert mock-device to a "real" one
					log_debug(DEBUG_ARP, "Network table: Un-mocking ARP device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\"",
					          hwaddr, ip, hostname, macVendor);

					// Update/replace important device properties
					if(!unmock_netDB_device(db, hwaddr, macVendor, dbID))
						break;

					// Host name, count and last query timestamp will be set in the next
					// loop iteration for the sake of simplicity
				}
			}
			// Device in database AND client known to Pi-hole
			else if(client_valid)
			{
				log_debug(DEBUG_ARP, "Network table: Updating existing ARP device MAC = %s, IP = %s, hostname = \"%s\"",
				          hwaddr, ip, hostname);

				// Update timestamp of last query if applicable
				if(!update_netDB_lastQuery(db, dbID, lastQuery))
					break;

				// Update number of queries if applicable
				if(!update_netDB_numQueries(db, dbID, numQueries))
					break;

				lock_shm();
				// Acquire client pointer
				clientsData *client = getClient(clientID, true);
				if(client != NULL)
				{
					// Reset client ARP counter (we stored the entry in the database)
					client->numQueriesARP = 0;
				}
				unlock_shm();

				// Update hostname if available
				if(!update_netDB_name(db, ip, hostname))
					break;
			}
			// else: Device in database but not known to Pi-hole

			// Store interface if available
			if(dbID > DB_NODATA && !update_netDB_interface(db, dbID, iface))
				break;

			// Add unique IP address / mock-MAC pair to network_addresses table
			if(dbID > DB_NODATA && !add_netDB_network_address(db, dbID, ip))
				break;

			// Count number of processed ARP cache entries
			entries++;
		}

		// Free allocated JSON array
		cJSON_Delete(json);

		log_debug(DEBUG_ARP, "Network table: Finished parsing ARP cache with %u entries", entries);

		if(rc != SQLITE_OK)
		{
			log_err("Database error in ARP cache processing loop");
			free(client_status);
			return;
		}
	}

	// Check thread cancellation
	if(killed)
	{
		free(client_status);
		return;
	}

	// Loop over all clients known to FTL and ensure we add them all to the
	// database
	if(!add_FTL_clients_to_network_table(db, client_status, clients, now, &additional_entries))
	{
		free(client_status);
		return;
	}

	free(client_status);
	client_status = NULL;

	// Check thread cancellation
	if(killed)
		return;

	// Finally, loop over the available interfaces to ensure we list the
	// IP addresses correctly (local addresses are NOT contained in the
	// ARP/neighbor cache).
	if(!add_local_interfaces_to_network_table(db, now, &additional_entries))
		return;

	// Check thread cancellation
	if(killed)
		return;

	// Ensure mock-devices which are not assigned to any addresses any more
	// (they have been converted to "real" devices), are removed at this point
	log_debug(DEBUG_ARP, "Network table: Cleaning up mock-devices");
	rc = dbquery(db, "DELETE FROM network WHERE id NOT IN "
	                                           "(SELECT network_id from network_addresses) "
	                                           "AND hwaddr LIKE 'ip-%%';");
	if(rc != SQLITE_OK)
	{
		log_err("Database error in mock-device cleaning statement");
		checkFTLDBrc(rc);
		return;
	}

	// Actually update the database
	log_debug(DEBUG_ARP, "Network table: Committing changes to database");
	if((rc = dbquery(db, "END TRANSACTION")) != SQLITE_OK)
	{
		if( rc == SQLITE_BUSY )
			log_warn("Storing devices in network table failed: %s", sqlite3_errstr(rc));
		else
			log_err("Storing devices in network table failed: %s", sqlite3_errstr(rc));

		checkFTLDBrc(rc);
		return;
	}

	// Debug logging
	log_debug(DEBUG_ARP, "ARP table processing (%u entries from ARP, %u from FTL's cache) took %.1f ms",
	          entries, additional_entries, timer_elapsed_msec(ARP_TIMER));
}

// Loop over all entries in network table and unify entries by their hwaddr
// If we find duplicates, we keep the most recent entry, while
// - we replace the first-seen date by the earliest across all rows
// - we sum up the number of queries of all clients with the same hwaddr
bool unify_hwaddr(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

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

	// Start transaction
	SQL_bool(db, "BEGIN TRANSACTION");

	// Perform SQL query
	bool success = false;
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("unify_hwaddr(\"%s\") - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return false;
	}

	// Loop until no further (id,hwaddr) sets are available
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE)
	{
		// Check if we ran into an error
		if(rc != SQLITE_ROW)
		{
			log_err("unify_hwaddr(\"%s\") - SQL error step: %s", querystr, sqlite3_errstr(rc));
			goto unify_hwaddr_end;
		}

		// Obtain id and hwaddr of the most recent entry for this particular client
		const int id = sqlite3_column_int(stmt, 0);
		const char *hwaddr = (char*)sqlite3_column_text(stmt, 1);

		// Reset statement
		sqlite3_reset(stmt);

		// Update firstSeen with lowest value across all rows with the same hwaddr
		dbquery(db, "UPDATE network "\
		            "SET firstSeen = (SELECT MIN(firstSeen) FROM network WHERE hwaddr = \'%s\' COLLATE NOCASE) "\
		            "WHERE id = %i;", hwaddr, id);

		// Update numQueries with sum of all rows with the same hwaddr
		dbquery(db, "UPDATE network "\
		            "SET numQueries = (SELECT SUM(numQueries) FROM network WHERE hwaddr = \'%s\' COLLATE NOCASE) "\
		            "WHERE id = %i;", hwaddr, id);

		// Remove all other lines with the same hwaddr but a different id
		dbquery(db, "DELETE FROM network "\
		            "WHERE hwaddr = \'%s\' COLLATE NOCASE "\
		            "AND id != %i;", hwaddr, id);
	}

	// Update database version to 4
	if(!db_set_FTL_property(db, DB_VERSION, 4))
		goto unify_hwaddr_end;

	success = true;

unify_hwaddr_end:

	if(!success)
		checkFTLDBrc(rc);

	// Reset statement
	sqlite3_reset(stmt);

	// Finalize statement
	sqlite3_finalize(stmt);

	// End transaction
	SQL_bool(db, "COMMIT");

	return success;
}

/**
 * @brief Retrieves the vendor name associated with a given MAC address.
 *
 * This function queries a local SQLite database to find the vendor name
 * corresponding to the provided MAC address. It handles special cases such as
 * loopback interfaces and invalid MAC addresses.
 *
 * @param hwaddr The MAC address to look up, in the format "XX:XX:XX:XX:XX:XX".
 * @return A dynamically allocated string containing the vendor name. The caller
 *         is responsible for freeing this string. If the vendor name is not found
 *         or an error occurs, an empty string is returned.
 *
 * Special cases:
 * - If the MAC address is "00:00:00:00:00:00", the function returns "virtual interface".
 * - If the MAC address is invalid (not 17 characters long or contains "ip-"), an empty string is returned.
 */
static bool getMACVendor(const char *hwaddr, char vendor[MAXVENDORLEN])
{
	// Special handling for the loopback interface
	if(strcmp(hwaddr, "00:00:00:00:00:00") == 0)
	{
		strncpy(vendor, "virtual interface", MAXVENDORLEN);
		return true;
	}

	log_debug(DEBUG_ARP, "getMACVendor(\"%s\")", hwaddr);

	log_debug(DEBUG_ARP, "getMACVendor(\"%s\")", hwaddr);

	struct stat st;
	if(stat(config.files.macvendor.v.s, &st) != 0)
	{
		// File does not exist
		log_debug(DEBUG_ARP, "getMACVendor(\"%s\"): %s does not exist", hwaddr, config.files.macvendor.v.s);
		return false;
	}
	else if(strlen(hwaddr) != 17 || strstr(hwaddr, "ip-") != NULL)
	{
		// MAC address is incomplete or mock address (for distant clients)
		log_debug(DEBUG_ARP, "getMACVendor(\"%s\"): MAC invalid (length %zu)", hwaddr, strlen(hwaddr));
		return false;
	}

	bool success = false;
	sqlite3 *macvendor_db = NULL;
	int rc = sqlite3_open_v2(config.files.macvendor.v.s, &macvendor_db, SQLITE_OPEN_READONLY, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getMACVendor(\"%s\") - SQL error: %s", hwaddr, sqlite3_errstr(rc));
		sqlite3_close(macvendor_db);
		return false;
	}

	// Only keep "XX:YY:ZZ" (8 characters)
	char hwaddrshort[9];
	strncpy(hwaddrshort, hwaddr, 8);
	hwaddrshort[8] = '\0';
	const char querystr[] = "SELECT vendor FROM macvendor WHERE mac LIKE ?;";

	sqlite3_stmt *stmt = NULL;
	rc = sqlite3_prepare_v2(macvendor_db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getMACVendor(\"%s\") - SQL error prepare \"%s\": %s", hwaddr, querystr, sqlite3_errstr(rc));
		goto getMACVendor_end;
	}

	// Bind hwaddrshort to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, hwaddrshort, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("getMACVendor(\"%s\" -> \"%s\"): Failed to bind hwaddrshort: %s",
		        hwaddr, hwaddrshort, sqlite3_errstr(rc));
		goto getMACVendor_end;
	}

	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		strncpy(vendor, (char*)sqlite3_column_text(stmt, 0), MAXVENDORLEN);
		vendor[MAXVENDORLEN - 1] = '\0';
	}

	if(rc != SQLITE_DONE && rc != SQLITE_ROW)
	{
		// Error
		log_err("getMACVendor(\"%s\") - SQL error step: %s", hwaddr, sqlite3_errstr(rc));
	}
	else
		success = true;

getMACVendor_end:

	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement and close database
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);
	sqlite3_close(macvendor_db);

	log_debug(DEBUG_ARP, "MAC Vendor lookup for %s returned \"%s\"", hwaddr, vendor);

	return success;
}

/**
 * @brief Updates the MAC vendor records in the database
 *
 * @param db A pointer to the SQLite database.
 */
bool updateMACVendorRecords(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	log_debug(DEBUG_DATABASE, "Updating MAC vendor records");

	struct stat st;
	if(stat(config.files.macvendor.v.s, &st) != 0)
	{
		// File does not exist
		log_debug(DEBUG_ARP, "updateMACVendorRecords(): \"%s\" does not exist", config.files.macvendor.v.s);
		return false;
	}

	bool success = false;
	sqlite3_stmt *stmt = NULL;
	const char *selectstr = "SELECT id,hwaddr FROM network;";
	int rc = sqlite3_prepare_v2(db, selectstr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("updateMACVendorRecords() - SQL error prepare \"%s\": %s", selectstr, sqlite3_errstr(rc));
		goto updateMACVendorRecords_end;
	}

	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const int id = sqlite3_column_int(stmt, 0);

		// Get vendor for MAC
		char vendor[MAXVENDORLEN];
		getMACVendor((char*)sqlite3_column_text(stmt, 1), vendor);

		// Prepare statement
		sqlite3_stmt *stmt2 = NULL;
		const char *updatestr = "UPDATE network SET macVendor = ?1 WHERE id = ?2";
		rc = sqlite3_prepare_v2(db, updatestr, -1, &stmt2, NULL);
		if(rc != SQLITE_OK)
		{
			log_err("updateMACVendorRecords() - SQL error prepare \"%s\": %s", updatestr, sqlite3_errstr(rc));
			goto updateMACVendorRecords_end;
		}

		// Bind vendor to prepared statement
		if((rc = sqlite3_bind_text(stmt2, 1, vendor, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			log_err("updateMACVendorRecords() - Failed to bind vendor: %s", sqlite3_errstr(rc));
			goto updateMACVendorRecords_end;
		}

		// Bind id to prepared statement
		if((rc = sqlite3_bind_int(stmt2, 2, id)) != SQLITE_OK)
		{
			log_err("updateMACVendorRecords() - Failed to bind id: %s", sqlite3_errstr(rc));
			goto updateMACVendorRecords_end;
		}

		// Execute statement
		rc = sqlite3_step(stmt2);
		if(rc != SQLITE_DONE)
			goto updateMACVendorRecords_end;

	}
	if(rc != SQLITE_DONE)
	{
		// Error
		log_err("updateMACVendorRecords() - SQL error step: %s", sqlite3_errstr(rc));
		goto updateMACVendorRecords_end;
	}

	success = true;

updateMACVendorRecords_end:
	if(!success)
		checkFTLDBrc(rc);

	// Reset statement
	sqlite3_reset(stmt);

	// Finalize statement
	sqlite3_finalize(stmt);

	return success;
}

// Get hardware address of device identified by IP address
bool getMACfromIP(sqlite3 *db, char hwaddr[MAXMACLEN], const char *ipaddr)
{
	bool got_hwaddr = false;

	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false, false)) == NULL)
		{
			log_warn("getMACfromIP(\"%s\") - Failed to open DB", ipaddr);
			return false;
		}

		// Successful
		db_opened = true;
	}

	// Prepare SQLite statement
	// We request the most recent IP entry in case there an IP appears
	// multiple times in the network_addresses table
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT hwaddr FROM network WHERE id = "
	                       "(SELECT network_id FROM network_addresses "
	                       "WHERE ip = ? GROUP BY ip HAVING max(lastSeen));";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getMACfromIP(\"%s\") - SQL error prepare: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getMACfromIP_end;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("getMACfromIP(\"%s\"): Failed to bind ip: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getMACfromIP_end;
	}

	rc = sqlite3_step(stmt);
	got_hwaddr = (rc == SQLITE_ROW);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		strncpy(hwaddr, (char*)sqlite3_column_text(stmt, 0), MAXMACLEN);
		hwaddr[MAXMACLEN - 1] = '\0'; // Ensure NULL termination
	}
	else if(rc != SQLITE_DONE)
	{
		log_err("getMACfromIP(\"%s\"): Failed step: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getMACfromIP_end;
	}

	if(got_hwaddr)
		log_debug(DEBUG_DATABASE, "Found database hardware address %s -> %s", ipaddr, hwaddr);

getMACfromIP_end:

	if(!got_hwaddr)
		checkFTLDBrc(rc);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened)
		dbclose(&db);

	// Return hardware address, may be NULL on error
	return got_hwaddr;
}

// Get aliasclient ID of device identified by IP address (if available)
int getAliasclientIDfromIP(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false, false)) == NULL)
		{
			log_warn("getAliasclientIDfromIP(\"%s\") - Failed to open DB", ipaddr);
			return DB_FAILED;
		}

		// Successful
		db_opened = true;
	}

	// Prepare SQLite statement
	// We request the most recent IP entry in case there an IP appears
	// multiple times in the network_addresses table
	bool success = false;
	sqlite3_stmt *stmt = NULL;
	int aliasclient_id = DB_FAILED;
	const char *querystr = "SELECT aliasclient_id FROM network WHERE id = "
	                       "(SELECT network_id FROM network_addresses "
	                       "WHERE ip = ? "
	                             "AND aliasclient_id IS NOT NULL "
	                       "GROUP BY ip HAVING max(lastSeen));";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getAliasclientIDfromIP(\"%s\") - SQL error prepare: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getAliasclientIDfromIP_end;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getAliasclientIDfromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		goto getAliasclientIDfromIP_end;
	}

	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found
		aliasclient_id = sqlite3_column_int(stmt, 0);
	}
	else if(rc != SQLITE_DONE)
	{
		// Error
		goto getAliasclientIDfromIP_end;
	}
	else
	{
		// Not found
		aliasclient_id = DB_NODATA;
	}

	log_debug(DEBUG_ALIASCLIENTS, "   Aliasclient ID %s -> %i%s", ipaddr, aliasclient_id,
	          aliasclient_id < 0 ? " (NOT FOUND)" : "");

	success = true;

getAliasclientIDfromIP_end:

	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened)
		dbclose(&db);

	return aliasclient_id;
}

// Get host name of device identified by IP address
bool getNameFromIP(sqlite3 *db, char hostn[MAXDOMAINLEN], const char *ipaddr)
{
	bool got_name = false;

	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;
	log_debug(DEBUG_RESOLVER, "Trying to obtain host name of \"%s\" from network_addresses table", ipaddr);

	// Check if we want to resolve host names
	if(!resolve_this_name(ipaddr))
	{
		log_debug(DEBUG_RESOLVER, "getNameFromIP(\"%s\") - configured to not resolve host name", ipaddr);
		return false;
	}

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false, false)) == NULL)
		{
			log_warn("getNameFromIP(\"%s\") - Failed to open DB", ipaddr);
			return false;
		}

		// Successful
		db_opened = true;
	}

	// Check for a host name associated with the same IP address
	bool success = false;
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT name FROM network_addresses WHERE name IS NOT NULL AND ip = ?;";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getNameFromIP(\"%s\") - SQL error prepare: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getNameFromIP_end;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getNameFromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		goto getNameFromIP_end;
	}

	log_debug(DEBUG_RESOLVER, "Check for a host name associated with IP address %s", ipaddr);

	rc = sqlite3_step(stmt);
	got_name = rc == SQLITE_ROW;
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		strncpy(hostn, (char*)sqlite3_column_text(stmt, 0), MAXDOMAINLEN);
		hostn[MAXDOMAINLEN - 1] = '\0';

		log_debug(DEBUG_RESOLVER, "Found database host name (same address) %s -> %s", ipaddr, hostn);
	}
	else if(rc != SQLITE_DONE)
	{
		// Error
		log_err("getNameFromIP(\"%s\") - SQL error step: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getNameFromIP_end;
	}

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Return here if we found the name
	if(got_name)
	{
		if(db_opened)
			dbclose(&db);

		// Return early
		return true;
	}

	log_debug(DEBUG_RESOLVER, " ---> not found");

	// Nothing found for the exact IP address
	// Check for a host name associated with the same device (but another IP address)
	querystr = "SELECT name FROM network_addresses "
	                       "WHERE name IS NOT NULL AND "
	                             "network_id = (SELECT network_id FROM network_addresses "
	                                                             "WHERE ip = ?) "
	                       "ORDER BY lastSeen DESC LIMIT 1";
	rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getNameFromIP(\"%s\") - SQL error prepare: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getNameFromIP_end;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getNameFromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		goto getNameFromIP_end;
	}

	log_debug(DEBUG_RESOLVER, "Checking for a host name associated with the same device (but another IP address)");

	rc = sqlite3_step(stmt);
	got_name = rc == SQLITE_ROW;
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		strncpy(hostn, (char*)sqlite3_column_text(stmt, 0), MAXDOMAINLEN);
		hostn[MAXDOMAINLEN - 1] = '\0';

		if(config.debug.resolver.v.b)
			log_debug(DEBUG_RESOLVER, "Found database host name (same device) %s -> %s",
			          ipaddr, hostn);
	}
	else if(rc == SQLITE_DONE)
	{
		// Not found
		if(config.debug.resolver.v.b)
			log_debug(DEBUG_RESOLVER, " ---> not found");
	}
	else
	{
		// Error
		log_err("getNameFromIP(\"%s\") - SQL error step: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getNameFromIP_end;
	}

	success = true;

getNameFromIP_end:

	if(!success)
		checkFTLDBrc(rc);

	// Finalize statement and close database handle (if opened)
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened)
		dbclose(&db);

	return got_name;
}

// Get most recently seen host name of device identified by MAC address
bool getNameFromMAC(const char *client, char hostn[MAXDOMAINLEN])
{
	bool got_name = false;

	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Open pihole-FTL.db database file
	sqlite3 *db = NULL;
	if((db = dbopen(false, false)) == NULL)
	{
		log_warn("getNameFromMAC(\"%s\") - Failed to open DB", client);
		return false;
	}

	// Check for a host name associated with the given client as MAC address
	// COLLATE NOCASE: Case-insensitive comparison
	const char *querystr = "SELECT name FROM network_addresses "
	                               "WHERE name IS NOT NULL AND "
	                                     "network_id = (SELECT id FROM network WHERE hwaddr = ? COLLATE NOCASE) "
	                               "ORDER BY lastSeen DESC LIMIT 1";
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getNameFromMAC(\"%s\") - SQL error prepare: %s",
		        client, sqlite3_errstr(rc));
		goto getNameFromMAC_end;
	}

	// Bind client to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, client, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getNameFromMAC(\"%s\"): Failed to bind ip: %s",
		         client, sqlite3_errstr(rc));
		goto getNameFromMAC_end;
	}

	log_debug(DEBUG_RESOLVER, "Check for a host name associated with MAC address %s", client);

	rc = sqlite3_step(stmt);
	got_name = (rc == SQLITE_ROW);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		strncpy(hostn, (char*)sqlite3_column_text(stmt, 0), MAXDOMAINLEN);
		hostn[MAXDOMAINLEN - 1] = '\0';

		if(config.debug.resolver.v.b)
			log_debug(DEBUG_RESOLVER, "Found database host name (by MAC) %s -> %s",
			          client, hostn);
	}
	else if(rc == SQLITE_DONE)
	{
		// Not found
		if(config.debug.resolver.v.b)
			log_debug(DEBUG_RESOLVER, " ---> not found");
	}
	else
	{
		// Error
		log_err("getNameFromMAC(\"%s\") - SQL error step: %s",
		        client, sqlite3_errstr(rc));
		goto getNameFromMAC_end;
	}

getNameFromMAC_end:

	if(!got_name)
		checkFTLDBrc(rc);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	dbclose(&db);
	return got_name;
}

// Get interface of device identified by IP address
bool getIfaceFromIP(sqlite3 *db, char iface[MAXIFACESTRLEN], const char *ipaddr)
{
	bool got_iface = false;

	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false, false)) == NULL)
		{
			log_warn("getIfaceFromIP(\"%s\") - Failed to open DB", ipaddr);
			return false;
		}

		// Successful
		db_opened = true;
	}

	// Prepare SQLite statement
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT interface FROM network "
	                               "JOIN network_addresses "
	                                    "ON network_addresses.network_id = network.id "
	                               "WHERE network_addresses.ip = ? AND "
	                                     "interface != 'N/A' AND "
	                                     "interface IS NOT NULL;";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getIfaceFromIP(\"%s\") - SQL error prepare: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getIfaceFromIP_end;
	}

	log_debug(DEBUG_DATABASE, "getIfaceFromIP(): \"%s\" with ? = \"%s\"",
	          querystr, ipaddr);

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getIfaceFromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		goto getIfaceFromIP_end;
	}

	rc = sqlite3_step(stmt);
	got_iface = (rc == SQLITE_ROW);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		strncpy(iface, (char*)sqlite3_column_text(stmt, 0), MAXIFACESTRLEN);
		iface[MAXIFACESTRLEN - 1] = '\0';
	}
	else if(rc != SQLITE_DONE)
	{
		// Error
		log_err("getIfaceFromIP(\"%s\") - SQL error step: %s",
		        ipaddr, sqlite3_errstr(rc));
		goto getIfaceFromIP_end;
	}

	if(iface != NULL)
		log_debug(DEBUG_DATABASE, "Found database interface %s -> %s", ipaddr, iface);

getIfaceFromIP_end:

	if(!got_iface)
		checkFTLDBrc(rc);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened)
		dbclose(&db);

	return got_iface;
}

// Select records from the network table
bool networkTable_readDevices(sqlite3 *db, sqlite3_stmt **read_stmt, const char **message)
{
	// Prepare SQLite statement
	const char *querystr = "SELECT id,hwaddr,interface,firstSeen,lastQuery,numQueries,macVendor FROM network ORDER BY lastQuery DESC;";
	const int rc = sqlite3_prepare_v2(db, querystr, -1, read_stmt, NULL);
	if(rc != SQLITE_OK){
		*message = sqlite3_errstr(rc);
		log_err("networkTable_readDevices() - SQL error prepare (%i): %s",
		        rc, *message);
		return false;
	}

	return true;
}

// Get a record from the network table
bool networkTable_readDevicesGetRecord(sqlite3_stmt *read_stmt, network_record *network, const char **message)
{
	// Perform step
	const int rc = sqlite3_step(read_stmt);

	// Valid row
	if(rc == SQLITE_ROW)
	{
		network->id = sqlite3_column_int(read_stmt, 0);
		network->hwaddr = (char*)sqlite3_column_text(read_stmt, 1);
		network->iface = (char*)sqlite3_column_text(read_stmt, 2);
		network->firstSeen = sqlite3_column_int(read_stmt, 3);
		network->lastQuery = sqlite3_column_int(read_stmt, 4);
		network->numQueries = sqlite3_column_int(read_stmt, 5);
		network->macVendor = (char*)sqlite3_column_text(read_stmt, 6);
		return true;
	}

	// Check for error. An error happened when the result is neither
	// SQLITE_ROW (we returned earlier in this case), nor
	// SQLITE_DONE (we are finished reading the table)
	if(rc != SQLITE_DONE)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_readDevicesGetRecord() - SQL error step (%i): %s",
		        rc, *message);
		return false;
	}

	// Finished reading, nothing to get here
	return false;
}

// Finalize statement of a gravity database transaction
void networkTable_readDevicesFinalize(sqlite3_stmt *read_stmt)
{
	// Finalize statement
	sqlite3_finalize(read_stmt);
}

// Select records from the network table (IPs)
bool networkTable_readIPs(sqlite3 *db, sqlite3_stmt **read_stmt, const int id, const char **message)
{
	// Prepare SQLite statement
	const char *querystr = "SELECT ip,lastSeen,name,nameUpdated FROM network_addresses WHERE network_id = ? ORDER BY lastSeen DESC;";
	int rc = sqlite3_prepare_v2(db, querystr, -1, read_stmt, NULL);
	if( rc != SQLITE_OK ){
		*message = sqlite3_errstr(rc);
		log_err("networkTable_readIPs(%i) - SQL error prepare (%i): %s",
		        id, rc, *message);
		return false;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_int(*read_stmt, 1, id)) != SQLITE_OK)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_readIPs(%i): Failed to bind domain (error %d) - %s",
		        id, rc, *message);
		return false;
	}

	return true;
}

// Get a record from the network_addresses table (IPs)
bool networkTable_readIPsGetRecord(sqlite3_stmt *read_stmt, network_addresses_record *network_addresses, const char **message)
{
	// Perform step
	const int rc = sqlite3_step(read_stmt);

	// Valid row
	if(rc == SQLITE_ROW)
	{
		network_addresses->ip = (char*)sqlite3_column_text(read_stmt, 0);
		network_addresses->lastSeen = sqlite3_column_int64(read_stmt, 1);
		network_addresses->name = (char*)sqlite3_column_text(read_stmt, 2);
		network_addresses->nameUpdated = sqlite3_column_int64(read_stmt, 1);
		return true;
	}

	// Check for error. An error happened when the result is neither
	// SQLITE_ROW (we returned earlier in this case), nor
	// SQLITE_DONE (we are finished reading the table)
	if(rc != SQLITE_DONE)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_readDevicesGetIP() - SQL error step (%i): %s",
		        rc, *message);
		return false;
	}

	// Finished reading, nothing to get here
	return false;
}

// Finalize statement of a gravity database transaction
void networkTable_readIPsFinalize(sqlite3_stmt *read_stmt)
{
	// Finalize statement
	sqlite3_finalize(read_stmt);
}

// Delete a device from the network table
bool networkTable_deleteDevice(sqlite3 *db, const int id, int *deleted, const char **message)
{
	// First step: Delete all associated IPs of this device
	// Prepare SQLite statement
	const char *querystr = "DELETE FROM network_addresses WHERE network_id = ?;";
	bool success = false;
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i) - SQL error prepare (%i): %s",
		        id, rc, *message);
		return false;
	}

	// Bind id to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, id)) != SQLITE_OK)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i): Failed to bind id (error %d) - %s",
		        id, rc, *message);
		goto networkTable_deleteDevice_end;
	}

	// Execute statement
	rc = sqlite3_step(stmt);
	if(rc != SQLITE_DONE)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i) - SQL error step (%i): %s",
		        id, rc, *message);
		goto networkTable_deleteDevice_end;
	}

	// Check if we deleted any rows
	*deleted += sqlite3_changes(db);

	// Finalize statement
	sqlite3_finalize(stmt);

	// Second step: Delete the device itself
	querystr = "DELETE FROM network WHERE id = ?;";
	rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i) - SQL error prepare (%i): %s",
		        id, rc, *message);
		goto networkTable_deleteDevice_end;
	}

	// Bind id to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, id)) != SQLITE_OK)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i): Failed to bind id (error %d) - %s",
		        id, rc, *message);
		goto networkTable_deleteDevice_end;
	}

	// Execute statement
	rc = sqlite3_step(stmt);
	if(rc != SQLITE_DONE)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i) - SQL error step (%i): %s",
		        id, rc, *message);
		goto networkTable_deleteDevice_end;
	}

	// Check if we deleted any rows
	*deleted += sqlite3_changes(db);

	success = true;

networkTable_deleteDevice_end:

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return success;
}

// Counting number of occurrences of a specific char in a string
static size_t __attribute__ ((pure)) count_char(const char *haystack, const char needle)
{
	size_t count = 0u;
	while(*haystack)
		if (*haystack++ == needle)
			++count;
	return count;
}

// Identify MAC addresses using a set of suitable criteria
bool __attribute__ ((pure)) isMAC(const char *input)
{
	if(input != NULL &&                // Valid input
	   strlen(input) == 17u &&         // MAC addresses are always 17 chars long (6 bytes + 5 colons)
	   count_char(input, ':') == 5u && // MAC addresses always have 5 colons
	   strstr(input, "::") == NULL)    // No double-colons (IPv6 address abbreviation)
	   {
		// This is a MAC address of the form AA:BB:CC:DD:EE:FF
		return true;
	   }

	// Not a MAC address
	return false;
}
