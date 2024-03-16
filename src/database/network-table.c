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
#include "../log.h"
// timer_elapsed_msec()
#include "../timers.h"
#include "../config/config.h"
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// resolve_this_name()
#include "../resolve.h"
// killed
#include "../signals.h"

// Private prototypes
static char *getMACVendor(const char *hwaddr) __attribute__ ((malloc));
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

// Try to find device by recent usage of this IP address
static int find_device_by_recent_ip(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return -1;

	char *querystr = NULL;
	int ret = asprintf(&querystr,
	                   "SELECT network_id FROM network_addresses "
	                   "WHERE ip = \'%s\' AND "
	                   "lastSeen > (cast(strftime('%%s', 'now') as int)-86400) "
	                   "ORDER BY lastSeen DESC LIMIT 1;", ipaddr);
	if(querystr == NULL || ret < 0)
	{
		log_warn("Memory allocation failed in find_device_by_recent_ip(\"%s\"): %i",
		         ipaddr, ret);
		return -1;
	}

	// Perform SQL query
	int network_id = db_query_int(db, querystr);
	free(querystr);
	querystr = NULL;

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

	char *querystr = NULL;
	int ret = asprintf(&querystr, "SELECT id FROM network WHERE hwaddr = \'ip-%s\';", ipaddr);
	if(querystr == NULL || ret < 0)
	{
		log_warn("Memory allocation failed in find_device_by_mock_hwaddr(\"%s\"): %i",
		         ipaddr, ret);
		return -1;
	}

	// Perform SQL query
	int network_id = db_query_int(db, querystr);
	free(querystr);

	return network_id;
}

// Try to find device by hardware address
static int find_device_by_hwaddr(sqlite3 *db, const char hwaddr[])
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	char *querystr = NULL;
	int ret = asprintf(&querystr, "SELECT id FROM network WHERE hwaddr = \'%s\' COLLATE NOCASE;", hwaddr);
	if(querystr == NULL || ret < 0)
	{
		log_warn("Memory allocation failed in find_device_by_hwaddr(\"%s\"): %i",
		         hwaddr, ret);
		return -1;
	}

	// Perform SQL query
	int network_id = db_query_int(db, querystr);
	free(querystr);

	return network_id;
}

// Try to find device by RECENT mock hardware address (generated from IP address)
static int find_recent_device_by_mock_hwaddr(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return DB_FAILED;

	char *querystr = NULL;
	int ret = asprintf(&querystr,
	                   "SELECT id FROM network WHERE "
	                   "hwaddr = \'ip-%s\' AND "
	                   "firstSeen > (cast(strftime('%%s', 'now') as int)-3600);",
	                   ipaddr);
	if(querystr == NULL || ret < 0)
	{
		log_warn("Memory allocation failed in find_device_by_recent_mock_hwaddr(\"%s\"): %i",
		         ipaddr, ret);
		return -1;
	}

	// Perform SQL query
	int network_id = db_query_int(db, querystr);
	free(querystr);

	return network_id;
}

// Store hostname of device identified by dbID
static int update_netDB_name(sqlite3 *db, const char *ip, const char *name)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	// Skip if hostname is NULL or an empty string (= no result)
	if(name == NULL || strlen(name) < 1)
		return SQLITE_OK;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network_addresses SET name = ?1, "
	                               "nameUpdated = (cast(strftime('%s', 'now') as int)) "
	                               "WHERE ip = ?2";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("update_netDB_name(%s, \"%s\") - SQL error prepare (%i): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return rc;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments 1 = \"%s\" and 2 = \"%s\"",
	          querystr, name, ip);


	// Bind name to prepared statement (1st argument)
	// We can do this as name has dynamic scope that exceeds that of the binding.
	if((rc = sqlite3_bind_text(query_stmt, 1, name, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("update_netDB_name(%s, \"%s\"): Failed to bind ip (error %d): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}
	// Bind ip (unique key) to prepared statement (2nd argument)
	// We can do this as name has dynamic scope that exceeds that of the binding.
	if((rc = sqlite3_bind_text(query_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("update_netDB_name(%s, \"%s\"): Failed to bind name (error %d): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("update_netDB_name(%s, \"%s\"): Failed to step (error %d): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		log_err("update_netDB_name(%s, \"%s\"): Failed to finalize (error %d): %s",
		        ip, name, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}

	return SQLITE_OK;
}

// Updates lastQuery. Only use new value if larger than zero.
// client->lastQuery may be zero if this client is only known
// from a database entry but has not been seen since then (skip in this case)
static int update_netDB_lastQuery(sqlite3 *db, const int network_id, const time_t lastQuery)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	// Return early if there is nothing to update
	if(lastQuery < 1)
		return SQLITE_OK;

	const int ret = dbquery(db, "UPDATE network "\
	                            "SET lastQuery = MAX(lastQuery, %lu) "\
	                            "WHERE id = %i;",
	                            (unsigned long)lastQuery, network_id);

	return ret;
}


// Update numQueries.
// Add queries seen since last update and reset counter afterwards
static int update_netDB_numQueries(sqlite3 *db, const int dbID, const int numQueries)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	// Return early if there is nothing to update
	if(numQueries < 1)
		return SQLITE_OK;

	const int ret = dbquery(db, "UPDATE network "
	                            "SET numQueries = numQueries + %i "
	                            "WHERE id = %i;",
	                            numQueries, dbID);

	return ret;
}

// Add IP address record if it does not exist (INSERT). If it already exists,
// the UNIQUE(ip) trigger becomes active and the line is instead REPLACEd.
// We preserve a possibly existing IP -> host name association here
static int add_netDB_network_address(sqlite3 *db, const int network_id, const char *ip)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

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

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("add_netDB_network_address(%i, \"%s\") - SQL error prepare (%i): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return rc;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1 = %i and ?2 = \"%s\"",
		     querystr, network_id, ip);

	// Bind network_id to prepared statement (1st argument)
	if((rc = sqlite3_bind_int(query_stmt, 1, network_id)) != SQLITE_OK)
	{
		log_err("add_netDB_network_address(%i, \"%s\"): Failed to bind network_id (error %d): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}
	// Bind ip to prepared statement (2nd argument)
	if((rc = sqlite3_bind_text(query_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_netDB_network_address(%i, \"%s\"): Failed to bind name (error %d): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("add_netDB_network_address(%i, \"%s\"): Failed to step (error %d): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		log_err("add_netDB_network_address(%i, \"%s\"): Failed to finalize (error %d): %s",
		        network_id, ip, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(query_stmt);
		return rc;
	}

	return SQLITE_OK;
}

// Insert a new record into the network table
static int insert_netDB_device(sqlite3 *db, const char *hwaddr, time_t now, time_t lastQuery,
                               unsigned int numQueriesARP, const char *macVendor)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "INSERT INTO network "\
	                        "(hwaddr,interface,firstSeen,lastQuery,numQueries,macVendor) "\
	                        "VALUES (?1,\'N/A\',?2,?3,?4,?5);";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\", %lu, %lu, %u, \"%s\") - SQL error prepare (%i): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return rc;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1-?5 = (\"%s\", %lu, %lu, %u, \"%s\")",
		      querystr, hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor);

	// Bind hwaddr to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\", %lu, %lu, %u, \"%s\"): Failed to bind hwaddr (error %d): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Bind now to prepared statement (2nd argument)
	if((rc = sqlite3_bind_int(query_stmt, 2, now)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind now (error %d): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Bind lastQuery to prepared statement (3rd argument)
	if((rc = sqlite3_bind_int(query_stmt, 3, lastQuery)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind lastQuery (error %d): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Bind numQueriesARP to prepared statement (4th argument)
	if((rc = sqlite3_bind_int(query_stmt, 4, numQueriesARP)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind numQueriesARP (error %d): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Bind macVendor to prepared statement (5th argument) - the macVendor can be NULL here
	if((rc = sqlite3_bind_text(query_stmt, 5, macVendor, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to bind macVendor (error %d): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to step (error %d): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		log_err("insert_netDB_device(\"%s\",%lu, %lu, %u, \"%s\"): Failed to finalize (error %d): %s",
		        hwaddr, (unsigned long)now, (unsigned long)lastQuery, numQueriesARP, macVendor, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	return SQLITE_OK;
}

// Convert mock-device into a real one by changing the hardware address (and possibly adding a vendor string)
static int unmock_netDB_device(sqlite3 *db, const char *hwaddr, const char *macVendor, const int dbID)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network SET "\
	                        "hwaddr = ?1, macVendor=?2 WHERE id = ?3;";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i) - SQL error prepare (%i): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return rc;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1 = \"%s\", ?2 = \"%s\", ?3 = %i",
		     querystr, hwaddr, macVendor, dbID);

	// Bind hwaddr to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind hwaddr (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Bind macVendor to prepared statement (2nd argument) - the macVendor can be NULL here
	if((rc = sqlite3_bind_text(query_stmt, 2, macVendor, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind macVendor (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Bind now to prepared statement (3rd argument)
	if((rc = sqlite3_bind_int(query_stmt, 3, dbID)) != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to bind now (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to step (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		log_err("unmock_netDB_device(\"%s\", \"%s\", %i): Failed to finalize (error %d): %s",
		        hwaddr, macVendor, dbID, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	return SQLITE_OK;
}

// Update interface of device
static int update_netDB_interface(sqlite3 *db, const int network_id, const char *iface)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return SQLITE_ERROR;

	// Return early if there is nothing to be done in here
	if(iface == NULL || strlen(iface) == 0)
		return SQLITE_OK;

	sqlite3_stmt *query_stmt = NULL;
	const char querystr[] = "UPDATE network SET interface = ?1 WHERE id = ?2";

	int rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("update_netDB_interface(%i, \"%s\") - SQL error prepare (%i): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return rc;
	}

	log_debug(DEBUG_DATABASE, "dbquery: \"%s\" with arguments ?1 = \"%s\" and ?2 = %i",
		     querystr, iface, network_id);

	// Bind iface to prepared statement (1st argument)
	if((rc = sqlite3_bind_text(query_stmt, 1, iface, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("update_netDB_interface(%i, \"%s\"): Failed to bind iface (error %d): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}
	// Bind network_id to prepared statement (2nd argument)
	if((rc = sqlite3_bind_int(query_stmt, 2, network_id)) != SQLITE_OK)
	{
		log_err("update_netDB_interface(%i, \"%s\"): Failed to bind name (error %d): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Perform step
	if ((rc = sqlite3_step(query_stmt)) != SQLITE_DONE)
	{
		log_err("update_netDB_interface(%i, \"%s\"): Failed to step (error %d): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	// Finalize statement
	if ((rc = sqlite3_finalize(query_stmt)) != SQLITE_OK)
	{
		log_err("update_netDB_interface(%i, \"%s\"): Failed to finalize (error %d): %s",
		        network_id, iface, rc, sqlite3_errstr(rc));
		sqlite3_reset(query_stmt);
		checkFTLDBrc(rc);
		return rc;
	}

	return SQLITE_OK;
}

// Loop over all clients known to FTL and ensure we add them all to the database
static bool add_FTL_clients_to_network_table(sqlite3 *db, const enum arp_status *client_status,
                                             const int clients, const time_t now, unsigned int *additional_entries)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	int rc = SQLITE_OK;
	char hwaddr[128];
	for(int clientID = 0; clientID < clients; clientID++)
	{
		// Check thread cancellation
		if(killed)
			break;

		// Get client pointer
		lock_shm();
		clientsData *client = getClient(clientID, true);
		if(client == NULL)
		{
			log_debug(DEBUG_ARP, "Network table: Client %d returned NULL pointer", clientID);
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
		char *hostname, *ipaddr, *interface;
		ipaddr = strdup(getstr(client->ippos));
		hostname = strdup(getstr(client->namepos));
		interface = strdup(getstr(client->ifacepos));

		// Skip if already handled above (first check against clients_array_size as we might have added
		// more clients to FTL's memory herein (those known only from the database))
		if(client_status[clientID] != CLIENT_NOT_HANDLED)
		{
			log_debug(DEBUG_ARP, "Network table: Client %s known through ARP/neigh cache",
			          ipaddr);
			if(ipaddr) free(ipaddr);
			if(hostname) free(hostname);
			if(interface) free(interface);
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
		else
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

			if(dbID >= 0)
			{
				log_debug(DEBUG_ARP, "Network table: Client with IP %s has no MAC info but was recently be seen for network ID %i",
						ipaddr, dbID);
			}

			//
			// Variant 3: Try to find a device with mock IP address
			// Only try this when there is no EDNS(0) MAC address available
			//
			if(dbID < 0)
			{
				unlock_shm();
				dbID = find_device_by_mock_hwaddr(db, ipaddr);
				lock_shm();

				// Reacquire client pointer (if may have changed when unlocking above)
				client = getClient(clientID, true);

				if(dbID >= 0)
				{
					log_debug(DEBUG_ARP, "Network table: Client with IP %s has no MAC info but is known as mock-hwaddr client with network ID %i",
					          ipaddr, dbID);
				}
			}

			// Create mock hardware address in the style of "ip-<IP address>", like "ip-127.0.0.1"
			strcpy(hwaddr, "ip-");
			strncpy(hwaddr+3, ipaddr, sizeof(hwaddr)-4);
			hwaddr[sizeof(hwaddr)-1] = '\0';
		}

		if(dbID == DB_FAILED)
		{
			// SQLite error
			if(ipaddr) free(ipaddr);
			if(hostname) free(hostname);
			if(interface) free(interface);
			break;
		}

		// Device not in database, add new entry
		else if(dbID == DB_NODATA)
		{
			char *macVendor = NULL;
			if(client->hwlen == 6)
			{
				// Normal client, MAC was likely obtained from EDNS(0) data
				unlock_shm();
				macVendor = getMACVendor(hwaddr);
				lock_shm();

				// Reacquire client pointer (if may have changed when unlocking above)
				client = getClient(clientID, true);
			}

			log_debug(DEBUG_ARP, "Network table: Creating new FTL device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\", interface = \"%s\"",
			          hwaddr, ipaddr, hostname, macVendor, interface);

			// Add new device to database
			const time_t lastQuery = client->lastQuery;
			const unsigned int numQueriesARP = client->numQueriesARP;
			unlock_shm();
			insert_netDB_device(db, hwaddr, now, lastQuery, numQueriesARP, macVendor);
			lock_shm();

			// Reacquire client pointer (if may have changed when unlocking above)
			client = getClient(clientID, true);

			// Reset client counter
			client->numQueriesARP = 0;

			// Free allocated memory (if allocated)
			if(macVendor != NULL)
			{
				free(macVendor);
				macVendor = NULL;
			}

			// Obtain ID which was given to this new entry
			dbID = sqlite3_last_insert_rowid(db);
		}
		else	// Device already in database
		{
			log_debug(DEBUG_ARP, "Network table: Updating existing FTL device MAC = %s, IP = %s, hostname = \"%s\", interface = \"%s\"",
			          hwaddr, ipaddr, hostname, interface);

			// Update timestamp of last query if applicable
			const time_t lastQuery = client->lastQuery;
			const unsigned int numQueriesARP = client->numQueriesARP;
			unlock_shm();
			rc = update_netDB_lastQuery(db, dbID, lastQuery);
			if(rc != SQLITE_OK)
			{
				if(ipaddr) free(ipaddr);
				if(hostname) free(hostname);
				if(interface) free(interface);
				break;
			}

			// Update number of queries if applicable
			rc = update_netDB_numQueries(db, dbID, numQueriesARP);
			if(rc != SQLITE_OK)
			{
				if(ipaddr) free(ipaddr);
				if(hostname) free(hostname);
				if(interface) free(interface);
				break;
			}

			lock_shm();
			// Reacquire client pointer (if may have changed when unlocking above)
			client = getClient(clientID, true);
			client->numQueriesARP = 0;
		}

		unlock_shm();

		// Add unique IP address / mock-MAC pair to network_addresses table
		// ipaddr is a local copy
		rc = add_netDB_network_address(db, dbID, ipaddr);
		if(rc != SQLITE_OK)
		{
			if(ipaddr) free(ipaddr);
			if(hostname) free(hostname);
			if(interface) free(interface);
			break;
		}

		// Update hostname if available
		// hostname is a local copy
		rc = update_netDB_name(db, ipaddr, hostname);
		if(rc != SQLITE_OK)
		{
			if(ipaddr) free(ipaddr);
			if(hostname) free(hostname);
			if(interface) free(interface);
			break;
		}

		// Update interface if available
		// interface is a local copy
		rc = update_netDB_interface(db, dbID, interface);
		if(rc != SQLITE_OK)
		{
			if(ipaddr) free(ipaddr);
			if(hostname) free(hostname);
			if(interface) free(interface);
			break;
		}

		// Add to number of processed ARP cache entries
		(*additional_entries)++;

		// Free allocated memory
		free(ipaddr);
		free(hostname);
		free(interface);
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

	// Try to access the kernel's Internet protocol address management
	FILE *ip_pipe = NULL;
	const char cmd[] = "ip address show";
	errno = ENOMEM;
	if((ip_pipe = popen(cmd, "r")) == NULL)
	{
		log_warn("Command \"%s\" failed: %s", cmd, strerror(errno));
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
		if(sscanf(linebuffer, "    inet%*[ ]%127[0-9.] brd", ipaddr) == 1)
		{
			// Obtained an IPv4 address
			ipaddr[sizeof(ipaddr)-1] = '\0';
		}
		else
		{
			// Try to read IPv6 address
			if(sscanf(linebuffer, "    inet6%*[ ]%127[0-9a-fA-F:] scope", ipaddr) == 1)
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
		char *macVendor = getMACVendor(hwaddr);

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
				char *querystr = NULL;
				if(asprintf(&querystr, "SELECT lastQuery from network where id = %i", mockID) < 10)
				{
					free(macVendor);
					return false;
				}
				lastQuery = db_query_int(db, querystr);
				free(querystr);

				if(asprintf(&querystr, "SELECT firstSeen from network where id = %i", mockID) < 10)
				{
					free(macVendor);
					return false;
				}
				firstSeen = db_query_int(db, querystr);
				free(querystr);

				if(asprintf(&querystr, "SELECT numQueries from network where id = %i", mockID) < 10)
				{
					free(macVendor);
					return false;
				}
				numQueries = db_query_int(db, querystr);
				free(querystr);
			}

			// Add new device to database
			insert_netDB_device(db, hwaddr, firstSeen, lastQuery, numQueries, macVendor);

			// Obtain ID which was given to this new entry
			dbID = sqlite3_last_insert_rowid(db);
		}
		else	// Device already in database
		{
			log_debug(DEBUG_ARP, "Network table: Updating existing ip a device MAC = %s, IP = %s, interface = \"%s\"",
			          hwaddr, ipaddr, iface);
		}

		//Free allocated memory
		if(macVendor != NULL)
		{
			free(macVendor);
			macVendor = NULL;
		}

		// Add unique IP address / mock-MAC pair to network_addresses table
		rc = add_netDB_network_address(db, dbID, ipaddr);
		if(rc != SQLITE_OK)
			break;

		// Update interface if available
		rc = update_netDB_interface(db, dbID, iface);
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

static bool clean_network_table(sqlite3* db)
{
	// Do not clean if disabled
	if(config.database.network.expire.v.ui == 0)
		return true;

	// Remove all but the most recent IP addresses not seen for more than a certain time
	const time_t limit = time(NULL)-24*3600*config.database.network.expire.v.ui;
	int rc = dbquery(db, "DELETE FROM network_addresses "
	                     "WHERE lastSeen < %lu;", (unsigned long)limit);
	if(rc != SQLITE_OK)
		return false;

	rc = dbquery(db, "UPDATE network_addresses SET name = NULL "
	                 "WHERE nameUpdated < %lu;", (unsigned long)limit);
	if(rc != SQLITE_OK)
		return false;

	return true;
}

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
void parse_neighbor_cache(sqlite3* db)
{
	// Prepare buffers
	char *linebuffer = NULL;
	size_t linebuffersize = 0u;
	unsigned int entries = 0u, additional_entries = 0u;
	time_t now = time(NULL);

	// Start ARP timer
	if(config.debug.arp.v.b)
		timer_start(ARP_TIMER);

	// Start transaction to speed up database queries, to avoid that the
	// database is locked by other processes and to allow for a rollback in
	// case of an error
	const char sql[] = "BEGIN TRANSACTION IMMEDIATE";
	int rc = dbquery(db, sql);
	if(rc != SQLITE_OK)
	{
		const char *text;
		if( rc == SQLITE_BUSY )
			text = "WARNING";
		else
			text = "ERROR";

		// dbquery() above already logs the reason for why the query failed
		log_warn("%s: Storing devices in network table (\"%s\") failed", text, sql);
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
	if (config.database.network.parseARPcache.v.b)
	{
		// Parse ARP cache and add new entries to network table
		FILE *arpfp = NULL;
		const char cmd[] = "ip neigh show";
		errno = ENOMEM;
		if((arpfp = popen(cmd, "r")) == NULL)
		{
			log_warn("Command \"%s\" failed: %s", cmd, strerror(errno));
			return;
		}

		// Read ARP cache line by line
		while(getline(&linebuffer, &linebuffersize, arpfp) != -1)
		{
			// Skip if line buffer is invalid
			if(linebuffer == NULL)
				continue;

			// Check thread cancellation
			if(killed)
				break;

			// Analyze line
			char ip[128], hwaddr[128], iface[128];
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
					lock_shm();
					int clientID = findClientID(ip, false, false);
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
			// false = do not create a new record if the client is
			//         unknown (only DNS requesting clients do this)
			lock_shm();
			int clientID = findClientID(ip, false, false);

			// Get hostname of this client if the client is known
			char *hostname = NULL;
			bool client_valid = false;
			time_t lastQuery = 0;
			unsigned int numQueries = 0;

			// This client is known (by its IP address) to pihole-FTL if
			// findClientID() returned a non-negative index
			if(clientID >= 0 && clientID < clients)
			{
				clientsData *client = getClient(clientID, true);
				if(!client)
					continue;

				client_valid = true;
				hostname = strdup(getstr(client->namepos));
				lastQuery = client->lastQuery;
				numQueries = client->numQueriesARP;
				client_status[clientID] = CLIENT_ARP_COMPLETE;
			}
			else
			{
				hostname = strdup("");
			}
			unlock_shm();

			// Device not in database, add new entry
			if(dbID == DB_NODATA)
			{
				// Try to obtain vendor from MAC database
				char *macVendor = getMACVendor(hwaddr);

				// Check if we recently added a mock-device with the same IP address
				// and the ARP entry just came a bit delayed (reported by at least one user)
				dbID = find_recent_device_by_mock_hwaddr(db, ip);

				if(dbID == DB_NODATA)
				{
					// Device not known AND no recent mock-device found ---> create new device record
					log_debug(DEBUG_ARP, "Network table: Creating new ARP device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\"",
					          hwaddr, ip, hostname, macVendor);

					// Create new record (INSERT)
					insert_netDB_device(db, hwaddr, now, lastQuery, numQueries, macVendor);

					lock_shm();
					clientsData *client = getClient(clientID, true);
					if(client != NULL)
					{
						// Reacquire client pointer (if may have changed when unlocking above)
						client = getClient(clientID, true);
						// Reset client ARP counter (we stored the entry in the database)
						client->numQueriesARP = 0;
					}
					unlock_shm();

					// Obtain ID which was given to this new entry
					dbID = sqlite3_last_insert_rowid(db);

					// Store hostname in the appropriate network_address record (if available)
					if(strlen(hostname) > 0)
					{
						rc = update_netDB_name(db, ip, hostname);
						if(rc != SQLITE_OK)
						{
							// Free allocated memory
							free(hostname);
							free(macVendor);
							break;
						}
					}
				}
				else
				{
					// Device is ALREADY KNOWN ---> convert mock-device to a "real" one
					log_debug(DEBUG_ARP, "Network table: Un-mocking ARP device MAC = %s, IP = %s, hostname = \"%s\", vendor = \"%s\"",
					          hwaddr, ip, hostname, macVendor);

					// Update/replace important device properties
					unmock_netDB_device(db, hwaddr, macVendor, dbID);

					// Host name, count and last query timestamp will be set in the next
					// loop iteration for the sake of simplicity
				}

				// Free allocated memory
				free(macVendor);
			}
			// Device in database AND client known to Pi-hole
			else if(client_valid)
			{
				log_debug(DEBUG_ARP, "Network table: Updating existing ARP device MAC = %s, IP = %s, hostname = \"%s\"",
				          hwaddr, ip, hostname);

				// Update timestamp of last query if applicable
				rc = update_netDB_lastQuery(db, dbID, lastQuery);
				if(rc != SQLITE_OK)
				{
					// Free allocated memory
					free(hostname);
					break;
				}

				// Update number of queries if applicable
				rc = update_netDB_numQueries(db, dbID, numQueries);
				if(rc != SQLITE_OK)
				{
					// Free allocated memory
					free(hostname);
					break;
				}

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
				rc = update_netDB_name(db, ip, hostname);
				if(rc != SQLITE_OK)
				{
					// Free allocated memory
					free(hostname);
					break;
				}
			}
			// else: Device in database but not known to Pi-hole

			free(hostname);
			hostname = NULL;

			// Store interface if available
			rc = update_netDB_interface(db, dbID, iface);
			if(rc != SQLITE_OK)
				break;

			// Add unique IP address / mock-MAC pair to network_addresses table
			rc = add_netDB_network_address(db, dbID, ip);
			if(rc != SQLITE_OK)
				break;

			// Count number of processed ARP cache entries
			entries++;
		}

		// Close pipe handle and free allocated memory
		pclose(arpfp);
		if(linebuffer != NULL)
			free(linebuffer);

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
	if((rc = dbquery(db, "END TRANSACTION")) != SQLITE_OK) {
		const char *text;
		if( rc == SQLITE_BUSY )
			text = "WARNING";
		else
			text = "ERROR";

		log_err("%s: Storing devices in network table failed: %s", text, sqlite3_errstr(rc));
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
			checkFTLDBrc(rc);
			return false;
		}

		// Obtain id and hwaddr of the most recent entry for this particular client
		const int id = sqlite3_column_int(stmt, 0);
		char *hwaddr = strdup((char*)sqlite3_column_text(stmt, 1));

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

		free(hwaddr);
	}

	// Finalize statement
	sqlite3_finalize(stmt);

	// Update database version to 4
	if(!db_set_FTL_property(db, DB_VERSION, 4))
		return false;

	// End transaction
	SQL_bool(db, "COMMIT");

	return true;
}

static char * __attribute__ ((malloc)) getMACVendor(const char *hwaddr)
{
	// Special handling for the loopback interface
	if(strcmp(hwaddr, "00:00:00:00:00:00") == 0)
			return strdup("virtual interface");

	struct stat st;
	if(stat(config.files.macvendor.v.s, &st) != 0)
	{
		// File does not exist
		log_debug(DEBUG_ARP, "getMACVenor(\"%s\"): %s does not exist", hwaddr, config.files.macvendor.v.s);
		return strdup("");
	}
	else if(strlen(hwaddr) != 17 || strstr(hwaddr, "ip-") != NULL)
	{
		// MAC address is incomplete or mock address (for distant clients)
		log_debug(DEBUG_ARP, "getMACVenor(\"%s\"): MAC invalid (length %zu)", hwaddr, strlen(hwaddr));
		return strdup("");
	}

	sqlite3 *macvendor_db = NULL;
	int rc = sqlite3_open_v2(config.files.macvendor.v.s, &macvendor_db, SQLITE_OPEN_READONLY, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getMACVendor(\"%s\") - SQL error: %s", hwaddr, sqlite3_errstr(rc));
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
	if(rc != SQLITE_OK)
	{
		log_err("getMACVendor(\"%s\") - SQL error prepare \"%s\": %s", hwaddr, querystr, sqlite3_errstr(rc));
		sqlite3_close(macvendor_db);
		return strdup("");
	}

	// Bind hwaddrshort to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, hwaddrshort, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("getMACVendor(\"%s\" -> \"%s\"): Failed to bind hwaddrshort: %s",
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
		log_err("getMACVendor(\"%s\") - SQL error step: %s", hwaddr, sqlite3_errstr(rc));
	}

	sqlite3_finalize(stmt);
	sqlite3_close(macvendor_db);

	log_debug(DEBUG_ARP, "DEBUG: MAC Vendor lookup for %s returned \"%s\"", hwaddr, vendor);

	return vendor;
}

void updateMACVendorRecords(sqlite3 *db)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return;

	struct stat st;
	if(stat(config.files.macvendor.v.s, &st) != 0)
	{
		// File does not exist
		log_debug(DEBUG_ARP, "updateMACVendorRecords(): \"%s\" does not exist", config.files.macvendor.v.s);
		return;
	}

	sqlite3_stmt *stmt = NULL;
	const char *selectstr = "SELECT id,hwaddr FROM network;";
	int rc = sqlite3_prepare_v2(db, selectstr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("updateMACVendorRecords() - SQL error prepare \"%s\": %s", selectstr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
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
			log_err("updateMACVendorRecords() - Allocation error");
			free(vendor);
			break;
		}

		// Execute prepared statement
		char *zErrMsg = NULL;
		rc = sqlite3_exec(db, updatestr, NULL, NULL, &zErrMsg);
		if(rc != SQLITE_OK)
		{
			log_err("updateMACVendorRecords() - SQL exec error: \"%s\": %s", updatestr, zErrMsg);
			checkFTLDBrc(rc);
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
		log_err("updateMACVendorRecords() - SQL error step: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return;
	}

	sqlite3_finalize(stmt);
}

// Get hardware address of device identified by IP address
char *__attribute__((malloc)) getMACfromIP(sqlite3* db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return NULL;

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false, false)) == NULL)
		{
			log_warn("getMACfromIP(\"%s\") - Failed to open DB", ipaddr);
			return NULL;
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
		checkFTLDBrc(rc);

		if(db_opened) dbclose(&db);

		return NULL;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("getMACfromIP(\"%s\"): Failed to bind ip: %s",
		        ipaddr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		if(db_opened) dbclose(&db);

		return NULL;
	}

	char *hwaddr = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		hwaddr = strdup((char*)sqlite3_column_text(stmt, 0));
	}
	else if(rc == SQLITE_DONE)
	{
		// Not found
		hwaddr = NULL;
	}
	else
	{
		log_err("getMACfromIP(\"%s\"): Failed step: %s",
		        ipaddr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		return NULL;
	}

	if(hwaddr != NULL)
		log_debug(DEBUG_DATABASE, "Found database hardware address %s -> %s", ipaddr, hwaddr);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened) dbclose(&db);

	return hwaddr;
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
	sqlite3_stmt *stmt = NULL;
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
		checkFTLDBrc(rc);

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getAliasclientIDfromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		if(db_opened) dbclose(&db);

		return DB_FAILED;
	}

	int aliasclient_id = DB_NODATA;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found
		aliasclient_id = sqlite3_column_int(stmt, 0);
	}
	else if(rc != SQLITE_DONE)
	{
		// Error, check for database corruption
		checkFTLDBrc(rc);
		return DB_FAILED;
	}

	log_debug(DEBUG_ALIASCLIENTS, "   Aliasclient ID %s -> %i%s", ipaddr, aliasclient_id,
	          (aliasclient_id == DB_NODATA) ? " (NOT FOUND)" : "");

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened) dbclose(&db);

	return aliasclient_id;
}

// Get host name of device identified by IP address
char *__attribute__((malloc)) getNameFromIP(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return NULL;

	// Check if we want to resolve host names
	if(!resolve_this_name(ipaddr))
	{
		log_debug(DEBUG_DATABASE, "getNameFromIP(\"%s\") - configured to not resolve host name", ipaddr);
		return NULL;
	}

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false, false)) == NULL)
		{
			log_warn("getNameFromIP(\"%s\") - Failed to open DB", ipaddr);
			return NULL;
		}

		// Successful
		db_opened = true;
	}

	// Check for a host name associated with the same IP address
	sqlite3_stmt *stmt = NULL;
	const char *querystr = "SELECT name FROM network_addresses WHERE name IS NOT NULL AND ip = ?;";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("getNameFromIP(\"%s\") - SQL error prepare: %s",
		        ipaddr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);

		if(db_opened) dbclose(&db);

		return NULL;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getNameFromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		if(db_opened) dbclose(&db);

		return NULL;
	}

	char *name = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		name = strdup((char*)sqlite3_column_text(stmt, 0));

		log_debug(DEBUG_DATABASE, "Found database host name (same address) %s -> %s", ipaddr, name);
	}
	else if(rc != SQLITE_DONE)
	{
		// Error
		checkFTLDBrc(rc);
		return NULL;
	}

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Return here if we found the name
	if(name != NULL)
	{
		if(db_opened) dbclose(&db);

		return name;
	}

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
		if(db_opened) dbclose(&db);
		return NULL;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getNameFromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		if(db_opened) dbclose(&db);

		return NULL;
	}

	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		name = strdup((char*)sqlite3_column_text(stmt, 0));

		if(config.debug.resolver.v.b)
			log_debug(DEBUG_RESOLVER, "Found database host name (same device) %s -> %s",
			          ipaddr, name);
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
		checkFTLDBrc(rc);
		return NULL;
	}

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened) dbclose(&db);

	return name;
}

// Get most recently seen host name of device identified by MAC address
char *__attribute__((malloc)) getNameFromMAC(const char *client)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return NULL;

	log_debug(DEBUG_DATABASE,"Looking up host name for %s", client);

	// Open pihole-FTL.db database file
	sqlite3 *db = NULL;
	if((db = dbopen(false, false)) == NULL)
	{
		log_warn("getNameFromMAC(\"%s\") - Failed to open DB", client);
		return NULL;
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
		dbclose(&db);
		return NULL;
	}

	// Bind client to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, client, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getNameFromMAC(\"%s\"): Failed to bind ip: %s",
		         client, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		dbclose(&db);
		return NULL;
	}

	char *name = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		name = strdup((char*)sqlite3_column_text(stmt, 0));

		if(config.debug.resolver.v.b)
			log_debug(DEBUG_RESOLVER, "Found database host name (by MAC) %s -> %s",
			          client, name);
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
		checkFTLDBrc(rc);
		return NULL;
	}

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	dbclose(&db);
	return name;
}

// Get interface of device identified by IP address
char *__attribute__((malloc)) getIfaceFromIP(sqlite3 *db, const char *ipaddr)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return NULL;

	// Open pihole-FTL.db database file if needed
	bool db_opened = false;
	if(db == NULL)
	{
		if((db = dbopen(false, false)) == NULL)
		{
			log_warn("getIfaceFromIP(\"%s\") - Failed to open DB", ipaddr);
			return NULL;
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
		if(db_opened) dbclose(&db);
		return NULL;
	}

	if(config.debug.resolver.v.b)
	{
		log_debug(DEBUG_RESOLVER, "getIfaceFromIP(): \"%s\" with ? = \"%s\"",
		          querystr, ipaddr);
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, ipaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_warn("getIfaceFromIP(\"%s\"): Failed to bind ip: %s",
		         ipaddr, sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		if(db_opened) dbclose(&db);

		return NULL;
	}

	char *iface = NULL;
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_ROW)
	{
		// Database record found (result might be empty)
		iface = strdup((char*)sqlite3_column_text(stmt, 0));
	}
	else if(rc != SQLITE_DONE)
	{
		// Error
		checkFTLDBrc(rc);
		return NULL;
	}

	if(iface != NULL)
		log_debug(DEBUG_DATABASE, "Found database interface %s -> %s", ipaddr, iface);

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	if(db_opened) dbclose(&db);

	return iface;
}

bool networkTable_readDevices(sqlite3 *db, sqlite3_stmt **read_stmt, const char **message)
{
	// Prepare SQLite statement
	const char *querystr = "SELECT id,hwaddr,interface,firstSeen,lastQuery,numQueries,macVendor FROM network ORDER BY lastQuery DESC;";
	int rc = sqlite3_prepare_v2(db, querystr, -1, read_stmt, NULL);
	if( rc != SQLITE_OK ){
		*message = sqlite3_errstr(rc);
		log_err("networkTable_readDevices() - SQL error prepare (%i): %s",
		        rc, *message);
		dbclose(&db);
		return false;
	}

	return true;
}

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
		sqlite3_reset(*read_stmt);
		sqlite3_finalize(*read_stmt);
		return false;
	}

	return true;
}

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

bool networkTable_deleteDevice(sqlite3 *db, const int id, int *deleted, const char **message)
{
	// First step: Delete all associated IPs of this device
	// Prepare SQLite statement
	const char *querystr = "DELETE FROM network_addresses WHERE network_id = ?;";
	sqlite3_stmt *stmt;
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
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Execute statement
	rc = sqlite3_step(stmt);
	if(rc != SQLITE_DONE)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i) - SQL error step (%i): %s",
		        id, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
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
		return false;
	}

	// Bind id to prepared statement
	if((rc = sqlite3_bind_int(stmt, 1, id)) != SQLITE_OK)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i): Failed to bind id (error %d) - %s",
		        id, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Execute statement
	rc = sqlite3_step(stmt);
	if(rc != SQLITE_DONE)
	{
		*message = sqlite3_errstr(rc);
		log_err("networkTable_deleteDevice(%i) - SQL error step (%i): %s",
		        id, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Check if we deleted any rows
	*deleted += sqlite3_changes(db);

	// Finalize statement
	sqlite3_finalize(stmt);

	return true;
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
