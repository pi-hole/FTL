/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "sqlite3.h"
#include "gravity-db.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// getstr()
#include "../shmem.h"
// SQLite3 prepared statement vectors
#include "../vector.h"
// log_subnet_warning()
// logg_inaccessible_adlist
#include "message-table.h"
// getMACfromIP()
#include "network-table.h"
// struct DNSCacheData
#include "../datastructure.h"
// reset_aliasclient()
#include "aliasclients.h"

// Definition of struct regexData
#include "../regex_r.h"

// Prefix of interface names in the client table
#define INTERFACE_SEP ":"

// Process-private prepared statements are used to support multiple forks (might
// be TCP workers) to use the database simultaneously without corrupting the
// gravity database
sqlite3_stmt_vec *whitelist_stmt = NULL;
sqlite3_stmt_vec *gravity_stmt = NULL;
sqlite3_stmt_vec *antigravity_stmt = NULL;
sqlite3_stmt_vec *blacklist_stmt = NULL;

// Private variables
static sqlite3 *gravity_db = NULL;
static sqlite3_stmt* table_stmt = NULL;
bool gravityDB_opened = false;
static bool gravity_abp_format = false;

// Table names corresponding to the enum defined in gravity-db.h
static const char* tablename[] = { "vw_gravity", "vw_blacklist", "vw_whitelist", "vw_regex_blacklist", "vw_regex_whitelist" , "client", "group", "adlist", "denied_domains", "allowed_domains", "" };

// Prototypes from functions in dnsmasq's source
extern void rehash(int size);

// Initialize gravity subroutines
void gravityDB_forked(void)
{
	// See "How To Corrupt An SQLite Database File"
	// (https://www.sqlite.org/howtocorrupt.html):
	// 2.6. Carrying an open database connection across a fork()
	//
	// Do not open an SQLite database connection, then fork(), then try to
	// use that database connection in the child process. All kinds of
	// locking problems will result and you can easily end up with a corrupt
	// database. SQLite is not designed to support that kind of behavior.
	// Any database connection that is used in a child process must be
	// opened in the child process, not inherited from the parent.
	//
	// Do not even call sqlite3_close() on a database connection from a
	// child process if the connection was opened in the parent. It is safe
	// to close the underlying file descriptor, but the sqlite3_close()
	// interface might invoke cleanup activities that will delete content
	// out from under the parent, leading to errors and perhaps even
	// database corruption.
	//
	// Hence, we pretend that we did not open the database so far
	// NOTE: Yes, this will leak memory into the forks, however, there isn't
	// much we can do about this. The "proper" solution would be to close
	// the finalize the prepared gravity database statements and close the
	// database connection *before* forking and re-open and re-prepare them
	// afterwards (independently once in the parent, once in the fork). It
	// is clear that this in not what we want to do as this is a slow
	// process and many TCP queries could lead to a DoS attack.
	gravityDB_opened = false;
	gravity_db = NULL;

	// Also pretend we have not yet prepared the list statements
	whitelist_stmt = NULL;
	blacklist_stmt = NULL;
	gravity_stmt = NULL;
	antigravity_stmt = NULL;

	// Open the database
	gravityDB_open();
}

static void gravity_check_ABP_format(void)
{
	// Check if we have a valid ABP format
	// We do this by checking the "abp_domains" property in the "info" table

	// Prepare statement
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(gravity_db,
	                            "SELECT value FROM info WHERE property = 'abp_domains';",
	                            -1, &stmt, NULL);

	if( rc != SQLITE_OK )
	{
		log_warn("gravity_check_ABP_format() - SQL error prepare: %s", sqlite3_errstr(rc));
		return;
	}

	// Execute statement
	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW )
	{
		// No result
		gravity_abp_format = false;
		sqlite3_finalize(stmt);
		return;
	}

	// Get result (SQLite3 stores 1 for TRUE, 0 for FALSE)
	gravity_abp_format = sqlite3_column_int(stmt, 0) != 0;

	// Finalize statement
	sqlite3_finalize(stmt);
}

// Open gravity database
bool gravityDB_open(void)
{
	struct stat st;
	if(stat(config.files.gravity.v.s, &st) != 0)
	{
		// File does not exist
		log_warn("gravityDB_open(): %s does not exist", config.files.gravity.v.s);
		return false;
	}

	if(gravityDB_opened && gravity_db != NULL)
	{
		log_debug(DEBUG_DATABASE, "gravityDB_open(): Database already connected");
		return true;
	}

	log_debug(DEBUG_DATABASE, "gravityDB_open(): Trying to open %s in read-only mode", config.files.gravity.v.s);
	int rc = sqlite3_open_v2(config.files.gravity.v.s, &gravity_db, SQLITE_OPEN_READWRITE, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("gravityDB_open() - SQL error: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}

	// Database connection is now open
	gravityDB_opened = true;

	// Tell SQLite3 to store temporary tables in memory. This speeds up read operations on
	// temporary tables, indices, and views.
	log_debug(DEBUG_DATABASE, "gravityDB_open(): Setting location for temporary object to MEMORY");
	char *zErrMsg = NULL;
	rc = sqlite3_exec(gravity_db, "PRAGMA temp_store = MEMORY", NULL, NULL, &zErrMsg);
	if( rc != SQLITE_OK )
	{
		log_err("gravityDB_open(PRAGMA temp_store) - SQL error (%i): %s", rc, zErrMsg);
		sqlite3_free(zErrMsg);
		gravityDB_close();
		return false;
	}

	// Set SQLite3 busy timeout to a user-defined value (defaults to 1 second)
	// to avoid immediate failures when the gravity database is still busy
	// writing the changes to disk
	log_debug(DEBUG_DATABASE, "gravityDB_open(): Setting busy timeout to %d", DATABASE_BUSY_TIMEOUT);
	sqlite3_busy_timeout(gravity_db, DATABASE_BUSY_TIMEOUT);

	// Prepare private vector of statements for this process (might be a TCP fork!)
	if(whitelist_stmt == NULL)
		whitelist_stmt = new_sqlite3_stmt_vec(counters->clients);
	if(blacklist_stmt == NULL)
		blacklist_stmt = new_sqlite3_stmt_vec(counters->clients);
	if(gravity_stmt == NULL)
		gravity_stmt = new_sqlite3_stmt_vec(counters->clients);
	if(antigravity_stmt == NULL)
		antigravity_stmt = new_sqlite3_stmt_vec(counters->clients);

	// Explicitly set busy handler to zero milliseconds
	log_debug(DEBUG_DATABASE, "gravityDB_open(): Setting busy timeout to zero");
	rc = sqlite3_busy_timeout(gravity_db, 0);
	if(rc != SQLITE_OK)
		log_err("gravityDB_open() - Cannot set busy handler: %s", sqlite3_errstr(rc));

	// Check (and remember in global variable) if there are any ABP-style
	// entries in the database
	gravity_check_ABP_format();

	log_debug(DEBUG_DATABASE, "gravityDB_open(): Successfully opened gravity.db");

	return true;
}

bool gravityDB_reopen(void)
{
	// We call this routine when reloading the cache.
	gravityDB_close();

	// Re-open gravity database
	return gravityDB_open();
}

static char* get_client_querystr(const char *table, const char *column, const char *groups)
{
	// Build query string with group filtering
	char *querystr = NULL;
	if(asprintf(&querystr, "SELECT %s from %s WHERE domain = ? AND group_id IN (%s);", column, table, groups) < 1)
	{
		log_err("get_client_querystr(%s, %s) - asprintf() error", table, groups);
		return NULL;
	}

	log_debug(DEBUG_DATABASE, "get_client_querystr: %s", querystr);

	return querystr;
}

// Determine whether to show IP or hardware address
static const char *show_client_string(const char *hwaddr, const char *hostname,
                                      const char *ip)
{
	if(hostname != NULL && strlen(hostname) > 0)
	{
		// Valid hostname address, display it
		return hostname;
	}
	else if(hwaddr != NULL && strncasecmp(hwaddr, "ip-", 3) != 0)
	{
		// Valid hardware address and not a mock-device
		return hwaddr;
	}

	// Fallback: display IP address
	return ip;
}

// Get associated groups for this client (if defined)
static bool get_client_groupids(clientsData* client)
{
	const char *ip = getstr(client->ippos);
	client->flags.found_group = false;
	client->groupspos = 0u;

	// Do not proceed when database is not available
	if(!gravityDB_opened && !gravityDB_open())
	{
		log_warn("get_client_groupids(): Gravity database not available");
		return false;
	}

	log_debug(DEBUG_DATABASE, "Querying gravity database for client with IP %s...", ip);

	// Check if client is configured through the client table
	// This will return nothing if the client is unknown/unconfigured
	const char *querystr = "SELECT count(id) matching_count, "
	                       "max(id) chosen_match_id, "
	                       "ip chosen_match_text, "
	                       "group_concat(id) matching_ids, "
	                       "subnet_match(ip,?) matching_bits FROM client "
	                       "WHERE matching_bits > 0 "
	                       "GROUP BY matching_bits "
	                       "ORDER BY matching_bits DESC LIMIT 1;";

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("get_client_groupids(\"%s\") - SQL error prepare: %s",
		        ip, sqlite3_errstr(rc));
		return false;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(table_stmt, 1, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("get_client_groupids(\"%s\"): Failed to bind ip: %s",
		        ip, sqlite3_errstr(rc));
		sqlite3_reset(table_stmt);
		sqlite3_finalize(table_stmt);
		return false;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	int matching_count = 0, chosen_match_id = -1, matching_bits = 0;
	char *matching_ids = NULL, *chosen_match_text = NULL;
	if(rc == SQLITE_ROW)
	{
		// There is a record for this client in the database,
		// extract the result (there can be at most one line)
		matching_count = sqlite3_column_int(table_stmt, 0);
		chosen_match_id = sqlite3_column_int(table_stmt, 1);
		chosen_match_text = strdup((const char*)sqlite3_column_text(table_stmt, 2));
		matching_ids = strdup((const char*)sqlite3_column_text(table_stmt, 3));
		matching_bits = sqlite3_column_int(table_stmt, 4);

		if(matching_count == 1)
			// Case matching_count > 1 handled below using logg_subnet_warning()
			log_debug(DEBUG_CLIENTS, "--> Found record for %s in the client table (group ID %d)", ip, chosen_match_id);
	}
	else if(rc == SQLITE_DONE)
	{
		log_debug(DEBUG_CLIENTS, "--> No record for %s in the client table", ip);
	}
	else
	{
		// Error
		log_err("get_client_groupids(\"%s\") - SQL error step: %s",
		        ip, sqlite3_errstr(rc));
		gravityDB_finalizeTable();
		return false;
	}

	// Finalize statement
	gravityDB_finalizeTable();

	if(matching_count > 1)
	{
		// There is more than one configured subnet that matches to current device
		// with the same number of subnet mask bits. This is likely unintended by
		// the user so we issue a warning so they can address it.
		// Example:
		//   Device 10.8.0.22
		//   Client 1: 10.8.0.0/24
		//   Client 2: 10.8.1.0/24
		logg_subnet_warning(ip, matching_count, matching_ids, matching_bits, chosen_match_text, chosen_match_id);
	}

	// Free memory if applicable
	if(matching_ids != NULL)
	{
		free(matching_ids);
		matching_ids = NULL;
	}
	if(chosen_match_text != NULL)
	{
		free(chosen_match_text);
		chosen_match_text = NULL;
	}

	// If we didn't find an IP address match above, try with MAC address matches
	// 1. Look up MAC address of this client
	//   1.1. Look up IP address in network_addresses table
	//   1.2. Get MAC address from this network_id
	// 2. If found -> Get groups by looking up MAC address in client table
	char *hwaddr = NULL;
	if(chosen_match_id < 0)
	{
		log_debug(DEBUG_CLIENTS, "Querying gravity database for MAC address of %s...", ip);

		// Do the lookup
		hwaddr = getMACfromIP(NULL, ip);

		if(hwaddr == NULL)
		{
			log_debug(DEBUG_CLIENTS, "--> No result.");
		}
		else if(strlen(hwaddr) > 3 && strncasecmp(hwaddr, "ip-", 3) == 0)
		{
			free(hwaddr);
			hwaddr = NULL;

			log_debug(DEBUG_CLIENTS, "Skipping mock-device hardware address lookup");
		}
		// Set MAC address from database information if available and the MAC address is not already set
		else if(client->hwlen != 6)
		{
			// Proper MAC parsing
			unsigned char data[6];
			const int n = sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			                     &data[0], &data[1], &data[2],
			                     &data[3], &data[4], &data[5]);

			// Set hwlen only if we got data
			if(n == 6)
			{
				memcpy(client->hwaddr, data, sizeof(data));
				client->hwlen = sizeof(data);
			}
		}

		// MAC address fallback: Try to synthesize MAC address from internal buffer
		if(hwaddr == NULL && client->hwlen == 6)
		{
			hwaddr = calloc(18, sizeof(char)); // 18 == sizeof("AA:BB:CC:DD:EE:FF")
			snprintf(hwaddr, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
			         client->hwaddr[0], client->hwaddr[1], client->hwaddr[2],
			         client->hwaddr[3], client->hwaddr[4], client->hwaddr[5]);

			log_debug(DEBUG_CLIENTS, "--> Obtained %s from internal ARP cache", hwaddr);
		}
	}

	// Check if we received a valid MAC address
	// This ensures we skip mock hardware addresses such as "ip-127.0.0.1"
	if(hwaddr != NULL)
	{
		log_debug(DEBUG_CLIENTS, "--> Querying client table for %s", hwaddr);

		// Check if client is configured through the client table
		// This will return nothing if the client is unknown/unconfigured
		// We use COLLATE NOCASE to ensure the comparison is done case-insensitive
		querystr = "SELECT id FROM client WHERE ip = ? COLLATE NOCASE;";

		// Prepare query
		rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
		if(rc != SQLITE_OK)
		{
			log_err("get_client_groupids(%s) - SQL error prepare: %s",
			        querystr, sqlite3_errstr(rc));
			free(hwaddr); // hwaddr != NULL -> memory has been allocated
			return false;
		}

		// Bind hwaddr to prepared statement
		if((rc = sqlite3_bind_text(table_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			log_err("get_client_groupids(\"%s\", \"%s\"): Failed to bind hwaddr: %s",
			        ip, hwaddr, sqlite3_errstr(rc));
			sqlite3_reset(table_stmt);
			sqlite3_finalize(table_stmt);
			free(hwaddr); // hwaddr != NULL -> memory has been allocated
			return false;
		}

		// Perform query
		rc = sqlite3_step(table_stmt);
		if(rc == SQLITE_ROW)
		{
			// There is a record for this client in the database,
			// extract the result (there can be at most one line)
			chosen_match_id = sqlite3_column_int(table_stmt, 0);

			log_debug(DEBUG_CLIENTS, "--> Found record for %s in the client table (group ID %d)", hwaddr, chosen_match_id);
		}
		else if(rc == SQLITE_DONE)
		{
			log_debug(DEBUG_CLIENTS, "--> There is no record for %s in the client table", hwaddr);
		}
		else
		{
			// Error
			log_err("get_client_groupids(\"%s\", \"%s\") - SQL error step: %s",
			        ip, hwaddr, sqlite3_errstr(rc));
			gravityDB_finalizeTable();
			free(hwaddr); // hwaddr != NULL -> memory has been allocated
			return false;
		}

		// Finalize statement and free allocated memory
		gravityDB_finalizeTable();
	}

	// If we did neither find an IP nor a MAC address match above, we try to look
	// up the client using its host name
	// 1. Look up host name address of this client
	// 2. If found -> Get groups by looking up host name in client table
	char *hostname = NULL;
	if(chosen_match_id < 0)
	{
		log_debug(DEBUG_CLIENTS, "Querying gravity database for host name of %s...", ip);

		// Do the lookup
		hostname = getNameFromIP(NULL, ip);

		if(hostname == NULL)
			log_debug(DEBUG_CLIENTS, "--> No result.");

		if(hostname != NULL && strlen(hostname) == 0)
		{
			free(hostname);
			hostname = NULL;
			log_debug(DEBUG_CLIENTS, "Skipping empty host name lookup");
		}
	}

	// Check if we received a valid MAC address
	// This ensures we skip mock hardware addresses such as "ip-127.0.0.1"
	if(hostname != NULL)
	{
		log_debug(DEBUG_CLIENTS, "--> Querying client table for %s", hostname);

		// Check if client is configured through the client table
		// This will return nothing if the client is unknown/unconfigured
		// We use COLLATE NOCASE to ensure the comparison is done case-insensitive
		querystr = "SELECT id FROM client WHERE ip = ? COLLATE NOCASE;";

		// Prepare query
		rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
		if(rc != SQLITE_OK)
		{
			log_err("get_client_groupids(%s) - SQL error prepare: %s",
			        querystr, sqlite3_errstr(rc));
			if(hwaddr) free(hwaddr);
			free(hostname); // hostname != NULL -> memory has been allocated
			return false;
		}

		// Bind hostname to prepared statement
		if((rc = sqlite3_bind_text(table_stmt, 1, hostname, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			log_err("get_client_groupids(\"%s\", \"%s\"): Failed to bind hostname: %s",
			        ip, hostname, sqlite3_errstr(rc));
			sqlite3_reset(table_stmt);
			sqlite3_finalize(table_stmt);
			if(hwaddr) free(hwaddr);
			free(hostname); // hostname != NULL -> memory has been allocated
			return false;
		}

		// Perform query
		rc = sqlite3_step(table_stmt);
		if(rc == SQLITE_ROW)
		{
			// There is a record for this client in the database,
			// extract the result (there can be at most one line)
			chosen_match_id = sqlite3_column_int(table_stmt, 0);

			log_debug(DEBUG_CLIENTS, "--> Found record for %s in the client table (group ID %d)", hostname, chosen_match_id);
		}
		else if(rc == SQLITE_DONE)
		{
			log_debug(DEBUG_CLIENTS, "--> There is no record for %s in the client table", hostname);
		}
		else
		{
			// Error
			log_err("get_client_groupids(\"%s\", \"%s\") - SQL error step: %s",
			        ip, hostname, sqlite3_errstr(rc));
			gravityDB_finalizeTable();
			if(hwaddr) free(hwaddr);
			free(hostname); // hostname != NULL -> memory has been allocated
			return false;
		}

		// Finalize statement and free allocated memory
		gravityDB_finalizeTable();
	}

	// If we did neither find an IP nor a MAC address and also no host name
	// match above, we try to look up the client using its interface
	// 1. Look up the interface of this client (FTL isn't aware of it
	//    when creating the client from history data!)
	// 2. If found -> Get groups by looking up interface in client table
	char *interface = NULL;
	if(chosen_match_id < 0)
	{
		log_debug(DEBUG_CLIENTS, "Querying gravity database for interface of %s...", ip);

		// Do the lookup
		interface = getIfaceFromIP(NULL, ip);

		if(interface == NULL)
			log_debug(DEBUG_CLIENTS, "--> No result.");

		if(interface != NULL && strlen(interface) == 0)
		{
			free(interface);
			interface = 0;
			log_debug(DEBUG_CLIENTS, "Skipping empty interface lookup");
		}
	}

	// Check if we received a valid interface
	if(interface != NULL)
	{
		log_debug(DEBUG_CLIENTS, "Querying client table for interface "INTERFACE_SEP"%s", interface);

		// Check if client is configured through the client table using its interface
		// This will return nothing if the client is unknown/unconfigured
		// We use the SQLite concatenate operator || to prepace the queried interface by ":"
		// We use COLLATE NOCASE to ensure the comparison is done case-insensitive
		querystr = "SELECT id FROM client WHERE ip = '"INTERFACE_SEP"' || ? COLLATE NOCASE;";

		// Prepare query
		rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
		if(rc != SQLITE_OK)
		{
			log_err("get_client_groupids(%s) - SQL error prepare: %s",
			        querystr, sqlite3_errstr(rc));
			if(hwaddr) free(hwaddr);
			if(hostname) free(hostname);
			free(interface); // interface != NULL -> memory has been allocated
			return false;
		}

		// Bind interface to prepared statement
		if((rc = sqlite3_bind_text(table_stmt, 1, interface, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			log_err("get_client_groupids(\"%s\", \"%s\"): Failed to bind interface: %s",
			        ip, interface, sqlite3_errstr(rc));
			sqlite3_reset(table_stmt);
			sqlite3_finalize(table_stmt);
			if(hwaddr) free(hwaddr);
			if(hostname) free(hostname);
			free(interface); // interface != NULL -> memory has been allocated
			return false;
		}

		// Perform query
		rc = sqlite3_step(table_stmt);
		if(rc == SQLITE_ROW)
		{
			// There is a record for this client in the database,
			// extract the result (there can be at most one line)
			chosen_match_id = sqlite3_column_int(table_stmt, 0);

			log_debug(DEBUG_CLIENTS, "--> Found record for interface "INTERFACE_SEP"%s in the client table (group ID %d)", interface, chosen_match_id);
		}
		else if(rc == SQLITE_DONE)
		{
			log_debug(DEBUG_CLIENTS, "--> There is no record for interface "INTERFACE_SEP"%s in the client table", interface);
		}
		else
		{
			// Error
			log_err("get_client_groupids(\"%s\", \"%s\") - SQL error step: %s",
			        ip, interface, sqlite3_errstr(rc));
			gravityDB_finalizeTable();
			if(hwaddr) free(hwaddr);
			if(hostname) free(hostname);
			free(interface); // interface != NULL -> memory has been allocated
			return false;
		}

		// Finalize statement and free allocated memory
		gravityDB_finalizeTable();
	}

	// We use the default group and return early here
	// if above lookups didn't return any results
	// (the client is not configured through the client table)
	if(chosen_match_id < 0)
	{
		log_debug(DEBUG_CLIENTS, "Gravity database: Client %s not found. Using default group.\n",
		          show_client_string(hwaddr, hostname, ip));

		client->groupspos = addstr("0");
		client->flags.found_group = true;

		if(hwaddr != NULL)
		{
			free(hwaddr);
			hwaddr = NULL;
		}

		if(hostname != NULL)
		{
			free(hostname);
			hostname = NULL;
		}

		if(interface != NULL)
		{
			free(interface);
			interface = NULL;
		}

		return true;
	}

	// Build query string to get possible group associations for this particular client
	// The SQL GROUP_CONCAT() function returns a string which is the concatenation of all
	// non-NULL values of group_id separated by ','. The order of the concatenated elements
	// is arbitrary, however, is of no relevance for your use case.
	// We check using a possibly defined subnet and use the first result
	querystr = "SELECT GROUP_CONCAT(group_id) FROM client_by_group "
	           "WHERE client_id = ?;";

	log_debug(DEBUG_CLIENTS, "Querying gravity database for client %s (getting groups)", ip);

	// Prepare query
	rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("get_client_groupids(\"%s\", \"%s\", %d) - SQL error prepare: %s",
		        ip, hwaddr, chosen_match_id, sqlite3_errstr(rc));
		sqlite3_finalize(table_stmt);
		return false;
	}

	// Bind hwaddr to prepared statement
	if((rc = sqlite3_bind_int(table_stmt, 1, chosen_match_id)) != SQLITE_OK)
	{
		log_err("get_client_groupids(\"%s\", \"%s\", %d): Failed to bind chosen_match_id: %s",
		        ip, hwaddr, chosen_match_id, sqlite3_errstr(rc));
		sqlite3_reset(table_stmt);
		sqlite3_finalize(table_stmt);
		return false;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	if(rc == SQLITE_ROW)
	{
		// There is a record for this client in the database
		const char* result = (const char*)sqlite3_column_text(table_stmt, 0);
		if(result != NULL)
		{
			client->groupspos = addstr(result);
			client->flags.found_group = true;
		}
	}
	else if(rc == SQLITE_DONE)
	{
		// Found no record for this client in the database
		// -> No associated groups
		client->groupspos = addstr("");
		client->flags.found_group = true;
	}
	else
	{
		log_err("get_client_groupids(\"%s\", \"%s\", %d) - SQL error step: %s",
		        ip, hwaddr, chosen_match_id, sqlite3_errstr(rc));
		gravityDB_finalizeTable();
		return false;
	}
	// Finalize statement
	gravityDB_finalizeTable();

	// Debug logging
	if(config.debug.clients.v.b)
	{
		if(interface != NULL)
		{
			log_debug(DEBUG_CLIENTS, "Gravity database: Client %s found (identified by interface %s). Using groups (%s)\n",
			          show_client_string(hwaddr, hostname, ip), interface, getstr(client->groupspos));
		}
		else
		{
			log_debug(DEBUG_CLIENTS, "Gravity database: Client %s found. Using groups (%s)\n",
			          show_client_string(hwaddr, hostname, ip), getstr(client->groupspos));
		}
	}

	// Free possibly allocated memory
	if(hwaddr != NULL)
	{
		free(hwaddr);
		hwaddr = NULL;
	}
	if(hostname != NULL)
	{
		free(hostname);
		hostname = NULL;
	}
	if(interface != NULL)
	{
		free(interface);
		interface = NULL;
	}

	// Return success
	return true;
}

char *__attribute__ ((malloc)) get_client_names_from_ids(const char *group_ids)
{
	// Build query string to get concatenated groups
	char *querystr = NULL;
	if(asprintf(&querystr, "SELECT GROUP_CONCAT(ip) FROM client "
	                       "WHERE id IN (%s);", group_ids) < 1)
	{
		log_err("group_names(%s) - asprintf() error", group_ids);
		return NULL;
	}

	log_debug(DEBUG_DATABASE, "Querying group names for IDs (%s)", group_ids);

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK){
		log_err("get_client_groupids(%s) - SQL error prepare: %s",
		        querystr, sqlite3_errstr(rc));
		sqlite3_finalize(table_stmt);
		free(querystr);
		return strdup("N/A");
	}

	// Perform query
	char *result = NULL;
	rc = sqlite3_step(table_stmt);
	if(rc == SQLITE_ROW)
	{
		// There is a record for this client in the database
		result = strdup((const char*)sqlite3_column_text(table_stmt, 0));
		if(result == NULL)
			result = strdup("N/A");
	}
	else if(rc == SQLITE_DONE)
	{
		// Found no record for this client in the database
		// -> No associated groups
		result = strdup("N/A");
	}
	else
	{
		log_err("group_names(%s) - SQL error step: %s",
		        querystr, sqlite3_errstr(rc));
		gravityDB_finalizeTable();
		free(querystr);
		return strdup("N/A");
	}
	// Finalize statement
	gravityDB_finalizeTable();
	free(querystr);
	return result;
}

// Prepare statements for scanning white- and blacklist as well as gravit for one client
bool gravityDB_prepare_client_statements(clientsData *client)
{
	// Return early if gravity database is not available
	if(!gravityDB_opened && !gravityDB_open())
		return false;

	const char *clientip = getstr(client->ippos);

	log_debug(DEBUG_DATABASE, "Initializing gravity statements for %s", clientip);

	// Get associated groups for this client (if defined)
	char *querystr = NULL;
	if(!client->flags.found_group && !get_client_groupids(client))
		return false;

	// Prepare whitelist statement
	// We use SELECT EXISTS() as this is known to efficiently use the index
	// We are only interested in whether the domain exists or not in the
	// list but don't case about duplicates or similar. SELECT EXISTS(...)
	// returns true as soon as it sees the first row from the query inside
	// of EXISTS().
	log_debug(DEBUG_DATABASE, "gravityDB_open(): Preparing vw_whitelist statement for client %s", clientip);
	querystr = get_client_querystr("vw_whitelist", "id", getstr(client->groupspos));
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v3(gravity_db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("gravityDB_open(\"SELECT(... vw_whitelist ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}
	whitelist_stmt->set(whitelist_stmt, client->id, stmt);
	free(querystr);

	// Prepare gravity statement
	log_debug(DEBUG_DATABASE, "gravityDB_open(): Preparing vw_gravity statement for client %s", clientip);
	querystr = get_client_querystr("vw_gravity", "adlist_id", getstr(client->groupspos));
	rc = sqlite3_prepare_v3(gravity_db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("gravityDB_open(\"SELECT(... vw_gravity ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}
	gravity_stmt->set(gravity_stmt, client->id, stmt);
	free(querystr);

	// Prepare antigravity statement
	log_debug(DEBUG_DATABASE, "gravityDB_open(): Preparing vw_antigravity statement for client %s", clientip);
	querystr = get_client_querystr("vw_antigravity", "adlist_id", getstr(client->groupspos));
	rc = sqlite3_prepare_v3(gravity_db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("gravityDB_open(\"SELECT(... vw_antigravity ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}
	antigravity_stmt->set(antigravity_stmt, client->id, stmt);
	free(querystr);

	// Prepare blacklist statement
	log_debug(DEBUG_DATABASE, "gravityDB_open(): Preparing vw_blacklist statement for client %s", clientip);
	querystr = get_client_querystr("vw_blacklist", "id", getstr(client->groupspos));
	rc = sqlite3_prepare_v3(gravity_db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("gravityDB_open(\"SELECT(... vw_blacklist ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}
	blacklist_stmt->set(blacklist_stmt, client->id, stmt);
	free(querystr);

	return true;
}

// Finalize non-NULL prepared statements and set them to NULL for a given client
static inline void gravityDB_finalize_client_statements(clientsData *client)
{
	log_debug(DEBUG_DATABASE, "Finalizing gravity statements for %s", getstr(client->ippos));

	if(whitelist_stmt != NULL &&
	   whitelist_stmt->get(whitelist_stmt, client->id) != NULL)
	{
		sqlite3_finalize(whitelist_stmt->get(whitelist_stmt, client->id));
		whitelist_stmt->set(whitelist_stmt, client->id, NULL);
	}
	if(blacklist_stmt != NULL &&
	   blacklist_stmt->get(blacklist_stmt, client->id) != NULL)
	{
		sqlite3_finalize(blacklist_stmt->get(blacklist_stmt, client->id));
		blacklist_stmt->set(blacklist_stmt, client->id, NULL);
	}
	if(gravity_stmt != NULL &&
	   gravity_stmt->get(gravity_stmt, client->id) != NULL)
	{
		sqlite3_finalize(gravity_stmt->get(gravity_stmt, client->id));
		gravity_stmt->set(gravity_stmt, client->id, NULL);
	}
	if(antigravity_stmt != NULL &&
	   antigravity_stmt->get(antigravity_stmt, client->id) != NULL)
	{
		sqlite3_finalize(antigravity_stmt->get(antigravity_stmt, client->id));
		antigravity_stmt->set(antigravity_stmt, client->id, NULL);
	}

	// Unset group found property to trigger a check next time the
	// client sends a query
	client->flags.found_group = false;
}

// Close gravity database connection
void gravityDB_close(void)
{
	// Return early if gravity database is not available
	if(!gravityDB_opened)
		return;

	// Finalize prepared list statements for all clients
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		clientsData *client = getClient(clientID, true);
		if(client != NULL)
			gravityDB_finalize_client_statements(client);
	}

	// Free allocated memory for vectors of prepared client statements
	free_sqlite3_stmt_vec(&whitelist_stmt);
	free_sqlite3_stmt_vec(&blacklist_stmt);
	free_sqlite3_stmt_vec(&gravity_stmt);
	free_sqlite3_stmt_vec(&antigravity_stmt);

	// Close table
	sqlite3_close(gravity_db);
	gravity_db = NULL;
	gravityDB_opened = false;
}

// Prepare a SQLite3 statement which can be used by gravityDB_getDomain() to get
// blocking domains from a table which is specified when calling this function
bool gravityDB_getTable(const unsigned char list)
{
	if(!gravityDB_opened && !gravityDB_open())
	{
		log_err("gravityDB_getTable(%u): Gravity database not available", list);
		return false;
	}

	// Checking for smaller than GRAVITY_LIST is omitted due to list being unsigned
	if(list >= UNKNOWN_TABLE)
	{
		log_warn("gravityDB_getTable(%u): Requested list is not known!", list);
		return false;
	}

	const char *querystr = NULL;
	// Build correct query string to be used depending on list to be read
	// We GROUP BY id as the view also includes the group_id leading to possible duplicates
	// when domains are included in more than one group
	if(list == GRAVITY_TABLE)
		querystr = "SELECT DISTINCT domain FROM vw_gravity";
	else if(list == EXACT_BLACKLIST_TABLE)
		querystr = "SELECT domain, id FROM vw_blacklist GROUP BY id";
	else if(list == EXACT_WHITELIST_TABLE)
		querystr = "SELECT domain, id FROM vw_whitelist GROUP BY id";
	else if(list == REGEX_DENY_TABLE)
		querystr = "SELECT domain, id FROM vw_regex_blacklist GROUP BY id";
	else if(list == REGEX_ALLOW_TABLE)
		querystr = "SELECT domain, id FROM vw_regex_whitelist GROUP BY id";

	// Prepare SQLite3 statement
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		log_err("readGravity(%s) - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}

	// Free allocated memory and return success
	return true;
}

// Get a single domain from a running SELECT operation
// This function returns a pointer to a string as long as there are domains
// available. Once we reached the end of the table, it returns NULL. It also
// returns NULL when it encounters an error (e.g., on reading errors). Errors
// are logged to FTL.log
// This function is performance critical as it might be called millions of times
// for large blocking lists
inline const char* gravityDB_getDomain(int *rowid)
{
	// Perform step
	const int rc = sqlite3_step(table_stmt);

	// Valid row
	if(rc == SQLITE_ROW)
	{
		const char* domain = (char*)sqlite3_column_text(table_stmt, 0);
		if(rowid != NULL)
			*rowid = sqlite3_column_int(table_stmt, 1);
		return domain;
	}

	// Check for error. An error happened when the result is neither
	// SQLITE_ROW (we returned earlier in this case), nor
	// SQLITE_DONE (we are finished reading the table)
	if(rc != SQLITE_DONE)
	{
		log_err("gravityDB_getDomain() - SQL error step: %s", sqlite3_errstr(rc));
		if(rowid != NULL)
			*rowid = -1;
		return NULL;
	}

	// Finished reading, nothing to get here
	if(rowid != NULL)
		*rowid = -1;
	return NULL;
}

// Finalize statement of a gravity database transaction
void gravityDB_finalizeTable(void)
{
	if(!gravityDB_opened)
		return;

	// Finalize statement
	sqlite3_finalize(table_stmt);
	table_stmt = NULL;
}

// Get number of domains in a specified table of the gravity database We return
// the constant DB_FAILED and log to FTL.log if we encounter any error
int gravityDB_count(const enum gravity_tables list)
{
	if(!gravityDB_opened && !gravityDB_open())
	{
		log_warn("gravityDB_count(%d): Gravity database not available", list);
		return DB_FAILED;
	}

	const char *querystr = NULL;
	// Build query string to be used depending on list to be read
	switch (list)
	{
		case GRAVITY_TABLE:
			// We get the number of unique gravity domains as counted and stored by gravity. Counting the number
			// of distinct domains in vw_gravity may take up to several minutes for very large blocking lists on
			// very low-end devices such as the Raspierry Pi Zero
			querystr = "SELECT value FROM info WHERE property = 'gravity_count';";
			break;
		case EXACT_BLACKLIST_TABLE:
			querystr = "SELECT COUNT(DISTINCT domain) FROM vw_blacklist";
			break;
		case EXACT_WHITELIST_TABLE:
			querystr = "SELECT COUNT(DISTINCT domain) FROM vw_whitelist";
			break;
		case REGEX_DENY_TABLE:
			querystr = "SELECT COUNT(DISTINCT domain) FROM vw_regex_blacklist";
			break;
		case REGEX_ALLOW_TABLE:
			querystr = "SELECT COUNT(DISTINCT domain) FROM vw_regex_whitelist";
			break;
		case CLIENTS_TABLE:
			querystr = "SELECT COUNT(1) FROM client";
			break;
		case GROUPS_TABLE:
			querystr = "SELECT COUNT(1) FROM \"group\" WHERE enabled != 0";
			break;
		case ADLISTS_TABLE:
			querystr = "SELECT COUNT(1) FROM adlist WHERE enabled != 0";
			break;
		case DENIED_DOMAINS_TABLE:
			querystr = "SELECT COUNT(1) FROM domainlist WHERE (type = 0 OR type = 2) AND enabled != 0";
			break;
		case ALLOWED_DOMAINS_TABLE:
			querystr = "SELECT COUNT(1) FROM domainlist WHERE (type = 1 OR type = 3) AND enabled != 0";
			break;
		case UNKNOWN_TABLE:
			log_err("List type %u unknown!", list);
			gravityDB_close();
			return DB_FAILED;
	}

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK){
		log_err("gravityDB_count(%s) - SQL error prepare %s", querystr, sqlite3_errstr(rc));
		gravityDB_finalizeTable();
		gravityDB_close();
		return DB_FAILED;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	if(rc != SQLITE_ROW){
		log_err("gravityDB_count(%s) - SQL error step %s", querystr, sqlite3_errstr(rc));

		if(list == GRAVITY_TABLE)
			log_warn("Count of gravity domains not available. Please run pihole -g");

		gravityDB_finalizeTable();
		gravityDB_close();
		return DB_FAILED;
	}

	// Get result when there was no error
	const int result = sqlite3_column_int(table_stmt, 0);
	log_debug(DEBUG_DATABASE, "Found %d distinct rows in gravity table %s", result, tablename[list]);

	// Finalize statement
	gravityDB_finalizeTable();

	// Return result
	return result;
}

static enum db_result domain_in_list(const char *domain, sqlite3_stmt *stmt, const char *listname, int *domain_id)
{
	// Do not try to bind text to statement when database is not available
	if(!gravityDB_opened && !gravityDB_open())
	{
		log_err("domain_in_list(\"%s\", %p, %s): Gravity database not available",
		        domain, stmt, listname);
		return LIST_NOT_AVAILABLE;
	}

	int rc;
	// Bind domain to prepared statement
	// SQLITE_STATIC: Use the string without first duplicating it internally.
	// We can do this as domain has dynamic scope that exceeds that of the binding.
	// We need to bind the domain only once:
	//     When the same named SQL parameter is used more than once, second and
	//     subsequent occurrences have the same index as the first occurrence.
	//     (https://www.sqlite.org/c3ref/bind_blob.html)
	if((rc = sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("domain_in_list(\"%s\", %p, %s): Failed to bind domain: %s",
		        domain, stmt, listname, sqlite3_errstr(rc));
		return LIST_NOT_AVAILABLE;
	}

	// Perform step
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_BUSY)
	{
		// Database is busy
		log_warn("domain_in_list(\"%s\", %p, %s): Database is busy, assuming domain is NOT on list",
		         domain, stmt, listname);
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return LIST_NOT_AVAILABLE;
	}
	else if(rc != SQLITE_ROW && rc != SQLITE_DONE)
	{
		// Any return code that is neither SQLITE_BUSY not SQLITE_ROW
		// is a real error we should log
		log_err("domain_in_list(\"%s\", %p, %s): Failed to perform step: %s",
		        domain, stmt, listname, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return LIST_NOT_AVAILABLE;
	}

	// Get result of query (if available)
	const int result = (rc == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : -1;
	if(domain_id != NULL)
		*domain_id = result;

	log_debug(DEBUG_DATABASE, "domain_in_list(\"%s\", %p, %s): %d", domain, stmt, listname, result);

	// The sqlite3_reset() function is called to reset a prepared statement
	// object back to its initial state, ready to be re-executed. Note: Any SQL
	// statement variables that had values bound to them using the
	// sqlite3_bind_*() API retain their values.
	sqlite3_reset(stmt);

	// Contrary to the intuition of many, sqlite3_reset() does not reset the
	// bindings on a prepared statement. Use this routine to reset all host
	// parameters to NULL.
	sqlite3_clear_bindings(stmt);

	// Return if domain was found in current table
	return (rc == SQLITE_ROW) ? FOUND : NOT_FOUND;
}

void gravityDB_reload_groups(clientsData* client)
{
	// Rebuild client table statements (possibly from a different group set)
	gravityDB_finalize_client_statements(client);
	gravityDB_prepare_client_statements(client);

	// Reload regex for this client (possibly from a different group set)
	reload_per_client_regex(client);
}

// Check if this client needs a rechecking of group membership
// This client may be identified by something that wasn't there on its first query (hostname, MAC address, interface)
static void gravityDB_client_check_again(clientsData* client)
{
	const time_t diff = time(NULL) - client->firstSeen;
	const unsigned char check_count = client->reread_groups + 1u;
	if(check_count <= NUM_RECHECKS && diff > check_count * RECHECK_DELAY)
	{
		const char *ord = get_ordinal_suffix(check_count);
		log_debug(DEBUG_CLIENTS, "Reloading client groups after %u seconds (%u%s check)",
		          (unsigned int)diff, check_count, ord);
		client->reread_groups++;
		gravityDB_reload_groups(client);
	}
}

enum db_result in_allowlist(const char *domain, DNSCacheData *dns_cache, clientsData* client)
{
	// If list statement is not ready and cannot be initialized (e.g. no
	// access to the database), we return false to prevent an FTL crash
	if(whitelist_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Check if this client needs a rechecking of group membership
	gravityDB_client_check_again(client);

	// Check again as the client may have been reloaded if this is a TCP
	// worker
	if(whitelist_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Get whitelist statement from vector of prepared statements if available
	sqlite3_stmt *stmt = whitelist_stmt->get(whitelist_stmt, client->id);

	// If client statement is not ready and cannot be initialized (e.g. no access to
	// the database), we return false (not in whitelist) to prevent an FTL crash
	if(stmt == NULL && !gravityDB_prepare_client_statements(client))
	{
		log_err("Gravity database not available (allowlist)");
		return LIST_NOT_AVAILABLE;
	}

	// Update statement if has just been initialized
	if(stmt == NULL)
		stmt = whitelist_stmt->get(whitelist_stmt, client->id);

	// We have to check both the exact whitelist (using a prepared database statement)
	// as well the compiled regex whitelist filters to check if the current domain is
	// whitelisted.
	return domain_in_list(domain, stmt, "whitelist", &dns_cache->list_id);
}

cJSON *gen_abp_patterns(const char *domain, const bool antigravity)
{
	// Make a private copy of the domain we will slowly truncate while
	// extracting the individual components below
	char *domainBuf = strdup(domain);
	const size_t domainBufLen = strlen(domainBuf);

	// Buffer to hold the constructed (sub)domain in ABP format
	const char *abp_template = antigravity ? "@@||^" : "||^";
	const size_t intro_len = strlen(abp_template) - 1; // "@@||" or "||" without the trailing "^"
	char *abpDomain = calloc(domainBufLen + intro_len + 4, sizeof(char));
	// Prime abp matcher with minimal content
	strcpy(abpDomain, abp_template);

	// Get number of domain parts (equals the number of dots + 1)
	unsigned int N = 1u;
	for(const char *p = domainBuf; *p != '\0'; p++)
		if(*p == '.')
			N++;

	// Loop over domain parts, building matcher from the TLD
	// going down into domain and subdomains one by one
	cJSON *patterns = cJSON_CreateArray();
	while(N-- > 0)
	{
		// Get domain to the *last* occurrence of '.'
		char *ptr = strrchr(domainBuf, '.');

		// If there are no '.' left in the domain buffer, we use the
		// remainder which is the left-most domain component
		if(ptr == NULL)
			ptr = domainBuf;

		// Get size of this component...
		const size_t component_size = strlen(ptr);
		// ... and use it to create a "gap" of the right size in our ABP
		// format buffer
		// Insert the domain component into the gap
		if(ptr[0] == '.')
		{
			// If the component starts with a dot, we need
			// to skip it when copying it into the ABP buffer
			// Move excluding initial "(@@)||" but including final \0 (strlen-intro_len+1 = strlen-1)
			// Example: We need to insert "defg." into "||abc^:
			//                111
			//      0123456789012
			//      @@||abc^
			// to:  @@||_____abc^ (_ = space made by memmove), because strlen("defg.") = 5
			memmove(abpDomain + intro_len + (component_size - 1), abpDomain + intro_len, strlen(abpDomain) - (intro_len - 1));
			// Copy component bytes, we use component_size - 1
			// because we exclude the trailing null-byte (we insert
			// in the middle of the other string)
			// Example: We need to insert "defg." into "||___abc^:
			//                111
			//      0123456789012
			//      @@||_____abc^
			// to:  @@||defg.abc^
			memcpy(abpDomain + intro_len, ptr + 1, component_size - 1);
		}
		else
		{
			// Otherwise, we copy the component as-is
			// Example: We need to insert "abc" into "||^:
			//                1
			//      01234567890
			//      @@||^
			// to:  @@||___^ (_ = space made by memmove), because strlen("abc") = 3
			memmove(abpDomain + intro_len + component_size, abpDomain + intro_len, strlen(abpDomain) - (intro_len - 1));
			// Copy component bytes (excl. trailing null-byte)
			// Example: We need to insert "abc" into "||___^:
			//                1
			//      01234567890
			//      @@||___^
			// to:  @@||abc^
			memcpy(abpDomain + intro_len, ptr, component_size);
		}

		// Add the current ABP domain to the list of patterns
		cJSON_AddItemToArray(patterns, cJSON_CreateString(abpDomain));

		// Truncate the domain buffer to the left of the
		// last dot, effectively removing the last component
		const ssize_t truncate_pos = strlen(domainBuf) - component_size;
		if(truncate_pos < 1)
			// This was already the last iteration
			break;

		// Put a null-byte at the truncation position
		domainBuf[truncate_pos] = '\0';

		// Move the ABP buffer to the right by one byte ...
		memmove(abpDomain + intro_len + 1, abpDomain + intro_len, strlen(abpDomain));
		// ... and insert '.' for the next iteration
		abpDomain[intro_len] = '.';
	}

	free(domainBuf);
	free(abpDomain);

	return patterns;
}

enum db_result in_gravity(const char *domain, clientsData *client, const bool antigravity, int *domain_id)
{
	// If list statement is not ready and cannot be initialized (e.g. no
	// access to the database), we return false to prevent an FTL crash
	if(gravity_stmt == NULL || antigravity_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Check if this client needs a rechecking of group membership
	gravityDB_client_check_again(client);

	// Check again as the client may have been reloaded if this is a TCP
	// worker
	if(gravity_stmt == NULL || antigravity_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Get whitelist statement from vector of prepared statements
	sqlite3_stmt *stmt = antigravity ?
		antigravity_stmt->get(antigravity_stmt, client->id) :
		gravity_stmt->get(gravity_stmt, client->id);

	// Get string for debug logging
	const char *listname = antigravity ? "antigravity" : "gravity";

	// If client statement is not ready and cannot be initialized (e.g. no access to
	// the database), we return false (not in gravity list) to prevent an FTL crash
	if(stmt == NULL && !gravityDB_prepare_client_statements(client))
	{
		log_err("Gravity database not available (%s)", listname);
		return LIST_NOT_AVAILABLE;
	}

	// Update statement if has just been initialized
	if(stmt == NULL)
		antigravity ?
			antigravity_stmt->get(antigravity_stmt, client->id) :
			gravity_stmt->get(gravity_stmt, client->id);

	// Check if domain is exactly in gravity list
	const enum db_result exact_match = domain_in_list(domain, stmt, listname, domain_id);
	log_debug(DEBUG_QUERIES, "Checking if \"%s\" is in %s (exact): %s",
	          domain, listname, exact_match == FOUND ? "yes" : "no");
	// Return for anything else than "not found" (e.g. "found" or "list not available")
	if(exact_match != NOT_FOUND)
		return exact_match;

	// Return early if we are not supposed to check for ABP-style regex
	// matches. This needs to be enabled in the config file as it is
	// computationally expensive and not needed in most cases (HOSTS lists).
	if(!gravity_abp_format)
		return NOT_FOUND;

	// Generate ABP patterns for domain
	cJSON *abp_patterns = gen_abp_patterns(domain, antigravity);
	if(abp_patterns == NULL)
	{
		log_err("Failed to generate ABP patterns for domain \"%s\"", domain);
		return LIST_NOT_AVAILABLE;
	}

	// Check if any of the ABP patterns is in the (anti)gravity list
	cJSON * abp_pattern = NULL;
	cJSON_ArrayForEach(abp_pattern, abp_patterns)
	{
		const char *pattern = cJSON_GetStringValue(abp_pattern);
		log_debug(DEBUG_QUERIES, "Checking if \"%s\" is in %s (ABP): %s",
		          pattern, listname, exact_match == FOUND ? "yes" : "no");
		const enum db_result abp_match = domain_in_list(pattern, stmt, listname, domain_id);
		if(abp_match == FOUND || abp_match == LIST_NOT_AVAILABLE)
		{
			cJSON_Delete(abp_patterns);
			return FOUND;
		}
	}

	// Domain not found in gravity list
	cJSON_Delete(abp_patterns);
	return NOT_FOUND;
}

enum db_result in_denylist(const char *domain, DNSCacheData *dns_cache, clientsData *client)
{
	// If list statement is not ready and cannot be initialized (e.g. no
	// access to the database), we return false to prevent an FTL crash
	if(blacklist_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Check if this client needs a rechecking of group membership
	gravityDB_client_check_again(client);

	// Check again as the client may have been reloaded if this is a TCP
	// worker
	if(blacklist_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Get whitelist statement from vector of prepared statements
	sqlite3_stmt *stmt = blacklist_stmt->get(blacklist_stmt, client->id);

	// If client statement is not ready and cannot be initialized (e.g. no access to
	// the database), we return false (not in blacklist) to prevent an FTL crash
	if(stmt == NULL && !gravityDB_prepare_client_statements(client))
	{
		log_err("Gravity database not available (denylist)");
		return LIST_NOT_AVAILABLE;
	}

	// Update statement if has just been initialized
	if(stmt == NULL)
		stmt = blacklist_stmt->get(blacklist_stmt, client->id);

	return domain_in_list(domain, stmt, "blacklist", &dns_cache->list_id);
}

bool gravityDB_get_regex_client_groups(clientsData* client, const unsigned int numregex, const regexData *regex,
                                       const unsigned char type, const char* table)
{
	log_debug(DEBUG_REGEX, "Getting regex client groups for client with ID %u", client->id);

	char *querystr = NULL;
	if(!client->flags.found_group && !get_client_groupids(client))
		return false;

	// Group filtering
	const char *groups = getstr(client->groupspos);
	if(asprintf(&querystr, "SELECT id from %s WHERE group_id IN (%s);", table, groups) < 1)
	{
		log_err("gravityDB_get_regex_client_groups(%s, %s) - asprintf() error", table, groups);
		return false;
	}

	// Prepare query
	sqlite3_stmt *query_stmt;
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK){
		log_err("gravityDB_get_regex_client_groups(): %s - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		gravityDB_close();
		free(querystr);
		return false;
	}

	// Perform query
	log_debug(DEBUG_REGEX, "Regex %s: Querying groups for client %s: \"%s\"", regextype[type], getstr(client->ippos), querystr);
	while((rc = sqlite3_step(query_stmt)) == SQLITE_ROW)
	{
		const int result = sqlite3_column_int(query_stmt, 0);
		for(unsigned int regexID = 0; regexID < numregex; regexID++)
		{
			if(regex[regexID].database_id == result)
			{
				// Regular expressions are stored in one array
				if(type == REGEX_ALLOW)
					regexID += get_num_regex(REGEX_DENY);
				set_per_client_regex(client->id, regexID, true);

				log_debug(DEBUG_REGEX, "Regex %s: Enabling regex with DB ID %i for client %s",
				          regextype[type], result, getstr(client->ippos));

				break;
			}
		}
	}

	// Finalize statement
	sqlite3_finalize(query_stmt);

	// Free allocated memory and return result
	free(querystr);

	return true;
}

bool gravityDB_addToTable(const enum gravity_list_type listtype, tablerow *row,
                          const char **message, const enum http_method method)
{
	if(gravity_db == NULL)
	{
		*message = "Database not available";
		return false;
	}

	switch (listtype)
	{
		case GRAVITY_DOMAINLIST_ALLOW_EXACT:
			row->type_int = 0;
			break;
		case GRAVITY_DOMAINLIST_DENY_EXACT:
			row->type_int = 1;
			break;
		case GRAVITY_DOMAINLIST_ALLOW_REGEX:
			row->type_int = 2;
			break;
		case GRAVITY_DOMAINLIST_DENY_REGEX:
			row->type_int = 3;
			break;
		case GRAVITY_GRAVITY:
			row->type_int = 0;
			break;
		case GRAVITY_ANTIGRAVITY:
			row->type_int = 1;
			break;

		// Nothing to be done for these tables
		case GRAVITY_GROUPS:
		case GRAVITY_ADLISTS:
		case GRAVITY_ADLISTS_BLOCK:
		case GRAVITY_ADLISTS_ALLOW:
		case GRAVITY_CLIENTS:
			break;

		// Aggregate types are not handled by this routine
		case GRAVITY_DOMAINLIST_ALLOW_ALL:
		case GRAVITY_DOMAINLIST_DENY_ALL:
		case GRAVITY_DOMAINLIST_ALL_EXACT:
		case GRAVITY_DOMAINLIST_ALL_REGEX:
		case GRAVITY_DOMAINLIST_ALL_ALL:
			return false;
	}

	// Prepare SQLite statement
	sqlite3_stmt* stmt = NULL;
	const char *querystr;
	if(method == HTTP_POST) // Create NEW entry, error if existing
	{
		// The item is the item for all POST requests
		if(listtype == GRAVITY_GROUPS)
		{
			querystr = "INSERT INTO \"group\" (name,enabled,description) VALUES (:item,:enabled,:comment);";
		}
		else if(listtype == GRAVITY_ADLISTS ||
		        listtype == GRAVITY_ADLISTS_BLOCK ||
		        listtype == GRAVITY_ADLISTS_ALLOW)
		{
			querystr = "INSERT INTO adlist (address,enabled,comment,type) VALUES (:item,:enabled,:comment,:type);";
		}
		else if(listtype == GRAVITY_CLIENTS)
		{
			querystr = "INSERT INTO client (ip,comment) VALUES (:item,:comment);";
		}
		else // domainlist
		{
			querystr = "INSERT INTO domainlist (domain,type,enabled,comment) VALUES (:item,:type,:enabled,:comment);";
		}
	}
	else
	{	// Create new or replace existing entry, no error if existing
		// We UPSERT here to avoid violating FOREIGN KEY constraints
		if(listtype == GRAVITY_GROUPS)
			if(row->name == NULL)
			{
				// Name is not to be changed
				querystr = "INSERT INTO \"group\" (name,enabled,description) VALUES (:item,:enabled,:comment) "
				           "ON CONFLICT(name) DO UPDATE SET enabled = :enabled, description = :comment;";
			}
			else
			{
				querystr = "UPDATE \"group\" SET name = :name, enabled = :enabled, description = :comment "
				           "WHERE name = :item";
			}
		else if(listtype == GRAVITY_ADLISTS ||
		        listtype == GRAVITY_ADLISTS_BLOCK ||
		        listtype == GRAVITY_ADLISTS_ALLOW)
			querystr = "INSERT INTO adlist (address,enabled,comment,type) VALUES (:item,:enabled,:comment,:type) "\
			           "ON CONFLICT(address,type) DO UPDATE SET enabled = :enabled, comment = :comment, type = :type;";
		else if(listtype == GRAVITY_CLIENTS)
			querystr = "INSERT INTO client (ip,comment) VALUES (:item,:comment) "\
			           "ON CONFLICT(ip) DO UPDATE SET comment = :comment;";
		else // domainlist
			querystr = "INSERT INTO domainlist (domain,type,enabled,comment) VALUES (:item,:oldtype,:enabled,:comment) "\
			           "ON CONFLICT(domain,type) DO UPDATE SET type = :type, enabled = :enabled, comment = :comment;";
	}

	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_addToTable(%d, %s) - SQL error prepare (%i): %s",
		        row->type_int, row->item, rc, *message);
		return false;
	}

	// Bind item to prepared statement (if requested)
	const int item_idx = sqlite3_bind_parameter_index(stmt, ":item");
	if(item_idx > 0 && (rc = sqlite3_bind_text(stmt, item_idx, row->item, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_addToTable(%d, %s): Failed to bind item (error %d) - %s",
		        row->type_int, row->item, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind name to prepared statement (if requested)
	const int name_idx = sqlite3_bind_parameter_index(stmt, ":name");
	if(name_idx > 0 && (rc = sqlite3_bind_text(stmt, name_idx, row->name, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_addToTable(%d, %s): Failed to bind name (error %d) - %s",
		        row->type_int, row->item, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind type to prepared statement (if requested)
	const int type_idx = sqlite3_bind_parameter_index(stmt, ":type");
	if(type_idx > 0 && (rc = sqlite3_bind_int(stmt, type_idx, row->type_int)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_addToTable(%d, %s): Failed to bind type (error %d) - %s",
		        row->type_int, row->item, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind oldtype to prepared statement (if requested)
	const int oldtype_idx = sqlite3_bind_parameter_index(stmt, ":oldtype");
	int oldtype = -1;
	if(oldtype_idx > 0)
	{
		if(row->type == NULL && row->kind == NULL)
		{
			// User didn't specify oldtype/oldkind, just replace without moving
			oldtype = row->type_int;
		}
		else if(row->type == NULL)
		{
			// Error, one is not meaningful without the other
			*message = "Field type missing from request";
			log_err("gravityDB_addToTable(%d, %s): type missing",
			        row->type_int, row->item);
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			return false;
		}
		else if(row->kind == NULL)
		{
			// Error, one is not meaningful without the other
			*message = "Field oldkind missing from request";
			log_err("gravityDB_addToTable(%d, %s): Oldkind missing",
			        row->type_int, row->item);
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			return false;
		}
		else
		{
			if(strcasecmp("allow", row->type) == 0 &&
			   strcasecmp("exact", row->kind) == 0)
			        oldtype = 0;
			else if(strcasecmp("deny", row->type) == 0 &&
					strcasecmp("exact", row->kind) == 0)
			        oldtype = 1;
			else if(strcasecmp("allow", row->type) == 0 &&
					strcasecmp("regex", row->kind) == 0)
			        oldtype = 2;
			else if(strcasecmp("deny", row->type) == 0 &&
			        strcasecmp("regex", row->kind) == 0)
				oldtype = 3;
			else
			{
				*message = "Cannot interpret type/kind";
				log_err("gravityDB_addToTable(%d, %s): Failed to identify type=\"%s\", kind=\"%s\"",
				        row->type_int, row->item, row->type, row->kind);
				sqlite3_reset(stmt);
				sqlite3_finalize(stmt);
				return false;
			}
		}

		// Bind oldtype to database statement
		if((rc = sqlite3_bind_int(stmt, oldtype_idx, oldtype)) != SQLITE_OK)
		{
			*message = sqlite3_errmsg(gravity_db);
			log_err("gravityDB_addToTable(%d, %s): Failed to bind oldtype (error %d) - %s",
			        row->type_int, row->item, rc, *message);
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			return false;
		}
	}

	// Bind enabled boolean to prepared statement (if requested)
	const int enabled_idx = sqlite3_bind_parameter_index(stmt, ":enabled");
	if(enabled_idx > 0 && (rc = sqlite3_bind_int(stmt, enabled_idx, row->enabled ? 1 : 0)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_addToTable(%d, %s): Failed to bind enabled (error %d) - %s",
		        row->type_int, row->item, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind comment string to prepared statement (if requested)
	const int comment_idx = sqlite3_bind_parameter_index(stmt, ":comment");
	if(comment_idx > 0 && (rc = sqlite3_bind_text(stmt, comment_idx, row->comment, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_addToTable(%d, %s): Failed to bind comment (error %d) - %s",
		        row->type_int, row->item, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	bool okay = false;
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
	{
		// Domain added/modified
		okay = true;
	}
	else
	{
		*message = sqlite3_errmsg(gravity_db);
	}

	// Finalize statement and close database handle
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Debug output
	if(config.debug.api.v.b)
	{
		log_debug(DEBUG_API, "SQL: %s", querystr);
		if(item_idx > 0)
			log_debug(DEBUG_API, "     :item = \"%s\"", row->item);
		if(type_idx > 0)
			log_debug(DEBUG_API, "     :type = %i", row->type_int);
		if(oldtype_idx > 0)
			log_debug(DEBUG_API, "     :oldtype = %i", oldtype);
		if(comment_idx > 0)
			log_debug(DEBUG_API, "     :comment = \"%s\"", row->comment);
		if(enabled_idx > 0)
			log_debug(DEBUG_API, "     :enabled = %i", row->enabled ? 1 : 0);
	}

	return okay;
}

bool gravityDB_delFromTable(const enum gravity_list_type listtype, const cJSON* array, unsigned int *deleted, const char **message)
{
	// Return early if database is not available
	if(gravity_db == NULL)
	{
		*message = "Database not available";
		return false;
	}

	// Return early if passed JSON argument is not an array
	if(!cJSON_IsArray(array))
	{
		*message = "Argument is not an array";
		log_err("gravityDB_delFromTable(%d): %s",
		        listtype, *message);
		return false;
	}

	const bool hasType = listtype == GRAVITY_DOMAINLIST_ALLOW_EXACT ||
	                     listtype == GRAVITY_DOMAINLIST_DENY_EXACT ||
	                     listtype == GRAVITY_DOMAINLIST_ALLOW_REGEX ||
	                     listtype == GRAVITY_DOMAINLIST_DENY_REGEX ||
	                     listtype == GRAVITY_DOMAINLIST_ALL_ALL ||
	                     listtype == GRAVITY_ADLISTS ||
	                     listtype == GRAVITY_ADLISTS_BLOCK ||
	                     listtype == GRAVITY_ADLISTS_ALLOW;

	// Begin transaction
	const char *querystr = "BEGIN TRANSACTION;";
	int rc = sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);
	if(rc != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_delFromTable(%d): SQL error exec(\"%s\"): %s",
		        listtype, querystr, *message);
		return false;
	}

	// Create temporary table for JSON argument
	if(hasType)
		// Create temporary table for domains to be deleted
		querystr = "CREATE TEMPORARY TABLE deltable (type INT, item TEXT);";
	else
		querystr = "CREATE TEMPORARY TABLE deltable (item TEXT);";

	sqlite3_stmt* stmt = NULL;
	rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_delFromTable(%d) - SQL error prepare(\"%s\"): %s",
		        listtype, querystr, *message);

		// Rollback transaction
		querystr = "ROLLBACK TRANSACTION;";
		sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);

		return false;
	}

	// Execute statement
	if((rc = sqlite3_step(stmt)) != SQLITE_DONE)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_delFromTable(%d) - SQL error step(\"%s\"): %s",
		        listtype, querystr, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		// Rollback transaction
		querystr = "ROLLBACK TRANSACTION;";
		sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);

		return false;
	}

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Prepare statement for inserting items into virtual table
	if(hasType)
		querystr = "INSERT INTO deltable (type, item) VALUES (:type, :item);";
	else
		querystr = "INSERT INTO deltable (item) VALUES (:item);";

	rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_delFromTable(%d) - SQL error prepare(\"%s\"): %s",
		        listtype, querystr, *message);

		// Rollback transaction
		querystr = "ROLLBACK TRANSACTION;";
		sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);

		return false;
	}

	// Loop over all domains in the JSON array
	cJSON *it = NULL;
	cJSON_ArrayForEach(it, array)
	{
		// Bind type to prepared statement
		cJSON *type = cJSON_GetObjectItemCaseSensitive(it, "type");
		int type_int = cJSON_IsNumber(type) ? type->valueint : -1;
		if(listtype == GRAVITY_ADLISTS_BLOCK)
			type_int = ADLIST_BLOCK;
		else if(listtype == GRAVITY_ADLISTS_ALLOW)
			type_int = ADLIST_ALLOW;
		else if(listtype == GRAVITY_ADLISTS && cJSON_IsString(type))
		{
			if(strcasecmp(type->valuestring, "block") == 0)
				type_int = ADLIST_BLOCK;
			else if(strcasecmp(type->valuestring, "allow") == 0)
				type_int = ADLIST_ALLOW;
		}
		const int type_idx = sqlite3_bind_parameter_index(stmt, ":type");
		if(type_idx > 0 && (rc = sqlite3_bind_int(stmt, type_idx, type_int)) != SQLITE_OK)
		{
			*message = sqlite3_errmsg(gravity_db);
			log_err("gravityDB_delFromTable(%d): Failed to bind type (error %d) - %s",
			        type_int, rc, *message);
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);

			// Rollback transaction
			querystr = "ROLLBACK TRANSACTION;";
			sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);

			return false;
		}

		// Bind item to prepared statement
		cJSON *item = cJSON_GetObjectItemCaseSensitive(it, "item");
		const int item_idx = sqlite3_bind_parameter_index(stmt, ":item");
		if(item_idx > 0 && (!cJSON_IsString(item) || (rc = sqlite3_bind_text(stmt, item_idx, item->valuestring, -1, SQLITE_STATIC)) != SQLITE_OK))
		{
			*message = sqlite3_errmsg(gravity_db);
			log_err("gravityDB_delFromTable(%d): Failed to bind item (error %d) - %s",
			        listtype, rc, *message);
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);

			// Rollback transaction
			querystr = "ROLLBACK TRANSACTION;";
			sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);

			return false;
		}

		// Execute statement
		if((rc = sqlite3_step(stmt)) != SQLITE_DONE)
		{
			*message = sqlite3_errmsg(gravity_db);
			log_err("gravityDB_delFromTable(%d) - SQL error step(\"%s\"): %s",
			        listtype, querystr, *message);
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);

			// Rollback transaction
			querystr = "ROLLBACK TRANSACTION;";
			sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);

			return false;
		}

		// Reset statement
		sqlite3_reset(stmt);

		// Debug output
		if(config.debug.api.v.b)
		{
			log_debug(DEBUG_API, "SQL: %s", querystr);
			if(item_idx > 0)
				log_debug(DEBUG_API, "     :item = \"%s\"", item->valuestring);
			if(type_idx > 0)
				log_debug(DEBUG_API, "     :type = %i", cJSON_IsNumber(type) ? type->valueint : -1);
		}
	}

	// Finalize statement
	sqlite3_finalize(stmt);

	// Prepare SQL for deleting items from the requested table
	const char *querystrs[4] = {NULL, NULL, NULL, NULL};
	if(listtype == GRAVITY_GROUPS)
		querystrs[0] = "DELETE FROM \"group\" WHERE name IN (SELECT item FROM deltable);";
	else if(listtype == GRAVITY_ADLISTS ||
	        listtype == GRAVITY_ADLISTS_BLOCK ||
	        listtype == GRAVITY_ADLISTS_ALLOW)
	{
		// This is actually a four-step deletion to satisfy foreign-key constraints
		querystrs[0] = "DELETE FROM gravity WHERE adlist_id IN (SELECT id FROM adlist WHERE address IN (SELECT item FROM deltable WHERE type = 0));";
		querystrs[1] = "DELETE FROM antigravity WHERE adlist_id IN (SELECT id FROM adlist WHERE address IN (SELECT item FROM deltable WHERE type = 1));";
		querystrs[2] = "DELETE FROM adlist WHERE address IN (SELECT item FROM deltable WHERE type = 0) AND type = 0;";
		querystrs[3] = "DELETE FROM adlist WHERE address IN (SELECT item FROM deltable WHERE type = 1) AND type = 1;";
	}
	else if(listtype == GRAVITY_CLIENTS)
		querystrs[0] = "DELETE FROM client WHERE ip IN (SELECT item FROM deltable);";
	else // domainlist
	{
		querystrs[0] = "DELETE FROM domainlist WHERE domain IN (SELECT item FROM deltable WHERE type = 0) AND type = 0;";
		querystrs[1] = "DELETE FROM domainlist WHERE domain IN (SELECT item FROM deltable WHERE type = 1) AND type = 1;";
		querystrs[2] = "DELETE FROM domainlist WHERE domain IN (SELECT item FROM deltable WHERE type = 2) AND type = 2;";
		querystrs[3] = "DELETE FROM domainlist WHERE domain IN (SELECT item FROM deltable WHERE type = 3) AND type = 3;";
	}

	for(unsigned int i = 0; i < ArraySize(querystrs); i++)
	{
		// Finish if no more queries
		if(querystrs[i] == NULL)
			break;

		// Execute statement
		rc = sqlite3_exec(gravity_db, querystrs[i], NULL, NULL, NULL);
		if(rc != SQLITE_OK)
		{
			*message = sqlite3_errmsg(gravity_db);
			log_err("gravityDB_delFromTable(%d): SQL error exec(\"%s\"): %s",
			        listtype, querystrs[i], *message);

			// Rollback transaction
			querystr = "ROLLBACK TRANSACTION;";
			sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);

			return false;
		}

		// Add number of deleted rows
		*deleted += sqlite3_changes(gravity_db);
	}

	// Drop temporary table
	querystr = "DROP TABLE deltable;";
	rc = sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);
	if(rc != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_delFromTable(%d): SQL error exec(\"%s\"): %s",
		        listtype, querystr, *message);

		// Rollback transaction
		querystr = "ROLLBACK TRANSACTION;";
		sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);
	}

	// Commit transaction
	querystr = "COMMIT TRANSACTION;";
	rc = sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);
	if(rc != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_delFromTable(%d): SQL error exec(\"%s\"): %s",
		        listtype, querystr, *message);

		// Rollback transaction
		querystr = "ROLLBACK TRANSACTION;";
		sqlite3_exec(gravity_db, querystr, NULL, NULL, NULL);
	}

	return true;
}

static sqlite3_stmt* read_stmt = NULL;
bool gravityDB_readTable(const enum gravity_list_type listtype,
                         const char *item, const char **message,
                         const bool exact, const char *ids)
{
	if(gravity_db == NULL)
	{
		*message = "Database not available";
		return false;
	}

	// Get filter string for the requested list type
	const char *type = "N/A";
	switch (listtype)
	{
		case GRAVITY_DOMAINLIST_ALLOW_EXACT:
			type = "0";
			break;
		case GRAVITY_DOMAINLIST_ALLOW_REGEX:
			type = "2";
			break;
		case GRAVITY_DOMAINLIST_ALLOW_ALL:
			type = "0,2";
			break;
		case GRAVITY_DOMAINLIST_DENY_EXACT:
			type = "1";
			break;
		case GRAVITY_DOMAINLIST_DENY_REGEX:
			type = "3";
			break;
		case GRAVITY_DOMAINLIST_DENY_ALL:
			type = "1,3";
			break;
		case GRAVITY_DOMAINLIST_ALL_EXACT:
			type = "0,1";
			break;
		case GRAVITY_DOMAINLIST_ALL_REGEX:
			type = "2,3";
			break;
		case GRAVITY_DOMAINLIST_ALL_ALL:
			type = "0,1,2,3";
			break;

		// No type required for these tables
		case GRAVITY_GRAVITY:
		case GRAVITY_ANTIGRAVITY:
		case GRAVITY_GROUPS:
		case GRAVITY_CLIENTS:
		case GRAVITY_ADLISTS:
		// Type is set in the SQL query directly
		case GRAVITY_ADLISTS_BLOCK:
		case GRAVITY_ADLISTS_ALLOW:
			break;
	}

	// Build query statement
	const size_t buflen = 512u + (ids != NULL ? strlen(ids) : 0u);
	char *querystr = calloc(buflen, sizeof(char));
	char *like_name = (char*)item;
	if(!exact && item != NULL && item[0] != '\0')
	{
		// Build LIKE string (% + item + %)
		like_name = calloc(strlen(item)+3, sizeof(char));
		if(like_name == NULL)
		{
			log_err("Failed to allocate memory for like_name");
			*message = "Failed to allocate memory for like_name";
			return false;
		}
		sprintf(like_name, "%%%s%%", item);
	}
	const char *filter = "";
	if(listtype == GRAVITY_GROUPS)
	{
		if(item != NULL && item[0] != '\0')
		{
			if(exact)
				filter = " WHERE name = :item";
			else
				filter = " WHERE name LIKE :item";
		}
		snprintf(querystr, buflen, "SELECT id,name,enabled,date_added,date_modified,description AS comment FROM \"group\"%s;", filter);
	}
	else if(listtype == GRAVITY_ADLISTS ||
	        listtype == GRAVITY_ADLISTS_BLOCK ||
	        listtype == GRAVITY_ADLISTS_ALLOW)
	{
		if(listtype == GRAVITY_ADLISTS_BLOCK)
			filter = "type = 0";
		else if(listtype == GRAVITY_ADLISTS_ALLOW)
			filter = "type = 1";
		else
			filter = "TRUE";

		const char *filter2 = "";
		if(item != NULL && item[0] != '\0')
		{
			if(exact)
				filter2 = " AND address = :item";
			else
				filter2 = " AND address LIKE :item";
		}
		snprintf(querystr, buflen, "SELECT id,type,address,enabled,date_added,date_modified,comment,"
		                                     "(SELECT GROUP_CONCAT(group_id) FROM adlist_by_group g WHERE g.adlist_id = a.id) AS group_ids,"
		                                     "date_updated,number,invalid_domains,status,abp_entries "
		                                     "FROM adlist a WHERE %s%s;", filter, filter2);
	}
	else if(listtype == GRAVITY_CLIENTS)
	{
		if(item != NULL && item[0] != '\0')
		{
			if(exact)
				filter = " WHERE ip = :item";
			else
				filter = " WHERE ip LIKE :item";
		}
		snprintf(querystr, buflen, "SELECT id,ip AS client,date_added,date_modified,comment,"
		                                     "(SELECT GROUP_CONCAT(group_id) FROM client_by_group g WHERE g.client_id = c.id) AS group_ids "
		                                     "FROM client c%s;", filter);
	}
	else if(listtype == GRAVITY_GRAVITY || listtype == GRAVITY_ANTIGRAVITY)
	{
		if(item != NULL && item[0] != '\0')
		{
			if(exact)
				filter = " WHERE g.domain = :item";
			else
				filter = " WHERE g.domain LIKE :item";
		}
		const char *table = listtype == GRAVITY_GRAVITY ? "gravity" : "antigravity";
		snprintf(querystr, buflen, "SELECT domain,a.id,a.address,a.enabled,a.date_added,a.date_modified,a.comment,a.date_updated,a.number,a.invalid_domains,a.status,a.abp_entries,a.type,"
		                                     "(SELECT GROUP_CONCAT(group_id) FROM adlist_by_group ag WHERE ag.adlist_id = g.adlist_id) AS group_ids "
		                                     "FROM %s g JOIN adlist a ON a.id = g.adlist_id %s;", table, filter);
	}
	else // domainlist
	{
		if(item != NULL && item[0] != '\0')
		{
			if(exact)
				filter = " AND domain = :item";
			else
				filter = " AND domain LIKE :item";
		}

		snprintf(querystr, buflen, "SELECT id,domain,type,enabled,date_added,date_modified,comment,"
		                                     "(SELECT GROUP_CONCAT(group_id) FROM domainlist_by_group g WHERE g.domainlist_id = d.id) AS group_ids "
		                                     "FROM domainlist d WHERE d.type IN (%s)%s", type, filter);

		// Append id array filter to query string
		// We have to do it this way as binding a sequence of int via a prepared
		// statement isn't possible in SQLite3
		if(ids != NULL)
			snprintf(querystr+strlen(querystr), buflen-strlen(querystr), " AND id IN (%s)", ids);
	}

	// Prepare SQLite statement
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &read_stmt, NULL);
	if( rc != SQLITE_OK ){
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_readTable(%d => (%s)) - SQL error prepare (%i): %s => %s",
		        listtype, type, rc, querystr, *message);
		if(!exact)
			free(like_name);
		free(querystr);
		return false;
	}

	// Bind item to prepared statement (if requested)
	int idx = sqlite3_bind_parameter_index(read_stmt, ":item");
	if(idx > 0 && (rc = sqlite3_bind_text(read_stmt, idx, like_name, -1, SQLITE_TRANSIENT)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_readTable(%d => (%s), %s): Failed to bind item (error %d) - %s",
		        listtype, type, like_name, rc, *message);
		sqlite3_reset(read_stmt);
		sqlite3_finalize(read_stmt);
		if(!exact)
			free(like_name);
		free(querystr);
		return false;
	}

	// Bind ids to prepared statement (if requested)
	idx = sqlite3_bind_parameter_index(read_stmt, ":ids");
	if(idx > 0 && (rc = sqlite3_bind_text(read_stmt, idx, ids, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_readTable(%d => (%s), %s): Failed to bind ids (error %d) - %s",
		        listtype, type, like_name, rc, *message);
		sqlite3_reset(read_stmt);
		sqlite3_finalize(read_stmt);
		if(!exact)
			free(like_name);
		free(querystr);
		return false;
	}

	// Debug output
	if(config.debug.api.v.b)
	{
		log_debug(DEBUG_API, "SQL: %s", querystr);
		log_debug(DEBUG_API, "     :item = \"%s\"", like_name);
		log_debug(DEBUG_API, "     :ids = \"%s\"", ids);
	}

	// Free memory
	free(querystr);
	if(!exact)
		free(like_name);

	return true;
}

bool gravityDB_readTableGetRow(const enum gravity_list_type listtype, tablerow *row, const char **message)
{
	// Perform step
	const int rc = sqlite3_step(read_stmt);

	// Ensure no old data stayed in here
	memset(row, 0, sizeof(*row));

	// Valid row
	if(rc == SQLITE_ROW)
	{
		const int cols = sqlite3_column_count(read_stmt);
		for(int c = 0; c < cols; c++)
		{
			const char *cname = sqlite3_column_name(read_stmt, c);
			if(strcasecmp(cname, "id") == 0)
				row->id = sqlite3_column_int(read_stmt, c);

			else if(strcasecmp(cname, "type") == 0)
			{
				// Get raw type
				row->type_int = sqlite3_column_int(read_stmt, c);

				// Convert to string
				if(listtype == GRAVITY_DOMAINLIST_ALLOW_EXACT ||
				   listtype == GRAVITY_DOMAINLIST_ALLOW_REGEX ||
				   listtype == GRAVITY_DOMAINLIST_ALLOW_ALL ||
				   listtype == GRAVITY_DOMAINLIST_DENY_EXACT ||
				   listtype == GRAVITY_DOMAINLIST_DENY_REGEX ||
				   listtype == GRAVITY_DOMAINLIST_DENY_ALL ||
				   listtype == GRAVITY_DOMAINLIST_ALL_EXACT ||
				   listtype == GRAVITY_DOMAINLIST_ALL_REGEX ||
				   listtype == GRAVITY_DOMAINLIST_ALL_ALL)
				{
					switch(row->type_int)
					{
						case 0:
							row->type = "allow";
							row->kind = "exact";
							break;
						case 1:
							row->type = "deny";
							row->kind = "exact";
							break;
						case 2:
							row->type = "allow";
							row->kind = "regex";
							break;
						case 3:
							row->type = "deny";
							row->kind = "regex";
							break;
						default:
							row->type = "unknown";
							row->kind = "unknown";
							break;
					}
				}
				else if(listtype == GRAVITY_ADLISTS ||
				        listtype == GRAVITY_ADLISTS_ALLOW ||
				        listtype == GRAVITY_ADLISTS_BLOCK ||
				        listtype == GRAVITY_GRAVITY ||
				        listtype == GRAVITY_ANTIGRAVITY)
				{
					switch(row->type_int)
					{
						case 0:
							row->type = "block";
							break;
						case 1:
							row->type = "allow";
							break;
						default:
							row->type = "unknown";
							break;
					}
				}
				else
				{
					row->type = "unknown";
				}
			}

			else if(strcasecmp(cname, "domain") == 0)
				row->domain = (char*)sqlite3_column_text(read_stmt, c);

			else if(strcasecmp(cname, "address") == 0)
				row->address = (char*)sqlite3_column_text(read_stmt, c);

			else if(strcasecmp(cname, "enabled") == 0)
				row->enabled = sqlite3_column_int(read_stmt, c) != 0;

			else if(strcasecmp(cname, "date_added") == 0)
				row->date_added = sqlite3_column_int64(read_stmt, c);

			else if(strcasecmp(cname, "date_modified") == 0)
				row->date_modified = sqlite3_column_int64(read_stmt, c);

			else if(strcasecmp(cname, "comment") == 0)
				row->comment = (char*)sqlite3_column_text(read_stmt, c);

			else if(strcasecmp(cname, "group_ids") == 0)
				row->group_ids = (char*)sqlite3_column_text(read_stmt, c);

			else if(strcasecmp(cname, "address") == 0)
				row->address = (char*)sqlite3_column_text(read_stmt, c);

			else if(strcasecmp(cname, "name") == 0)
				row->name = (char*)sqlite3_column_text(read_stmt, c);

			else if(strcasecmp(cname, "client") == 0)
				row->client = (char*)sqlite3_column_text(read_stmt, c);

			else if(strcasecmp(cname, "date_updated") == 0)
				row->date_updated = sqlite3_column_int64(read_stmt, c);

			else if(strcasecmp(cname, "number") == 0)
				row->number = sqlite3_column_int(read_stmt, c);

			else if(strcasecmp(cname, "type") == 0)
				row->type_int = sqlite3_column_int(read_stmt, c);

			else if(strcasecmp(cname, "invalid_domains") == 0)
				row->invalid_domains = sqlite3_column_int(read_stmt, c);

			else if(strcasecmp(cname, "status") == 0)
				row->status = sqlite3_column_int(read_stmt, c);

			else if(strcasecmp(cname, "abp_entries") == 0)
				row->abp_entries = sqlite3_column_int(read_stmt, c);

			else
				log_err("API: Encountered unknown column %s", cname);
		}
		return true;
	}

	// Check for error. An error happened when the result is neither
	// SQLITE_ROW (we returned earlier in this case), nor
	// SQLITE_DONE (we are finished reading the table)
	if(rc != SQLITE_DONE)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_readTableGetRow() - SQL error step (%i): %s",
		        rc, *message);
		return false;
	}

	// Finished reading, nothing to get here
	return false;
}

// Finalize statement of a gravity database transaction
void gravityDB_readTableFinalize(void)
{
	// Finalize statement
	sqlite3_finalize(read_stmt);
}

bool gravityDB_edit_groups(const enum gravity_list_type listtype, cJSON *groups,
                           const tablerow *row, const char **message)
{
	if(gravity_db == NULL)
	{
		*message = "Database not available";
		return false;
	}

	// Prepare SQLite statements
	const char *get_querystr, *del_querystr, *add_querystr;
	if(listtype == GRAVITY_GROUPS)
		return false;
	else if(listtype == GRAVITY_CLIENTS)
	{
		get_querystr = "SELECT id FROM client WHERE ip = :item";
		del_querystr = "DELETE FROM client_by_group WHERE client_id = :id;";
		add_querystr = "INSERT INTO client_by_group (client_id,group_id) VALUES (:id,:gid);";
	}
	else if(listtype == GRAVITY_ADLISTS ||
	        listtype == GRAVITY_ADLISTS_BLOCK ||
	        listtype == GRAVITY_ADLISTS_ALLOW)
	{
		if(listtype == GRAVITY_ADLISTS)
			get_querystr = "SELECT id FROM adlist WHERE address = :item";
		else
			get_querystr = "SELECT id FROM adlist WHERE address = :item AND type = :type";
		del_querystr = "DELETE FROM adlist_by_group WHERE adlist_id = :id;";
		add_querystr = "INSERT INTO adlist_by_group (adlist_id,group_id) VALUES (:id,:gid);";
	}
	else // domainlist
	{
		get_querystr = "SELECT id FROM domainlist WHERE domain = :item AND type = :type";
		del_querystr = "DELETE FROM domainlist_by_group WHERE domainlist_id = :id;";
		add_querystr = "INSERT INTO domainlist_by_group (domainlist_id,group_id) VALUES (:id,:gid);";
	}

	// First step: Get ID of the item to modify
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(gravity_db, get_querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_edit_groups(%d) - SQL error prepare SELECT (%i): %s",
		        listtype, rc, *message);
		return false;
	}

	// Bind item string to prepared statement (if requested)
	int idx = sqlite3_bind_parameter_index(stmt, ":item");
	if(idx > 0 && (rc = sqlite3_bind_text(stmt, idx, row->item, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_edit_groups(%d): Failed to bind item SELECT (error %d) - %s",
		        listtype, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Bind type to prepared statement (if requested)
	idx = sqlite3_bind_parameter_index(stmt, ":type");
	if(idx > 0 && (rc = sqlite3_bind_int(stmt, idx, row->type_int)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_edit_groups(%d): Failed to bind type SELECT (error %d) - %s",
		        listtype, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	bool okay = false;
	int id = -1;
	if((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// Get ID of domain
		id = sqlite3_column_int(stmt, 0);
		okay = true;
	}
	else
	{
		*message = sqlite3_errmsg(gravity_db);
	}

	// Debug output
	if(config.debug.api.v.b)
	{
		log_debug(DEBUG_API, "SQL: %s", get_querystr);
		log_debug(DEBUG_API, "     :item = \"%s\"", row->item);
		log_debug(DEBUG_API, "     :type = \"%d\"", row->type_int);
	}

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Return early if getting the ID failed
	if(!okay)
		return false;

	// Second step: Delete all existing group associations for this item
	rc = sqlite3_prepare_v2(gravity_db, del_querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_edit_groups(%d) - SQL error prepare DELETE (%i): %s",
		        listtype, rc, *message);
		return false;
	}

	// Bind id to prepared statement (if requested)
	idx = sqlite3_bind_parameter_index(stmt, ":id");
	if(idx > 0 && (rc = sqlite3_bind_int(stmt, idx, id)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_edit_groups(%d): Failed to bind id DELETE (error %d) - %s",
		        listtype, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Perform step
	if((rc = sqlite3_step(stmt)) == SQLITE_DONE)
	{
		// All groups deleted
	}
	else
	{
		okay = false;
		*message = sqlite3_errmsg(gravity_db);
	}

	// Debug output
	if(config.debug.api.v.b)
	{
		log_debug(DEBUG_API, "SQL: %s", del_querystr);
		log_debug(DEBUG_API, "     :id = \"%d\"", id);
	}

	// Finalize statement
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Return early if deleting the existing group associations failed
	if(!okay)
		return false;

	// Third step: Create new group associations for this item
	rc = sqlite3_prepare_v2(gravity_db, add_querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_edit_groups(%d) - SQL error prepare INSERT (%i): %s",
		        listtype, rc, *message);
		return false;
	}

	// Bind id to prepared statement (if requested)
	idx = sqlite3_bind_parameter_index(stmt, ":id");
	if(idx > 0 && (rc = sqlite3_bind_int(stmt, idx, id)) != SQLITE_OK)
	{
		*message = sqlite3_errmsg(gravity_db);
		log_err("gravityDB_edit_groups(%d): Failed to bind id INSERT (error %d) - %s",
		        listtype, rc, *message);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		return false;
	}

	// Loop over all loops in array
	const int groupcount = cJSON_GetArraySize(groups);
	log_debug(DEBUG_API, "groupscount = %d", groupcount);
	for(int i = 0; i < groupcount; i++)
	{
		cJSON *group = cJSON_GetArrayItem(groups, i);
		if(group == NULL || !cJSON_IsNumber(group))
			continue;

		idx = sqlite3_bind_parameter_index(stmt, ":gid");
		if(idx > 0 && (rc = sqlite3_bind_int(stmt, idx, group->valueint)) != SQLITE_OK)
		{
			*message = sqlite3_errmsg(gravity_db);
			log_err("gravityDB_edit_groups(%d): Failed to bind gid INSERT (error %d) - %s",
			listtype, rc, *message);
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			return false;
		}

		// Perform step
		if((rc = sqlite3_step(stmt)) != SQLITE_DONE)
		{
			okay = false;
			*message = sqlite3_errmsg(gravity_db);
			break;
		}

		// Debug output
		if(config.debug.api.v.b)
		{
			log_debug(DEBUG_API, "INSERT: %i -> (%i,%i)", rc, id, group->valueint);
			log_debug(DEBUG_API, "SQL: %s", add_querystr);
			log_debug(DEBUG_API, "     :id = \"%d\"", id);
			log_debug(DEBUG_API, "     :gid = \"%d\"", group->valueint);
		}

		// Reset before next iteration, this will not clear the id binding
		sqlite3_reset(stmt);
	}

	// Finalize statement
	sqlite3_finalize(stmt);

	return okay;
}

void check_inaccessible_adlists(void)
{
	// Check if any adlist was inaccessible in the last gravity run
	// If so, gravity stored `status` in the adlist table with
	// "3": List unavailable, Pi-hole used a local copy
	// "4": List unavailable, there is no local copy available

	// Do not proceed when database is not available
	if(!gravityDB_opened && !gravityDB_open())
	{
		log_err("check_inaccessible_adlists(): Gravity database not available");
		return;
	}

	const char *querystr = "SELECT id, address FROM adlist WHERE status IN (3,4) AND enabled=1";

	// Prepare query
	sqlite3_stmt *query_stmt;
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK){
		log_err("check_inaccessible_adlists(): %s - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		gravityDB_close();
		return;
	}

	// Perform query
	while((rc = sqlite3_step(query_stmt)) == SQLITE_ROW)
	{
		int id = sqlite3_column_int(query_stmt, 0);
		const char *address = (const char*)sqlite3_column_text(query_stmt, 1);

		// log to the message table
		logg_inaccessible_adlist(id, address);
	}

	// Finalize statement
	sqlite3_finalize(query_stmt);
}

static sqlite3_int64 last_updated = -1;
bool gravity_updated(void)
{
	bool changed = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *query_stmt = NULL;

	// Open database
	int rc = sqlite3_open_v2(config.files.gravity.v.s, &db, SQLITE_OPEN_READONLY, NULL);
	if(db == NULL)
	{
		log_err("gravity_updated(): %s - SQL error open: %s", config.files.gravity.v.s, sqlite3_errstr(rc));
		return false;
	}

	// Get *updated* timestamp from gravity database
	const char *querystr = "SELECT value FROM info WHERE property = 'updated';";
	rc = sqlite3_prepare_v2(db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK){
		// Ignore SQLITE_BUSY errors, as this is not a critical error
		// We will just try again later
		if(rc != SQLITE_BUSY)
			log_warn("gravity_updated(): %s - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		sqlite3_close(db);
		return false;
	}

	// Perform query
	rc = sqlite3_step(query_stmt);
	if(rc != SQLITE_ROW)
	{
		log_err("gravity_updated(): %s - SQL error step: %s", querystr, sqlite3_errstr(rc));
		sqlite3_finalize(query_stmt);
		sqlite3_close(db);
		return false;
	}

	// Get timestamp from database
	const sqlite3_int64 updated = sqlite3_column_int64(query_stmt, 0);

	// Check if timestamp has changed
	if(last_updated == -1)
	{
		// First run, set last_updated
		last_updated = updated;
	}
	else if(last_updated < updated)
	{
		// Gravity database has been updated
		last_updated = updated;
		changed = true;
		log_info("Gravity database has been updated, reloading now");
	}

	// Finalize statement
	sqlite3_finalize(query_stmt);

	// Close database
	sqlite3_close(db);

	return changed;
}
