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
#include "../config.h"
// logg()
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
sqlite3_stmt_vec *blacklist_stmt = NULL;

// Private variables
static sqlite3 *gravity_db = NULL;
static sqlite3_stmt* table_stmt = NULL;
static sqlite3_stmt* auditlist_stmt = NULL;
bool gravityDB_opened = false;

// Table names corresponding to the enum defined in gravity-db.h
static const char* tablename[] = { "vw_gravity", "vw_blacklist", "vw_whitelist", "vw_regex_blacklist", "vw_regex_whitelist" , "" };

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

	// Open the database
	gravityDB_open();
}

// Open gravity database
bool gravityDB_open(void)
{
	struct stat st;
	if(stat(FTLfiles.gravity_db, &st) != 0)
	{
		// File does not exist
		logg("gravityDB_open(): %s does not exist", FTLfiles.gravity_db);
		return false;
	}

	if(gravityDB_opened && gravity_db != NULL)
	{
		if(config.debug & DEBUG_DATABASE)
			logg("gravityDB_open(): Database already connected");
		return true;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Trying to open %s in read-only mode", FTLfiles.gravity_db);
	int rc = sqlite3_open_v2(FTLfiles.gravity_db, &gravity_db, SQLITE_OPEN_READONLY, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open() - SQL error: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}

	// Database connection is now open
	gravityDB_opened = true;

	// Tell SQLite3 to store temporary tables in memory. This speeds up read operations on
	// temporary tables, indices, and views.
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Setting location for temporary object to MEMORY");
	char *zErrMsg = NULL;
	rc = sqlite3_exec(gravity_db, "PRAGMA temp_store = MEMORY", NULL, NULL, &zErrMsg);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(PRAGMA temp_store) - SQL error (%i): %s", rc, zErrMsg);
		sqlite3_free(zErrMsg);
		gravityDB_close();
		return false;
	}

	// Prepare audit statement
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Preparing audit query");

	// We support adding audit domains with a wildcard character (*)
	// Example 1: google.de
	//            matches only google.de
	// Example 2: *.google.de
	//            matches all subdomains of google.de
	//            BUT NOT google.de itself
	// Example 3: *google.de
	//            matches 'google.de' and all of its subdomains but
	//            also other domains starting in google.de, like
	//            abcgoogle.de
	rc = sqlite3_prepare_v3(gravity_db,
	        "SELECT EXISTS("
	          "SELECT domain, "
	            "CASE WHEN substr(domain, 1, 1) = '*' " // Does the database string start in '*' ?
	              "THEN '*' || substr(:input, - length(domain) + 1) " // If so: Crop the input domain and prepend '*'
	              "ELSE :input " // If not: Use input domain directly for comparison
	            "END matcher "
	          "FROM domain_audit WHERE matcher = domain" // Match where (modified) domain equals the database domain
	        ");", -1, SQLITE_PREPARE_PERSISTENT, &auditlist_stmt, NULL);

	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT EXISTS(... domain_audit ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}

	// Set SQLite3 busy timeout to a user-defined value (defaults to 1 second)
	// to avoid immediate failures when the gravity database is still busy
	// writing the changes to disk
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Setting busy timeout to %d", DATABASE_BUSY_TIMEOUT);
	sqlite3_busy_timeout(gravity_db, DATABASE_BUSY_TIMEOUT);

	// Prepare private vector of statements for this process (might be a TCP fork!)
	if(whitelist_stmt == NULL)
		whitelist_stmt = new_sqlite3_stmt_vec(counters->clients);
	if(blacklist_stmt == NULL)
		blacklist_stmt = new_sqlite3_stmt_vec(counters->clients);
	if(gravity_stmt == NULL)
		gravity_stmt = new_sqlite3_stmt_vec(counters->clients);

	// Explicitly set busy handler to zero milliseconds
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Setting busy timeout to zero");
	rc = sqlite3_busy_timeout(gravity_db, 0);
	if(rc != SQLITE_OK)
	{
		logg("gravityDB_open() - Cannot set busy handler: %s", sqlite3_errstr(rc));
	}

	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Successfully opened gravity.db");
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
		logg("get_client_querystr(%s, %s) - asprintf() error", table, groups);
		return NULL;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("get_client_querystr: %s", querystr);

	return querystr;
}

// Determine whether to show IP or hardware address
static inline const char *show_client_string(const char *hwaddr, const char *hostname,
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
		logg("get_client_groupids(): Gravity database not available");
		return false;
	}

	if(config.debug & DEBUG_CLIENTS)
		logg("Querying gravity database for client with IP %s...", ip);

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
		logg("get_client_groupids(\"%s\") - SQL error prepare: %s",
		     ip, sqlite3_errstr(rc));
		return false;
	}

	// Bind ipaddr to prepared statement
	if((rc = sqlite3_bind_text(table_stmt, 1, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("get_client_groupids(\"%s\"): Failed to bind ip: %s",
		     ip, sqlite3_errstr(rc));
		sqlite3_reset(table_stmt);
		sqlite3_finalize(table_stmt);
		return NULL;
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

		if(config.debug & DEBUG_CLIENTS && matching_count == 1)
			// Case matching_count > 1 handled below using logg_subnet_warning()
			logg("--> Found record for %s in the client table (group ID %d)", ip, chosen_match_id);
	}
	else if(rc == SQLITE_DONE)
	{
		if(config.debug & DEBUG_CLIENTS)
			logg("--> No record for %s in the client table", ip);
	}
	else
	{
		// Error
		logg("get_client_groupids(\"%s\") - SQL error step: %s",
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
		if(config.debug & DEBUG_CLIENTS)
			logg("Querying gravity database for MAC address of %s...", ip);

		// Do the lookup
		hwaddr = getMACfromIP(NULL, ip);

		if(hwaddr == NULL && config.debug & DEBUG_CLIENTS)
		{
			logg("--> No result.");
		}
		else if(hwaddr != NULL && strlen(hwaddr) > 3 && strncasecmp(hwaddr, "ip-", 3) == 0)
		{
			free(hwaddr);
			hwaddr = NULL;

			if(config.debug & DEBUG_CLIENTS)
				logg("Skipping mock-device hardware address lookup");
		}
		// Set MAC address from database information if available and the MAC address is not already set
		else if(hwaddr != NULL && client->hwlen != 6)
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
			const size_t strlen = sizeof("AA:BB:CC:DD:EE:FF");
			hwaddr = calloc(18, strlen);
			snprintf(hwaddr, strlen, "%02X:%02X:%02X:%02X:%02X:%02X",
			         client->hwaddr[0], client->hwaddr[1], client->hwaddr[2],
			         client->hwaddr[3], client->hwaddr[4], client->hwaddr[5]);

			if(config.debug & DEBUG_CLIENTS)
				logg("--> Obtained %s from internal ARP cache", hwaddr);
		}
	}

	// Check if we received a valid MAC address
	// This ensures we skip mock hardware addresses such as "ip-127.0.0.1"
	if(hwaddr != NULL)
	{
		if(config.debug & DEBUG_CLIENTS)
			logg("--> Querying client table for %s", hwaddr);

		// Check if client is configured through the client table
		// This will return nothing if the client is unknown/unconfigured
		// We use COLLATE NOCASE to ensure the comparison is done case-insensitive
		querystr = "SELECT id FROM client WHERE ip = ? COLLATE NOCASE;";

		// Prepare query
		rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
		if(rc != SQLITE_OK)
		{
			logg("get_client_groupids(%s) - SQL error prepare: %s",
				querystr, sqlite3_errstr(rc));
			free(hwaddr); // hwaddr != NULL -> memory has been allocated
			return false;
		}

		// Bind hwaddr to prepared statement
		if((rc = sqlite3_bind_text(table_stmt, 1, hwaddr, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			logg("get_client_groupids(\"%s\", \"%s\"): Failed to bind hwaddr: %s",
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

			if(config.debug & DEBUG_CLIENTS)
				logg("--> Found record for %s in the client table (group ID %d)", hwaddr, chosen_match_id);
		}
		else if(rc == SQLITE_DONE)
		{
			if(config.debug & DEBUG_CLIENTS)
				logg("--> There is no record for %s in the client table", hwaddr);
		}
		else
		{
			// Error
			logg("get_client_groupids(\"%s\", \"%s\") - SQL error step: %s",
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
		if(config.debug & DEBUG_CLIENTS)
			logg("Querying gravity database for host name of %s...", ip);

		// Do the lookup
		hostname = getNameFromIP(NULL, ip);

		if(hostname == NULL && config.debug & DEBUG_CLIENTS)
			logg("--> No result.");

		if(hostname != NULL && strlen(hostname) == 0)
		{
			free(hostname);
			hostname = NULL;
			if(config.debug & DEBUG_CLIENTS)
				logg("Skipping empty host name lookup");
		}
	}

	// Check if we received a valid MAC address
	// This ensures we skip mock hardware addresses such as "ip-127.0.0.1"
	if(hostname != NULL)
	{
		if(config.debug & DEBUG_CLIENTS)
			logg("--> Querying client table for %s", hostname);

		// Check if client is configured through the client table
		// This will return nothing if the client is unknown/unconfigured
		// We use COLLATE NOCASE to ensure the comparison is done case-insensitive
		querystr = "SELECT id FROM client WHERE ip = ? COLLATE NOCASE;";

		// Prepare query
		rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
		if(rc != SQLITE_OK)
		{
			logg("get_client_groupids(%s) - SQL error prepare: %s",
				querystr, sqlite3_errstr(rc));
			if(hwaddr) free(hwaddr);
			free(hostname); // hostname != NULL -> memory has been allocated
			return false;
		}

		// Bind hostname to prepared statement
		if((rc = sqlite3_bind_text(table_stmt, 1, hostname, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			logg("get_client_groupids(\"%s\", \"%s\"): Failed to bind hostname: %s",
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

			if(config.debug & DEBUG_CLIENTS)
				logg("--> Found record for %s in the client table (group ID %d)", hostname, chosen_match_id);
		}
		else if(rc == SQLITE_DONE)
		{
			if(config.debug & DEBUG_CLIENTS)
				logg("--> There is no record for %s in the client table", hostname);
		}
		else
		{
			// Error
			logg("get_client_groupids(\"%s\", \"%s\") - SQL error step: %s",
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
		if(config.debug & DEBUG_CLIENTS)
			logg("Querying gravity database for interface of %s...", ip);

		// Do the lookup
		interface = getIfaceFromIP(NULL, ip);

		if(interface == NULL && config.debug & DEBUG_CLIENTS)
			logg("--> No result.");

		if(interface != NULL && strlen(interface) == 0)
		{
			free(interface);
			interface = 0;
			if(config.debug & DEBUG_CLIENTS)
				logg("Skipping empty interface lookup");
		}
	}

	// Check if we received a valid interface
	if(interface != NULL)
	{
		if(config.debug & DEBUG_CLIENTS)
			logg("Querying client table for interface "INTERFACE_SEP"%s", interface);

		// Check if client is configured through the client table using its interface
		// This will return nothing if the client is unknown/unconfigured
		// We use the SQLite concatenate operator || to prepace the queried interface by ":"
		// We use COLLATE NOCASE to ensure the comparison is done case-insensitive
		querystr = "SELECT id FROM client WHERE ip = '"INTERFACE_SEP"' || ? COLLATE NOCASE;";

		// Prepare query
		rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
		if(rc != SQLITE_OK)
		{
			logg("get_client_groupids(%s) - SQL error prepare: %s",
				querystr, sqlite3_errstr(rc));
			if(hwaddr) free(hwaddr);
			if(hostname) free(hostname);
			free(interface); // interface != NULL -> memory has been allocated
			return false;
		}

		// Bind interface to prepared statement
		if((rc = sqlite3_bind_text(table_stmt, 1, interface, -1, SQLITE_STATIC)) != SQLITE_OK)
		{
			logg("get_client_groupids(\"%s\", \"%s\"): Failed to bind interface: %s",
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

			if(config.debug & DEBUG_CLIENTS)
				logg("--> Found record for interface "INTERFACE_SEP"%s in the client table (group ID %d)", interface, chosen_match_id);
		}
		else if(rc == SQLITE_DONE)
		{
			if(config.debug & DEBUG_CLIENTS)
				logg("--> There is no record for interface "INTERFACE_SEP"%s in the client table", interface);
		}
		else
		{
			// Error
			logg("get_client_groupids(\"%s\", \"%s\") - SQL error step: %s",
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
		if(config.debug & DEBUG_CLIENTS)
			logg("Gravity database: Client %s not found. Using default group.\n",
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

	if(config.debug & DEBUG_CLIENTS)
		logg("Querying gravity database for client %s (getting groups)", ip);

	// Prepare query
	rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("get_client_groupids(\"%s\", \"%s\", %d) - SQL error prepare: %s",
		     ip, hwaddr, chosen_match_id, sqlite3_errstr(rc));
		sqlite3_finalize(table_stmt);
		return false;
	}

	// Bind hwaddr to prepared statement
	if((rc = sqlite3_bind_int(table_stmt, 1, chosen_match_id)) != SQLITE_OK)
	{
		logg("get_client_groupids(\"%s\", \"%s\", %d): Failed to bind chosen_match_id: %s",
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
		logg("get_client_groupids(\"%s\", \"%s\", %d) - SQL error step: %s",
		     ip, hwaddr, chosen_match_id, sqlite3_errstr(rc));
		gravityDB_finalizeTable();
		return false;
	}
	// Finalize statement
	gravityDB_finalizeTable();

	if(config.debug & DEBUG_CLIENTS)
	{
		if(interface != NULL)
		{
			logg("Gravity database: Client %s found (identified by interface %s). Using groups (%s)\n",
			     show_client_string(hwaddr, hostname, ip), interface, getstr(client->groupspos));
		}
		else
		{
			logg("Gravity database: Client %s found. Using groups (%s)\n",
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

char* __attribute__ ((malloc)) get_client_names_from_ids(const char *group_ids)
{
	// Build query string to get concatenated groups
	char *querystr = NULL;
	if(asprintf(&querystr, "SELECT GROUP_CONCAT(ip) FROM client "
	                       "WHERE id IN (%s);", group_ids) < 1)
	{
		logg("group_names(%s) - asprintf() error", group_ids);
		return NULL;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("Querying group names for IDs (%s)", group_ids);

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("get_client_groupids(%s) - SQL error prepare: %s",
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
		logg("group_names(%s) - SQL error step: %s",
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

	if(config.debug & DEBUG_DATABASE)
		logg("Initializing gravity statements for %s", clientip);

	// Get associated groups for this client (if defined)
	char *querystr = NULL;
	if(!client->flags.found_group && !get_client_groupids(client))
		return false;

	// Prepare whitelist statement
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Preparing vw_whitelist statement for client %s", clientip);
	querystr = get_client_querystr("vw_whitelist", "id", getstr(client->groupspos));
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v3(gravity_db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT(... vw_whitelist ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}
	whitelist_stmt->set(whitelist_stmt, client->id, stmt);
	free(querystr);

	// Prepare gravity statement
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Preparing vw_gravity statement for client %s", clientip);
	querystr = get_client_querystr("vw_gravity", "domain", getstr(client->groupspos));
	rc = sqlite3_prepare_v3(gravity_db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT(... vw_gravity ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}
	gravity_stmt->set(gravity_stmt, client->id, stmt);
	free(querystr);

	// Prepare blacklist statement
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Preparing vw_blacklist statement for client %s", clientip);
	querystr = get_client_querystr("vw_blacklist", "id", getstr(client->groupspos));
	rc = sqlite3_prepare_v3(gravity_db, querystr, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT(... vw_blacklist ...)\") - SQL error prepare: %s", sqlite3_errstr(rc));
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
	if(config.debug & DEBUG_DATABASE)
		logg("Finalizing gravity statements for %s", getstr(client->ippos));

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

	// Unset group found property to trigger a check next time the
	// client sends a query
	if(client != NULL)
	{
		client->flags.found_group = false;
	}
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

	// Finalize audit list statement
	sqlite3_finalize(auditlist_stmt);
	auditlist_stmt = NULL;

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
		logg("gravityDB_getTable(%u): Gravity database not available", list);
		return false;
	}

	// Checking for smaller than GRAVITY_LIST is omitted due to list being unsigned
	if(list >= UNKNOWN_TABLE)
	{
		logg("gravityDB_getTable(%u): Requested list is not known!", list);
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
	else if(list == REGEX_BLACKLIST_TABLE)
		querystr = "SELECT domain, id FROM vw_regex_blacklist GROUP BY id";
	else if(list == REGEX_WHITELIST_TABLE)
		querystr = "SELECT domain, id FROM vw_regex_whitelist GROUP BY id";

	// Prepare SQLite3 statement
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("readGravity(%s) - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		gravityDB_close();
		return false;
	}

	// Free allocated memory and return success
	return true;
}

// Get a single domain from a running SELECT operation
// This function returns a pointer to a string as long
// as there are domains available. Once we reached the
// end of the table, it returns NULL. It also returns
// NULL when it encounters an error (e.g., on reading
// errors). Errors are logged to FTL.log
// This function is performance critical as it might
// be called millions of times for large blocking lists
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
		logg("gravityDB_getDomain() - SQL error step: %s", sqlite3_errstr(rc));
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
		logg("gravityDB_count(%d): Gravity database not available", list);
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
		case REGEX_BLACKLIST_TABLE:
			querystr = "SELECT COUNT(DISTINCT domain) FROM vw_regex_blacklist";
			break;
		case REGEX_WHITELIST_TABLE:
			querystr = "SELECT COUNT(DISTINCT domain) FROM vw_regex_whitelist";
			break;
		case UNKNOWN_TABLE:
			logg("Error: List type %u unknown!", list);
			gravityDB_close();
			return DB_FAILED;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("Querying count of distinct domains in gravity database table %s: %s",
		     tablename[list], querystr);

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("gravityDB_count(%s) - SQL error prepare %s", querystr, sqlite3_errstr(rc));
		gravityDB_finalizeTable();
		gravityDB_close();
		return DB_FAILED;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	if(rc != SQLITE_ROW){
		logg("gravityDB_count(%s) - SQL error step %s", querystr, sqlite3_errstr(rc));
		if(list == GRAVITY_TABLE)
		{
			logg("Count of gravity domains not available. Please run pihole -g");
		}
		gravityDB_finalizeTable();
		gravityDB_close();
		return DB_FAILED;
	}

	// Get result when there was no error
	const int result = sqlite3_column_int(table_stmt, 0);

	// Finalize statement
	gravityDB_finalizeTable();

	if(config.debug & DEBUG_DATABASE)
	{
		logg("gravityDB_count(%d): %i entries in %s",
		     list, result, tablename[list]);
	}

	// Return result
	return result;
}

static enum db_result domain_in_list(const char *domain, sqlite3_stmt *stmt, const char *listname, int *domain_id)
{
	// Do not try to bind text to statement when database is not available
	if(!gravityDB_opened && !gravityDB_open())
	{
		logg("Gravity database not available (%s)", listname);
		return LIST_NOT_AVAILABLE;
	}

	int rc;
	// Bind domain to prepared statement
	// SQLITE_STATIC: Use the string without first duplicating it internally.
	// We can do this as domain has dynamic scope that exceeds that of the binding.
	// We need to bind the domain only once even to the prepared audit statement as:
	//     When the same named SQL parameter is used more than once, second and
	//     subsequent occurrences have the same index as the first occurrence.
	//     (https://www.sqlite.org/c3ref/bind_blob.html)
	if((rc = sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("domain_in_list(\"%s\", %p, %s): Failed to bind domain: %s",
		     domain, stmt, listname, sqlite3_errstr(rc));
		return LIST_NOT_AVAILABLE;
	}

	// Perform step
	rc = sqlite3_step(stmt);
	if(rc == SQLITE_BUSY)
	{
		// Database is busy
		logg("Gravity database is busy (%s)", listname);
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return LIST_NOT_AVAILABLE;
	}
	else if(rc != SQLITE_ROW && rc != SQLITE_DONE)
	{
		// Any return code that is neither SQLITE_BUSY nor SQLITE_ROW or
		// SQLITE_DONE is an error we should log
		logg("domain_in_list(\"%s\", %p, %s): Failed to perform step: %s",
		     domain, stmt, listname, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return LIST_NOT_AVAILABLE;
	}

	// Get result of query (if available)
	const int result = (rc == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : -1;
	if(domain_id != NULL)
		*domain_id = result;

	if(config.debug & DEBUG_DATABASE)
		logg("domain_in_list(\"%s\", %p, %s): %d", domain, stmt, listname, result);

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
		if(config.debug & DEBUG_CLIENTS)
			logg("Reloading client groups after %u seconds (%u%s check)",
			     (unsigned int)diff, check_count, ord);
		client->reread_groups++;
		gravityDB_reload_groups(client);
	}
}

enum db_result in_whitelist(const char *domain, DNSCacheData *dns_cache, clientsData* client)
{
	// If list statement is not ready and cannot be initialized (e.g. no
	// access to the database), we return false to prevent an FTL crash
	if(whitelist_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Check if this client needs a rechecking of group membership
	gravityDB_client_check_again(client);

	// Get whitelist statement from vector of prepared statements if available
	sqlite3_stmt *stmt = whitelist_stmt->get(whitelist_stmt, client->id);

	// If client statement is not ready and cannot be initialized (e.g. no access to
	// the database), we return false (not in whitelist) to prevent an FTL crash
	if(stmt == NULL && !gravityDB_prepare_client_statements(client))
	{
		logg("ERROR: Gravity database not available");
		return LIST_NOT_AVAILABLE;
	}

	// Update statement if has just been initialized
	if(stmt == NULL)
		stmt = whitelist_stmt->get(whitelist_stmt, client->id);

	// We have to check both the exact whitelist (using a prepared database statement)
	// as well the compiled regex whitelist filters to check if the current domain is
	// whitelisted.
	return domain_in_list(domain, stmt, "whitelist", &dns_cache->domainlist_id);
}

enum db_result in_gravity(const char *domain, clientsData *client)
{
	// If list statement is not ready and cannot be initialized (e.g. no
	// access to the database), we return false to prevent an FTL crash
	if(gravity_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Check if this client needs a rechecking of group membership
	gravityDB_client_check_again(client);

	// Get whitelist statement from vector of prepared statements
	sqlite3_stmt *stmt = gravity_stmt->get(gravity_stmt, client->id);

	// If client statement is not ready and cannot be initialized (e.g. no access to
	// the database), we return false (not in gravity list) to prevent an FTL crash
	if(stmt == NULL && !gravityDB_prepare_client_statements(client))
	{
		logg("ERROR: Gravity database not available");
		return LIST_NOT_AVAILABLE;
	}

	// Update statement if has just been initialized
	if(stmt == NULL)
		stmt = gravity_stmt->get(gravity_stmt, client->id);

	return domain_in_list(domain, stmt, "gravity", NULL);
}

enum db_result in_blacklist(const char *domain, DNSCacheData *dns_cache, clientsData *client)
{
	// If list statement is not ready and cannot be initialized (e.g. no
	// access to the database), we return false to prevent an FTL crash
	if(blacklist_stmt == NULL)
		return LIST_NOT_AVAILABLE;

	// Check if this client needs a rechecking of group membership
	gravityDB_client_check_again(client);

	// Get whitelist statement from vector of prepared statements
	sqlite3_stmt *stmt = blacklist_stmt->get(blacklist_stmt, client->id);

	// If client statement is not ready and cannot be initialized (e.g. no access to
	// the database), we return false (not in blacklist) to prevent an FTL crash
	if(stmt == NULL && !gravityDB_prepare_client_statements(client))
	{
		logg("ERROR: Gravity database not available");
		return LIST_NOT_AVAILABLE;
	}

	// Update statement if has just been initialized
	if(stmt == NULL)
		stmt = blacklist_stmt->get(blacklist_stmt, client->id);

	return domain_in_list(domain, stmt, "blacklist", &dns_cache->domainlist_id);
}

bool in_auditlist(const char *domain)
{
	// If audit list statement is not ready and cannot be initialized (e.g. no access
	// to the database), we return false (not in audit list) to prevent an FTL crash
	if(auditlist_stmt == NULL)
		return false;

	// We check the domain_audit table for the given domain
	return domain_in_list(domain, auditlist_stmt, "auditlist", NULL) == FOUND;
}

bool gravityDB_get_regex_client_groups(clientsData* client, const unsigned int numregex, const regexData *regex,
                                       const unsigned char type, const char* table)
{
	if(config.debug & DEBUG_REGEX)
		logg("Getting regex client groups for client with ID %i", client->id);

	char *querystr = NULL;
	if(!client->flags.found_group && !get_client_groupids(client))
		return false;

	// Group filtering
	const char *groups = getstr(client->groupspos);
	if(asprintf(&querystr, "SELECT id from %s WHERE group_id IN (%s);", table, groups) < 1)
	{
		logg("gravityDB_get_regex_client_groups(%s, %s) - asprintf() error", table, groups);
		return false;
	}

	// Prepare query
	sqlite3_stmt *query_stmt;
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("gravityDB_get_regex_client_groups(): %s - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
		gravityDB_close();
		free(querystr);
		return false;
	}

	// Perform query
	if(config.debug & DEBUG_REGEX)
		logg("Regex %s: Querying groups for client %s: \"%s\"", regextype[type], getstr(client->ippos), querystr);
	while((rc = sqlite3_step(query_stmt)) == SQLITE_ROW)
	{
		const int result = sqlite3_column_int(query_stmt, 0);
		for(unsigned int regexID = 0; regexID < numregex; regexID++)
		{
			if(regex[regexID].database_id == result)
			{
				// Regular expressions are stored in one array
				if(type == REGEX_WHITELIST)
					regexID += get_num_regex(REGEX_BLACKLIST);
				set_per_client_regex(client->id, regexID, true);

				if(config.debug & DEBUG_REGEX)
					logg("Regex %s: Enabling regex with DB ID %i for client %s", regextype[type], result, getstr(client->ippos));

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

void check_inaccessible_adlists(void)
{

	// check if any adlist was inaccessible in the last gravity run
	// if so, gravity stored `status` in the adlist table with
	// "3": List unavailable, Pi-hole used a local copy
	// "4": List unavailable, there is no local copy available 

	// Do not proceed when database is not available
	if(!gravityDB_opened && !gravityDB_open())
	{
		logg("check_inaccessible_adlists(): Gravity database not available");
		return;
	}

	const char *querystr = "SELECT id, address FROM adlist WHERE status IN (3,4) AND enabled=1";
	
	// Prepare query
	sqlite3_stmt *query_stmt;
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("check_inaccessible_adlists(): %s - SQL error prepare: %s", querystr, sqlite3_errstr(rc));
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
