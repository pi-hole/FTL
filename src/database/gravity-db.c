/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "sqlite3.h"
#include "datastructure.h"
#include "gravity-db.h"
#include "config.h"
#include "log.h"
// global variable counters
#include "memory.h"
// match_regex()
#include "regex_r.h"
// getstr()
#include "shmem.h"

// Private variables
static sqlite3 *gravity_db = NULL;
static sqlite3_stmt* table_stmt = NULL;
static sqlite3_stmt* auditlist_stmt = NULL;
bool gravity_database_avail = false;

// Table names corresponding to the enum defined in gravity-db.h
static const char* tablename[] = { "vw_gravity", "vw_blacklist", "vw_whitelist", "vw_regex_blacklist", "vw_regex_whitelist" , ""};

// Prototypes from functions in dnsmasq's source
void rehash(int size);

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

	int rc = sqlite3_open_v2(FTLfiles.gravity_db, &gravity_db, SQLITE_OPEN_READONLY, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open() - SQL error (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}

	// Explicitly set busy handler to zero milliseconds
	rc = sqlite3_busy_timeout(gravity_db, 0);
	if(rc != SQLITE_OK)
	{
		logg("gravityDB_open() - Cannot set busy handler (%i): %s", rc, sqlite3_errmsg(gravity_db));
	}

	// Tell SQLite3 to store temporary tables in memory. This speeds up read operations on
	// temporary tables, indices, and views.
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
	rc = sqlite3_prepare_v2(gravity_db, "SELECT EXISTS(SELECT domain from domain_audit WHERE domain = ?);", -1, &auditlist_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT EXISTS(... domain_audit ...)\") - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}

	// Database connection is now open
	gravity_database_avail = true;
	if(config.debug & DEBUG_DATABASE)
		logg("gravityDB_open(): Successfully opened gravity.db");

	return true;
}

static char* get_client_querystr(const char* table, const char* groups)
{
	// Build query string with group filtering
	char *querystr = NULL;
	if(asprintf(&querystr, "SELECT EXISTS(SELECT domain from %s WHERE domain = ? AND group_id IN (%s));", table, groups) < 1)
	{
		logg("get_client_querystr(%s, %s) - asprintf() error", table, groups);
		return NULL;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("get_client_querystr: %s", querystr);

	return querystr;
}

static bool get_client_groupids(const clientsData* client, char **groups)
{
	// Get associated groups for this client (if defined)
	char *querystr = NULL;
	const char *ip = getstr(client->ippos);
	*groups = NULL;

	// Do not proceed when database is not available
	if(!gravity_database_avail)
	{
		logg("get_client_groupids(): Gravity database not available");
		return false;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("Querying gravity database for client %s", ip);

	// Check if client is configured through the client table
	if(asprintf(&querystr, "SELECT COUNT(*) FROM client WHERE ip = \'%s\';", ip) < 1)
	{
		logg("get_client_groupids() - asprintf() error 1");
		return false;
	}

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("get_client_groupids(%s) - SQL error prepare (%i): %s",
		     querystr, rc, sqlite3_errmsg(gravity_db));
		sqlite3_finalize(table_stmt);
		gravityDB_close();
		free(querystr);
		return false;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	if(rc == SQLITE_ROW)
	{
		// There is a record for this client in the database
		const int result = sqlite3_column_int(table_stmt, 0);

		// Found no record for this client in the database
		// This makes this client qualify for the special "all" group
		if(result == 0)
			*groups = strdup("0");
	}
	else if(rc == SQLITE_DONE)
	{
		// Found no record for this client in the database
		// This makes this client qualify for the special "all" group
		*groups = strdup("0");
	}
	else
	{
		logg("get_client_groupids(%s) - SQL error step (%i): %s",
		     querystr, rc, sqlite3_errmsg(gravity_db));
		sqlite3_finalize(table_stmt);
		gravityDB_close();
		free(querystr);
		return false;
	}
	// Finalize statement
	gravityDB_finalizeTable();

	if(*groups != NULL)
	{
		// The client is not configured through the client table, return early
		return true;
	}

	// Build query string to get possible group associations for this particular client
	// The SQL GROUP_CONCAT() function returns a string which is the concatenation of all
	// non-NULL values of group_id separated by ','. The order of the concatenated elements
	// is arbitrary, however, is of no relevance for your use case.
	if(asprintf(&querystr, "SELECT GROUP_CONCAT(group_id) FROM client_by_group WHERE client_id = (SELECT id FROM client WHERE ip = \'%s\');", ip) < 1)
	{
		logg("get_client_groupids() - asprintf() error 2");
		return false;
	}

	// Prepare query
	rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("get_client_groupids(%s) - SQL error prepare (%i): %s",
		     querystr, rc, sqlite3_errmsg(gravity_db));
		sqlite3_finalize(table_stmt);
		gravityDB_close();
		free(querystr);
		return false;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	if(rc == SQLITE_ROW)
	{
		// There is a record for this client in the database
		const char* result = (const char*)sqlite3_column_text(table_stmt, 0);
		if(result != NULL)
			*groups = strdup(result);
		else
			*groups = strdup("");
	}
	else if(rc == SQLITE_DONE)
	{
		// Found no record for this client in the database
		// -> No associated groups
		*groups = strdup("");
	}
	else
	{
		logg("get_client_groupids(%s) - SQL error step (%i): %s",
		     querystr, rc, sqlite3_errmsg(gravity_db));
		sqlite3_finalize(table_stmt);
		gravityDB_close();
		free(querystr);
		return false;
	}
	// Finalize statement
	gravityDB_finalizeTable();
	// Free allocated memory and return result
	free(querystr);
	return true;
}

bool gravityDB_prepare_client_statements(clientsData* client)
{
	// Return early if gravity database is not available
	if(!gravity_database_avail)
		return false;

	if(config.debug & DEBUG_DATABASE)
		logg("Initializing gravity statements for %s", getstr(client->ippos));

	// Get associated groups for this client (if defined)
	char *querystr = NULL;
	char *groups = NULL;
	if(!get_client_groupids(client, &groups))
		return false;

	// Prepare whitelist statement
	// We use SELECT EXISTS() as this is known to efficiently use the index
	// We are only interested in whether the domain exists or not in the
	// list but don't case about duplicates or similar. SELECT EXISTS(...)
	// returns true as soon as it sees the first row from the query inside
	// of EXISTS().
	querystr = get_client_querystr("vw_whitelist", groups);
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &client->whitelist_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT EXISTS(... vw_whitelist ...)\") - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}
	free(querystr);

	// Prepare gravity statement
	querystr = get_client_querystr("vw_gravity", groups);
	rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &client->gravity_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT EXISTS(... vw_gravity ...)\") - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}
	free(querystr);

	// Prepare blacklist statement
	querystr = get_client_querystr("vw_blacklist", groups);
	rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &client->blacklist_stmt, NULL);
	if( rc != SQLITE_OK )
	{
		logg("gravityDB_open(\"SELECT EXISTS(... vw_blacklist ...)\") - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		return false;
	}
	free(querystr);

	// Free groups
	free(groups);

	return true;
}

inline void gravityDB_finalize_client_statements(clientsData* client)
{
	sqlite3_finalize(client->gravity_stmt);
	sqlite3_finalize(client->blacklist_stmt);
	sqlite3_finalize(client->whitelist_stmt);
}

void gravityDB_reload_client_statements(void)
{
	for(int i=0; i < counters->clients; i++)
	{
		clientsData* client = getClient(i, true);
		if(client != NULL)
			gravityDB_prepare_client_statements(client);
	}
}

void gravityDB_close(void)
{
	// Return early if gravity database is not available
	if(!gravity_database_avail)
		return;

	// Finalize list statements
	for(int i=0; i < counters->clients; i++)
	{
		clientsData* client = getClient(i, true);
		if(client != NULL)
			gravityDB_finalize_client_statements(client);
	}
	sqlite3_finalize(auditlist_stmt);

	// Close table
	sqlite3_close(gravity_db);
	gravity_database_avail = false;
}

// Prepare a SQLite3 statement which can be used by
// gravityDB_getDomain() to get blocking domains from
// a table which is specified when calling this function
bool gravityDB_getTable(const unsigned char list)
{
	if(!gravity_database_avail)
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

	char *querystr = NULL;
	// Build correct query string to be used depending on list to be read
	if(asprintf(&querystr, "SELECT domain, id FROM %s", tablename[list]) < 18)
	{
		logg("readGravity(%u) - asprintf() error", list);
		return false;
	}

	// Prepare SQLite3 statement
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("readGravity(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(gravity_db));
		gravityDB_close();
		free(querystr);
		return false;
	}

	// Free allocated memory and return success
	free(querystr);
	return true;
}

// Get a single domain from a running SELECT operation
// This function returns a pointer to a string as long
// as there are domains available. Once we reached the
// end of the table, it returns NULL. It also returns
// NULL when it encounters an error (e.g., on reading
// errors). Errors are logged to pihole-FTL.log
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
		*rowid = sqlite3_column_int(table_stmt, 1);
		return domain;
	}

	// Check for error. An error happened when the result is neither
	// SQLITE_ROW (we returned earlier in this case), nor
	// SQLITE_DONE (we are finished reading the table)
	if(rc != SQLITE_DONE)
	{
		logg("gravityDB_getDomain() - SQL error step (%i): %s", rc, sqlite3_errmsg(gravity_db));
		*rowid = -1;
		return NULL;
	}

	// Finished reading, nothing to get here
	*rowid = -1;
	return NULL;
}

// Finalize statement of a gravity database transaction
void gravityDB_finalizeTable(void)
{
	if(!gravity_database_avail)
		return;

	// Finalize statement
	sqlite3_finalize(table_stmt);
}

// Get number of domains in a specified table of the gravity database
// We return the constant DB_FAILED and log to pihole-FTL.log if we
// encounter any error
int gravityDB_count(const unsigned char list)
{
	if(!gravity_database_avail)
	{
		logg("gravityDB_count(%d): Gravity database not available", list);
		return DB_FAILED;
	}

	// Checking for smaller than GRAVITY_LIST is omitted due to list being unsigned
	if(list >= UNKNOWN_TABLE)
	{
		logg("gravityDB_getTable(%u): Requested list is not known!", list);
		return false;
	}

	char *querystr = NULL;
	// Build correct query string to be used depending on list to be read
	if(list != GRAVITY_TABLE && asprintf(&querystr, "SELECT COUNT(DISTINCT domain) FROM %s", tablename[list]) < 18)
	{
		logg("readGravity(%u) - asprintf() error", list);
		return false;
	}
	// We get the number of unique gravity domains as counted and stored by gravity. Counting the number
	// of distinct domains in vw_gravity may take up to several minutes for very large blocking lists on
	// very low-end devices such as the Raspierry Pi Zero
	else if(list == GRAVITY_TABLE && asprintf(&querystr, "SELECT value FROM info WHERE property = 'gravity_count';") < 18)
	{
		logg("readGravity(%u) - asprintf() error", list);
		return false;
	}

	if(config.debug & DEBUG_DATABASE)
		logg("Querying gravity database table %s", tablename[list]);

	// Prepare query
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("gravityDB_count(%s) - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(gravity_db));
		gravityDB_finalizeTable();
		gravityDB_close();
		free(querystr);
		return DB_FAILED;
	}

	// Perform query
	rc = sqlite3_step(table_stmt);
	if(rc != SQLITE_ROW){
		logg("gravityDB_count(%s) - SQL error step (%i): %s", querystr, rc, sqlite3_errmsg(gravity_db));
		if(list == GRAVITY_TABLE)
		{
			logg("Count of gravity domains not available. Please run pihole -g");
		}
		gravityDB_finalizeTable();
		free(querystr);
		return DB_FAILED;
	}

	// Get result when there was no error
	const int result = sqlite3_column_int(table_stmt, 0);

	// Finalize statement
	gravityDB_finalizeTable();

	// Free allocated memory and return result
	free(querystr);
	return result;
}

static bool domain_in_list(const char *domain, sqlite3_stmt* stmt, const char* listname)
{
	// Do not try to bind text to statement when database is not available
	if(!gravity_database_avail)
	{
		logg("domain_in_list(%s): Gravity database not available", domain);
		return false;
	}

	int retval;
	// Bind domain to prepared statement
	// SQLITE_STATIC: Use the string without first duplicating it internally.
	// We can do this as domain has dynamic scope that exceeds that of the binding.
	if((retval = sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		logg("domain_in_list(\"%s\"): Failed to bind domain (error %d) - %s",
		     domain, retval, sqlite3_errmsg(gravity_db));
		sqlite3_reset(stmt);
		return false;
	}

	// Perform step
	retval = sqlite3_step(stmt);
	if(retval == SQLITE_BUSY)
	{
		// Database is busy
		logg("domain_in_list(\"%s\"): Database is busy, assuming domain is NOT on list",
		     domain);
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return false;
	}
	else if(retval != SQLITE_ROW)
	{
		// Any return code that is neither SQLITE_BUSY not SQLITE_ROW
		// is a real error we should log
		logg("domain_in_list(\"%s\"): Failed to perform step (error %d) - %s",
		     domain, retval, sqlite3_errmsg(gravity_db));
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return false;
	}

	// Get result of query "SELECT EXISTS(...)"
	const int result = sqlite3_column_int(stmt, 0);

	if(config.debug & DEBUG_DATABASE)
		logg("domain_in_%s(\"%s\"): %d", listname, domain, result);

	// The sqlite3_reset() function is called to reset a prepared
	// statement object back to its initial state, ready to be
	// re-executed. Note: Any SQL statement variables that had values
	// bound to them using the sqlite3_bind_*() API retain their values.
	sqlite3_reset(stmt);

	// Contrary to the intuition of many, sqlite3_reset() does not reset
	// the bindings on a prepared statement. Use this routine to reset
	// all host parameters to NULL.
	sqlite3_clear_bindings(stmt);

	// Return if domain was found in current table
	// SELECT EXISTS(...) either returns 0 (false) or 1 (true).
	return (result == 1);
}

inline bool in_whitelist(const char *domain, clientsData* client, const int clientID)
{
	if(client->whitelist_stmt == NULL)
		gravityDB_prepare_client_statements(client);
	// We have to check both the exact whitelist (using a prepared database statement)
	// as well the compiled regex whitelist filters to check if the current domain is
	// whitelisted. Due to short-circuit-evaluation in C, the regex evaluations is executed
	// only if the exact whitelist lookup does not deliver a positive match. This is an
	// optimization as the database lookup will most likely hit (a) more domains and (b)
	// will be faster (given a sufficiently large number of regex whitelisting filters).
	return domain_in_list(domain, client->whitelist_stmt, "whitelist") ||
	       match_regex(domain, clientID, REGEX_WHITELIST);
}

inline bool in_gravity(const char *domain, clientsData* client)
{
	if(client->gravity_stmt == NULL)
		gravityDB_prepare_client_statements(client);
	return domain_in_list(domain, client->gravity_stmt, "gravity");
}

inline bool in_blacklist(const char *domain, clientsData* client)
{
	if(client->blacklist_stmt == NULL)
		gravityDB_prepare_client_statements(client);
	return domain_in_list(domain, client->blacklist_stmt, "blacklist");
}

bool in_auditlist(const char *domain)
{
	// We check the domain_audit table for the given domain
	return domain_in_list(domain, auditlist_stmt, "auditlist");
}

bool gravityDB_get_regex_client_groups(clientsData* client, const int numregex, const int *regexid,
                                       const unsigned char type, const char* table, const int clientID)
{
	char *querystr = NULL;
	char *groups = NULL;
	if(!get_client_groupids(client, &groups))
		return false;

	// Group filtering
	if(asprintf(&querystr, "SELECT id from %s WHERE group_id IN (%s);", table, groups) < 1)
	{
		logg("gravityDB_get_regex_client_groups(%s, %s) - asprintf() error", table, groups);
		return false;
	}

	// Prepare query
	sqlite3_stmt *query_stmt;
	int rc = sqlite3_prepare_v2(gravity_db, querystr, -1, &query_stmt, NULL);
	if(rc != SQLITE_OK){
		logg("gravityDB_get_regex_client_groups(): %s - SQL error prepare (%i): %s", querystr, rc, sqlite3_errmsg(gravity_db));
		sqlite3_finalize(query_stmt);
		gravityDB_close();
		free(querystr);
		free(groups);
		return false;
	}

	// Perform query
	if(config.debug & DEBUG_DATABASE)
		logg("Querying regex groups: %s", querystr);
	while((rc = sqlite3_step(query_stmt)) == SQLITE_ROW)
	{
		const int result = sqlite3_column_int(query_stmt, 0);
		for(int i = 0; i < numregex; i++)
		{
			if(regexid[i] == result)
			{
				unsigned int regexID = i;
				if(type == REGEX_WHITELIST)
					regexID += counters->num_regex[REGEX_BLACKLIST];
				set_per_client_regex(clientID, regexID, true);
				break;
			}
		}
	}

	// Finalize statement
	sqlite3_finalize(query_stmt);

	// Free allocated memory and return result
	free(querystr);
	free(groups);

	return true;
}
