/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DNS Client Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "shmem.h"
#include "memory.h"
#include "datastructure.h"
#include "resolve.h"
#include "config.h"
#include "timers.h"
#include "log.h"
// global variable killed
#include "signals.h"
// getDatabaseHostname()
#include "database/network-table.h"
// struct _res
#include <resolv.h>
// FTL_db
#include "database/common.h"
// resolver_ready
#include "daemon.h"

static bool res_initialized = false;

// Validate given hostname
static bool valid_hostname(char* name, const char* clientip)
{
	// Check for validity of input
	if(name == NULL)
		return false;

	// Check for maximum length of hostname
	// Truncate if too long (MAXHOSTNAMELEN defaults to 64, see asm-generic/param.h)
	if(strlen(name) > MAXHOSTNAMELEN)
	{
		logg("WARNING: Hostname of client %s too long, truncating to %d chars!",
		     clientip, MAXHOSTNAMELEN);
		// We can modify the string in-place as the target is
		// shorter than the source
		name[MAXHOSTNAMELEN] = '\0';
	}

	// Iterate over characters in hostname
	// to check for legal char: A-Z a-z 0-9 - _ .
	for (char c; (c = *name); name++)
	{
		if ((c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') ||
			 c == '-' ||
			 c == '_' ||
			 c == '.' )
			continue;

		// Invalid character found, log and return hostname being invalid
		logg("WARN: Hostname of client %s contains invalid character: %c (char code %d)",
		     clientip, (unsigned char)c, (unsigned char)c);
		return false;
	}

	// No invalid characters found
	return true;
}

static void print_used_resolvers(const char *message)
{
	logg("%s", message);
	for(unsigned int i = 0u; i < MAXNS; i++)
		logg(" %u: %s:%d", i,
		     inet_ntoa(_res.nsaddr_list[i].sin_addr),
		     ntohs(_res.nsaddr_list[i].sin_port));
}

static char *resolveHostname(const char *addr)
{
	// Get host name
	struct hostent *he = NULL;
	char *hostname = NULL;
	bool IPv6 = false;

	if(config.debug & DEBUG_RESOLVER)
		logg("Trying to resolve %s", addr);

	// Check if this is a hidden client
	// if so, return "hidden" as hostname
	if(strcmp(addr, "0.0.0.0") == 0)
	{
		hostname = strdup("hidden");
		if(config.debug & DEBUG_RESOLVER)
			logg("---> \"%s\" (privacy settings)", hostname);
		return hostname;
	}

	// Test if we want to resolve an IPv6 address
	if(strstr(addr,":") != NULL)
	{
		IPv6 = true;
	}

	if( (IPv6 && !config.resolveIPv6) ||
	   (!IPv6 && !config.resolveIPv4))
	{
		if(config.debug & DEBUG_RESOLVER)
		{
			logg(" ---> \"\" (configured to not resolve %s host names)",
			     IPv6 ? "IPv6" : "IPv4");
			return strdup("");
		}
	}

	// Initialize resolver subroutines if trying to resolve for the first time
	// res_init() reads resolv.conf to get the default domain name and name server
	// address(es). If no server is given, the local host is tried. If no domain
	// is given, that associated with the local host is used.
	if(!res_initialized)
	{
		res_init();
		res_initialized = true;
	}

	// Step 1: Backup configured name servers and invalidate them
	struct in_addr ns_addr_bck[MAXNS];
	in_port_t ns_port_bck[MAXNS];
	for(unsigned int i = 0u; i < MAXNS; i++)
	{
		ns_addr_bck[i] = _res.nsaddr_list[i].sin_addr;
		ns_port_bck[i] = _res.nsaddr_list[i].sin_port;
		_res.nsaddr_list[i].sin_addr.s_addr = 0; // 0.0.0.0
	}
	// Step 2: Set 127.0.0.1 (FTL) as the only resolver
	const char *FTLip = "127.0.0.1";
	// Set resolver address
	inet_pton(AF_INET, FTLip, &_res.nsaddr_list[0].sin_addr);
	// Set resolver port (have to convert from host to network byte order)
	_res.nsaddr_list[0].sin_port = htons(config.dns_port);

	if(config.debug & DEBUG_RESOLVER)
		print_used_resolvers("Setting nameservers to:");

	// Step 3: Try to resolve addresses
	if(IPv6) // Resolve IPv6 address
	{
		struct in6_addr ipaddr;
		inet_pton(AF_INET6, addr, &ipaddr);
		// Known to leak some tiny amounts of memory under certain conditions
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET6);
	}
	else // Resolve IPv4 address
	{
		struct in_addr ipaddr;
		inet_pton(AF_INET, addr, &ipaddr);
		// Known to leak some tiny amounts of memory under certain conditions
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET);
	}

	// Step 4: Check if gethostbyaddr() returned a host name
	// First check for he not being NULL before trying to dereference it
	if(he != NULL)
	{
		if(valid_hostname(he->h_name, addr))
		{
			// Return hostname copied to new memory location
			hostname = strdup(he->h_name);

			// Convert hostname to lower case
			if(hostname != NULL)
				strtolower(hostname);
		}
		else
		{
			hostname = strdup("[invalid host name]");
		}

		if(config.debug & DEBUG_RESOLVER)
			logg(" ---> \"%s\" (found internally)", hostname);
	}

	// Step 5: Restore resolvers (without forced FTL)
	for(unsigned int i = 0u; i < MAXNS; i++)
	{
		_res.nsaddr_list[i].sin_addr = ns_addr_bck[i];
		_res.nsaddr_list[i].sin_port = ns_port_bck[i];
	}
	if(config.debug & DEBUG_RESOLVER)
		print_used_resolvers("Setting nameservers back to default:");

	// Step 6: If no host name was found before, try again with system-configured
	// resolvers (necessary for docker and friends)
	if(hostname == NULL)
	{
		if(IPv6) // Resolve IPv6 address
		{
			struct in6_addr ipaddr;
			inet_pton(AF_INET6, addr, &ipaddr);
			// Known to leak some tiny amounts of memory under certain conditions
			he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET6);
		}
		else // Resolve IPv4 address
		{
			struct in_addr ipaddr;
			inet_pton(AF_INET, addr, &ipaddr);
			// Known to leak some tiny amounts of memory under certain conditions
			he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET);
		}

		// Step 6.1: Check if gethostbyaddr() returned a host name this time
		// First check for he not being NULL before trying to dereference it
		if(he != NULL)
		{
			if(valid_hostname(he->h_name, addr))
			{
				// Return hostname copied to new memory location
				hostname = strdup(he->h_name);

				// Convert hostname to lower case
				if(hostname != NULL)
					strtolower(hostname);
			}
			else
			{
				hostname = strdup("[invalid host name]");
			}

			if(config.debug & DEBUG_RESOLVER)
				logg(" ---> \"%s\" (found externally)", hostname);
		}
		else
		{
			// No (he == NULL) or invalid (valid_hostname returned false) hostname found
			hostname = strdup("");

			if(config.debug & DEBUG_RESOLVER)
				logg(" ---> \"%s\" (%s)", hostname, he != NULL ? he->h_name : "N/A");
		}
	}

	// Return result
	return hostname;
}

// Resolve upstream destination host names
static size_t resolveAndAddHostname(size_t ippos, size_t oldnamepos)
{
	// Get IP and host name strings. They are cloned in case shared memory is
	// resized before the next lock
	lock_shm();
	char* ipaddr = strdup(getstr(ippos));
	char* oldname = strdup(getstr(oldnamepos));
	unlock_shm();

	// Important: Don't hold a lock while resolving as the main thread
	// (dnsmasq) needs to be operable during the call to resolveHostname()
	char* newname = resolveHostname(ipaddr);

	// If no hostname was found, try to obtain hostname from the network table
	if(strlen(newname) == 0)
	{
		free(newname);
		newname = getDatabaseHostname(ipaddr);
	}

	// Only store new newname if it is valid and differs from oldname
	// We do not need to check for oldname == NULL as names are
	// always initialized with an empty string at position 0
	if(newname != NULL && strcmp(oldname, newname) != 0)
	{
		lock_shm();
		size_t newnamepos = addstr(newname);
		// newname has already been checked against NULL
		// so we can safely free it
		free(newname);
		free(ipaddr);
		free(oldname);
		unlock_shm();
		return newnamepos;
	}
	else if(config.debug & DEBUG_SHMEM)
	{
		// Debugging output
		logg("Not adding \"%s\" to buffer (unchanged)", oldname);
	}

	free(newname);
	free(ipaddr);
	free(oldname);

	// Not changed, return old namepos
	return oldnamepos;
}

// Resolve client host names
void resolveClients(const bool onlynew)
{
	// Lock counter access here, we use a copy in the following loop
	lock_shm();
	int clientscount = counters->clients;
	unlock_shm();

	int skipped = 0;
	for(int clientID = 0; clientID < clientscount; clientID++)
	{
		// Get client pointer
		clientsData* client = getClient(clientID, true);
		if(client == NULL)
		{
			logg("ERROR: Unable to get client pointer with ID %i, skipping...", clientID);
			skipped++;
			continue;
		}

		// Memory access needs to get locked
		lock_shm();
		bool newflag = client->new;
		size_t ippos = client->ippos;
		size_t oldnamepos = client->namepos;
		unlock_shm();

		// If onlynew flag is set, we will only resolve new clients
		// If not, we will try to re-resolve all known clients
		if(onlynew && !newflag)
		{
			skipped++;
			continue;
		}

		// Obtain/update hostname of this client
		size_t newnamepos = resolveAndAddHostname(ippos, oldnamepos);

		lock_shm();
		// Store obtained host name (may be unchanged)
		client->namepos = newnamepos;
		// Mark entry as not new
		client->new = false;
		unlock_shm();
	}

	if(config.debug & DEBUG_RESOLVER)
	{
		logg("%i / %i client host names resolved",
		     clientscount-skipped, clientscount);
	}
}

// Resolve upstream destination host names
void resolveForwardDestinations(const bool onlynew)
{
	// Lock counter access here, we use a copy in the following loop
	lock_shm();
	int upstreams = counters->upstreams;
	unlock_shm();

	int skipped = 0;
	for(int upstreamID = 0; upstreamID < upstreams; upstreamID++)
	{
		// Get upstream pointer
		upstreamsData* upstream = getUpstream(upstreamID, true);
		if(upstream == NULL)
		{
			logg("ERROR: Unable to get upstream pointer with ID %i, skipping...", upstreamID);
			skipped++;
			continue;
		}

		// Memory access needs to get locked
		lock_shm();
		bool newflag = upstream->new;
		size_t ippos = upstream->ippos;
		size_t oldnamepos = upstream->namepos;
		unlock_shm();

		// If onlynew flag is set, we will only resolve new upstream destinations
		// If not, we will try to re-resolve all known upstream destinations
		if(onlynew && !newflag)
		{
			skipped++;
			continue;
		}

		// Obtain/update hostname of this client
		size_t newnamepos = resolveAndAddHostname(ippos, oldnamepos);

		lock_shm();
		// Store obtained host name (may be unchanged)
		upstream->namepos = newnamepos;
		// Mark entry as not new
		upstream->new = false;
		unlock_shm();
	}

	if(config.debug & DEBUG_RESOLVER)
	{
		logg("%i / %i upstream server host names resolved",
		     upstreams-skipped, upstreams);
	}
}

// Resolve unknown names of recently seen IP addresses in network table
static void resolveNetworkTableNames(void)
{
	// Open database file
	if(!dbopen())
	{
		logg("resolveNetworkTableNames() - Failed to open DB");
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
		dbclose();
		return;
	}

	// Get IP addresses seen within the last 24 hours with empty or NULL host names
	const char querystr[] = "SELECT ip FROM network_addresses "
	                               "WHERE (name IS NULL OR "
	                                      "name = '') AND "
	                                     "lastSeen > cast(strftime('%%s', 'now') as int)-86400;";

	// Prepare query
	sqlite3_stmt *table_stmt = NULL;
	rc = sqlite3_prepare_v2(FTL_db, querystr, -1, &table_stmt, NULL);
	if(rc != SQLITE_OK)
	{
		logg("resolveNetworkTableNames() - SQL error prepare: %s",
		     sqlite3_errstr(rc));
		sqlite3_finalize(table_stmt);
		dbclose();
		return;
	}

	// Get data
	while((rc = sqlite3_step(table_stmt)) == SQLITE_ROW)
	{
		// Get IP address from database
		const char* ip = (const char*)sqlite3_column_text(table_stmt, 0);

		// Try to obtain host name
		char* newname = resolveHostname(ip);

		if(config.debug & DEBUG_RESOLVER)
			logg("Resolving database IP %s -> %s", ip, newname);

		// Store new host name in database if not empty
		if(strlen(newname) > 0)
		{
			const char updatestr[] = "UPDATE network_addresses "
			                                "SET name = ?1,"
			                                    "nameUpdated = cast(strftime('%%s', 'now') as int) "
			                                "WHERE ip = ?2";
			sqlite3_stmt *update_stmt = NULL;
			int rc2 = sqlite3_prepare_v2(FTL_db, updatestr, -1, &update_stmt, NULL);
			if(rc2 != SQLITE_OK){
				logg("resolveNetworkTableNames(%s -> %s) - SQL error prepare: %s",
					ip, newname, sqlite3_errstr(rc2));
				sqlite3_finalize(update_stmt);
				break;
			}

			// Bind newname to prepared statement
			if((rc2 = sqlite3_bind_text(update_stmt, 1, newname, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				logg("resolveNetworkTableNames(%s -> %s): Failed to bind newname: %s",
					ip, newname, sqlite3_errstr(rc2));
				sqlite3_finalize(update_stmt);
				break;
			}

			// Bind ip to prepared statement
			if((rc2 = sqlite3_bind_text(update_stmt, 2, ip, -1, SQLITE_STATIC)) != SQLITE_OK)
			{
				logg("resolveNetworkTableNames(%s -> %s): Failed to bind ip: %s",
					ip, newname, sqlite3_errstr(rc2));
				sqlite3_finalize(update_stmt);
				break;
			}
			rc2 = sqlite3_step(update_stmt);
			if(rc2 != SQLITE_BUSY && rc2 != SQLITE_DONE)
			{
				// Any return code that is neither SQLITE_BUSY not SQLITE_ROW
				// is a real error we should log
				logg("resolveNetworkTableNames(%s -> %s): Failed to perform step: %s",
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
		dbclose();
		return;
	}

	// Close and unlock database connection
	sqlite3_finalize(table_stmt);
	dbclose();
}

void *DNSclient_thread(void *val)
{
	// Set thread name
	prctl(PR_SET_NAME, "DNS client", 0, 0, 0);

	// Initial delay until we first try to resolve anything
	sleepms(2000);

	while(!killed)
	{
		// Run every minute to resolve only new clients and upstream servers
		if(resolver_ready && time(NULL) % RESOLVE_INTERVAL == 0)
		{
			// Try to resolve new client host names (onlynew=true)
			resolveClients(true);
			// Try to resolve new upstream destination host names (onlynew=true)
			resolveForwardDestinations(true);
			// Prevent immediate re-run of this routine
			sleepms(500);
		}

		// Run every hour to update possibly changed client host names
		if(resolver_ready && time(NULL) % RERESOLVE_INTERVAL == 0)
		{
			// Try to resolve all client host names (onlynew=false)
			resolveClients(false);
			// Try to resolve all upstream destination host names (onlynew=false)
			resolveForwardDestinations(false);
			// Try to resolve host names from clients in the network table
			// which have empty/undefined host names
			resolveNetworkTableNames();
			// Prevent immediate re-run of this routine
			sleepms(500);
		}

		// Idle for 0.5 sec before checking again the time criteria
		sleepms(500);
	}

	return NULL;
}
