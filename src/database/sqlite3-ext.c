/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  SQLite3 database engine extensions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "sqlite3.h"
#include "sqlite3-ext.h"

// inet_pton
#include <arpa/inet.h>
// sscanf()
#include <stdio.h>
// type bool
#include <stdbool.h>
// strstr()
#include <string.h>
// free()
#include <stdlib.h>
// logging routines
#include "log.h"
// struct config
#include "config/config.h"

// isMAC()
#include "network-table.h"

static void subnet_match_impl(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	// Exactly two arguments should be submitted to this routine
	if(argc != 2)
	{
		sqlite3_result_error(context, "Passed an invalid number of arguments", -1);
		return;
	}

	// Return NO MATCH if invoked with non-TEXT arguments
	if (sqlite3_value_type(argv[0]) != SQLITE_TEXT ||
	    sqlite3_value_type(argv[1]) != SQLITE_TEXT)
	{
		log_err("SQL: Invoked subnet_match() with non-text arguments: %d, %d",
		        sqlite3_value_type(argv[0]), sqlite3_value_type(argv[1]));
		sqlite3_result_int(context, 0);
		return;
	}

	// Analyze input supplied to our SQLite subroutine
	// From the DB side (first argument) ...
	const char *addrDBcidr = (const char*)sqlite3_value_text(argv[0]);
	// ... and from FTL's side (second argument)
	const char *addrFTL = (const char*)sqlite3_value_text(argv[1]);

	// Return early (no match) if database entry is a MAC address
	// We can skip all computations in this case
	if(isMAC(addrDBcidr))
	{
		sqlite3_result_int(context, 0);
		return;
	}

	// Return early (no match) if IP types are different
	// We can skip all computations in this case
	bool isIPv6_DB = strchr(addrDBcidr, ':') != NULL;
	bool isIPv6_FTL = strchr(addrFTL, ':') != NULL;
	if(isIPv6_DB != isIPv6_FTL)
	{
		sqlite3_result_int(context, 0);
		return;
	}

	// Extract possible CIDR from database IP string
	// sscanf() will not overwrite the pre-defined CIDR in cidr if
	// no CIDR is specified in the database
	int cidr = isIPv6_DB ? 128 : 32;
	char *addrDB = NULL;
	const int rt = sscanf(addrDBcidr, "%m[^/]/%i", &addrDB, &cidr);

	// Limit CIDR to valid values
	if(cidr < 0 || cidr > (isIPv6_DB ? 128 : 32))
	{
		log_err("SQL: Invalid CIDR value %d in database entry: %s", cidr, addrDBcidr);
		sqlite3_result_int(context, 0);
		return;
	}

	// Skip if database row seems to be a CIDR but does not contain an address ('/32' is invalid)
	// Passing an invalid IP address to inet_pton() causes a SEGFAULT
	if(rt < 1 || addrDB == NULL)
	{
		sqlite3_result_int(context, 0);
		return;
	}

	// Convert the Internet host address into binary form in network byte order
	// We use in6_addr as variable type here as it is guaranteed to be large enough
	// for both, IPv4 and IPv6 addresses (128 bits variable size).
	struct in6_addr saddrDB = {{{ 0 }}}, saddrFTL = {{{ 0 }}};
	if (inet_pton(isIPv6_DB ? AF_INET6 : AF_INET, addrDB, &saddrDB) == 0)
	{
		// This may happen when trying to analyze a hostname, skip this entry and return NO MATCH (= 0)
		free(addrDB);
		sqlite3_result_int(context, 0);
		return;
	}

	// Free allocated memory
	free(addrDB);
	addrDB = NULL;

	// Check and convert client IP address as seen by FTL
	if (inet_pton(isIPv6_FTL ? AF_INET6 : AF_INET, addrFTL, &saddrFTL) == 0)
	{
		//sqlite3_result_error(context, "Passed a malformed IP address (FTL)", -1);
		// Return non-fatal "NO MATCH" if address is invalid
		log_err("Malformed FTL IP address: %s", addrFTL);
		sqlite3_result_int(context, 0);
		return;
	}

	// Construct binary mask from CIDR field
	uint8_t bitmask[16] = { 0 };
	for(int i = 0; i < cidr; i++)
	{
		bitmask[i/8] |= (1 << (7-(i%8)));
	}

	// Apply bitmask to both IP addresses
	// Note: the upper 12 byte of IPv4 addresses are zero
	int match = 1;
	for(unsigned int i = 0u; i < 16u; i++)
	{
		saddrDB.s6_addr[i] &= bitmask[i];
		saddrFTL.s6_addr[i] &= bitmask[i];

		// Are the addresses different given the applied mask?
		if(saddrDB.s6_addr[i] != saddrFTL.s6_addr[i])
		{
			match = 0;
			break;
		}
	}

	// Possible debug logging
	if(config.debug.database.v.b)
	{
		char subnet[INET6_ADDRSTRLEN];
		inet_ntop(isIPv6_FTL ? AF_INET6 : AF_INET, &bitmask, subnet, sizeof(subnet));
		log_debug(DEBUG_DATABASE, "SQL: Comparing %s vs. %s (subnet %s) - %s",
		          addrFTL, addrDBcidr, subnet,
		          match == 1 ? "!! MATCH !!" : "NO MATCH");
	}

	// Return if we found a match between the two addresses
	// given a possibly specified mask. We return the number of
	// matching bits (cannot be more than the CIDR field specified)
	// so the algorithm can decide which subnet match is the most
	// exact one and prefer it (e.g., 10.8.1.0/24 beats 10.0.0.0/8)
	sqlite3_result_int(context, match ? cidr : 0);
}

// Identify IPv6 addresses
static void isIPv6_impl(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	// Exactly one argument should be submitted to this routine
	if(argc != 1)
	{
		sqlite3_result_error(context, "Passed an invalid number of arguments", -1);
		return;
	}

	// Return NO MATCH if invoked with non-TEXT argument
	if (sqlite3_value_type(argv[0]) != SQLITE_TEXT)
	{
		sqlite3_result_error(context, "Invoked isIPv6() with non-text argument", -1);
		return;
	}

	const char *input = (const char*)sqlite3_value_text(argv[0]);
	if(input == NULL)
	{
		sqlite3_result_error(context, "Invoked isIPv6() with NULL argument", -1);
		return;
	}

	struct in6_addr addr = { 0 };
	if(inet_pton(AF_INET6, input, &addr) == 1)
	{
		// IPv6 address, return 1 and exit
		sqlite3_result_int(context, 1);
		return;
	}

	// Not an IPv6 address, return 0
	sqlite3_result_int(context, 0);
}

// Initialize Pi-hole SQLite3 extension
static int sqlite3_pihole_extensions_init(sqlite3 *db, char **pzErrMsg, const struct sqlite3_api_routines *pApi)
{
	// Register new sqlite function subnet_match taking 2 arguments in UTF8 format.
	// The function is deterministic in the sense of always returning the same output for the same input.
	// We define a scalar function here so the last two pointers are NULL.
	int rc = sqlite3_create_function(db, "subnet_match", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
	                                 subnet_match_impl, NULL, NULL);

	if(rc != SQLITE_OK)
	{
		log_err("Error while initializing the SQLite3 extension subnet_match: %s",
		        sqlite3_errstr(rc));
	}

	// Register new sqlite function isIPv6 taking 1 argument in UTF8 format.
	// The function is deterministic in the sense of always returning the same output for the same input.
	// We define a scalar function here so the last two pointers are NULL.
	rc = sqlite3_create_function(db, "isIPv6", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
	                                 isIPv6_impl, NULL, NULL);

	if(rc != SQLITE_OK)
	{
		log_err("Error while initializing the SQLite3 extension isIPv6: %s",
		        sqlite3_errstr(rc));
	}

	return rc;
}

// The following logic implements lightweight memory allocation tracer for
// SQLite3. It tracks the total amount of memory allocated by SQLite3 and makes
// this information available via the sqlite3_mem_used() function. We do not use
// the provided memory allocation tracing of SQLite3 as it does a lot more
// bookkeeping which we do not need here and which significantly slows down
// memory allocations.

/* The original memory allocation routines */
static sqlite3_mem_methods memtraceBase;
struct sqlite3_memory_usage mem = { 0 };

/* Methods that trace memory allocations */
static void *memtraceMalloc(int n)
{
	// Allocate memory and track usage
	const int m = memtraceBase.xRoundup(n);
	mem.total += m;
	if(mem.total > mem.highwater)
		mem.highwater = mem.total;
	if(m > mem.largest_block)
		mem.largest_block = m;
	mem.current_allocations++;
	return memtraceBase.xMalloc(m);
}

static void memtraceFree(void *p)
{
	// Handle free of NULL pointer as no-op
	if(p == NULL)
		return;

	// Free memory and track usage
	mem.current_allocations--;
	mem.total -= memtraceBase.xSize(p);
	if(mem.total < 0)
		mem.total = 0;
	memtraceBase.xFree(p);
}

static void *memtraceRealloc(void *p, int n)
{
	// Handle realloc of NULL pointer as malloc
	if(p == NULL)
		return memtraceMalloc(n);

	// Handle realloc to zero bytes as free
	if(n == 0)
	{
		memtraceFree(p);
		return 0;
	}

	// Reallocate memory and track usage
	mem.total -= memtraceBase.xSize(p);
	if(mem.total < 0)
		mem.total = 0;
	mem.total += memtraceBase.xRoundup(n);
	return memtraceBase.xRealloc(p, n);
}

// xSize should return the allocated size of a memory allocation previously
// obtained from xMalloc or xRealloc. The allocated size is always at least as
// big as the requested size but may be larger.
static int memtraceSize(void *p)
{
	return memtraceBase.xSize(p);
}

// The xRoundup method returns what would be the allocated size of a memory
// allocation given a particular requested size.
static int memtraceRoundup(int n)
{
	return memtraceBase.xRoundup(n);
}

// Initialize memory allocator
static int memtraceInit(void *p)
{
	return memtraceBase.xInit(p);
}

// Shutdown memory allocator
static void memtraceShutdown(void *p)
{
	memtraceBase.xShutdown(p);
}

/* The substitute memory allocator */
static sqlite3_mem_methods ersatzMethods = {
	memtraceMalloc,
	memtraceFree,
	memtraceRealloc,
	memtraceSize,
	memtraceRoundup,
	memtraceInit,
	memtraceShutdown,
	0
};

/**
 * @brief Initializes the Pi-hole SQLite3 extensions and the SQLite3 engine.
 *
 * This function registers the Pi-hole provided SQLite3 extensions and initializes
 * the SQLite3 engine. It should be called before any SQLite3 operations are performed.
 */
void pihole_sqlite3_initalize(void)
{
	// Set up memory allocation tracing
	int rc = sqlite3_config(SQLITE_CONFIG_GETMALLOC, &memtraceBase);
	if (rc == SQLITE_OK)
	{
		// Set our memory allocation tracing methods
		rc = sqlite3_config(SQLITE_CONFIG_MALLOC, &ersatzMethods);
		if (rc != SQLITE_OK)
			log_warn("Error while setting up SQLite3 memory allocation tracing: %s",
			         sqlite3_errstr(rc));
	}
	else
	{
		// Most likely, the database is already initialized at this
		// point
		log_warn("Error while retrieving SQLite3 memory allocation methods: %s",
		         sqlite3_errstr(rc));
	}

	// Register Pi-hole provided SQLite3 extensions
	// This may also initialize the database engine. It is, nonetheless,
	// safe to call sqlite3_initialize() again afterwards and actually
	// recommended as auto-init may be removed in future SQLite3 versions.
	sqlite3_auto_extension((void (*)(void))sqlite3_pihole_extensions_init);

	// Initialize the SQLite3 engine
	sqlite3_initialize();
}

struct sqlite3_memory_usage * __attribute__((const)) sqlite3_mem_used(void)
{
	return &mem;
}

