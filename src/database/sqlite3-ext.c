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
#include "../log.h"
// struct config
#include "../config/config.h"

// isMAC()
#include "network-table.h"

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
static bool __attribute__ ((pure)) isMAC(const char *input)
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
	if(config.debug & DEBUG_DATABASE)
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

int sqlite3_pihole_extensions_init(sqlite3 *db, const char **pzErrMsg, const struct sqlite3_api_routines *pApi)
{
	(void)pzErrMsg;  /* Unused parameter */

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

	return rc;
}