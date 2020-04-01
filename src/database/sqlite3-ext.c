/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  SQLite3 database engine extensions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "database/sqlite3.h"
#include "database/sqlite3-ext.h"

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
// logg()
#include "log.h"
// struct config
#include "config.h"

static void subnet_match_impl(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	// Exactly two arguments should be submitted to this routine
	if(argc != 2)
	{
		sqlite3_result_error(context, "Passed an invalid number of arguments", -1);
		return;
	}

	// Return if invoked with NULL argument
	if (sqlite3_value_type(argv[0]) == SQLITE_NULL ||
	    sqlite3_value_type(argv[1]) == SQLITE_NULL)
	{
		return;
	}

	// Analyze input supplied to our SQLite subroutine
	// From the DB side (first argument) ...
	const char *addrDBcidr = (const char*)sqlite3_value_text(argv[0]);
	bool isIPv6_DB = strchr(addrDBcidr, ':') != NULL;
	// ... and from FTL's side (second argument)
	const char *addrFTL = (const char*)sqlite3_value_text(argv[1]);
	bool isIPv6_FTL = strchr(addrFTL, ':') != NULL;

	// Return early (no match) if IP types are different
	// We can skip all computations in this case
	if(isIPv6_DB != isIPv6_FTL)
	{
		sqlite3_result_int(context, 0);
		return;
	}

	// Extract possible CIDR from database IP string
	int cidr = isIPv6_DB ? 128 : 32;
	char *addrDB = NULL;
	// sscanf() will not overwrite the pre-defined CIDR in cidr if
	// no CIDR is specified in the database
	sscanf(addrDBcidr, "%m[^/]/%i", &addrDB, &cidr);

	// Convert the Internet host address into binary form in network byte order
	// We use in6_addr as variable type here as it is guaranteed to be large enough
	// for both, IPv4 and IPv6 addresses (128 bits variable size).
	struct in6_addr saddrDB = {{{ 0 }}}, saddrFTL = {{{ 0 }}};
	if (inet_pton(isIPv6_DB ? AF_INET6 : AF_INET, addrDB, &saddrDB) == 0)
	{
		//sqlite3_result_error(context, "Passed a malformed IP address (database)", -1);
		// Return non-fatal "NO MATCH" if address is invalid
		logg("Passed a malformed DB IP address: %s/%i (%s)", addrDB, cidr, addrDBcidr);
		sqlite3_result_int(context, 0);
		free(addrDB);
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
		logg("Passed a malformed FTL IP address: %s", addrFTL);
		sqlite3_result_int(context, 0);
		return;
	}

	// Construct binary mask from CIDR field
	uint8_t bitmask[16] = { 0 };
	for(int i = 0; i < cidr; i++)
	{
		bitmask[i/8] |= (1 << (i%8));
	}

	// Apply bitmask to both IP addresses
	// Note: the upper 12 byte of IPv4 addresses are zero
	int match = 1;
	for(int i = 0; i < 16; i++)
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

	// Return if we found a match between the two addresses
	// given a possibly specified mask
	sqlite3_result_int(context, match);

	// Possible debug logging
	if(config.debug & DEBUG_DATABASE)
	{
		logg("SQL: Comparing %s vs. %s (database) - %s",
		     addrFTL, addrDBcidr,
			 match == 1 ? "!! MATCH !!" : "NO MATCH");
	}
}

int sqlite3_pihole_extensions_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi)
{
	(void)pzErrMsg;  /* Unused parameter */

	// Register new sqlite function subnet_match taking 2 arguments in UTF8 format.
	// The function is deterministic in the sense of always returning the same output for the same input.
	// We define a scalar function here so the last two pointers are NULL.
	int rc = sqlite3_create_function(db, "subnet_match", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
	                                 subnet_match_impl, NULL, NULL);

	if(rc != SQLITE_OK)
	{
		logg("Error while initializing the SQLite3 extension subnet_match: %s",
		     sqlite3_errstr(rc));
	}

	return rc;
}