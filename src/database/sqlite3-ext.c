/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  SQLite3 database engine extensions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "database/sqlite3ext.h"
SQLITE_EXTENSION_INIT1
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
#include "log.h"

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
	const char *addrDBcidr = (const char*)sqlite3_value_text(argv[0]);
	bool isIPv6_DB = strchr(addrDBcidr, ':') != NULL;

	const char *addrFTL = (const char*)sqlite3_value_text(argv[1]);
	bool isIPv6_FTL = strchr(addrFTL, ':') != NULL;

	// Skip if IP types do not match
	if(isIPv6_DB != isIPv6_FTL)
	{
		sqlite3_result_int(context, 0);
		return;
	}

	// Extract possible CIDR from database IP string
	int cidr = isIPv6_DB ? 128 : 32;
	char *addrDB = NULL;
	sscanf(addrDBcidr, "%m[^/]/%i", &addrDB, &cidr);

	// Converts the Internet host address into binary form in network byte order
	// We use in6_addr as variable type here as it is guaranteed to be large enough
	// for both, IPv4 and IPv6 addresses (128 bits variable size)
	struct in6_addr saddrDB = {{{ 0 }}}, saddrFTL = {{{ 0 }}};
	if (inet_pton(isIPv6_DB ? AF_INET6 : AF_INET, addrDB, &saddrDB) == 0)
	{
		sqlite3_result_error(context, "Passed a malformed IP address (database)", -1);
		free(addrDB);
		return;
	}
	if (inet_pton(isIPv6_FTL ? AF_INET6 : AF_INET, addrFTL, &saddrFTL) == 0)
	{
		sqlite3_result_error(context, "Passed a malformed IP address (FTL)", -1);
		free(addrDB);
		return;
	}

	// Free allocated memory
	free(addrDB);

	// Translate CIDR into a binary masking field
	uint8_t bitmask[16] = { 0 };
	for(int i = 0; i < 128; i++)
	{
		if(i >= cidr) break;
		bitmask[i/8] |= (1 << (i%8));
	}

	// Apply bitmask
	for(int i = 0; i < 16; i++)
	{
		saddrDB.__in6_u.__u6_addr8[i] &= bitmask[i];
		saddrFTL.__in6_u.__u6_addr8[i] &= bitmask[i];

		// Are the addresses different given the applied mask?
		if(saddrDB.__in6_u.__u6_addr8[i] != saddrFTL.__in6_u.__u6_addr8[i])
		{
			sqlite3_result_int(context, 0);
			logg("Comparing database %s (extracted CIDR: /%i) to %s - NO MATCH", addrDBcidr, cidr, addrFTL);
			return;
		}
	}

	// Found no difference between the two addresses given a possibly specified mask
	sqlite3_result_int(context, 1);
	logg("Comparing database %s (extracted CIDR: /%i) to %s - !!! MATCH !!!", addrDBcidr, cidr, addrFTL);
}

int sqlite3_pihole_extensions_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi)
{
	SQLITE_EXTENSION_INIT2(pApi);
	(void)pzErrMsg;  /* Unused parameter */

	// Register new sqlite function
	int rc = sqlite3_create_function(db, "subnet_match", 2, SQLITE_UTF8, 0, subnet_match_impl, 0, 0);

	return rc;
}