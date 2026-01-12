/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity parseDomains prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef GRAVITY_PARSEDOMAINS_H
#define GRAVITY_PARSEDOMAINS_H

#include "FTL.h"

// Domain list types (matches database schema)
typedef enum {
	DOMAINLIST_TYPE_WHITELIST = 0,   // Exact allowed domains
	DOMAINLIST_TYPE_BLACKLIST = 1,   // Exact denied domains
	DOMAINLIST_TYPE_REGEX_WHITE = 2, // Regex allowed filters
	DOMAINLIST_TYPE_REGEX_BLACK = 3, // Regex denied filters
	DOMAINLIST_TYPE_INVALID = -1
} domainlist_type_t;

// Parse domain list type from string
domainlist_type_t parse_domainlist_type(const char *type_str);

// Import domains from file into domainlist table
int gravity_parseDomains(const char *infile, const char *outfile,
                         const char *type_str, const char *comment);

#endif // GRAVITY_PARSEDOMAINS_H
