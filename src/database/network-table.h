/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL.db -> network tables prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef NETWORKTABLE_H
#define NETWORKTABLE_H

#include "sqlite3.h"

bool create_network_table(sqlite3 *db);
bool create_network_addresses_table(sqlite3 *db);
bool create_network_addresses_with_names_table(sqlite3 *db);
void parse_neighbor_cache(sqlite3 *db);
void updateMACVendorRecords(sqlite3 *db);
bool unify_hwaddr(sqlite3 *db);
char* getDatabaseHostname(const char* ipaddr) __attribute__((malloc));
char* __attribute__((malloc)) getMACfromIP(sqlite3 *db, const char* ipaddr);
int getAliasclientIDfromIP(sqlite3 *db, const char *ipaddr);
char* __attribute__((malloc)) getNameFromIP(sqlite3 *db, const char* ipaddr);
char* __attribute__((malloc)) getIfaceFromIP(sqlite3 *db, const char* ipaddr);
void resolveNetworkTableNames(void);

#endif //NETWORKTABLE_H
