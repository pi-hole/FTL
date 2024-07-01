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
char *getMACfromIP(sqlite3 *db, const char* ipaddr) __attribute__((malloc));
int getAliasclientIDfromIP(sqlite3 *db, const char *ipaddr);
char *getNameFromIP(sqlite3 *db, const char* ipaddr) __attribute__((malloc));
char *getNameFromMAC(const char *client) __attribute__((malloc));
char *getIfaceFromIP(sqlite3 *db, const char* ipaddr) __attribute__((malloc));
void resolveNetworkTableNames(void);
bool flush_network_table(void);
bool isMAC(const char *input) __attribute__ ((pure));

typedef struct {
	unsigned int id;
	const char *hwaddr;
	const char *iface;
	const char *macVendor;
	unsigned long numQueries;
	time_t firstSeen;
	time_t lastQuery;
} network_record;

bool networkTable_readDevices(sqlite3 *db, sqlite3_stmt **read_stmt, const char **message);
bool networkTable_readDevicesGetRecord(sqlite3_stmt *read_stmt, network_record *network, const char **message);
void networkTable_readDevicesFinalize(sqlite3_stmt *read_stmt);

typedef struct {
	const char *ip;
	const char *name;
	time_t lastSeen;
	time_t nameUpdated;
} network_addresses_record;

bool networkTable_readIPs(sqlite3 *db, sqlite3_stmt **read_stmt, const int id, const char **message);
bool networkTable_readIPsGetRecord(sqlite3_stmt *read_stmt, network_addresses_record *network_addresses, const char **message);
void networkTable_readIPsFinalize(sqlite3_stmt *read_stmt);

bool networkTable_deleteDevice(sqlite3 *db, const int id, int *deleted, const char **message);

#endif //NETWORKTABLE_H
