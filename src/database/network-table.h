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

bool create_network_table(void);
bool create_network_addresses_table(void);
void parse_neighbor_cache(void);
void updateMACVendorRecords(void);
bool unify_hwaddr(void);
char* getDatabaseHostname(const char* ipaddr) __attribute__((malloc));

typedef struct networkrecord {
        unsigned int id;
	const char *hwaddr;
        const char* interface;
        const char *name;
        const char *macVendor;
        unsigned long numQueries;
        time_t firstSeen;
        time_t lastQuery;
} networkrecord;

bool networkTable_readDevices(const char **message);
bool networkTable_readDevicesGetRecord(networkrecord *network, const char **message);
void networkTable_readDevicesFinalize(void);

bool networkTable_readIPs(const int id);
const char *networkTable_readIPsGetRecord(void);
void networkTable_readIPsFinalize(void);

#endif //NETWORKTABLE_H
