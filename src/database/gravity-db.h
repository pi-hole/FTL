/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  gravity database prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef GRAVITY_H
#define GRAVITY_H

// clientsData
#include "../datastructure.h"
// regex_data
#include "../regex_r.h"

// Table indices
enum gravity_tables { GRAVITY_TABLE, EXACT_BLACKLIST_TABLE, EXACT_WHITELIST_TABLE, REGEX_BLACKLIST_TABLE, REGEX_WHITELIST_TABLE, UNKNOWN_TABLE } __attribute__ ((packed));

void gravityDB_forked(void);
void gravityDB_reopen(void);
bool gravityDB_open(void);
bool gravityDB_prepare_client_statements(const int clientID, clientsData* client);
void gravityDB_close(void);
bool gravityDB_getTable(unsigned char list);
const char* gravityDB_getDomain(int *rowid);
char* get_client_names_from_ids(const char *group_ids) __attribute__ ((malloc));
void gravityDB_finalizeTable(void);
int gravityDB_count(const enum gravity_tables list);
bool in_auditlist(const char *domain);

bool in_gravity(const char *domain, const int clientID, clientsData* client);
bool in_blacklist(const char *domain, const int clientID, clientsData* client);
bool in_whitelist(const char *domain, const DNSCacheData *dns_cache, const int clientID, clientsData* client);

bool gravityDB_get_regex_client_groups(clientsData* client, const unsigned int numregex, const regex_data *regex,
                                       const unsigned char type, const char* table, const int clientID);

#endif //GRAVITY_H
