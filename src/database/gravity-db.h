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

// Table indices
enum { GRAVITY_TABLE, EXACT_BLACKLIST_TABLE, EXACT_WHITELIST_TABLE, REGEX_BLACKLIST_TABLE, REGEX_WHITELIST_TABLE, UNKNOWN_TABLE };

bool gravityDB_open(void);
bool gravityDB_prepare_client_statements(clientsData* client);
void gravityDB_finalize_client_statements(clientsData* client);
void gravityDB_reload_client_statements(void);
void gravityDB_close(void);
bool gravityDB_getTable(unsigned char list);
const char* gravityDB_getDomain(int *rowid);
void gravityDB_finalizeTable(void);
int gravityDB_count(unsigned char list);
bool in_auditlist(const char *domain);

bool in_gravity(const char *domain, clientsData* client);
bool in_whitelist(const char *domain, clientsData* client);
bool in_blacklist(const char *domain, clientsData* client);

bool gravityDB_get_regex_client_groups(clientsData* client, const int numregex, const int *regexid,
                                       const unsigned char type, const char* table);


#endif //GRAVITY_H
