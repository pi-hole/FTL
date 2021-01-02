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

// clients data structure
#include "../datastructure.h"
// enum http_method
#include "../webserver/http-common.h"
// Definition of struct regex_data
#include "../regex_r.h"

typedef struct domainrecord {
	const char *domain;
	time_t date_added;
	time_t date_modified;
	const char *comment;
	bool enabled;
} domainrecord;

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

bool gravityDB_readTable(const int type, const char *domain, const char **message);
bool gravityDB_readTableGetDomain(domainrecord *domain, const char **message);
void gravityDB_readTableFinalize(void);
bool gravityDB_addToTable(const int type, const char *domain,
                          const bool enabled, const char *comment,
                          const char **message, const enum http_method method);
bool gravityDB_delFromTable(const int type, const char* domain, const char **message);

#endif //GRAVITY_H
