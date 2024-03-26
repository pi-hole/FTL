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
#include "datastructure.h"
// Definition of struct regexData
#include "regex_r.h"

// Table row record, not all fields are used by all tables
typedef struct {
	bool enabled;
	int type_int;
	int number;
	int invalid_domains;
	int abp_entries;
	int status;
	const char *name;
	const char *domain;
	const char *address;
	const char *type;
	const char *kind;
	const char *comment;
	const char *group_ids;
	const char *client;
	const char *item;
	cJSON *items;
	long id;
	time_t date_added;
	time_t date_modified;
	time_t date_updated;
} tablerow;

bool gravityDB_open(void);
bool gravityDB_reopen(void);
void gravityDB_forked(void);
void gravityDB_reload_groups(clientsData* client);
bool gravityDB_prepare_client_statements(clientsData* client);
void gravityDB_close(void);
bool gravityDB_getTable(unsigned char list);
const char* gravityDB_getDomain(int *rowid);
char* get_client_names_from_ids(const char *group_ids) __attribute__ ((malloc));
void gravityDB_finalizeTable(void);
int gravityDB_count(const enum gravity_tables list);
void check_inaccessible_adlists(void);
bool gravity_updated(void);

cJSON *gen_abp_patterns(const char *domain, const bool antigravity);
enum db_result in_gravity(const char *domain, clientsData *client, const bool antigravity, int* domain_id);
enum db_result in_denylist(const char *domain, DNSCacheData *dns_cache, clientsData *client);
enum db_result in_allowlist(const char *domain, DNSCacheData *dns_cache, clientsData *client);

bool gravityDB_get_regex_client_groups(clientsData* client, const unsigned int numregex, const regexData *regex,
                                       const unsigned char type, const char* table);

bool gravityDB_readTable(const enum gravity_list_type listtype, const char *filter,
                         const char **message, const bool exact, const char *ids);
bool gravityDB_readTableGetRow(const enum gravity_list_type listtype, tablerow *row, const char **message);
void gravityDB_readTableFinalize(void);
bool gravityDB_addToTable(const enum gravity_list_type listtype, tablerow *row,
                          const char **message, const enum http_method method);
bool gravityDB_delFromTable(const enum gravity_list_type listtype, const cJSON* array, unsigned int *deleted, const char **message);
bool gravityDB_edit_groups(const enum gravity_list_type listtype, cJSON *groups,
                           const tablerow *row, const char **message);

#endif //GRAVITY_H
