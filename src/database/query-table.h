/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef QUERY_TABLE_PRIVATE_H
#define QUERY_TABLE_PRIVATE_H

// queriesData*
#include "../datastructure.h"

#define CREATE_QUERIES_TABLE_V1 "CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );"
#define CREATE_QUERIES_TABLE_V7 "CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT, additional_info TEXT );"
#define CREATE_QUERIES_TIMESTAMP_INDEX "CREATE INDEX idx_queries_timestamp ON queries (timestamp);"
#define CREATE_QUERIES_TYPE_INDEX "CREATE INDEX idx_queries_type ON queries (type);"
#define CREATE_QUERIES_STATUS_INDEX "CREATE INDEX idx_queries_status ON queries (status);"
#define CREATE_QUERIES_DOMAIN_INDEX "CREATE INDEX idx_queries_domain ON queries (domain);"
#define CREATE_CLIENT_DOMAIN_INDEX "CREATE INDEX idx_queries_client ON queries (client);"
#define CREATE_FORWARD_DOMAIN_INDEX "CREATE INDEX idx_queries_forward ON queries (forward);"
#ifdef QUERY_TABLE_PRIVATE
const char *index_creation[] = { CREATE_QUERIES_TIMESTAMP_INDEX,
                                 CREATE_QUERIES_TYPE_INDEX,
                                 CREATE_QUERIES_STATUS_INDEX,
                                 CREATE_QUERIES_DOMAIN_INDEX,
                                 CREATE_CLIENT_DOMAIN_INDEX,
                                 CREATE_FORWARD_DOMAIN_INDEX };
#endif

bool init_memory_database(void);
bool import_queries_from_disk(void);
int get_number_of_queries_in_DB(bool disk);
bool export_queries_to_disk(bool final);
bool delete_query_from_db(const sqlite3_int64 id);
void DB_read_queries(void);
bool query_to_database(queriesData* query);

#endif //QUERY_TABLE_PRIVATE_H
