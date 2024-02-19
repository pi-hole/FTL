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

// struct queriesData
#include "datastructure.h"

#define CREATE_FTL_TABLE "CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );"

#define CREATE_QUERIES_TABLE_V1 "CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                                                       "timestamp INTEGER NOT NULL, " \
                                                       "type INTEGER NOT NULL, " \
                                                       "status INTEGER NOT NULL, " \
                                                       "domain TEXT NOT NULL, " \
                                                       "client TEXT NOT NULL, " \
                                                       "forward TEXT );"

#define MEMDB_VERSION 17
#define CREATE_QUERY_STORAGE_TABLE "CREATE TABLE query_storage ( id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                                                                "timestamp INTEGER NOT NULL, " \
                                                                "type INTEGER NOT NULL, " \
                                                                "status INTEGER NOT NULL, " \
                                                                "domain INTEGER NOT NULL, " \
                                                                "client INTEGER NOT NULL, " \
                                                                "forward INTEGER, " \
                                                                "additional_info INTEGER, " \
                                                                "reply_type INTEGER, " \
                                                                "reply_time REAL, " \
                                                                "dnssec INTEGER, " \
                                                                "list_id INTEGER );"

#define CREATE_QUERIES_VIEW "CREATE VIEW queries AS " \
                                    "SELECT id, timestamp, type, status, " \
                                      "CASE typeof(domain) " \
                                        "WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain," \
                                      "CASE typeof(client) " \
                                        "WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client," \
                                      "CASE typeof(forward) " \
                                        "WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward," \
                                      "CASE typeof(additional_info) "\
                                        "WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info, " \
                                      "reply_type, reply_time, dnssec, list_id FROM query_storage q"

// Version 1
#define CREATE_QUERIES_TIMESTAMP_INDEX		"CREATE INDEX idx_queries_timestamp ON queries (timestamp);"
// Version 12
#define CREATE_QUERY_STORAGE_ID_INDEX			"CREATE UNIQUE INDEX idx_query_storage_id ON query_storage (id);"
#define CREATE_QUERY_STORAGE_TIMESTAMP_INDEX		"CREATE INDEX idx_query_storage_timestamp ON query_storage (timestamp);"
#define CREATE_QUERY_STORAGE_TYPE_INDEX		"CREATE INDEX idx_query_storage_type ON query_storage (type);"
#define CREATE_QUERY_STORAGE_STATUS_INDEX		"CREATE INDEX idx_query_storage_status ON query_storage (status);"
#define CREATE_QUERY_STORAGE_DOMAIN_INDEX		"CREATE INDEX idx_query_storage_domain ON query_storage (domain);"
#define CREATE_QUERY_STORAGE_CLIENT_INDEX		"CREATE INDEX idx_query_storage_client ON query_storage (client);"
#define CREATE_QUERY_STORAGE_FORWARD_INDEX		"CREATE INDEX idx_query_storage_forward ON query_storage (forward);"
#define CREATE_QUERY_STORAGE_ADDITIONAL_INFO_INDEX	"CREATE INDEX idx_query_storage_additional_info ON query_storage (additional_info);"
#define CREATE_QUERY_STORAGE_REPLY_TYPE_INDEX		"CREATE INDEX idx_query_storage_reply_type ON query_storage (reply_type);"
#define CREATE_QUERY_STORAGE_REPLY_TIME_INDEX		"CREATE INDEX idx_query_storage_reply_time ON query_storage (reply_time);"
#define CREATE_QUERY_STORAGE_DNSSEC_INDEX		"CREATE INDEX idx_query_storage_dnssec ON query_storage (dnssec);"
#define CREATE_QUERY_STORAGE_LIST_ID_INDEX		"CREATE INDEX idx_query_storage_list_id ON query_storage (list_id);"

#define CREATE_DOMAINS_BY_ID "CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);"
#define CREATE_CLIENTS_BY_ID "CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);"
#define CREATE_FORWARD_BY_ID "CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT NOT NULL);"
#define CREATE_ADDINFO_BY_ID "CREATE TABLE addinfo_by_id (id INTEGER PRIMARY KEY, type INTEGER NOT NULL, content NOT NULL);"

#define CREATE_DOMAIN_BY_ID_DOMAIN_INDEX "CREATE UNIQUE INDEX domain_by_id_domain_idx ON domain_by_id(domain);"
#define CREATE_CLIENTS_BY_ID_IPNAME_INDEX "CREATE UNIQUE INDEX client_by_id_client_idx ON client_by_id(ip,name);"
#define CREATE_FORWARD_BY_ID_FORWARD_INDEX "CREATE UNIQUE INDEX forward_by_id_forward_idx ON forward_by_id(forward);"
#define CREATE_ADDINFO_BY_ID_TYPECONTENT_INDEX "CREATE UNIQUE INDEX addinfo_by_id_idx ON addinfo_by_id(type,content);"

#ifdef QUERY_TABLE_PRIVATE
const char *table_creation[] = {
	CREATE_QUERY_STORAGE_TABLE,
	CREATE_DOMAINS_BY_ID,
	CREATE_CLIENTS_BY_ID,
	CREATE_FORWARD_BY_ID,
	CREATE_ADDINFO_BY_ID,
	CREATE_QUERIES_VIEW,
};
const char *index_creation[] = {
	CREATE_QUERY_STORAGE_ID_INDEX,
	CREATE_QUERY_STORAGE_TIMESTAMP_INDEX,
	CREATE_QUERY_STORAGE_TYPE_INDEX,
	CREATE_QUERY_STORAGE_STATUS_INDEX,
	CREATE_QUERY_STORAGE_DOMAIN_INDEX,
	CREATE_QUERY_STORAGE_CLIENT_INDEX,
	CREATE_QUERY_STORAGE_FORWARD_INDEX,
	CREATE_QUERY_STORAGE_ADDITIONAL_INFO_INDEX,
	CREATE_QUERY_STORAGE_REPLY_TYPE_INDEX,
	CREATE_QUERY_STORAGE_REPLY_TIME_INDEX,
	CREATE_QUERY_STORAGE_DNSSEC_INDEX,
	CREATE_QUERY_STORAGE_LIST_ID_INDEX
	CREATE_DOMAIN_BY_ID_DOMAIN_INDEX,
	CREATE_CLIENTS_BY_ID_IPNAME_INDEX,
	CREATE_FORWARD_BY_ID_FORWARD_INDEX,
	CREATE_ADDINFO_BY_ID_TYPECONTENT_INDEX,
};
#endif

unsigned long get_max_db_idx(void) __attribute__((pure));
void db_counts(unsigned long *last_idx, unsigned long *mem_num, unsigned long *disk_num);
bool init_memory_database(void);
sqlite3 *get_memdb(void) __attribute__((pure));
void close_memory_database(void);
bool import_queries_from_disk(void);
bool attach_database(sqlite3* db, const char **message, const char *path, const char *alias);
bool detach_database(sqlite3* db, const char **message, const char *alias);
int get_number_of_queries_in_DB(sqlite3 *db, const char *tablename);
bool export_queries_to_disk(bool final);
bool delete_old_queries_from_db(const bool use_memdb, const double mintime);
bool add_additional_info_column(sqlite3 *db);
void DB_read_queries(void);
void update_disk_db_idx(void);
bool queries_to_database(void);

bool optimize_queries_table(sqlite3 *db);
bool create_addinfo_table(sqlite3 *db);
bool add_query_storage_columns(sqlite3 *db);
bool add_query_storage_column_regex_id(sqlite3 *db);
bool add_ftl_table_description(sqlite3 *db);
bool rename_query_storage_column_regex_id(sqlite3 *db);

#endif //QUERY_TABLE_PRIVATE_H
