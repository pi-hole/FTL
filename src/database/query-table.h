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
#include "../datastructure.h"

#define CREATE_FTL_TABLE "CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );"

#define CREATE_QUERIES_TABLE_V1 "CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                                                       "timestamp INTEGER NOT NULL, " \
                                                       "type INTEGER NOT NULL, " \
                                                       "status INTEGER NOT NULL, " \
                                                       "domain TEXT NOT NULL, " \
                                                       "client TEXT NOT NULL, " \
                                                       "forward TEXT );"

#define CREATE_QUERIES_TABLE_V10 "CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                                                        "timestamp INTEGER NOT NULL, " \
                                                        "type INTEGER NOT NULL, " \
                                                        "status INTEGER NOT NULL, " \
                                                        "domain TEXT NOT NULL, " \
                                                        "client TEXT NOT NULL, " \
                                                        "forward TEXT, " \
                                                        "additional_info TEXT, " \
                                                        "reply INTEGER, " \
                                                        "dnssec INTEGER, " \
                                                        "reply_time NUMBER, " \
                                                        "client_name TEXT, " \
                                                        "ttl INTEGER, " \
                                                        "regex_id INTEGER );"

#define CREATE_QUERIES_ID_INDEX			"CREATE INDEX idx_queries_id ON queries (id);"
#define CREATE_QUERIES_TIMESTAMP_INDEX		"CREATE INDEX idx_queries_timestamp ON queries (timestamp);"
#define CREATE_QUERIES_TYPE_INDEX		"CREATE INDEX idx_queries_type ON queries (type);"
#define CREATE_QUERIES_STATUS_INDEX		"CREATE INDEX idx_queries_status ON queries (status);"
#define CREATE_QUERIES_DOMAIN_INDEX		"CREATE INDEX idx_queries_domain ON queries (domain);"
#define CREATE_QUERIES_CLIENT_INDEX		"CREATE INDEX idx_queries_client ON queries (client);"
#define CREATE_QUERIES_FORWARD_INDEX		"CREATE INDEX idx_queries_forward ON queries (forward);"
#define CREATE_QUERIES_ADDITIONAL_INFO_INDEX	"CREATE INDEX idx_queries_additional_info ON queries (additional_info);"
#define CREATE_QUERIES_DNSSEC_INDEX		"CREATE INDEX idx_queries_dnssec ON queries (dnssec);"
#define CREATE_QUERIES_REPLY_TIME_INDEX		"CREATE INDEX idx_queries_reply_time ON queries (reply_time);"
#define CREATE_QUERIES_CLIENT_NAME_INDEX	"CREATE INDEX idx_queries_client_name ON queries (client_name);"
#define CREATE_QUERIES_TTL_INDEX		"CREATE INDEX idx_queries_ttl ON queries (ttl);"
#define CREATE_QUERIES_REGEX_ID_INDEX		"CREATE INDEX idx_queries_regex_id ON queries (regex_id);"
#ifdef QUERY_TABLE_PRIVATE
const char *index_creation[] = {
	CREATE_QUERIES_ID_INDEX,
	CREATE_QUERIES_TIMESTAMP_INDEX,
	CREATE_QUERIES_TYPE_INDEX,
	CREATE_QUERIES_STATUS_INDEX,
	CREATE_QUERIES_DOMAIN_INDEX,
	CREATE_QUERIES_CLIENT_INDEX,
	CREATE_QUERIES_FORWARD_INDEX,
	CREATE_QUERIES_ADDITIONAL_INFO_INDEX,
	CREATE_QUERIES_DNSSEC_INDEX,
	CREATE_QUERIES_REPLY_TIME_INDEX,
	CREATE_QUERIES_CLIENT_NAME_INDEX,
	CREATE_QUERIES_TTL_INDEX,
	CREATE_QUERIES_REGEX_ID_INDEX
};
#endif

bool init_memory_databases(void);
sqlite3 *get_memdb(void) __attribute__((pure));
bool import_queries_from_disk(void);
int get_number_of_queries_in_DB(sqlite3 *db, bool disk);
bool export_queries_to_disk(bool final);
bool delete_query_from_db(const sqlite3_int64 id);
bool mv_newdb_memdb(void);
bool add_additional_info_column(sqlite3 *db);
void DB_read_queries(void);
bool query_to_database(queriesData *query);
bool create_more_queries_columns(sqlite3 *db);

#endif //QUERY_TABLE_PRIVATE_H
