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

// The schema version of the query database
#define MEMDB_VERSION 22

// Version 1
#define CREATE_QUERIES_TIMESTAMP_INDEX		"CREATE INDEX idx_queries_timestamp ON queries (timestamp);"

void init_query_database(void);
void close_query_database(void);
void interrupt_import(void);
bool attach_database(sqlite3* db, const char **message, const char *path, const char *alias);
bool detach_database(sqlite3* db, const char **message, const char *alias);
void get_db_info(const bool disk, uint64_t *count, double *earliest_timestamp);
void get_import_window(double *from, double *until);
bool delete_old_queries_batch(sqlite3 *db, const double until, int64_t *deleted);
void log_deleted_old_queries(const int64_t deleted, const bool complete);
bool export_queries_to_disk(const bool final);
bool delete_recent_queries_from_db(const double mintime);
bool add_additional_info_column(sqlite3 *db);
void DB_read_queries(void);
unsigned int get_export_index(void) __attribute__((pure));
void clear_addinfo_id_cache(void);

bool optimize_queries_table(sqlite3 *db);
bool create_addinfo_table(sqlite3 *db);
bool add_query_storage_columns(sqlite3 *db);
bool add_query_storage_column_regex_id(sqlite3 *db);
bool add_ftl_table_description(sqlite3 *db);
bool rename_query_storage_column_regex_id(sqlite3 *db);
bool add_query_storage_column_ede(sqlite3 *db);
bool replace_queries_view_with_joins(sqlite3 *db);

#endif //QUERY_TABLE_PRIVATE_H
