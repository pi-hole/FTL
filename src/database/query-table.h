/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DATABASE_QUERY_TABLE_H
#define DATABASE_QUERY_TABLE_H

#include "sqlite3.h"

int get_number_of_queries_in_DB(sqlite3 *db);
void delete_old_queries_in_DB(sqlite3 *db);
bool add_additional_info_column(sqlite3 *db);
bool optimize_queries_table(sqlite3 *db);
bool create_addinfo_table(sqlite3 *db);
int DB_save_queries(sqlite3 *db);
void DB_read_queries(void);

#endif //DATABASE_QUERY_TABLE_H
