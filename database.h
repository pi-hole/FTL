/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Database prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DATABASE_H
#define DATABASE_H

void db_init(void);
void *DB_thread(void *val);
int get_number_of_queries_in_DB(void);
void save_to_DB(void);
void read_data_from_DB(void);
bool db_set_FTL_property(const unsigned int ID, const int value);
bool dbquery(const char *format, ...);
bool dbopen(void);
void dbclose(void);
int db_query_int(const char*);
void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg);

#endif //DATABASE_H
