/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Database prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DATABASE_COMMON_H
#define DATABASE_COMMON_H

#include "sqlite3.h"

bool check_database(int rc);
void db_init(void);
int db_get_FTL_property(const unsigned int ID);
bool db_set_FTL_property(const unsigned int ID, const int value);
bool dbquery(const char *format, ...);
bool dbopen(void);
void dbclose(void);
int db_query_int(const char*);
long get_lastID(void);
void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg);
long int get_max_query_ID(void);
bool db_set_counter(const unsigned int ID, const int value);
bool db_update_counters(const int total, const int blocked);
const char *get_sqlite3_version(void);

extern sqlite3 *FTL_db;
extern bool database;
extern long int lastdbindex;
extern bool DBdeleteoldqueries;

// Database macros
#define SQL_bool(sql) {\
	if(!dbquery(sql)) {\
		logg("%s(): \"%s\" failed!", __FUNCTION__, sql);\
		return false;\
	}\
}

#define SQL_void(sql) {\
	if(!dbquery(sql)) {\
		logg("%s(): \"%s\" failed!", __FUNCTION__, sql);\
		return;\
	}\
}

// Database table "ftl"
enum { DB_VERSION, DB_LASTTIMESTAMP, DB_FIRSTCOUNTERTIMESTAMP };
// Database table "counters"
enum { DB_TOTALQUERIES, DB_BLOCKEDQUERIES };

#endif //DATABASE_COMMON_H
