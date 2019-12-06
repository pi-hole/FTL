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

void db_init(void);
int db_get_FTL_property(const unsigned int ID);
bool db_set_FTL_property(const unsigned int ID, const int value);

/// Execute a formatted SQL query and get the return code
int dbquery(const char *format, ...);

bool dbopen(void);
void dbclose(void);
int db_query_int(const char*);
int db_query_int_from_until(const char* querystr, const int from, const int until);
int db_query_int_from_until_type(const char* querystr, const int from, const int until, const int type);
long get_lastID(void);
void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg);
long int get_max_query_ID(void);
bool db_set_counter(const unsigned int ID, const int value);
bool db_update_counters(const int total, const int blocked);
const char *get_sqlite3_version(void);
bool use_database(void)  __attribute__ ((pure));

extern sqlite3 *FTL_db;
extern bool database;
extern long int lastdbindex;
extern bool DBdeleteoldqueries;

// Database macros
#define SQL_bool(sql) {\
	int ret;\
	if((ret = dbquery(sql)) != SQLITE_OK) {\
		if(ret == SQLITE_BUSY)\
			logg("WARNING: Database busy in %s()!", __FUNCTION__);\
		else\
			logg("ERROR: %s() failed!", __FUNCTION__);\
		return false;\
	}\
}

#define SQL_void(sql) {\
	int ret;\
	if((ret = dbquery(sql)) != SQLITE_OK) {\
		if(ret == SQLITE_BUSY)\
			logg("WARNING: Database busy in %s()!", __FUNCTION__);\
		else\
			logg("ERROR: %s() failed!", __FUNCTION__);\
		return;\
	}\
}

// Database table "ftl"
enum { DB_VERSION, DB_LASTTIMESTAMP, DB_FIRSTCOUNTERTIMESTAMP };
// Database table "counters"
enum { DB_TOTALQUERIES, DB_BLOCKEDQUERIES };

#endif //DATABASE_COMMON_H
