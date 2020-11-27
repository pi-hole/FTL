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

// Database table "ftl"
enum ftl_table_props {
	DB_VERSION,
	DB_LASTTIMESTAMP,
	DB_FIRSTCOUNTERTIMESTAMP
} __attribute__ ((packed));

// Database table "counters"
enum counters_table_props {
	DB_TOTALQUERIES,
	DB_BLOCKEDQUERIES
} __attribute__ ((packed));

void db_init(void);
int db_get_FTL_property(const enum ftl_table_props ID);
bool db_set_FTL_property(const enum ftl_table_props ID, const int value);

/// Execute a formatted SQL query and get the return code
int dbquery(const char *format, ...);

bool FTL_DB_avail(void) __attribute__ ((pure));
bool dbopen(void);
void dbclose(void);
void piholeFTLDB_reopen(void);
int db_query_int(const char*);
long get_lastID(void);
void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg);
long int get_max_query_ID(void);
bool db_set_counter(const enum counters_table_props ID, const int value);
bool db_update_counters(const int total, const int blocked);
const char *get_sqlite3_version(void);

extern sqlite3 *FTL_db;
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

#endif //DATABASE_COMMON_H
