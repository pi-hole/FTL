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

// logging routines
#include "log.h"

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
int db_get_int(sqlite3* db, const enum ftl_table_props ID);
int db_get_FTL_property(sqlite3* db, const enum ftl_table_props ID);
double db_get_FTL_property_double(sqlite3* db, const enum ftl_table_props ID);
bool db_set_FTL_property(sqlite3* db, const enum ftl_table_props ID, const int value);
bool db_set_FTL_property_double(sqlite3* db, const enum ftl_table_props ID, const double value);

/// Execute a formatted SQL query and get the return code
int dbquery(sqlite3* db, const char *format, ...) __attribute__ ((format (gnu_printf, 2, 3)));;

#define dbopen(readonly, create) _dbopen(readonly, create, __FUNCTION__, __LINE__, __FILE__)
sqlite3 *_dbopen(const bool readonly, const bool create, const char *func, const int line, const char *file) __attribute__((warn_unused_result));
#define dbclose(db) _dbclose(db, __FUNCTION__, __LINE__, __FILE__)
void _dbclose(sqlite3 **db, const char *func, const int line, const char *file);

void piholeFTLDB_reopen(void);
int db_query_int(sqlite3 *db, const char *querystr);
double db_query_double(sqlite3 *db, const char *querystr);
int db_query_int_from_until(sqlite3 *db, const char* querystr, const double from, const double until);
int db_query_int_from_until_type(sqlite3 *db, const char* querystr, const double from, const double until, const int type);

void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg);
bool db_set_counter(sqlite3 *db, const enum counters_table_props ID, const int value);
bool db_update_counters(sqlite3 *db, const int total, const int blocked);
const char *get_sqlite3_version(void);

extern bool DBdeleteoldqueries;

// Return if FTL's database is known to be broken
// We abort execution of all database-related activities in this case
bool FTLDBerror(void) __attribute__ ((pure));

// Check SQLite3 non-success return codes for possible database corruption
bool checkFTLDBrc(const int rc);

// Get human-readable *extended* error codes (defined in sqlite3.c)
extern const char *sqlite3ErrName(int rc);

// Database macros
#define SQL_bool(db, ...) {\
	int ret;\
	if((ret = dbquery(db, __VA_ARGS__)) != SQLITE_OK) {\
		if(ret == SQLITE_BUSY)\
			log_warn("Database busy in %s()!", __FUNCTION__);\
		else\
			log_err("%s() failed!", __FUNCTION__);\
		return false;\
	}\
}

#define SQL_void(db, ...) {\
	int ret;\
	if((ret = dbquery(db, __VA_ARGS__)) != SQLITE_OK) {\
		if(ret == SQLITE_BUSY)\
			log_warn("Database busy in %s()!", __FUNCTION__);\
		else\
			log_err("%s() failed!", __FUNCTION__);\
		return;\
	}\
}

#endif //DATABASE_COMMON_H
