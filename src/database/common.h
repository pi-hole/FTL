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
bool db_set_FTL_property(sqlite3* db, const enum ftl_table_props ID, const int value);

/// Execute a formatted SQL query and get the return code
int dbquery(sqlite3* db, const char *format, ...) __attribute__ ((format (printf, 2, 3)));;

int sqliteBusyCallback(void *ptr, int count);
#define dbopen(readonly, create) _dbopen(readonly, create, __FUNCTION__, __LINE__, __FILE__)
sqlite3 *_dbopen(const bool readonly, const bool create, const char *func, const int line, const char *file) __attribute__((warn_unused_result));
#define dbclose(db) _dbclose(db, __FUNCTION__, __LINE__, __FILE__)
void _dbclose(sqlite3 **db, const char *func, const int line, const char *file);

void piholeFTLDB_reopen(void);
int db_query_int(sqlite3 *db, const char *querystr);
int db_query_int_int(sqlite3 *db, const char* querystr, const int arg);
int db_query_int_str(sqlite3 *db, const char* querystr, const char *arg);
double db_query_double(sqlite3 *db, const char *querystr);
int db_query_int_from_until(sqlite3 *db, const char* querystr, const double from, const double until);
int db_query_int_from_until_type(sqlite3 *db, const char* querystr, const double from, const double until, const int type);

void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg);
bool db_set_counter(sqlite3 *db, const enum counters_table_props ID, const int value);
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

// Macro to time a database operation expression EXPR if debug.timing is
// enabled.
#define TIMED_DB_OP(EXPR) { \
	if(!config.debug.timing.v.b) { EXPR; } \
	else { \
		struct timespec _timed_start, _timed_end; \
		clock_gettime(CLOCK_MONOTONIC, &_timed_start); \
		(EXPR); \
		clock_gettime(CLOCK_MONOTONIC, &_timed_end); \
		long _timed_elapsed = (_timed_end.tv_sec - _timed_start.tv_sec) * 10000 + (_timed_end.tv_nsec - _timed_start.tv_nsec) / 100000; \
		log_debug(DEBUG_TIMING, "Database operation %s took %.1f ms", str(EXPR), 0.1*_timed_elapsed); \
	}}

// Macro to time a database operation expression EXPR that returns a value if
// debug.timing is enabled.
#define TIMED_DB_OP_RESULT(_result, EXPR) { \
	if(!config.debug.timing.v.b) { _result = EXPR; } \
	else { \
		struct timespec _timed_start, _timed_end; \
		clock_gettime(CLOCK_MONOTONIC, &_timed_start); \
		 _result = (EXPR); \
		clock_gettime(CLOCK_MONOTONIC, &_timed_end); \
		long _timed_elapsed = (_timed_end.tv_sec - _timed_start.tv_sec) * 10000 + (_timed_end.tv_nsec - _timed_start.tv_nsec) / 100000; \
		log_debug(DEBUG_TIMING, "Database operation %s took %.1f ms", str(EXPR), 0.1*_timed_elapsed); \
	}}

#endif //DATABASE_COMMON_H
