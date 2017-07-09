/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  GeoIP database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

sqlite3 *geodb;
pthread_mutex_t geodblock;
bool geoIPdatabase = false;

void geodbclose(void)
{
	sqlite3_close(geodb);
	pthread_mutex_unlock(&geodblock);
}

bool geodbopen(void)
{
	pthread_mutex_lock(&geodblock);
	int rc = sqlite3_open_v2(FTLfiles.geodb, &geodb, SQLITE_OPEN_READWRITE, NULL);
	if( rc ){
		logg("Cannot open GeoIP database: %s", sqlite3_errmsg(geodb));
		geodbclose();
		return false;
	}

	return true;
}

bool geodbquery(const char *format, ...)
{
	char *zErrMsg = NULL;
	va_list args;
	int rc;

	va_start(args, format);
	char *query = sqlite3_vmprintf(format, args);
	if(query == NULL)
	{
		logg("Memory allocation failed in geodbquery()");
		va_end(args);
		return false;
	}
	rc = sqlite3_exec(geodb, query, NULL, NULL, &zErrMsg);
	sqlite3_free(query);
	va_end(args);

	if( rc != SQLITE_OK ){
		logg("GeoIP SQLite error (%i): %s", rc, zErrMsg);
		sqlite3_free(zErrMsg);
		return false;
	}

	return true;
}

void geodb_init(void)
{
	int rc = sqlite3_open_v2(FTLfiles.geodb, &geodb, SQLITE_OPEN_READWRITE, NULL);
	if( rc ){
		logg("Cannot open GeoIP database: %s", sqlite3_errmsg(geodb));
		logg("GeoIP information not available");
		geodbclose();
		return;
	}

	if (pthread_mutex_init(&geodblock, NULL) != 0)
	{
		logg("FATAL: Geo DB mutex init failed\n");
		// Return failure
		exit(EXIT_FAILURE);
	}

	geoIPdatabase = true;
	logg("GeoIP database initialized");
}

unsigned char getGeoID(uint32_t IP)
{
	int rc, ret = 0;
	sqlite3_stmt* dbstmt;
	char *querystring = NULL;

	// Prepare SQL statement
	ret = asprintf(&querystring, "SELECT rowid FROM countries WHERE country ==  (SELECT country from GeoIPv4 where IP >= %u LIMIT 1);", IP);

	if(querystring == NULL || ret < 0)
	{
		logg("Memory allocation failed in getGeoID, (%u, %i)", IP, ret);
		return false;
	}

	rc = sqlite3_prepare(geodb, querystring, -1, &dbstmt, NULL);
	if( rc ){
		logg("Cannot read from GeoIP database: %s", sqlite3_errmsg(geodb));
		geodbclose();
		return -1;
	}
	free(querystring);

	// Evaluate SQL statement
	sqlite3_step(dbstmt);
	if( rc ){
		logg("Cannot evaluate in GeoIP database: %s", sqlite3_errmsg(geodb));
		geodbclose();
		return -1;
	}

	int result = sqlite3_column_int(dbstmt, 0);
	sqlite3_finalize(dbstmt);

	return (unsigned char)result;
}

unsigned int getGeoIDfromIP(char *IP)
{
	struct in_addr addr;

	if(inet_aton(IP, &addr) == 0)
	{
		logg("Invalid address\n");
		exit(EXIT_FAILURE);
	}

	return getGeoID(addr.s_addr);
}
