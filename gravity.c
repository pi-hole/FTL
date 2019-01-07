/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Needed for SRC_GRAVITYDB
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "shmem.h"

// Semi-private prototypes. Routines are defined in dnsmasq_interface.c
int add_blocked_domain_cache(struct all_addr *addr4, struct all_addr *addr6, bool has_IPv4, bool has_IPv6,
                             char *domain, struct crec **rhash, int hashsz, unsigned int index);
void prepare_blocking_mode(struct all_addr *addr4, struct all_addr *addr6, bool *has_IPv4, bool *has_IPv6);

// Prototypes from functions in dnsmasq's source
void rehash(int size);

bool readGravity(void)
{
	struct stat st;
	if(stat(FTLfiles.gravitydb, &st) != 0)
	{
		// File does not exist
		if(debug) logg("readGravity(): %s does not exist", FTLfiles.gravitydb);
		return false;
	}

	// Start timer for list analysis
	timer_start(LISTS_TIMER);

	sqlite3 *gravitydb = NULL;
	int rc = sqlite3_open_v2(FTLfiles.gravitydb, &gravitydb, SQLITE_OPEN_READONLY, NULL);
	if( rc ){
		logg("readGravity() - SQL error (%i): %s", rc, sqlite3_errmsg(gravitydb));
		sqlite3_close(gravitydb);
		return false;
	}

	// Read gravity domains
	sqlite3_stmt* stmt = NULL;
	rc = sqlite3_prepare_v2(gravitydb, "SELECT * FROM vw_gravity;", -1, &stmt, NULL);
	if( rc ){
		logg("readGravity(vw_gravity) - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravitydb));
		sqlite3_close(gravitydb);
		return false;
	}

	// Prepare cache ingredients
	struct all_addr addr4 = {{{ 0 }}}, addr6 = {{{ 0 }}};
	bool has_IPv4 = false, has_IPv6 = false;
	// Get IPv4/v6 addresses for blocking depending on user configured blocking mode
	prepare_blocking_mode(&addr4, &addr6, &has_IPv4, &has_IPv6);

	char *domain = NULL;
	unsigned int added = 0;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		domain = (char*)sqlite3_column_text(stmt, 0);
		add_blocked_domain_cache(&addr4, &addr6, has_IPv4, has_IPv6, domain, NULL, 0, SRC_GRAVITYDB);
		added++;

		if(added % 1000 == 0)
			rehash(added);
	}

	if(rc != SQLITE_DONE)
	{
		// Error
		logg("readGravity(vw_gravity) - SQL error step (%i): %s", rc, sqlite3_errmsg(gravitydb));
		sqlite3_finalize(stmt);
		sqlite3_close(gravitydb);
		return false;
	}
	sqlite3_finalize(stmt);

	logg("Imported %u domains from vw_gravity database (took %.1f ms)", added, timer_elapsed_msec(LISTS_TIMER));

	// Read blacklist domains
	timer_start(LISTS_TIMER);
	rc = sqlite3_prepare_v2(gravitydb, "SELECT domain FROM blacklist;", -1, &stmt, NULL);
	if( rc ){
		logg("readGravity(blacklist) - SQL error prepare (%i): %s", rc, sqlite3_errmsg(gravitydb));
		sqlite3_close(gravitydb);
		return false;
	}

	unsigned int gravity = added;
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		domain = (char*)sqlite3_column_text(stmt, 0);
		add_blocked_domain_cache(&addr4, &addr6, has_IPv4, has_IPv6, domain, NULL, 0, SRC_BLACKDB);
		added++;

		if(added % 1000 == 0)
			rehash(added);
	}

	if(rc != SQLITE_DONE)
	{
		// Error
		logg("readGravity(blacklist) - SQL error step (%i): %s", rc, sqlite3_errmsg(gravitydb));
		sqlite3_finalize(stmt);
		sqlite3_close(gravitydb);
		return false;
	}

	logg("Imported %u domains from blacklist database (took %.1f ms)", added-gravity, timer_elapsed_msec(LISTS_TIMER));

	sqlite3_finalize(stmt);
	sqlite3_close(gravitydb);

	counters->gravity += added;
	return true;
}
