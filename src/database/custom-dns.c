/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Custom DNS database routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "sqlite3.h"
#include "gravity-db.h"
#include "custom-dns.h"
#include "shmem.h"
#include "config/config.h"
#include "log.h"

// Private variables
static sqlite3_stmt* custom_dns_stmt = NULL;

bool find_custom_dns(const char *domain, const clientsData *client, char **targetIP, int *type, int *ttl)
{
	if(domain == NULL || client == NULL)
		return false;

	// Open database if not already open
	if(!gravityDB_is_opened() && !gravityDB_open())
	{
		log_warn("find_custom_dns(): Gravity database not available");
		return false;
	}

	const char *groups = getstr(client->groupspos);
	if(groups == NULL || strlen(groups) == 0)
	{
		// Fallback to default group (0) if no groups found
		groups = "0";
	}

	// Prepare query string
	// We want to find a matching domain that is assigned to one of the client's groups
	// We order by group_id to have deterministic behavior (e.g. lower group ID wins, or just pick one)
	// For now, we just pick the first one found.
	char *querystr = NULL;
	int ret = asprintf(&querystr,
	                   "SELECT c.ip, c.type, c.ttl FROM custom_dns c "
	                   "JOIN custom_dns_by_group g ON c.id = g.custom_dns_id "
	                   "WHERE c.domain = ? AND g.group_id IN (%s) "
	                   "LIMIT 1;", groups);

	if(ret < 0 || querystr == NULL)
	{
		log_err("find_custom_dns(): Failed to allocate memory for query string");
		return false;
	}

	// Prepare statement
	// Note: We cannot use a prepared statement with variable IN clause easily without re-preparing
	// or binding many variables. Since groups string is dynamic, we might need to finalize the statement each time
	// or use a different approach.
	// Given the frequency of DNS queries, this might be slow.
	// However, for a first implementation, we will prepare and finalize.
	// Optimization: Cache the statement if groups are constant? No, groups vary per client.
	
	int rc = sqlite3_prepare_v2(gravityDB_get_handle(), querystr, -1, &custom_dns_stmt, NULL);
	free(querystr); // Free the allocated query string

	if(rc != SQLITE_OK)
	{
		log_err("find_custom_dns() - SQL error prepare: %s", sqlite3_errstr(rc));
		return false;
	}

	// Bind domain
	if((rc = sqlite3_bind_text(custom_dns_stmt, 1, domain, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("find_custom_dns(): Failed to bind domain: %s", sqlite3_errstr(rc));
		sqlite3_finalize(custom_dns_stmt);
		return false;
	}

	// Execute
	bool found = false;
	rc = sqlite3_step(custom_dns_stmt);
	if(rc == SQLITE_ROW)
	{
		const char *ip_text = (const char*)sqlite3_column_text(custom_dns_stmt, 0);
		int type_val = sqlite3_column_int(custom_dns_stmt, 1);
		int ttl_val = sqlite3_column_int(custom_dns_stmt, 2);

		if(ip_text != NULL)
		{
			*targetIP = strdup(ip_text);
			*type = type_val;
			*ttl = ttl_val;
			found = true;
		}
	}
	else if(rc != SQLITE_DONE)
	{
		log_err("find_custom_dns() - SQL error step: %s", sqlite3_errstr(rc));
	}

	sqlite3_finalize(custom_dns_stmt);
	return found;
}
