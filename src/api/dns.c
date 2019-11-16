/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/dns
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
// counters
#include "shmem.h"
#include "database/gravity-db.h"

int api_dns_status(struct mg_connection *conn)
{
	// Send status
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_REF_STR(json, "status", (counters->gravity > 0 ? "enabled" : "disabled"));
	JSON_SENT_OBJECT(json);
}

int api_dns_somelist(struct mg_connection *conn,
                     bool show_exact, bool show_regex,
                     bool whitelist)
{
	cJSON *exact = NULL;
	cJSON *regex = NULL;
	const char *domain = NULL;
	int rowid = 0;

	if(show_exact)
	{
		exact = JSON_NEW_ARRAY()
		gravityDB_getTable(whitelist ? EXACT_WHITELIST_TABLE : EXACT_BLACKLIST_TABLE);
		while((domain = gravityDB_getDomain(&rowid)) != NULL)
		{
			JSON_ARRAY_COPY_STR(exact, domain);
		}
		gravityDB_finalizeTable();
	}

	if(show_regex)
	{
		regex = JSON_NEW_ARRAY()
		gravityDB_getTable(whitelist ? REGEX_WHITELIST_TABLE : REGEX_BLACKLIST_TABLE);
		while((domain = gravityDB_getDomain(&rowid)) != NULL)
		{
			JSON_ARRAY_COPY_STR(regex, domain);
		}
		gravityDB_finalizeTable();
	}
	if(show_exact && ! show_regex)
	{
		JSON_SENT_OBJECT(exact);
	}
	else if(!show_exact && show_regex)
	{
		JSON_SENT_OBJECT(regex);
	}
	else
	{
		cJSON *json = JSON_NEW_OBJ();
		JSON_OBJ_ADD_ITEM(json, "exact", exact);
		JSON_OBJ_ADD_ITEM(json, "regex", regex);
		JSON_SENT_OBJECT(json);
	}
}
