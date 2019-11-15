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

// TODO: Return object with property regex = true/false
int api_dns_whitelist(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_ARRAY();
	const char *domain = NULL;
	int rowid = 0;

	gravityDB_getTable(EXACT_WHITELIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	gravityDB_getTable(REGEX_WHITELIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	JSON_SENT_OBJECT(json);
}

int api_dns_whitelist_exact(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_ARRAY();
	const char *domain = NULL;
	int rowid = 0;

	gravityDB_getTable(EXACT_WHITELIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	JSON_SENT_OBJECT(json);
}

int api_dns_whitelist_regex(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_ARRAY();
	const char *domain = NULL;
	int rowid = 0;

	gravityDB_getTable(REGEX_WHITELIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	JSON_SENT_OBJECT(json);
}

// TODO: Return object with property regex = true/false
int api_dns_blacklist(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_ARRAY();
	const char *domain = NULL;
	int rowid = 0;

	gravityDB_getTable(EXACT_BLACKLIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	gravityDB_getTable(REGEX_BLACKLIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	JSON_SENT_OBJECT(json);
}

int api_dns_blacklist_exact(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_ARRAY();
	const char *domain = NULL;
	int rowid = 0;

	gravityDB_getTable(EXACT_BLACKLIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	JSON_SENT_OBJECT(json);
}

int api_dns_blacklist_regex(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_ARRAY();
	const char *domain = NULL;
	int rowid = 0;

	gravityDB_getTable(REGEX_BLACKLIST_TABLE);
	while((domain = gravityDB_getDomain(&rowid)) != NULL)
	{
		JSON_ARRAY_COPY_STR(json, domain);
	}
	gravityDB_finalizeTable();

	JSON_SENT_OBJECT(json);
}