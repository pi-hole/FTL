/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
#include "version.h"

void getClientID(int *sock)
{
	if(istelnet[*sock])
		ssend(*sock,"%i\n", *sock);
	else
		pack_int32(*sock, *sock);
}

void getVersion(int *sock)
{
	const char * commit = GIT_HASH;
	const char * tag = GIT_TAG;

	// Extract first 7 characters of the hash
	char hash[8];
	strncpy(hash, commit, 7); hash[7] = 0;

	if(strlen(tag) > 1) {
		if(istelnet[*sock])
			ssend(
					*sock,
					"version %s\ntag %s\nbranch %s\nhash %s\ndate %s\n",
					GIT_VERSION, tag, GIT_BRANCH, hash, GIT_DATE
			);
		else {
			if(!pack_str32(*sock, GIT_VERSION) ||
					!pack_str32(*sock, (char *) tag) ||
					!pack_str32(*sock, GIT_BRANCH) ||
					!pack_str32(*sock, hash) ||
					!pack_str32(*sock, GIT_DATE))
				return;
		}
	}
	else {
		if(istelnet[*sock])
			ssend(
					*sock,
					"version vDev-%s\ntag %s\nbranch %s\nhash %s\ndate %s\n",
					hash, tag, GIT_BRANCH, hash, GIT_DATE
			);
		else {
			char *hashVersion = calloc(6 + strlen(hash), sizeof(char));
			if(hashVersion == NULL) return;
			sprintf(hashVersion, "vDev-%s", hash);

			if(!pack_str32(*sock, hashVersion) ||
					!pack_str32(*sock, (char *) tag) ||
					!pack_str32(*sock, GIT_BRANCH) ||
					!pack_str32(*sock, hash) ||
					!pack_str32(*sock, GIT_DATE))
				return;

			free(hashVersion);
		}
	}
}

void getDBstats(int *sock)
{
	// Get file details
	struct stat st;
	long int filesize = 0;
	if(stat(FTLfiles.db, &st) != 0)
		// stat() failed (maybe the file does not exist?)
		filesize = -1;
	else
		filesize = st.st_size;

	char *prefix = calloc(2, sizeof(char));
	if(prefix == NULL) return;
	double formated = 0.0;
	format_memory_size(prefix, filesize, &formated);

	if(istelnet[*sock])
		ssend(*sock,"queries in database: %i\ndatabase filesize: %.2f %sB\nSQLite version: %s\n", get_number_of_queries_in_DB(), formated, prefix, sqlite3_libversion());
	else {
		pack_int32(*sock, get_number_of_queries_in_DB());
		pack_int64(*sock, filesize);

		if(!pack_str32(*sock, (char *) sqlite3_libversion()))
			return;
	}
}

void getUnknownQueries(int *sock)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
		return;

	int i;
	for(i=0; i < counters->queries; i++)
	{
		validate_access("queries", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(queries[i].status != QUERY_UNKNOWN && queries[i].complete) continue;

		char type[5];
		if(queries[i].type == TYPE_A)
		{
			strcpy(type,"IPv4");
		}
		else
		{
			strcpy(type,"IPv6");
		}

		validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
		validate_access("clients", queries[i].clientID, true, __LINE__, __FUNCTION__, __FILE__);


		char *client = getstr(clients[queries[i].clientID].ippos);

		if(istelnet[*sock])
			ssend(*sock, "%i %i %i %s %s %s %i %s\n", queries[i].timestamp, i, queries[i].id, type, getstr(domains[queries[i].domainID].domainpos), client, queries[i].status, queries[i].complete ? "true" : "false");
		else {
			pack_int32(*sock, queries[i].timestamp);
			pack_int32(*sock, queries[i].id);

			// Use a fixstr because the length of qtype is always 4 (max is 31 for fixstr)
			if(!pack_fixstr(*sock, type))
				return;

			// Use str32 for domain and client because we have no idea how long they will be (max is 4294967295 for str32)
			if(!pack_str32(*sock, getstr(domains[queries[i].domainID].domainpos)) || !pack_str32(*sock, client))
				return;

			pack_uint8(*sock, queries[i].status);
			pack_bool(*sock, queries[i].complete);
		}
	}
}

void getDomainDetails(char *client_message, int *sock)
{
	// Get domain name
	char domain[128];
	if(sscanf(client_message, "%*[^ ] %127s", domain) < 1)
	{
		ssend(*sock, "Need domain for this request\n");
		return;
	}

	int i;
	for(i = 0; i < counters->domains; i++)
	{
		validate_access("domains", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(strcmp(getstr(domains[i].domainpos), domain) == 0)
		{
			ssend(*sock,"Domain \"%s\", ID: %i\n", domain, i);
			ssend(*sock,"Total: %i\n", domains[i].count);
			ssend(*sock,"Blocked: %i\n", domains[i].blockedcount);
			char *regexstatus;
			if(domains[i].regexmatch == REGEX_BLOCKED)
				regexstatus = "blocked";
			if(domains[i].regexmatch == REGEX_NOTBLOCKED)
				regexstatus = "not blocked";
			else
				regexstatus = "unknown";
			ssend(*sock,"Regex status: %s\n", regexstatus);
			return;
		}
	}

	// for loop finished without an exact match
	ssend(*sock,"Domain \"%s\" is unknown\n", domain);
}
