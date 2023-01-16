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
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api.h"
// {s,g}et_blockingstatus()
#include "setupVars.h"
// set_blockingmode_timer()
#include "timers.h"
#include "shmem.h"
// getCacheInformation()
#include "cache_info.h"
// config struct
#include "config/config.h"
// regex functions for domain validation
#include "regex_r.h"
// file_exists()
#include "files.h"
// flock(), LOCK_SH
#include <sys/file.h>

// Location of custom.list
#include "config/dnsmasq_config.h"

#define DOMAIN_VALIDATION_REGEX "^((-|_)*[a-z0-9]((-|_)*[a-z0-9])*(-|_)*)(\\.(-|_)*([a-z0-9]((-|_)*[a-z0-9])*))*$"
#define LABEL_VALIDATION_REGEX "^[^\\.]{1,63}(\\.[^\\.]{1,63})*$"

static int get_blocking(struct ftl_conn *api)
{
	// Return current status
	cJSON *json = JSON_NEW_OBJECT();
	const bool blocking = get_blockingstatus();
	JSON_ADD_BOOL_TO_OBJECT(json, "blocking", blocking);

	// Get timer information (if applicable)
	int delay;
	bool target_status;
	get_blockingmode_timer(&delay, &target_status);
	if(delay > -1)
	{
		JSON_ADD_NUMBER_TO_OBJECT(json, "timer", delay);
	}
	else
	{
		JSON_ADD_NULL_TO_OBJECT(json, "timer");
	}

	// Send object (HTTP 200 OK)
	JSON_SEND_OBJECT(json);
}

static int set_blocking(struct ftl_conn *api)
{
	// Verify requesting client is allowed to access this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	if (api->payload.json == NULL) {
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid request body data (no valid JSON)",
		                       NULL);
	}

	cJSON *elem = cJSON_GetObjectItemCaseSensitive(api->payload.json, "blocking");
	if (!cJSON_IsBool(elem)) {
		return send_json_error(api, 400,
		                       "body_error",
		                       "No \"blocking\" boolean in body data",
		                       NULL);
	}
	const bool target_status = cJSON_IsTrue(elem);

	// Get (optional) timer
	int timer = -1;
	elem = cJSON_GetObjectItemCaseSensitive(api->payload.json, "timer");
	if (cJSON_IsNumber(elem) && elem->valuedouble > 0.0)
		timer = elem->valueint;

	if(target_status == get_blockingstatus())
	{
		// The blocking status does not need to be changed

		// Delete a possibly running timer
		set_blockingmode_timer(-1, true);
	}
	else
	{
		// Activate requested status
		set_blockingstatus(target_status);

		// Start timer (-1 disables all running timers)
		set_blockingmode_timer(timer, !target_status);
	}

	// Return GET property as result of POST/PUT/PATCH action
	// if no error happened above
	return get_blocking(api);
}

int api_dns_blocking(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
	{
		lock_shm();
		const int ret = get_blocking(api);
		unlock_shm();
		return ret;
	}
	else if(api->method == HTTP_POST)
	{
		lock_shm();
		const int ret = set_blocking(api);
		unlock_shm();
		return ret;
	}
	else
	{
		// This results in error 404
		return 0;
	}
}

int api_dns_cache(struct ftl_conn *api)
{
	// Verify requesting client is allowed to access this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	struct cache_info ci = { 0 };
	get_dnsmasq_cache_info(&ci);
	cJSON *cache = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(cache, "size", ci.cache_size);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "inserted", ci.cache_inserted);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "evicted", ci.cache_live_freed);
	cJSON *valid = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(valid, "ipv4", ci.valid.ipv4);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "ipv6", ci.valid.ipv6);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "cname", ci.valid.cname);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "srv", ci.valid.srv);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "ds", ci.valid.ds);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "dnskey", ci.valid.dnskey);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "other", ci.valid.other);
	JSON_ADD_ITEM_TO_OBJECT(cache, "valid", valid);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "expired", ci.expired);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "immortal", ci.immortal);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "cache", cache);
	JSON_SEND_OBJECT(json);
}

int api_dns_port(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(json, "dns_port", dns_port);
	JSON_SEND_OBJECT(json);
}

static regex_t domain_validation_regex = { 0 };
static regex_t label_validation_regex = { 0 };
static const char *check_domain(const char *domain)
{
	// Compiled regular expressions
	if(domain_validation_regex.value == NULL)
	{
		if(regcomp(&domain_validation_regex, DOMAIN_VALIDATION_REGEX, REG_EXTENDED))
		{
			log_err("Could not compile domain validation regex: "DOMAIN_VALIDATION_REGEX"\n");
			return "Internal error: Cannot compile regex (1)";
		}
	}
	if(label_validation_regex.value == NULL)
	{
		if(regcomp(&label_validation_regex, LABEL_VALIDATION_REGEX, REG_EXTENDED))
		{
			log_err("Could not compile label validation regex: "LABEL_VALIDATION_REGEX"\n");
			return "Internal error: Cannot compile regex (2)";
		}
	}

	// Execute compiled regular expression
	if(regexec(&domain_validation_regex, domain, 0, NULL, 0) != REG_OK)
	{
		return "Domain validation failed";
	}
	if(regexec(&label_validation_regex, domain, 0, NULL, 0) != REG_OK)
	{
		return "Domain label validation failed";
	}

	return NULL;
}

static int read_custom_list(struct ftl_conn *api, cJSON *entries)
{
	if(file_exists(DNSMASQ_CUSTOM_LIST))
	{
		FILE *fp = fopen(DNSMASQ_CUSTOM_LIST, "r");
		if(!fp)
		{
			cJSON_Delete(entries);
			return send_json_error(api, 500,
			                       "file_error",
			                       "Cannot open custom DNS records file for reading",
			                       DNSMASQ_CUSTOM_LIST);
		}
		char *linebuffer = NULL;
		size_t size = 0u;
		while(getline(&linebuffer, &size, fp) != -1)
		{
			// Check if memory allocation failed
			if(linebuffer == NULL)
				break;

			// Parse lines in the file
			// Skip lines which are not in the format
			//   IPADDRESS HOSTNAME
			char *save_ptr = NULL;
			char *file_ip = strtok_r(linebuffer, " \t\n", &save_ptr);
			if(file_ip == NULL)
				continue;
			char *file_host = strtok_r(NULL, " \t\n", &save_ptr);
			if(file_host == NULL)
				continue;

			cJSON *entry = JSON_NEW_OBJECT();
			JSON_COPY_STR_TO_OBJECT(entry, "ip", file_ip);
			JSON_COPY_STR_TO_OBJECT(entry, "host", file_host);
			JSON_ADD_ITEM_TO_ARRAY(entries, entry);
		}

		// Free allocated memory
		free(linebuffer);
		fclose(fp);
	}

	return 200;
}

static int write_custom_list(struct ftl_conn *api, cJSON *entries)
{
	// Write list of entries to the file
	FILE *fp = fopen(DNSMASQ_CUSTOM_LIST, "w");
	if(!fp)
	{
		const int err = errno;
		const char *error = "Cannot open "DNSMASQ_CUSTOM_LIST" for writing";
		log_err("%s: %s", error, strerror(err));
		cJSON_Delete(entries);
		return send_json_error(api, 500,
		                       "internal_error",
		                       error,
		                       strerror(err));
	}

	// Lock file, may block if the file is currently opened
	if(flock(fileno(fp), LOCK_EX) != 0)
	{
		const int err = errno;
		const char *error = "Cannot lock "DNSMASQ_CUSTOM_LIST" for writing";
		log_err("%s: %s", error, strerror(err));
		cJSON_Delete(entries);
		return send_json_error(api, 500,
		                       "internal_error",
		                       error,
		                       strerror(err));
	}

	// Write lines into the file
	for(int i = 0; i < cJSON_GetArraySize(entries); i++)
	{
		cJSON *entry = cJSON_GetArrayItem(entries, i);
		cJSON *list_ip = cJSON_GetObjectItem(entry, "ip");
		cJSON *list_host = cJSON_GetObjectItem(entry, "host");

		// Add "IP HOSTNAME" line
		fputs(list_ip->valuestring, fp);
		fputc(' ', fp);
		fputs(list_host->valuestring, fp);
		fputc('\n', fp);
	}

	// Unlock file
	if(flock(fileno(fp), LOCK_UN) != 0)
	{
		const int err = errno;
		const char *error = "Cannot unlock file "DNSMASQ_CUSTOM_LIST" after writing";
		log_err("%s: %s", error, strerror(err));
		cJSON_Delete(entries);
		return send_json_error(api, 500,
		                       "internal_error",
		                       error,
		                       strerror(err));
	}

	// Close file
	fclose(fp);

	return 200;
}

static int add_to_custom_list(struct ftl_conn *api, cJSON *entries)
{
	// Split URI into IP and host
	char *ip = NULL;
	char *host = NULL;
	if(sscanf(api->item, "%m[^/]/%m[^/]", &ip, &host) != 2)
	{
		cJSON_Delete(entries);
		if(ip != NULL)
			free(ip);
		if(host != NULL)
			free(host);
		return send_json_error(api, 400,
		                       "validation_error",
		                       "Invalid URI",
		                       "URI must be in the format /api/dns/entries/{ip}/{host}");
	}

	// Convert domain to lowercase
	strtolower(host);

	// Validate domain
	const char *error = check_domain(host);
	if(error != NULL)
	{
		cJSON_Delete(entries);
		free(ip);
		free(host);
		return send_json_error(api, 400,
		                       "validation_error",
		                       "Specified host is not valid",
		                       error);
		return false;
	}

	// Validate address
	if(!isValidIPv4(ip) && !isValidIPv6(ip))
	{
		cJSON_Delete(entries);
		free(ip);
		free(host);
		return send_json_error(api, 400,
		                       "validation_error",
		                       "Specified IP address is neither a valid IPv4 nor IPv6 address",
		                       ip);
	}

	// If we reach this point, validation succeeded

	// Read list from disk
	int ret = read_custom_list(api, entries);
	if(ret != 200)
		return ret;

	// Check if this entry does already exist in the list
	for(int i = 0; i < cJSON_GetArraySize(entries); i++)
	{
		cJSON *entry = cJSON_GetArrayItem(entries, i);
		cJSON *list_ip = cJSON_GetObjectItem(entry, "ip");
		cJSON *list_host = cJSON_GetObjectItem(entry, "host");

		if(list_ip->valuestring != NULL &&
		   list_host->valuestring != NULL &&
		   strcmp(ip, list_ip->valuestring) == 0 &&
		   strcmp(host, list_host->valuestring) == 0)
		{
			// Entry already present in list, no need to add it
			free(ip);
			free(host);
			return 200;
		}
	}

	// If we reach this point, the combination is unique
	cJSON *entry = JSON_NEW_OBJECT();
	JSON_COPY_STR_TO_OBJECT(entry, "ip", ip);
	JSON_COPY_STR_TO_OBJECT(entry, "host", host);
	JSON_ADD_ITEM_TO_ARRAY(entries, entry);

	// Write the file
	free(ip);
	free(host);
	return write_custom_list(api, entries);
}

static int remove_from_custom_list(struct ftl_conn *api, cJSON *entries)
{
	// Split URI into IP and host
	char *ip = NULL;
	char *host = NULL;
	if(sscanf(api->item, "%m[^/]/%m[^/]", &ip, &host) != 2)
	{
		cJSON_Delete(entries);
		if(ip != NULL)
			free(ip);
		if(host != NULL)
			free(host);
		return send_json_error(api, 400,
		                       "validation_error",
		                       "Invalid URI",
		                       "URI must be in the format /api/dns/entries/{ip}/{host}");
	}

	// Convert domain to lowercase
	strtolower(host);

	// Read list from disk
	int ret = read_custom_list(api, entries);
	if(ret != 200)
	{
		free(ip);
		free(host);
		return ret;
	}

	// Check if this entry exists in the list
	for(int i = 0; i < cJSON_GetArraySize(entries); i++)
	{
		cJSON *entry = cJSON_GetArrayItem(entries, i);
		cJSON *list_ip = cJSON_GetObjectItem(entry, "ip");
		cJSON *list_host = cJSON_GetObjectItem(entry, "host");

		if(list_ip->valuestring != NULL &&
		   list_host->valuestring != NULL &&
		   strcmp(ip, list_ip->valuestring) == 0 &&
		   strcmp(host, list_host->valuestring) == 0)
		{
			// Entry exists in the array at index i, remove this item.
			// We rewrite the file afterwards
			cJSON_DeleteItemFromArray(entries, i);
		}
	}

	// Write the file
	free(ip);
	free(host);
	return write_custom_list(api, entries);
}

int api_dns_entries(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	if(api->method == HTTP_GET)
	{
		// Read list item identified by URI (or read them all)
		// We would not actually need the SHM lock here, however, we do
		// this for simplicity to ensure nobody else is editing the
		// lists while we're doing this here
		cJSON *entries = JSON_NEW_ARRAY();
		int ret = read_custom_list(api, entries);
		if(ret == 200)
		{
			cJSON *json = JSON_NEW_OBJECT();
			JSON_ADD_ITEM_TO_OBJECT(json, "entries", entries);
			JSON_SEND_OBJECT(json);
		}
	}
	else if(api->method == HTTP_PUT)
	{
		// Add item to list identified by payload
		cJSON *entries = JSON_NEW_ARRAY();
		int ret = add_to_custom_list(api, entries);
		if(ret == 200)
		{
			cJSON *json = JSON_NEW_OBJECT();
			JSON_ADD_ITEM_TO_OBJECT(json, "entries", entries);
			JSON_SEND_OBJECT(json);
		}
		else
			return ret;
	}
	else if(api->method == HTTP_DELETE)
	{
		// Delete item from list
		cJSON *entries = JSON_NEW_ARRAY();
		int ret = remove_from_custom_list(api, entries);
		if(ret == 200)
		{
			cJSON *json = JSON_NEW_OBJECT();
			JSON_ADD_ITEM_TO_OBJECT(json, "entries", entries);
			JSON_SEND_OBJECT(json);
		}
		else
			return ret;
	}

	// This results in error 404
	return 0;
}