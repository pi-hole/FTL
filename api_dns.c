/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API /dns/
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"
#include "cJSON.h"

void getList(int *sock, char type, char list_type) {
	FILE *fp;
	char *line = NULL;
	size_t size = 0;

	sendAPIResponse(*sock, type, OK);
	ssend(*sock, "\"%s\":[", list_type == WHITELIST ? "whitelist" : "blacklist");

	if((fp = fopen(list_type == WHITELIST ? files.whitelist : files.blacklist, "r")) != NULL)
	{
		bool first = true;

		while(getline(&line, &size, fp) != -1) {
			// Skip empty lines
			if(line[0] == '\n')
				continue;

			if(!first) ssend(*sock, ",");
			first = false;

			// Trim off the newline, if it exists
			line[strcspn(line, "\r\n")] = 0;

			ssend(*sock, "\"%s\"", line);
		}
		// Free allocated memory
		if(line != NULL)
		{
			free(line);
			line = NULL;
		}

		fclose(fp);
	}

	ssend(*sock, "]");
}

void getPiholeStatus(int *sock, char type) {
	int status = countlineswith("#addn-hosts=/etc/pihole/gravity.list", files.dnsmasqconf);
	sendAPIResponse(*sock, type, OK);
	ssend(*sock, "\"status\":%i", status == 1 ? 0 : 1);
}

void addList(int *sock, char type, char list_type, char *data) {
	cJSON *input_root = cJSON_Parse(data);
	cJSON *domain_json = cJSON_GetObjectItemCaseSensitive(input_root, "domain");
	char *domain;

	// Validate domain
	if(!cJSON_IsString(domain_json)) {
		// No domain found
		sendAPIResponse(*sock, type, BAD_REQUEST);
		ssend(*sock, "\"status\":\"no_domain\"");
		return;
	}

	domain = domain_json->valuestring;

	if(!isValidDomain(domain)) {
		// Invalid domain
		sendAPIResponse(*sock, type, BAD_REQUEST);
		ssend(*sock, "\"status\":\"invalid_domain\"");
		return;
	}

	// Get command
	char *partial_command;

	if(list_type == WHITELIST)
		partial_command = "sudo pihole -w -q ";
	else if(list_type == BLACKLIST)
		partial_command = "sudo pihole -b -q ";
	else {
		logg("Invalid list type in addList");
		exit(EXIT_FAILURE);
	}

	// Run command
	char *command = malloc((strlen(domain) + strlen(partial_command) + 1) * sizeof(char));
	strcpy(command, partial_command);
	strcat(command, domain);
	int return_code = system(command);
	free(command);

	if(return_code == 0) {
		// Successfully added to list
		sendAPIResponse(*sock, type, OK);
		ssend(*sock, "\"status\":\"success\"");
	}
	else {
		// Failed to add to list
		sendAPIResponse(*sock, type, INTERNAL_ERROR);
		ssend(*sock, "\"status\":\"unknown_error\"");
	}

	cJSON_Delete(input_root);
}

void removeList(int *sock, char type, char list_type, char *client_message) {
	char *domain = strrchr(client_message, '/');

	// Remove leading '/'
	domain++;

	// Validate route
	char *expected_route_start;
	char *expected_route;

	if(list_type == WHITELIST)
		expected_route_start = "/dns/whitelist/";
	else if(list_type == BLACKLIST)
		expected_route_start = "/dns/blacklist/";
	else {
		logg("Invalid list type in removeList");
		exit(EXIT_FAILURE);
	}

	expected_route = malloc((strlen(expected_route_start) + strlen(domain) + 1) * sizeof(char));
	strcpy(expected_route, expected_route_start);
	strcat(expected_route, domain);

	if(!strstr(client_message, expected_route)) {
		// Invalid route
		free(expected_route);
		sendAPIResponse(*sock, type, NOT_FOUND);
		ssend(*sock, "\"status\":\"not_found\"");
		return;
	}

	free(expected_route);

	// Validate domain

	if(domain == NULL) {
		// No domain found
		sendAPIResponse(*sock, type, NOT_FOUND);
		ssend(*sock, "\"status\":\"not_found\"");
		return;
	}

	if(!isValidDomain(domain)) {
		// Invalid domain
		sendAPIResponse(*sock, type, BAD_REQUEST);
		ssend(*sock, "\"status\":\"invalid_domain\"");
		return;
	}

	// Get command
	char *partial_command;

	if(list_type == WHITELIST)
		partial_command = "sudo pihole -w -q -d ";
	else
		partial_command = "sudo pihole -b -q -d ";

	// Run command
	char *command = malloc((strlen(domain) + strlen(partial_command) + 1) * sizeof(char));
	strcpy(command, partial_command);
	strcat(command, domain);
	int return_code = system(command);
	free(command);

	if(return_code == 0) {
		// Successfully removed from list
		sendAPIResponse(*sock, type, OK);
		ssend(*sock, "\"status\":\"success\"");
	}
	else {
		// Failed to remove from list
		sendAPIResponse(*sock, type, INTERNAL_ERROR);
		ssend(*sock, "\"status\":\"unknown_error\"");
	}
}
