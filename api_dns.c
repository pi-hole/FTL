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

void removeList(int *sock, char type, char list_type, char *client_message) {
	char *domain = strrchr(client_message, '/');

	// Validate domain
	if(domain == NULL) {
		// No domain found
//		sendAPIResponse(*sock, type, NOT_FOUND);
		ssend(*sock, "\"status\":\"not_found\"");
		return;
	}

	// Remove leading '/'
	domain++;

	// Validate route
	char *expected_route_start;
	char *expected_route;

	if(list_type == WHITELIST)
		expected_route_start = "/dns/whitelist/";
	else if(list_type == BLACKLIST)
		expected_route_start = "/dns/blacklist/";
	else if(list_type == WILDLIST)
		expected_route_start = "/dns/wildlist/";
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
//		sendAPIResponse(*sock, type, NOT_FOUND);
		ssend(*sock, "\"status\":\"not_found\"");
		return;
	}

	free(expected_route);

	if(!isValidDomain(domain)) {
		// Invalid domain
//		sendAPIResponse(*sock, type, BAD_REQUEST);
		ssend(*sock, "\"status\":\"invalid_domain\"");
		return;
	}

	// Get command
	char *partial_command;

	if(list_type == WHITELIST)
		partial_command = "sudo pihole -w -q -d ";
	else if(list_type == BLACKLIST)
		partial_command = "sudo pihole -b -q -d ";
	else
		partial_command = "sudo pihole -wild -q -d ";

	// Run command
	char *command = malloc((strlen(domain) + strlen(partial_command) + 1) * sizeof(char));
	strcpy(command, partial_command);
	strcat(command, domain);
	int return_code = system(command);
	free(command);

	if(return_code == 0) {
		// Successfully removed from list
//		sendAPIResponse(*sock, type, OK);
		ssend(*sock, "\"status\":\"success\"");
	}
	else {
		// Failed to remove from list
//		sendAPIResponse(*sock, type, INTERNAL_ERROR);
		ssend(*sock, "\"status\":\"unknown_error\"");
	}
}
