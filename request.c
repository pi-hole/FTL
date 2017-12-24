/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Socket request handling routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"

void process_socket_request(char *client_message, int *sock)
{
	char EOT[2];
	EOT[0] = 0x04;
	EOT[1] = 0x00;
	bool processed = false;
	char type = SOCKET;

	if(command(client_message, ">stats"))
	{
		processed = true;
		getStats(sock, type);
	}
	else if(command(client_message, ">overTime"))
	{
		processed = true;
		getOverTime(sock, type);
	}
	else if(command(client_message, ">top-domains") || command(client_message, ">top-ads"))
	{
		processed = true;
		getTopDomains(client_message, sock, type);
	}
	else if(command(client_message, ">top-clients"))
	{
		processed = true;
		getTopClients(client_message, sock, type);
	}
	else if(command(client_message, ">forward-dest"))
	{
		processed = true;
		getForwardDestinations(client_message, sock, type);
	}
	else if(command(client_message, ">forward-names"))
	{
		processed = true;
		getForwardDestinations(">forward-dest unsorted", sock, type);
	}
	else if(command(client_message, ">querytypes"))
	{
		processed = true;
		getQueryTypes(sock, type);
	}
	else if(command(client_message, ">getallqueries"))
	{
		processed = true;
		getAllQueries(client_message, sock, type);
	}
	else if(command(client_message, ">recentBlocked"))
	{
		processed = true;
		getRecentBlocked(client_message, sock, type);
	}
	else if(command(client_message, ">memory"))
	{
		processed = true;
		getMemoryUsage(sock, type);
	}
	else if(command(client_message, ">clientID"))
	{
		processed = true;
		getClientID(sock, type);
	}
	else if(command(client_message, ">ForwardedoverTime"))
	{
		processed = true;
		getForwardDestinationsOverTime(sock, type);
	}
	else if(command(client_message, ">QueryTypesoverTime"))
	{
		processed = true;
		getQueryTypesOverTime(sock, type);
	}
	else if(command(client_message, ">version"))
	{
		processed = true;
		getVersion(sock, type);
	}
	else if(command(client_message, ">dbstats"))
	{
		processed = true;
		getDBstats(sock, type);
	}
	else if(command(client_message, ">ClientsoverTime"))
	{
		processed = true;
		getClientsOverTime(sock);
	}
	else if(command(client_message, ">client-names"))
	{
		processed = true;
		getClientNames(sock);
	}

	// Test only at the end if we want to quit or kill
	// so things can be processed before
	if(command(client_message, ">quit") || command(client_message, EOT))
	{
		processed = true;
		if(debugclients)
			logg("Client wants to disconnect, ID: %i",*sock);

		close(*sock);
		*sock = 0;
	}
	else if(command(client_message, ">kill"))
	{
		processed = true;
		ssend(*sock, "killed\n");
		logg("FTL killed by client ID: %i",*sock);
		killed = 1;
	}

	if(!processed)
	{
		ssend(*sock,"unknown command: %s",client_message);
	}

	// End of queryable commands
	if(*sock != 0)
	{
		// Send EOM
		seom(*sock);
	}
}

void process_api_request(char *client_message, char *full_message, int *sock, bool header)
{
	char type;
	if(header)
		type = APIH;
	else
		type = API;

	char *data = getPayload(full_message);
	long session;

	char authResult = authenticate(full_message, data, &session);
	if(authResult == AUTH_UNAUTHORIZED && !matchesEndpoint(client_message, "GET /stats/summary")
	                                  && !matchesEndpoint(client_message, "GET /stats/overTime/graph")
									  && !matchesEndpoint(client_message, "GET /dns/status")) {
		sendAPIResponse(*sock, type, UNAUTHORIZED);
		ssend(*sock, "\"status\":\"unauthorized\"}");
		return;
	}

	if(authResult == AUTH_NEW) {
		sendAPIResponseWithCookie(*sock, type, OK, &session);
		ssend(*sock, "\"status\":\"authorized\",\"session\":%ld}", session);
		return;
	}

	if(matchesEndpoint(client_message, "GET /stats/summary"))
	{
		getStats(sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/overTime/graph"))
	{
		getOverTime(sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/top_domains") || matchesEndpoint(client_message, "GET /stats/top_ads"))
	{
		getTopDomains(client_message, sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/top_clients"))
	{
		getTopClients(client_message, sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/forward_dest") || matchesEndpoint(client_message, "GET /stats/forward_destinations"))
	{
		getForwardDestinations(client_message, sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/dashboard"))
	{
		getStats(sock, type);
		type = API;
		ssend(*sock, ",");
		getOverTime(sock, type);
		ssend(*sock, ",");
		getTopDomains(client_message, sock, type);
		ssend(*sock, ",");
		getTopClients(client_message, sock, type);
		ssend(*sock, ",");
		getForwardDestinations(client_message, sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/query_types"))
	{
		getQueryTypes(sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/history"))
	{
		getAllQueries(client_message, sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/recent_blocked"))
	{
		getRecentBlocked(client_message, sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/overTime/forward_dest"))
	{
		getForwardDestinationsOverTime(sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /stats/overTime/query_types"))
	{
		getQueryTypesOverTime(sock, type);
	}
	else if(matchesEndpoint(client_message, "GET /dns/whitelist"))
	{
		getList(sock, type, WHITELIST);
	}
	else if(matchesEndpoint(client_message, "POST /dns/whitelist"))
	{
		addList(sock, type, WHITELIST, data);
	}
	else if(matchesRegex("DELETE \\/dns\\/whitelist\\/[^\\/]*$", client_message))
	{
		removeList(sock, type, WHITELIST, client_message);
	}
	else if(matchesEndpoint(client_message, "GET /dns/blacklist"))
	{
		getList(sock, type, BLACKLIST);
	}
	else if(matchesEndpoint(client_message, "POST /dns/blacklist"))
	{
		addList(sock, type, BLACKLIST, data);
	}
	else if(matchesRegex("DELETE \\/dns\\/blacklist\\/[^\\/]*$", client_message))
	{
		removeList(sock, type, BLACKLIST, client_message);
	}
	else if(matchesEndpoint(client_message, "GET /dns/wildlist"))
	{
		getList(sock, type, WILDLIST);
	}
	else if(matchesEndpoint(client_message, "POST /dns/wildlist"))
	{
		addList(sock, type, WILDLIST, data);
	}
	else if(matchesRegex("DELETE \\/dns\\/wildlist\\/[^\\/]*$", client_message))
	{
		removeList(sock, type, WILDLIST, client_message);
	}
	else if(matchesEndpoint(client_message, "GET /dns/status"))
	{
		getPiholeStatus(sock, type);
	}
	else if(header)
	{
		sendAPIResponse(*sock, type, NOT_FOUND);
		ssend(*sock, "\"status\":\"not_found\"");
	}

	ssend(*sock, "}");
}

bool command(char *client_message, const char* cmd) {
	return strstr(client_message, cmd) != NULL;
}

bool matchesEndpoint(char *client_message, const char *cmd) {
	char *get_params_start = strstr(client_message, "?");
	bool result;

	// Check if there are GET parameters to ignore
	if(get_params_start != NULL) {
		char without_get_params[256];

		// Check to make sure we don't overflow the buffer
		if(strlen(cmd)+1 > sizeof(without_get_params) / sizeof(char))
			return false;

		size_t msg_len = get_params_start - client_message;

		strncpy(without_get_params, client_message, msg_len);
		without_get_params[msg_len] = 0;

		result = strcmp(without_get_params, cmd) == 0;
	}
	else
		result = strcmp(client_message, cmd) == 0;

	return result;
}
