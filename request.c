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

bool command(char *client_message, const char* cmd) {
	return strstr(client_message, cmd) != NULL;
}

void process_request(char *client_message, int *sock)
{
	char EOT[2];
	EOT[0] = 0x04;
	EOT[1] = 0x00;
	bool processed = false;

	if(command(client_message, ">stats"))
	{
		processed = true;
		getStats(sock);
	}
	else if(command(client_message, ">overTime"))
	{
		processed = true;
		getOverTime(sock);
	}
	else if(command(client_message, ">top-domains") || command(client_message, ">top-ads"))
	{
		processed = true;
		getTopDomains(client_message, sock);
	}
	else if(command(client_message, ">top-clients"))
	{
		processed = true;
		getTopClients(client_message, sock);
	}
	else if(command(client_message, ">forward-dest"))
	{
		processed = true;
		getForwardDestinations(client_message, sock);
	}
	else if(command(client_message, ">forward-names"))
	{
		processed = true;
		getForwardDestinations(">forward-dest unsorted", sock);
	}
	else if(command(client_message, ">querytypes"))
	{
		processed = true;
		getQueryTypes(sock);
	}
	else if(command(client_message, ">getallqueries"))
	{
		processed = true;
		getAllQueries(client_message, sock);
	}
	else if(command(client_message, ">recentBlocked"))
	{
		processed = true;
		getRecentBlocked(client_message, sock);
	}
	else if(command(client_message, ">clientID"))
	{
		processed = true;
		getClientID(sock);
	}
	else if(command(client_message, ">QueryTypesoverTime"))
	{
		processed = true;
		getQueryTypesOverTime(sock);
	}
	else if(command(client_message, ">version"))
	{
		processed = true;
		getVersion(sock);
	}
	else if(command(client_message, ">dbstats"))
	{
		processed = true;
		getDBstats(sock);
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
	else if(command(client_message, ">unknown"))
	{
		processed = true;
		getUnknownQueries(sock);
	}
	else if(command(client_message, ">domain"))
	{
		processed = true;
		getDomainDetails(client_message, sock);
	}
	else if(command(client_message, ">cacheinfo"))
	{
		processed = true;
		getCacheInformation(sock);
	}
	else if(command(client_message, ">reresolve"))
	{
		processed = true;
		logg("Received API request to re-resolve host names");
		// Need to release the thread lock already here to allow
		// the resolver to process the incoming PTR requests
		disable_thread_lock();
		reresolveHostnames();
		logg("Done re-resolving host names");
	}
	else if(command(client_message, ">recompile-regex"))
	{
		processed = true;
		logg("Received API request to recompile regex");
		free_regex();
		read_regex_from_file();
	}

	// Test only at the end if we want to quit or kill
	// so things can be processed before
	if(command(client_message, ">quit") || command(client_message, EOT))
	{
		processed = true;
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
		ssend(*sock,"unknown command: %s\n",client_message);
	}

	// End of queryable commands
	if(*sock != 0)
	{
		// Send EOM
		seom(*sock);
	}
}
