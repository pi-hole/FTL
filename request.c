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
#include "shmem.h"

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
		lock_shm();
		getStats(sock);
		unlock_shm();
	}
	else if(command(client_message, ">overTime"))
	{
		processed = true;
		lock_shm();
		getOverTime(sock);
		unlock_shm();
	}
	else if(command(client_message, ">top-domains") || command(client_message, ">top-ads"))
	{
		processed = true;
		lock_shm();
		getTopDomains(client_message, sock);
		unlock_shm();
	}
	else if(command(client_message, ">top-clients"))
	{
		processed = true;
		lock_shm();
		getTopClients(client_message, sock);
		unlock_shm();
	}
	else if(command(client_message, ">forward-dest"))
	{
		processed = true;
		lock_shm();
		getForwardDestinations(client_message, sock);
		unlock_shm();
	}
	else if(command(client_message, ">forward-names"))
	{
		processed = true;
		lock_shm();
		getForwardDestinations(">forward-dest unsorted", sock);
		unlock_shm();
	}
	else if(command(client_message, ">querytypes"))
	{
		processed = true;
		lock_shm();
		getQueryTypes(sock);
		unlock_shm();
	}
	else if(command(client_message, ">getallqueries"))
	{
		processed = true;
		lock_shm();
		getAllQueries(client_message, sock);
		unlock_shm();
	}
	else if(command(client_message, ">recentBlocked"))
	{
		processed = true;
		lock_shm();
		getRecentBlocked(client_message, sock);
		unlock_shm();
	}
	else if(command(client_message, ">clientID"))
	{
		processed = true;
		lock_shm();
		getClientID(sock);
		unlock_shm();
	}
	else if(command(client_message, ">QueryTypesoverTime"))
	{
		processed = true;
		lock_shm();
		getQueryTypesOverTime(sock);
		unlock_shm();
	}
	else if(command(client_message, ">version"))
	{
		processed = true;
		// No lock required
		getVersion(sock);
	}
	else if(command(client_message, ">dbstats"))
	{
		processed = true;
		// No lock required. Access to the database
		// is guaranteed to be atomic
		getDBstats(sock);
	}
	else if(command(client_message, ">ClientsoverTime"))
	{
		processed = true;
		lock_shm();
		getClientsOverTime(sock);
		unlock_shm();
	}
	else if(command(client_message, ">client-names"))
	{
		processed = true;
		lock_shm();
		getClientNames(sock);
		unlock_shm();
	}
	else if(command(client_message, ">unknown"))
	{
		processed = true;
		lock_shm();
		getUnknownQueries(sock);
		unlock_shm();
	}
	else if(command(client_message, ">domain"))
	{
		processed = true;
		lock_shm();
		getDomainDetails(client_message, sock);
		unlock_shm();
	}
	else if(command(client_message, ">cacheinfo"))
	{
		processed = true;
		lock_shm();
		getCacheInformation(sock);
		unlock_shm();
	}
	else if(command(client_message, ">reresolve"))
	{
		processed = true;
		logg("Received API request to re-resolve host names");
		// Important: Don't obtain a lock for this request
		//            Locking will be done internally when needed
		// onlynew=false -> reresolve all host names
		resolveClients(false);
		resolveForwardDestinations(false);
		logg("Done re-resolving host names");
	}
	else if(command(client_message, ">recompile-regex"))
	{
		processed = true;
		logg("Received API request to recompile regex");
		lock_shm();
		free_regex();
		read_regex_from_database();
		unlock_shm();
	}
	else if(command(client_message, ">update-mac-vendor"))
	{
		processed = true;
		logg("Received API request to update vendors in network table");
		updateMACVendorRecords();
	}

	// Test only at the end if we want to quit or kill
	// so things can be processed before
	if(command(client_message, ">quit") || command(client_message, EOT))
	{
		processed = true;
		close(*sock);
		*sock = 0;
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
