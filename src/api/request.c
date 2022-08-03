/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Socket request handling routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "api.h"
#include "../shmem.h"
#include "../timers.h"
#include "request.h"
#include "socket.h"
#include "../resolve.h"
#include "../regex_r.h"
#include "../database/network-table.h"
#include "../log.h"
// Eventqueue routines
#include "../events.h"
#include "../config.h"

bool __attribute__((pure)) command(const char *client_message, const char* cmd) {
	return strstr(client_message, cmd) != NULL;
}

bool process_request(const char *client_message, const int sock, const bool istelnet)
{
	char EOT[2];
	EOT[0] = 0x04;
	EOT[1] = 0x00;
	bool processed = false;

	if(command(client_message, ">stats"))
	{
		processed = true;
		lock_shm();
		getStats(sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">overTime"))
	{
		processed = true;
		lock_shm();
		getOverTime(sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">top-domains") || command(client_message, ">top-ads"))
	{
		processed = true;
		lock_shm();
		getTopDomains(client_message, sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">top-clients"))
	{
		processed = true;
		lock_shm();
		getTopClients(client_message, sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">forward-dest"))
	{
		processed = true;
		lock_shm();
		getUpstreamDestinations(client_message, sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">forward-names"))
	{
		processed = true;
		lock_shm();
		getUpstreamDestinations(">forward-dest unsorted", sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">querytypes"))
	{
		processed = true;
		lock_shm();
		getQueryTypes(sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">getallqueries"))
	{
		processed = true;
		lock_shm();
		getAllQueries(client_message, sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">recentBlocked"))
	{
		processed = true;
		lock_shm();
		getRecentBlocked(client_message, sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">clientID"))
	{
		processed = true;
		lock_shm();
		getClientID(sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">version"))
	{
		processed = true;
		// No lock required
		getVersion(sock, istelnet);
	}
	else if(command(client_message, ">dbstats"))
	{
		processed = true;
		// No lock required. Access to the database
		// is guaranteed to be atomic
		getDBstats(sock, istelnet);
	}
	else if(command(client_message, ">ClientsoverTime"))
	{
		processed = true;
		lock_shm();
		getClientsOverTime(sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">client-names"))
	{
		processed = true;
		lock_shm();
		getClientNames(sock, istelnet);
		unlock_shm();
	}
	else if(command(client_message, ">unknown"))
	{
		processed = true;
		lock_shm();
		getUnknownQueries(sock, istelnet);
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
		set_event(RELOAD_PRIVACY_LEVEL);
	}
	else if(command(client_message, ">recompile-regex"))
	{
		processed = true;
		logg("Received API request to recompile regex");
		lock_shm();
		// Reread regex.list
		// Read and compile possible regex filters
		read_regex_from_database();
		unlock_shm();
	}
	else if(command(client_message, ">delete-lease"))
	{
		processed = true;
		delete_lease(client_message, sock);
	}
	else if(command(client_message, ">dns-port"))
	{
		processed = true;
		getDNSport(sock);
	}
	else if(command(client_message, ">maxlogage"))
	{
		processed = true;
		getMAXLOGAGE(sock);
	}
	else if(command(client_message, ">gateway"))
	{
		processed = true;
		getGateway(sock);
	}
	else if(command(client_message, ">interfaces"))
	{
		processed = true;
		getInterfaces(sock);
	}

	// Test only at the end if we want to quit or kill
	// so things can be processed before
	if(command(client_message, ">quit") || command(client_message, EOT))
	{
		if(config.debug & DEBUG_API)
			logg("Received >quit or EOT on socket %d", sock);
		return true;
	}

	if(!processed)
		ssend(sock, "unknown command: %s\n", client_message);

	// End of queryable commands: Send EOM
	seom(sock, istelnet);

	return false;
}
