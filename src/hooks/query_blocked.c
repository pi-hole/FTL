/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "query_blocked.h"
#include "../config.h"
#include "../log.h"
// force_next_DNS_reply
#include "blocking_metadata.h"
// in_allowlist
#include "../database/gravity-db.h"
// getstr
#include "../shmem.h"
// get_blockingstatus
#include "../setupVars.h"
// query_set_reply()
#include "set_reply.h"
// query_to_database()
#include "../database/query-table.h"

void query_blocked(queriesData* query, domainsData* domain, clientsData* client, const enum query_status new_status)
{
	// Get response time
	int blocking_flags = 0;
	struct timeval response;
	gettimeofday(&response, 0);
	query_set_reply(blocking_flags, NULL, query, response);

	// Adjust counters if we recorded a non-blocking status
	if(query->status == STATUS_FORWARDED)
	{
		// Get forward pointer
		upstreamsData* upstream = getUpstream(query->upstreamID, true);
		if(upstream != NULL)
			upstream->count--;
	}
	else if(is_blocked(query->status))
	{
		// Already a blocked query, no need to change anything
		return;
	}

	// Count as blocked query
	if(domain != NULL)
		domain->blockedcount++;
	if(client != NULL)
		change_clientcount(client, 0, 1, -1, 0);

	// Update status
	query_set_status(query, new_status);
	query->flags.blocked = true;

	// Update query in database
	query_to_database(query);
}