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
#include "set_reply.h"
#include "../config.h"
#include "../log.h"
// force_next_DNS_reply
#include "blocking_metadata.h"
// counters
#include "../shmem.h"
// converttimeval
#include "../timers.h"

static const char *reply_status_str[REPLY_MAX] = {
	"UNKNOWN",
	"NODATA",
	"NXDOMAIN",
	"CNAME",
	"IP",
	"DOMAIN",
	"RRNAME",
	"SERVFAIL",
	"REFUSED",
	"NOTIMP",
	"OTHER"
};

void query_set_reply(const unsigned int flags, const union all_addr *addr,
                     queriesData *query, const double now)
{
	// Iterate through possible values
	if(flags & F_NEG || force_next_DNS_reply == NXDOMAIN)
	{
		if(flags & F_NXDOMAIN)
			// NXDOMAIN
			query->reply = REPLY_NXDOMAIN;
		else
			// NODATA(-IPv6)
			query->reply = REPLY_NODATA;
	}
	else if(flags & F_CNAME)
		// <CNAME>
		query->reply = REPLY_CNAME;
	else if(flags & F_REVERSE)
		// reserve lookup
		query->reply = REPLY_DOMAIN;
	else if(flags & F_RRNAME)
		// TXT query
		query->reply = REPLY_RRNAME;
	else if((flags & F_RCODE && addr != NULL) || force_next_DNS_reply == REFUSED)
	{
		if((addr != NULL && addr->log.rcode == REFUSED)
		   || force_next_DNS_reply == REFUSED )
		{
			// REFUSED query
			query->reply = REPLY_REFUSED;
		}
		else if(addr != NULL && addr->log.rcode == SERVFAIL)
		{
			// SERVFAIL query
			query->reply = REPLY_SERVFAIL;
		}
	}
	else
	{
		// Valid IP
		query->reply = REPLY_IP;
	}

	if(config.debug & DEBUG_QUERIES)
		logg("Set reply to %s (%d)",
		     reply_status_str[query->reply],
		     query->reply);

	counters->reply[query->reply]++;

	// Save response time (relative time)
	query->response = now;
}
