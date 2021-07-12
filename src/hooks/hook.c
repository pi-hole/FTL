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
#include "hook.h"
#include "../config/config.h"
#include "../log.h"
#include "../edns0.h"
// FTL_forwarded
#include "forwarded.h"
// FTL_reply
#include "received_reply.h"
// FTL_dnssec
#include "dnssec.h"
// FTL_upstream_error
#include "upstream_error.h"
// short_path()
#include "../files.h"
// FTL_new_query()
#include "new_query.h"
// print_flags()
#include "print_flags.h"

void FTL_hook(unsigned int flags, char *name, union all_addr *addr, char *arg, int id, const char* file, const int line)
{
	// Extract filename from path
	const char *path = short_path(file);
	if(config.debug & DEBUG_FLAGS)
	{
		log_debug(DEBUG_FLAGS, "Processing FTL hook from %s:%d...", path, line);
		print_flags(flags, false);
	}

	// Note: The order matters here!
	if(strcmp(path, "src/dnsmasq_interface.c") == 0)
		; // Ignored - loopback from FTL_make_answer() below
	else if((flags & F_QUERY) && (flags & F_FORWARD))
		; // New query, handled by FTL_new_query via separate call
	else if(flags & F_FORWARD && flags & F_SERVER)
		// forwarded upstream
		FTL_forwarded(flags, name, addr, id, path, line);
	else if(flags == F_SECSTAT)
		// DNSSEC validation result
		FTL_dnssec(arg, addr, id, path, line);
	else if(flags == (F_UPSTREAM | F_RCODE) && name && strcasecmp(name, "error") == 0)
		// upstream sent something different than NOERROR or NXDOMAIN
		FTL_upstream_error(addr, id, path, line);
	else if(flags & F_NOEXTRA && flags & F_DNSSEC)
	{
		// This is a new DNSSEC query (dnssec-query[DS])
		if(!config.show_dnssec)
			return;

		const int qtype = strcmp(arg, "dnssec-query[DS]") == 0 ? T_DS : T_DNSKEY;
		const ednsData edns = { 0 };
		union mysockaddr saddr = {{ 0 }};
		if(flags & F_IPV4)
		{
			saddr.in.sin_addr = addr->addr4;
			saddr.sa.sa_family = AF_INET;
		}
		else
		{
			memcpy(&saddr.in6.sin6_addr, &addr->addr6, sizeof(addr->addr6));
			saddr.sa.sa_family = AF_INET;
		}
		_FTL_new_query(flags, name, NULL, arg, qtype, id, &edns, INTERNAL, file, line);
		FTL_forwarded(flags, name, addr, id, path, line);
	}
	else if(flags & F_AUTH)
		; // Ignored
	else if(flags & F_IPSET)
		; // Ignored
	else
		FTL_reply(flags, name, addr, arg, id, path, line);
}

