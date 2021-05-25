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
#include "print_flags.h"
#include "../config.h"
#include "../log.h"
// force_next_DNS_reply
#include "blocking_metadata.h"
// counters
#include "../shmem.h"
// converttimeval
#include "../timers.h"

const char flagnames[][12] = {
	"F_IMMORTAL ",
	"F_NAMEP ",
	"F_REVERSE ",
	"F_FORWARD ",
	"F_DHCP ",
	"F_NEG ",
	"F_HOSTS ",
	"F_IPV4 ",
	"F_IPV6 ",
	"F_BIGNAME ",
	"F_NXDOMAIN ",
	"F_CNAME ",
	"F_DNSKEY ",
	"F_CONFIG ",
	"F_DS ",
	"F_DNSSECOK ",
	"F_UPSTREAM ",
	"F_RRNAME ",
	"F_SERVER ",
	"F_QUERY ",
	"F_NOERR ",
	"F_AUTH ",
	"F_DNSSEC ",
	"F_KEYTAG ",
	"F_SECSTAT ",
	"F_NO_RR ",
	"F_IPSET ",
	"F_NOEXTRA ",
	"F_SERVFAIL",
	"F_RCODE"};

void print_flags(const unsigned int flags)
{
	// Debug function, listing resolver flags in clear text
	// e.g. "Flags: F_FORWARD F_NEG F_IPV6"

	// Only print flags if corresponding debugging flag is set
	if(!(config.debug & DEBUG_FLAGS))
		return;

	char flagstr[sizeof(flagnames) + 1];
	for (unsigned int i = 0; i < (sizeof(flagnames) / sizeof(*flagnames)); i++)
		if (flags & (1u << i))
			strcat(flagstr, flagnames[i]);
	logg("     Flags: %s", flagstr);
}
