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
#include "blocking_metadata.h"
#include "iface.h"
#include "../config.h"
#include "../log.h"

// Static blocking metadata
static union all_addr null_addrp = {{ 0 }};
unsigned char force_next_DNS_reply = 0u;

void _FTL_get_blocking_metadata(union all_addr **addrp, unsigned int *flags, const char *file, const int line)
{
	// Check first if we need to force our reply to something different than the
	// default/configured blocking mode. For instance, we need to force NXDOMAIN
	// for intercepted _esni.* queries.
	if(force_next_DNS_reply == NXDOMAIN)
	{
		*flags = F_NXDOMAIN;
		// Reset DNS reply forcing
		force_next_DNS_reply = 0u;
		return;
	}
	else if(force_next_DNS_reply == REFUSED)
	{
		// Empty flags result in REFUSED
		*flags = 0;
		// Reset DNS reply forcing
		force_next_DNS_reply = 0u;
		return;
	}

	// Add flags according to current blocking mode
	// We bit-add here as flags already contains either F_IPV4 or F_IPV6
	// Set blocking_flags to F_HOSTS so dnsmasq logs blocked queries being answered from a specific source
	// (it would otherwise assume it knew the blocking status from cache which would prevent us from
	// printing the blocking source (blacklist, regex, gravity) in dnsmasq's log file, our pihole.log)
	*flags |= F_HOSTS;

	if(*flags & F_IPV6)
	{
		// Pass blocking IPv6 address
		if(config.blockingmode == MODE_IP)
			*addrp = &next_iface.addr6;
		else
			*addrp = &null_addrp;
	}
	else
	{
		// Pass blocking IPv4 address
		if(config.blockingmode == MODE_IP || config.blockingmode == MODE_IP_NODATA_AAAA)
			*addrp = &next_iface.addr4;
		else
			*addrp = &null_addrp;
	}

	if(config.blockingmode == MODE_NX)
	{
		// If we block in NXDOMAIN mode, we add the NEGATIVE response
		// and the NXDOMAIN flags
		*flags = F_NXDOMAIN;
	}
	else if(config.blockingmode == MODE_NODATA ||
	       (config.blockingmode == MODE_IP_NODATA_AAAA && (*flags & F_IPV6)))
	{
		// If we block in NODATA mode or NODATA for AAAA queries, we apply
		// the NOERROR response flag. This ensures we're sending an empty response
		*flags = F_NOERR;
	}
}