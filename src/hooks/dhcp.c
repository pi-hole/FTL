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
#include "dhcp.h"

bool FTL_unlink_DHCP_lease(const char *ipaddr)
{
	struct dhcp_lease *lease;
	union all_addr addr;
	const time_t now = dnsmasq_time();

	// Try to extract IP address
	if (inet_pton(AF_INET, ipaddr, &addr.addr4) > 0)
	{
		lease = lease_find_by_addr(addr.addr4);
	}
#ifdef HAVE_DHCP6
	else if (inet_pton(AF_INET6, ipaddr, &addr.addr6) > 0)
	{
		lease = lease6_find_by_addr(&addr.addr6, 128, 0);
	}
#endif
	else
	{
		return false;
	}

	// If a lease exists for this IP address, we unlink it and immediately
	// update the lease file to reflect the removal of this lease
	if (lease)
	{
		// Unlink the lease for dnsmasq's database
		lease_prune(lease, now);
		// Update the lease file
		lease_update_file(now);
		// Argument force == 0 ensures the DNS records are only updated
		// when unlinking the lease above actually changed something
		// (variable lease.c:dns_dirty is used here)
		lease_update_dns(0);
	}

	// Return success
	return true;
}
