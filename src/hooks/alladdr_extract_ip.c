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
#include "alladdr_extract_ip.h"

void alladdr_extract_ip(union all_addr *addr, const sa_family_t family, char ip[ADDRSTRLEN+1])
{
	// Extract IP address
	inet_ntop(family, addr, ip, ADDRSTRLEN);
}
