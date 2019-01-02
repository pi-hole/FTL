/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Linux capability check routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include <sys/capability.h>

bool check_capabilities()
{
	if(!cap_get_bound(CAP_NET_ADMIN))
	{
		// Needed for ARP-injection (used when we're the DHCP server)
		logg("**************************************************************");
		logg("WARNING: Required linux capability CAP_NET_ADMIN not available");
		logg("**************************************************************");
		return false;
	}
	if(!cap_get_bound(CAP_NET_RAW))
	{
		// Needed for raw socket access (necessary for ICMP)
		logg("************************************************************");
		logg("WARNING: Required linux capability CAP_NET_RAW not available");
		logg("************************************************************");
		return false;
	}
	if(!cap_get_bound(CAP_NET_BIND_SERVICE))
	{
		// Necessary for dynamic port binding
		logg("*********************************************************************");
		logg("WARNING: Required linux capability CAP_NET_BIND_SERVICE not available");
		logg("*********************************************************************");
		return false;
	}

	// All okay!
	return true;
}
