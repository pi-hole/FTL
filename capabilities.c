/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Linux capability check routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Definition of LINUX_CAPABILITY_VERSION_*
#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"

bool check_capabilities()
{
	int capsize = 1; /* for header version 1 */
	cap_user_header_t hdr = NULL;
	cap_user_data_t data = NULL;

	/* find version supported by kernel */
	hdr = calloc(sizeof(*hdr), capsize);
	memset(hdr, 0, sizeof(*hdr));
	capget(hdr, NULL);

	if (hdr->version != LINUX_CAPABILITY_VERSION_1)
	{
	    /* if unknown version, use largest supported version (3) */
	    if (hdr->version != LINUX_CAPABILITY_VERSION_2)
	     hdr->version = LINUX_CAPABILITY_VERSION_3;
	    capsize = 2;
	}

	data = calloc(sizeof(*data), capsize);
	capget(hdr, data); /* Get current values, for verification */

	bool missing = true;
	if (!(data->permitted & (1 << CAP_NET_ADMIN)))
	{
		// Needed for ARP-injection (used when we're the DHCP server)
		logg("**************************************************************");
		logg("WARNING: Required linux capability CAP_NET_ADMIN not available");
		logg("**************************************************************");
		missing = true;
	}
	if (!(data->permitted & (1 << CAP_NET_RAW)))
	{
		// Needed for raw socket access (necessary for ICMP)
		logg("************************************************************");
		logg("WARNING: Required linux capability CAP_NET_RAW not available");
		logg("************************************************************");
		missing = true;
	}
	if (!(data->permitted & (1 << CAP_NET_BIND_SERVICE)))
	{
		// Necessary for dynamic port binding
		logg("*********************************************************************");
		logg("WARNING: Required linux capability CAP_NET_BIND_SERVICE not available");
		logg("*********************************************************************");
		missing = true;
	}
	if (!(data->permitted & (1 << CAP_SETUID)))
	{
		// Necessary for changing our own user ID ("daemonizing")
		logg("*********************************************************************");
		logg("WARNING: Required linux capability CAP_SETUID not available");
		logg("*********************************************************************");
		missing = true;
	}

	// All okay!
	return missing;
}
