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
#include "dns_name.h"

const char * __attribute__ ((pure)) dns_name(char *name)
{
	// This should not happen, we still handle it
	if(name == NULL)
		return "(NULL)";

	// Substitute empty domain with the root domain "."
	if(strlen(name) == 0)
		return ".";

	// Else: Everthing is okay
	return name;
}
