/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  PH7 extension: gethostname()
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../../ph7/ph7.h"
#include "extensions.h"
#include <string.h>
#include <unistd.h>

int gethostname_impl(ph7_context *pCtx, int argc, ph7_value **argv)
{
	// We do not accept input arguments here
	if(argc != 0)
	{
		// Invalid argument,throw a warning and return FALSE.
		ph7_context_throw_error(pCtx, PH7_CTX_WARNING, "No arguments allowed");
		ph7_result_bool(pCtx, 0);
		return PH7_OK;
	}

	// Get host name
	char name[256];
	if(gethostname(name, sizeof(name)) != 0)
	{
		strcpy(name, "N/A");
	}

	ph7_result_string(pCtx, name, strlen(name));

	/* All done */
	return PH7_OK;
}
