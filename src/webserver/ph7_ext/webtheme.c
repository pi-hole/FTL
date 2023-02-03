/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  PH7 extension: fileversion()
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "webserver/ph7/ph7.h"
#include "extensions.h"
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
// config
#include "config/config.h"
// get_web_theme_str()
#include "datastructure.h"

int webtheme_impl(ph7_context *pCtx, int argc, ph7_value **argv)
{
	// We do not accept input arguments here
	if(argc != 0)
	{
		// Invalid argument,throw a warning and return FALSE.
		ph7_context_throw_error(pCtx, PH7_CTX_WARNING, "This function does not accept any arguments");
		ph7_result_bool(pCtx, 0);
		return PH7_OK;
	}

	// Return current theme name
	const char *webtheme = get_web_theme_str(config.webserver.interface.theme.v.web_theme);
	ph7_result_string(pCtx, webtheme, -1);

	/* All done */
	return PH7_OK;
}
