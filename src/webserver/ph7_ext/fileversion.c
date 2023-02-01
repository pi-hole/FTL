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
// file_exists()
#include "files.h"
// config
#include "config/config.h"
#include "log.h"

// Avoid browser caching old versions of a file, using the last modification time
//   Receive the file URL (without "/admin/");
//   Return the string containin URL + "?v=xxx", where xxx is the last modified time of the file.
int fileversion_impl(ph7_context *pCtx, int argc, ph7_value **argv)
{
	// We do not accept input arguments here
	if(argc != 1 || !ph7_value_is_string(argv[0]))
	{
		// Invalid argument,throw a warning and return FALSE.
		ph7_context_throw_error(pCtx, PH7_CTX_WARNING, "Exactly one string argument required");
		ph7_result_bool(pCtx, 0);
		return PH7_OK;
	}

	int nLen;
	const char *filename = ph7_value_to_string(argv[0],&nLen);

	// Construct full filename
	char fullfilename[1024];
	size_t fullfilename_len = sizeof(fullfilename) - 1;
	strncpy(fullfilename, config.webserver.paths.webroot.v.s, fullfilename_len);
	fullfilename_len -= strlen(config.webserver.paths.webroot.v.s);
	strncat(fullfilename, config.webserver.paths.webhome.v.s, fullfilename_len);
	fullfilename_len -= strlen(config.webserver.paths.webhome.v.s);
	strncat(fullfilename, filename, fullfilename_len);

	// Check if file exists
	if(!file_exists(fullfilename))
	{
		// File does not exist, return filename.
		ph7_result_string(pCtx, filename, nLen);
		return PH7_OK;
	}

	// Get last modification time
	struct stat filestat;
	if (stat(fullfilename, &filestat) == -1)
	{
		log_err("Could not get file modification time for \"%s\": %s",
		        fullfilename, strerror(errno));
		ph7_result_string(pCtx, filename, nLen);
		return PH7_OK;
	}

	// Construct return string
	ph7_result_string_format(pCtx, "%s?v=%ld", filename, filestat.st_mtime);

	/* All done */
	return PH7_OK;
}
