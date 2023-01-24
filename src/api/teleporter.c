/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/teleporter
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "miniz/teleporter.h"
#include "api/api.h"

static int api_teleporter_GET(struct ftl_conn *api)
{
	mz_zip_archive zip = { 0 };
	void *ptr = NULL;
	size_t size = 0u;
	char filename[128] = "";
	const char *error = generate_teleporter_zip(&zip, filename, &ptr, &size);
	if(error != NULL)
		return send_json_error(api, 500,
		                       "compression_error",
		                       error,
		                       NULL);

	// Add header indicating that this is a file to be downloaded and stored as
	// teleporter.zip (rather than showing the binary data in teh browser
	// window). This client is free to ignore and do whatever it wants with this
	// data stream.
	snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers),
	         "Content-Disposition: attachment; filename=\"%s\"",
	         filename);

	// Send 200 OK with appropriate headers
	mg_send_http_ok(api->conn, "application/zip", size);

	// Clear extra headers
	pi_hole_extra_headers[0] = '\0';

	// Send raw (binary) ZIP content
	mg_write(api->conn, ptr, size);

	// Free allocated ZIP memory
	free_teleporter_zip(&zip);

	return 200;
}

int api_teleporter(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
		return api_teleporter_GET(api);

	return 0;
}