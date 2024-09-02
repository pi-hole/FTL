/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/docs
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "docs.h"

int api_docs(struct ftl_conn *api)
{
	// Handle resource request by redirecting to "/"
	if(strcmp(api->request->request_uri, "/api/docs") == 0)
	{
		log_debug(DEBUG_API, "Redirecting /api/docs --301--> /api/docs/");
		mg_send_http_redirect(api->conn, "/api/docs/", 301);
	}

	// Handle root request by redirecting to "/"
	bool serve_index = false;
	if(strcmp(api->request->request_uri, "/api/docs/") == 0)
	{
		serve_index = true;
	}

	// Loop over all available files and see if we can serve this request
	for(unsigned int i = 0; i < (sizeof(docs_files)/sizeof(docs_files[0])); i++)
	{
		// Check if this is the requested file
		if(strcmp(docs_files[i].path, api->item) == 0 ||
		   (serve_index && strcmp(docs_files[i].path, "index.html") == 0))
		{
			// Send the file
			mg_send_http_ok(api->conn, docs_files[i].mime_type, (long long)docs_files[i].content_size);
			return mg_write(api->conn, docs_files[i].content, docs_files[i].content_size);
		}
	}

	// Requested path was not found
	return 0;
}
