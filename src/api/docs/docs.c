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
// inflate_buffer()
#include "zip/gzip.h"

// Serve one documentation asset. The assets are stored GZIP-compressed (see
// CMakeLists.txt in this directory), so a client advertising gzip gets the
// stored stream verbatim. Everything else - most notably curl, which sends no
// Accept-Encoding at all - gets it inflated on the fly.
static int send_doc_file(struct ftl_conn *api, const unsigned int i)
{
	const char *content = docs_files[i].content;
	size_t content_size = docs_files[i].content_size;
	unsigned char *inflated = NULL;

	const char *accept = mg_get_header(api->conn, "Accept-Encoding");
	const bool send_gzip = accept != NULL && strstr(accept, "gzip") != NULL;

	if(!send_gzip)
	{
		// inflate_buffer() rewrites its input when the GZIP header carries an
		// extra field, so it must not be pointed at the read-only asset itself
		unsigned char *copy = malloc(content_size);
		if(copy == NULL)
			return send_http_internal_error(api);
		memcpy(copy, content, content_size);

		mz_ulong inflated_size = 0;
		const bool ok = inflate_buffer(copy, (mz_ulong)content_size,
		                               &inflated, &inflated_size);
		free(copy);
		if(!ok)
		{
			if(inflated != NULL)
				free(inflated);
			return send_http_internal_error(api);
		}

		content = (const char *)inflated;
		content_size = inflated_size;
	}

	// Both encodings are served from the same URL, so caches have to key on
	// the request header to not hand a gzip stream to a client asking for plain
	snprintf(pi_hole_extra_headers, sizeof(pi_hole_extra_headers),
	         "%sVary: Accept-Encoding",
	         send_gzip ? "Content-Encoding: gzip\r\n" : "");

	mg_send_http_ok(api->conn, docs_files[i].mime_type, (long long)content_size);
	const int ret = mg_write(api->conn, content, content_size);

	if(inflated != NULL)
		free(inflated);
	return ret;
}

int api_docs(struct ftl_conn *api)
{
	// Handle resource request by redirecting to "/"
	if(strcmp(api->request->request_uri, "/api/docs") == 0)
	{
		log_web_debug(DEBUG_API, "Redirecting /api/docs --301--> /api/docs/");
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
			return send_doc_file(api, i);
	}

	// Requested path was not found
	return 0;
}
