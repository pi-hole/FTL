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
#include "compression/teleporter.h"
#include "api/api.h"
// ERRBUF_SIZE
#include "config/dnsmasq_config.h"

#define MAXZIPSIZE (50u*1024*1024)

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

// Struct to store the data we want to process
struct upload_data {
	bool too_large;
	char *sid;
	char *zip_data;
	char *zip_filename;
	size_t zip_size;
};

// Callback function for CivetWeb to determine which fields we want to receive
static bool is_file = false;
static bool is_sid = false;
static int field_found(const char *key,
                       const char *filename,
                       char *path,
                       size_t pathlen,
                       void *user_data)
{
	struct upload_data *data = (struct upload_data *)user_data;
	log_debug(DEBUG_API, "Found field: \"%s\", filename: \"%s\"", key, filename);

	is_file = false;
	is_sid = false;
	if(strcasecmp(key, "file") == 0 && filename && *filename)
	{
		data->zip_filename = strdup(filename);
		is_file = true;
		return MG_FORM_FIELD_STORAGE_GET;
	}
	else if(strcasecmp(key, "import") == 0)
	{
		is_sid = true;
		return MG_FORM_FIELD_STORAGE_GET;
	}

	// Ignore any other fields
	return MG_FORM_FIELD_STORAGE_SKIP;
}

// Callback function for CivetWeb to receive the data of the fields we want to process.
// This function might be called several times for the same field (large (> 8KB)
// or chunked data), so we may need to append new data to existing data.
static int field_get(const char *key, const char *value, size_t valuelen, void *user_data)
{
	struct upload_data *data = (struct upload_data *)user_data;
	log_debug(DEBUG_API, "Received field: \"%s\" (length %zu bytes)", key, valuelen);

	if(is_file)
	{
		if(data->zip_size + valuelen > MAXZIPSIZE)
		{
			log_warn("Uploaded Teleporter ZIP archive is too large (limit is %u bytes)",
			         MAXZIPSIZE);
			data->too_large = true;
			return MG_FORM_FIELD_HANDLE_ABORT;
		}
		// Allocate memory for the raw ZIP archive data
		data->zip_data = realloc(data->zip_data, data->zip_size + valuelen);
		// Copy the raw ZIP archive data
		memcpy(data->zip_data + data->zip_size, value, valuelen);
		// Store the size of the ZIP archive raw data
		data->zip_size += valuelen;
		log_debug(DEBUG_API, "Received ZIP archive (%zu bytes, buffer is now %zu bytes)",
		          valuelen, data->zip_size);
	}
	else if(is_sid)
	{
		// Allocate memory for the SID
		data->sid = calloc(valuelen + 1, sizeof(char));
		// Copy the SID string
		memcpy(data->sid, value, valuelen);
		// Add terminating NULL byte (memcpy does not do this)
		data->sid[valuelen] = '\0';
	}

	// If there is more data in this field, get the next chunk.
	// Otherwise: handle the next field.
	return MG_FORM_FIELD_HANDLE_GET;
}

// We don't use this function, but it is required by the CivetWeb API
static int field_stored(const char *path, long long file_size, void *user_data)
{
	return 0;
}

static int free_upload_data(struct upload_data *data)
{
	// Free allocated memory
	if(data->zip_filename)
	{
		free(data->zip_filename);
		data->zip_filename = NULL;
	}
	if(data->sid)
	{
		free(data->sid);
		data->sid = NULL;
	}
	if(data->zip_data)
	{
		free(data->zip_data);
		data->zip_data = NULL;
	}
	return 0;
}

static int api_teleporter_POST(struct ftl_conn *api)
{
	struct upload_data data;
	memset(&data, 0, sizeof(struct upload_data));
	const struct mg_request_info *req_info = mg_get_request_info(api->conn);
	struct mg_form_data_handler fdh = {field_found, field_get, field_stored, &data};

	// Disallow large ZIP archives (> 50 MB) to prevent DoS attacks.
	// Typically, the ZIP archive size should be around 30-100 kB.
	if(req_info->content_length > MAXZIPSIZE)
	{
		free_upload_data(&data);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "ZIP archive too large",
		                       NULL);
	}

	// Call the form handler to process the POST request content
	const int ret = mg_handle_form_request(api->conn, &fdh);
	if(ret < 0)
	{
		free_upload_data(&data);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid form request",
		                       NULL);
	}

	// Check if we received something we consider being a file
	if(data.zip_data == NULL || data.zip_size == 0)
	{
		free_upload_data(&data);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "No ZIP archive received",
		                       NULL);
	}

	// Check if the file we received is too large
	if(data.too_large)
	{
		free_upload_data(&data);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "ZIP archive too large",
		                       NULL);
	}
/*
	// Set the payload to the SID we received (if available)
	if(data.sid != NULL)
	{
		const size_t bufsize = strlen(data.sid) + 5;
		api->payload.raw = calloc(bufsize, sizeof(char));
		strncpy(api->payload.raw, "sid=", 5);
		strncat(api->payload.raw, data.sid, bufsize - 4);
	}

	// Check if the client is authorized to use this API endpoint
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		free_upload_data(&data);
		return send_json_unauthorized(api);
	}
*/
	// Process what we received
	char hint[ERRBUF_SIZE];
	memset(hint, 0, sizeof(hint));
	cJSON *json_files = JSON_NEW_ARRAY();
	const char *error = read_teleporter_zip(data.zip_data, data.zip_size, hint, json_files);
	if(error != NULL)
	{
		char msg[strlen(error) + strlen(hint) + 4];
		memset(msg, 0, sizeof(msg));
		strncpy(msg, error, sizeof(msg));
		if(strlen(hint) > 0)
		{
			// Concatenate error message and hint into a single string
			strcat(msg, ": ");
			strcat(msg, hint);
		}
		free_upload_data(&data);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid ZIP archive",
		                       msg);
	}

	// Free allocated memory
	free_upload_data(&data);

	// Send response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "files", json_files);
	JSON_SEND_OBJECT(json);
}

int api_teleporter(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
		return api_teleporter_GET(api);
	if(api->method == HTTP_POST)
		return api_teleporter_POST(api);

	return 0;
}
