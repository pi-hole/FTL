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
#include "zip/teleporter.h"
#include "api/api.h"
// ERRBUF_SIZE
#include "config/dnsmasq_config.h"
// inflate_buffer()
#include "zip/gzip.h"
// find_file_in_tar()
#include "zip/tar.h"

#define MAXFILESIZE (50u*1024*1024)

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
	// teleporter.zip (rather than showing the binary data in the browser
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
	uint8_t *data;
	char *filename;
	size_t filesize;
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
		data->filename = strdup(filename);
		is_file = true;
		return MG_FORM_FIELD_STORAGE_GET;
	}
	else if(strcasecmp(key, "sid") == 0)
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
		if(data->filesize + valuelen > MAXFILESIZE)
		{
			log_warn("Uploaded Teleporter file is too large (limit is %u bytes)",
			         MAXFILESIZE);
			data->too_large = true;
			return MG_FORM_FIELD_HANDLE_ABORT;
		}
		// Allocate memory for the raw file data
		data->data = realloc(data->data, data->filesize + valuelen);
		// Copy the raw file data
		memcpy(data->data + data->filesize, value, valuelen);
		// Store the size of the file raw data
		data->filesize += valuelen;
		log_debug(DEBUG_API, "Received file (%zu bytes, buffer is now %zu bytes)",
		          valuelen, data->filesize);
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
	if(data->filename)
	{
		free(data->filename);
		data->filename = NULL;
	}
	if(data->sid)
	{
		free(data->sid);
		data->sid = NULL;
	}
	if(data->data)
	{
		free(data->data);
		data->data = NULL;
	}
	return 0;
}

// Private function prototypes
static int process_received_zip(struct ftl_conn *api, struct upload_data *data);
static int process_received_tar_gz(struct ftl_conn *api, struct upload_data *data);

static int api_teleporter_POST(struct ftl_conn *api)
{
	struct upload_data data;
	memset(&data, 0, sizeof(struct upload_data));
	const struct mg_request_info *req_info = mg_get_request_info(api->conn);
	struct mg_form_data_handler fdh = {field_found, field_get, field_stored, &data};

	// Disallow large ZIP archives (> 50 MB) to prevent DoS attacks.
	// Typically, the ZIP archive size should be around 30-100 kB.
	if(req_info->content_length > MAXFILESIZE)
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
	if(data.data == NULL || data.filesize == 0)
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

	// Check if we received something that claims to be a ZIP archive
	// - filename
	//   - shoud be at least 12 characters long,
	//   - should start in "pi-hole_",
	//   - have "_teleporter_" in the middle, and
	//   - end in ".zip"
	// - the data itself
	//   - should be at least 40 bytes long
	//   - start with 0x04034b50 (local file header signature, see https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT)
	if(strlen(data.filename) >= 12 &&
	   strncmp(data.filename, "pi-hole_", 8) == 0 &&
	   strstr(data.filename, "_teleporter_") != NULL &&
	   strcmp(data.filename + strlen(data.filename) - 4, ".zip") == 0 &&
	   data.filesize >= 40 &&
	   memcmp(data.data, "\x50\x4b\x03\x04", 4) == 0)
	{
		return process_received_zip(api, &data);
	}
	// Check if we received something that claims to be a TAR.GZ archive
	// - filename
	//   - shoud be at least 12 characters long,
	//   - should start in "pi-hole-",
	//   - have "-teleporter_" in the middle, and
	//   - end in ".tar.gz"
	// - the data itself
	//   - should be at least 40 bytes long
	//   - start with 0x8b1f (local file header signature, see https://www.ietf.org/rfc/rfc1952.txt)
	else if(strlen(data.filename) >= 12 &&
	        strncmp(data.filename, "pi-hole-", 8) == 0 &&
	        strstr(data.filename, "-teleporter_") != NULL &&
	        strcmp(data.filename + strlen(data.filename) - 7, ".tar.gz") == 0 &&
	        data.filesize >= 40 &&
	        memcmp(data.data, "\x1f\x8b", 2) == 0)
	{
		return process_received_tar_gz(api, &data);
	}

	// else: invalid file
	free_upload_data(&data);
	return send_json_error(api, 400,
	                       "bad_request",
	                       "Invalid file",
	                       "The uploaded file does not appear to be a valid Pi-hole Teleporter archive");
}

static int process_received_zip(struct ftl_conn *api, struct upload_data *data)
{
	char hint[ERRBUF_SIZE];
	memset(hint, 0, sizeof(hint));
	cJSON *json_files = JSON_NEW_ARRAY();
	const char *error = read_teleporter_zip(data->data, data->filesize, hint, json_files);
	if(error != NULL)
	{
		const size_t msglen = strlen(error) + strlen(hint) + 4;
		char *msg = calloc(msglen, sizeof(char));
		strncpy(msg, error, msglen);
		if(strlen(hint) > 0)
		{
			// Concatenate error message and hint into a single string
			strcat(msg, ": ");
			strcat(msg, hint);
		}
		free_upload_data(data);
		return send_json_error_free(api, 400,
		                            "bad_request",
		                            "Invalid ZIP archive",
		                            msg, true);
	}

	// Free allocated memory
	free_upload_data(data);

	// Send response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "files", json_files);
	JSON_SEND_OBJECT(json);
}

static int process_received_tar_gz(struct ftl_conn *api, struct upload_data *data)
{
	// Try to decompress the received data
	uint8_t *archive = NULL;
	mz_ulong archive_size = 0u;
	if(!inflate_buffer(data->data, data->filesize, &archive, &archive_size))
	{
		free_upload_data(data);
		return send_json_error(api, 400,
		                       "bad_request",
		                       "Invalid GZIP archive",
		                       "The uploaded file does not appear to be a valid gzip archive - decompression failed");
	}

	// Check if the decompressed data is a valid TAR archive
	cJSON *json_files = list_files_in_tar(archive, archive_size);

	// Print all files in the TAR archive
	cJSON *file = NULL;
	cJSON_ArrayForEach(file, json_files)
	{
		cJSON *name = cJSON_GetObjectItemCaseSensitive(file, "name");
		cJSON *size = cJSON_GetObjectItemCaseSensitive(file, "size");
		log_info("Found file in TAR archive: \"%s\" (%d bytes)",
		          name->valuestring, size->valueint);
	}

	// Parse adlist.json
	size_t fileSize = 0u;
	const char *adlist_json = find_file_in_tar(archive, archive_size, "adlist.json", &fileSize);
	if(adlist_json != NULL)
	{
		cJSON *adlists = cJSON_ParseWithLength(adlist_json, fileSize);
		if(adlists != NULL)
		{
			cJSON *adlist = NULL;
			cJSON_ArrayForEach(adlist, adlists)
			{
				cJSON *address = cJSON_GetObjectItemCaseSensitive(adlist, "address");
				cJSON *comment = cJSON_GetObjectItemCaseSensitive(adlist, "comment");
				log_info("Found adlist in TAR archive: \"%s\" (%s)",
				         address->valuestring, comment->valuestring);
			}
			cJSON_Delete(adlists);
		}
	}

	// Free allocated memory
	free_upload_data(data);

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
