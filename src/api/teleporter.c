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
// sqlite3_open_v2()
#include "database/sqlite3.h"
// dbquery()
#include "database/common.h"
// MAX_ROTATIONS
#include "files.h"

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
	cJSON *import;
	uint8_t *data;
	char *filename;
	size_t filesize;
	struct {
		bool file;
		bool sid;
		bool import;
	} field;
};

// Callback function for CivetWeb to determine which fields we want to receive
static int field_found(const char *key,
                       const char *filename,
                       char *path,
                       size_t pathlen,
                       void *user_data)
{
	struct upload_data *data = (struct upload_data *)user_data;
	log_debug(DEBUG_API, "Found field: \"%s\", filename: \"%s\"", key, filename);

	// Set all fields to false
	memset(&data->field, false, sizeof(data->field));
	if(strcasecmp(key, "file") == 0 && filename && *filename)
	{
		data->filename = strdup(filename);
		data->field.file = true;
		return MG_FORM_FIELD_STORAGE_GET;
	}
	else if(strcasecmp(key, "sid") == 0)
	{
		data->field.sid = true;
		return MG_FORM_FIELD_STORAGE_GET;
	}
	else if(strcasecmp(key, "import") == 0)
	{
		data->field.import = true;
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

	if(data->field.file)
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
	else if(data->field.sid)
	{
		// Allocate memory for the SID
		data->sid = calloc(valuelen + 1, sizeof(char));
		// Copy the SID string
		memcpy(data->sid, value, valuelen);
		// Add terminating NULL byte (memcpy does not do this)
		data->sid[valuelen] = '\0';
	}
	else if(data->field.import)
	{
		// Try to parse the JSON data
		const char *json_error = NULL;
		cJSON *json = cJSON_ParseWithLengthOpts(value, valuelen, &json_error, false);
		if(json == NULL)
		{
			log_err("Unable to parse JSON data in API request, error at: %.20s", json_error);
			return MG_FORM_FIELD_HANDLE_ABORT;
		}

		// Check if the JSON data is an object
		if(!cJSON_IsObject(json))
		{
			log_err("JSON data in API request is not an object");
			cJSON_Delete(json);
			return MG_FORM_FIELD_HANDLE_ABORT;
		}

		// Store the parsed JSON data
		data->import = json;
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
	if(data->import)
	{
		cJSON_Delete(data->import);
		data->import = NULL;
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
	// - filename should end in ".zip"
	// - the data itself
	//   - should be at least 40 bytes long
	//   - start with 0x04034b50 (local file header signature, see https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT)
	if(strlen(data.filename) > 4 &&
	   strcmp(data.filename + strlen(data.filename) - 4, ".zip") == 0 &&
	   data.filesize >= 40 &&
	   memcmp(data.data, "\x50\x4b\x03\x04", 4) == 0)
	{
		return process_received_zip(api, &data);
	}
	// Check if we received something that claims to be a TAR.GZ archive
	// - filename should end in ".tar.gz"
	// - the data itself
	//   - should be at least 40 bytes long
	//   - start with 0x8b1f (local file header signature, see https://www.ietf.org/rfc/rfc1952.txt)
	else if(strlen(data.filename) > 7 &&
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
	const char *error = read_teleporter_zip(data->data, data->filesize, hint, data->import, json_files);
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
		                            "Invalid request",
		                            msg, true);
	}

	// Free allocated memory
	free_upload_data(data);

	// Send response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "files", json_files);
	JSON_SEND_OBJECT(json);
}

static struct teleporter_files {
	const char *filename; // Filename of the file in the archive
	const char *table_name; // Name of the table in the database
	const int listtype; // Type of list (only used for domainlist table)
	const size_t num_columns; // Number of columns in the table
	const char *columns[10]; // List of columns in the table
} teleporter_v5_files[] = {
	{
		.filename = "adlist.json",
		.table_name = "adlist",
		.listtype = -1,
		.num_columns = 10,
		.columns = { "id", "address", "enabled", "date_added", "date_modified", "comment", "date_updated", "number", "invalid_domains", "status" } // abp_entries and type are not defined in Pi-hole v5.x
	},{
		.filename = "adlist_by_group.json",
		.table_name = "adlist_by_group",
		.listtype = -1,
		.num_columns = 2,
		.columns = { "group_id", "adlist_id" }
	},{
		.filename = "blacklist.exact.json",
		.table_name = "domainlist",
		.listtype = 1, // GRAVITY_DOMAINLIST_DENY_EXACT
		.num_columns = 7,
		.columns = { "id", "domain", "enabled", "date_added", "date_modified", "comment", "type" }
	},{
		.filename = "blacklist.regex.json",
		.table_name = "domainlist",
		.listtype = 3, // GRAVITY_DOMAINLIST_DENY_REGEX
		.num_columns = 7,
		.columns = { "id", "domain", "enabled", "date_added", "date_modified", "comment", "type" }
	},{
		.filename = "client.json",
		.table_name = "client",
		.listtype = -1,
		.num_columns = 5,
		.columns = { "id", "ip", "date_added", "date_modified", "comment" }
	},{
		.filename = "client_by_group.json",
		.table_name = "client_by_group",
		.listtype = -1,
		.num_columns = 2,
		.columns = { "group_id", "client_id" }
	},{
		.filename = "domainlist_by_group.json",
		.table_name = "domainlist_by_group",
		.listtype = -1,
		.num_columns = 2,
		.columns = { "group_id", "domainlist_id" }
	},{
		.filename = "group.json",
		.table_name = "group",
		.listtype = -1,
		.num_columns = 6,
		.columns = { "id", "enabled", "name", "date_added", "date_modified", "description" }
	},{
		.filename = "whitelist.exact.json",
		.table_name = "domainlist",
		.listtype = 0, // GRAVITY_DOMAINLIST_ALLOW_EXACT
		.num_columns = 7,
		.columns = { "id", "domain", "enabled", "date_added", "date_modified", "comment", "type" }
	},{
		.filename = "whitelist.regex.json",
		.table_name = "domainlist",
		.listtype = 2, // GRAVITY_DOMAINLIST_ALLOW_REGEX
		.num_columns = 7,
		.columns = { "id", "domain", "enabled", "date_added", "date_modified", "comment", "type" }
	}
};

static bool import_json_table(cJSON *json, struct teleporter_files *file)
{
	// Check if the JSON object is an array
	if(!cJSON_IsArray(json))
	{
		log_err("import_json_table(%s): JSON object is not an array", file->filename);
		return false;
	}

	// Check if the JSON array is empty, if so, we can return early
	const int num_entries = cJSON_GetArraySize(json);

	// Check if all the JSON entries contain all the expected columns
	cJSON *json_object = NULL;
	cJSON_ArrayForEach(json_object, json)
	{
		if(!cJSON_IsObject(json_object))
		{
			log_err("import_json_table(%s): JSON array does not contain objects", file->filename);
			return false;
		}

		// If this is a record for the domainlist table, add type/kind
		if(strcmp(file->table_name, "domainlist") == 0)
		{
			// Add type/kind to the JSON object
			cJSON_AddNumberToObject(json_object, "type", file->listtype);
		}

		// Check if the JSON object contains the expected columns
		for(size_t i = 0; i < file->num_columns; i++)
		{
			if(cJSON_GetObjectItemCaseSensitive(json_object, file->columns[i]) == NULL)
			{
				log_err("import_json_table(%s): JSON object does not contain column \"%s\"", file->filename, file->columns[i]);
				return false;
			}
		}
	}

	log_info("import_json_table(%s): JSON array contains %d entr%s", file->filename, num_entries, num_entries == 1 ? "y" : "ies");

	// Open database connection
	sqlite3 *db = NULL;
	if(sqlite3_open_v2(config.files.gravity.v.s, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		log_err("import_json_table(%s): Unable to open database file \"%s\": %s",
		        file->filename, config.files.database.v.s, sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}

	// Disable foreign key constraints
	if(sqlite3_exec(db, "PRAGMA foreign_keys = OFF;", NULL, NULL, NULL) != SQLITE_OK)
	{
		log_err("import_json_table(%s): Unable to disable foreign key constraints: %s", file->filename, sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}

	// Start transaction
	if(sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL) != SQLITE_OK)
	{
		log_err("import_json_table(%s): Unable to start transaction: %s", file->filename, sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}

	// Clear existing table entries
	if(file->listtype < 0)
	{
		// Delete all entries in the table
		log_debug(DEBUG_API, "import_json_table(%s): Deleting all entries from table \"%s\"", file->filename, file->table_name);
		if(dbquery(db, "DELETE FROM \"%s\";", file->table_name) != SQLITE_OK)
		{
			log_err("import_json_table(%s): Unable to delete entries from table \"%s\": %s",
			        file->filename, file->table_name, sqlite3_errmsg(db));
			sqlite3_close(db);
			return false;
		}
	}
	else
	{
		// Delete all entries in the table of the same type
		log_debug(DEBUG_API, "import_json_table(%s): Deleting all entries from table \"%s\" of type %d", file->filename, file->table_name, file->listtype);
		if(dbquery(db, "DELETE FROM \"%s\" WHERE type = %d;", file->table_name, file->listtype) != SQLITE_OK)
		{
			log_err("import_json_table(%s): Unable to delete entries from table \"%s\": %s",
			        file->filename, file->table_name, sqlite3_errmsg(db));
			sqlite3_close(db);
			return false;
		}
	}

	// Build dynamic SQL insertion statement
	// "INSERT OR IGNORE INTO table (column1, column2, ...) VALUES (?, ?, ...);"
	char *sql = sqlite3_mprintf("INSERT OR IGNORE INTO \"%s\" (", file->table_name);
	for(size_t i = 0; i < file->num_columns; i++)
	{
		char *sql2 = sqlite3_mprintf("%s%s", sql, file->columns[i]);
		sqlite3_free(sql);
		sql = NULL;
		if(i < file->num_columns - 1)
		{
			sql = sqlite3_mprintf("%s, ", sql2);
			sqlite3_free(sql2);
			sql2 = NULL;
		}
		else
		{
			sql = sqlite3_mprintf("%s) VALUES (", sql2);
			sqlite3_free(sql2);
			sql2 = NULL;
		}
	}
	for(size_t i = 0; i < file->num_columns; i++)
	{
		char *sql2 = sqlite3_mprintf("%s?", sql);
		sqlite3_free(sql);
		sql = NULL;
		if(i < file->num_columns - 1)
		{
			sql = sqlite3_mprintf("%s, ", sql2);
			sqlite3_free(sql2);
			sql2 = NULL;
		}
		else
		{
			sql = sqlite3_mprintf("%s);", sql2);
			sqlite3_free(sql2);
			sql2 = NULL;
		}
	}

	// Prepare SQL statement
	sqlite3_stmt *stmt = NULL;
	if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		log_err("Unable to prepare SQL statement: %s", sqlite3_errmsg(db));
		sqlite3_free(sql);
		sqlite3_close(db);
		return false;
	}

	// Free allocated memory
	sqlite3_free(sql);
	sql = NULL;

	// Iterate over all JSON objects
	cJSON_ArrayForEach(json_object, json)
	{
		// Bind values to SQL statement
		for(size_t i = 0; i < file->num_columns; i++)
		{
			cJSON *json_value = cJSON_GetObjectItemCaseSensitive(json_object, file->columns[i]);
			if(cJSON_IsString(json_value))
			{
				// Bind string value
				if(sqlite3_bind_text(stmt, i + 1, json_value->valuestring, -1, SQLITE_STATIC) != SQLITE_OK)
				{
					log_err("Unable to bind text value to SQL statement: %s", sqlite3_errmsg(db));
					sqlite3_finalize(stmt);
					sqlite3_close(db);
					return false;
				}
			}
			else if(cJSON_IsNumber(json_value))
			{
				// Bind integer value
				if(sqlite3_bind_int(stmt, i + 1, json_value->valueint) != SQLITE_OK)
				{
					log_err("Unable to bind integer value to SQL statement: %s", sqlite3_errmsg(db));
					sqlite3_finalize(stmt);
					sqlite3_close(db);
					return false;
				}
			}
			else if(cJSON_IsNull(json_value))
			{
				// Bind NULL value
				if(sqlite3_bind_null(stmt, i + 1) != SQLITE_OK)
				{
					log_err("Unable to bind NULL value to SQL statement: %s", sqlite3_errmsg(db));
					sqlite3_finalize(stmt);
					sqlite3_close(db);
					return false;
				}
			}
			else
			{
				log_err("Unable to bind value to SQL statement: type = %X", (unsigned int)json_value->type & 0xFF);
				sqlite3_finalize(stmt);
				sqlite3_close(db);
				return false;
			}
		}

		// Execute SQL statement
		if(sqlite3_step(stmt) != SQLITE_DONE)
		{
			log_err("Unable to execute SQL statement: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			sqlite3_close(db);
			return false;
		}

		// Reset SQL statement
		if(sqlite3_reset(stmt) != SQLITE_OK)
		{
			log_err("Unable to reset SQL statement: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			sqlite3_close(db);
			return false;
		}
	}

	// Finalize SQL statement
	if(sqlite3_finalize(stmt) != SQLITE_OK)
	{
		log_err("Unable to finalize SQL statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}

	// Commit transaction
	if(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK)
	{
		log_err("Unable to commit transaction: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}

	// Close database connection
	sqlite3_close(db);

	return true;
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

	// Print all files in the TAR archive if in debug mode
	if(config.debug.api.v.b)
	{
		cJSON *json_files = list_files_in_tar(archive, archive_size);

		cJSON *file = NULL;
		cJSON_ArrayForEach(file, json_files)
		{
			const cJSON *name = cJSON_GetObjectItemCaseSensitive(file, "name");
			const cJSON *size = cJSON_GetObjectItemCaseSensitive(file, "size");
			if(name == NULL || size == NULL)
				continue;

			log_debug(DEBUG_API, "Found file in TAR archive: \"%s\" (%d bytes)",
			          name->valuestring, size->valueint);
		}
	}

	// Parse JSON files in the TAR archive
	cJSON *imported_files = JSON_NEW_ARRAY();

	// Check if the archive contains gravity tables
	cJSON *gravity = data->import != NULL ? cJSON_GetObjectItemCaseSensitive(data->import, "gravity") : NULL;
	for(size_t i = 0; i < sizeof(teleporter_v5_files) / sizeof(struct teleporter_files); i++)
	{
		// - if import is non-NULL we may skip some tables
		if(data->import != NULL)
		{
			// - if import is non-NULL, but gravity is NULL we skip
			//   the import of gravity tables altogether
			// - if import is non-NULL, and gravity is non-NULL, we
			//   import the file/table if it is in the object, a
			//   boolean and true
			if(gravity == NULL || !JSON_KEY_TRUE(gravity, teleporter_v5_files[i].table_name))
			{
				log_info("Skipping import of \"%s\" as it was not requested for import (JSON: %s, gravity: %s)",
				         teleporter_v5_files[i].filename,
				         data->import != NULL ? "yes" : "no",
				         gravity != NULL ? "yes" : "no");
				continue;
			}
		}

		// Import the JSON file
		size_t fileSize = 0u;
		cJSON *json = NULL;
		const char *file = find_file_in_tar(archive, archive_size, teleporter_v5_files[i].filename, &fileSize);
		const char *json_error = NULL;
		if(file != NULL && fileSize > 0u && (json = cJSON_ParseWithLengthOpts(file, fileSize, &json_error, false)) != NULL)
		{
			if(import_json_table(json, &teleporter_v5_files[i]))
				JSON_COPY_STR_TO_ARRAY(imported_files, teleporter_v5_files[i].filename);
		}
		else if(json_error != NULL)
		{
			log_err("Unable to parse JSON file \"%s\", error at: %.20s",
			        teleporter_v5_files[i].filename, json_error);
		}
		else
		{
			log_debug(DEBUG_CONFIG, "Unable to find file \"%s\" in TAR archive",
			          teleporter_v5_files[i].filename);
		}
	}

	// Temporarily write further files to to disk so we can import them on restart
	struct {
		const char *archive_name;
		const char *destination;
	} extract_files[] = {
		{
			// i = 0
			.archive_name = "custom.list",
			.destination = DNSMASQ_CUSTOM_LIST_LEGACY
		},{
			// i = 1
			.archive_name = "dhcp.leases",
			.destination = DHCPLEASESFILE
		},{
			// i = 2
			.archive_name = "pihole-FTL.conf",
			.destination = GLOBALCONFFILE_LEGACY
		},{
			// i = 3
			.archive_name = "setupVars.conf",
			.destination = config.files.setupVars.v.s
		}
	};
	for(size_t i = 0; i < sizeof(extract_files) / sizeof(*extract_files); i++)
	{
		size_t fileSize = 0u;
		const char *file = find_file_in_tar(archive, archive_size, extract_files[i].archive_name, &fileSize);

		if(data->import != NULL && i == 1 && !JSON_KEY_TRUE(data->import, "dhcp_leases"))
		{
			log_info("Skipping import of \"%s\" as it was not requested for import",
			         extract_files[i].archive_name);
			continue;
		}
		// all other values of i belong to config files
		else if(data->import != NULL && !JSON_KEY_TRUE(data->import, "config"))
		{
			log_info("Skipping import of \"%s\" as it was not requested for import",
			         extract_files[i].archive_name);
			continue;
		}

		if(file != NULL && fileSize > 0u)
		{
			// Write file to disk
			log_info("Writing file \"%s\" (%zu bytes) to \"%s\"",
			         extract_files[i].archive_name, fileSize, extract_files[i].destination);
			FILE *fp = fopen(extract_files[i].destination, "wb");
			if(fp == NULL)
			{
				log_err("Unable to open file \"%s\" for writing: %s", extract_files[i].destination, strerror(errno));
				continue;
			}
			if(fwrite(file, fileSize, 1, fp) != 1)
			{
				log_err("Unable to write file \"%s\": %s", extract_files[i].destination, strerror(errno));
				fclose(fp);
				continue;
			}
			fclose(fp);
			JSON_COPY_STR_TO_ARRAY(imported_files, extract_files[i].destination);
		}
	}

	// Append WEB_PORTS to setupVars.conf
	FILE *fp = fopen(config.files.setupVars.v.s, "a");
	if(fp == NULL)
		log_err("Unable to open file \"%s\" for appending: %s", config.files.setupVars.v.s, strerror(errno));
	else
	{
		fprintf(fp, "WEB_PORTS=%s\n", config.webserver.port.v.s);
		fclose(fp);
	}

	// Remove pihole.toml to prevent it from being imported on restart
	if(remove(GLOBALTOMLPATH) != 0)
		log_err("Unable to remove file \"%s\": %s", GLOBALTOMLPATH, strerror(errno));

	// Remove all rotated pihole.toml files to avoid automatic config
	// restore on restart
	for(unsigned int i = MAX_ROTATIONS; i > 0; i--)
	{
		const char *fname = GLOBALTOMLPATH;
		const char *filename = basename(fname);
		// extra 6 bytes is enough space for up to 999 rotations ("/", ".", "\0", "999")
		const size_t buflen = strlen(filename) + strlen(BACKUP_DIR) + 6;
		char *path = calloc(buflen, sizeof(char));
		snprintf(path, buflen, BACKUP_DIR"/%s.%u", filename, i);

		// Remove file (if it exists)
		if(remove(path) != 0 && errno != ENOENT)
			log_err("Unable to remove file \"%s\": %s", path, strerror(errno));
	}

	// Free allocated memory
	free_upload_data(data);

	// Signal FTL we want to restart for re-import
	api->ftl.restart = true;

	// Send response
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "files", imported_files);
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
