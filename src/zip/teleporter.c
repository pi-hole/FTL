/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Teleporter un-/compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "zip/teleporter.h"
#include "config/config.h"
// hostname()
#include "daemon.h"
// get_timestr(), TIMESTR_SIZE
#include "log.h"
// directory_exists()
#include "files.h"
// DIR, dirent, opendir(), readdir(), closedir()
#include <dirent.h>
// sqlite3
#include "database/sqlite3.h"
// toml_parse()
#include "config/tomlc99/toml.h"
// readFTLtoml()
#include "config/toml_reader.h"
// writeFTLtoml()
#include "config/toml_writer.h"
// write_dnsmasq_config()
#include "config/dnsmasq_config.h"
// lock_shm(), unlock_shm()
#include "shmem.h"
// rotate_file()
#include "files.h"
// cJSON
#include "webserver/cJSON/cJSON.h"
// set_event()
#include "events.h"
// JSON_KEY_TRUE
#include "webserver/json_macros.h"

// Tables to copy from the gravity database to the Teleporter database
static const char *gravity_tables[] = {
	"group",
	"adlist",
	"adlist_by_group",
	"domainlist",
	"domainlist_by_group",
	"client",
	"client_by_group"
};

// Tables to copy from the FTL database to the Teleporter database
static const char *ftl_tables[] = {
	"message",
	"aliasclient",
	"network",
	"network_addresses"
};

// List of files to process from a Teleporter ZIP archive
static const char *extract_files[] = {
	"etc/pihole/pihole.toml",
	"etc/pihole/dhcp.leases",
	"etc/pihole/gravity.db"
};

// Create database in memory, copy selected tables to it, serialize and return a memory pointer to it
static bool create_teleporter_database(const char *filename, const char **tables, const unsigned int num_tables,
                                       void **buffer, size_t *size)
{
	// Open in-memory sqlite3 database
	sqlite3 *db;
	if(sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		log_warn("Failed to open in-memory database: %s", sqlite3_errmsg(db));
		return false;
	}
	// Attach the FTL database to the in-memory database
	char *err = NULL;
	char attach_stmt[128] = "";

	snprintf(attach_stmt, sizeof(attach_stmt), "ATTACH DATABASE '%s' AS \"disk\";", filename);

	if(sqlite3_exec(db, attach_stmt, NULL, NULL, &err) != SQLITE_OK)
	{
		log_warn("Failed to attach database \"%s\" to in-memory database: %s", filename, err);
		sqlite3_free(err);
		sqlite3_close(db);
		return false;
	}

	// Loop over the tables and copy them to the in-memory database
	for(unsigned int i = 0; i < num_tables; i++)
	{
		char create_stmt[128] = "";

		// Create in-memory table copy
		snprintf(create_stmt, sizeof(create_stmt), "CREATE TABLE \"%s\" AS SELECT * FROM disk.\"%s\";", tables[i], tables[i]);
		if(sqlite3_exec(db, create_stmt, NULL, NULL, &err) != SQLITE_OK)
		{
			log_warn("Failed to create %s in in-memory database: %s", tables[i], err);
			sqlite3_free(err);
			sqlite3_close(db);
			return false;
		}
	}

	// Detach the FTL database from the in-memory database
	if(sqlite3_exec(db, "DETACH DATABASE 'disk';", NULL, NULL, &err) != SQLITE_OK)
	{
		log_warn("Failed to detach FTL database from in-memory database: %s", err);
		sqlite3_free(err);
		sqlite3_close(db);
		return false;
	}

	// Serialize the in-memory database to a buffer
	// The sqlite3_serialize(D,S,P,F) interface returns a pointer to memory that
	// is a serialization of the S database on database connection D. If P is
	// not a NULL pointer, then the size of the database in bytes is written
	// into *P.
	// For an ordinary on-disk database file, the serialization is just a copy
	// of the disk file. For an in-memory database or a "TEMP" database, the
	// serialization is the same sequence of bytes which would be written to
	// disk if that database where backed up to disk.
	// The usual case is that sqlite3_serialize() copies the serialization of
	// the database into memory obtained from sqlite3_malloc64() and returns a
	// pointer to that memory. The caller is responsible for freeing the
	// returned value to avoid a memory leak.
	sqlite3_int64 isize = 0;
	*buffer = sqlite3_serialize(db, "main", &isize, 0);
	*size = isize;
	if(*buffer == NULL)
	{
		log_warn("Failed to serialize in-memory database to buffer: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return false;
	}

	// Close the in-memory database
	sqlite3_close(db);

	return true;
}

const char *generate_teleporter_zip(mz_zip_archive *zip, char filename[128], void **ptr, size_t *size)
{
	// Initialize ZIP archive
	memset(zip, 0, sizeof(*zip));

	// Start with 64KB allocation size (pihole.TOML is slightly larger than 32KB
	// at the time of writing thjs)
	if(!mz_zip_writer_init_heap(zip, 0, 64*1024))
	{
		return "Failed creating heap ZIP archive";
	}

	// Add pihole.toml to the ZIP archive
	const char *file_comment = "Pi-hole's configuration";
	const char *file_path = GLOBALTOMLPATH;
	if(!mz_zip_writer_add_file(zip, file_path+1, file_path, file_comment, (uint16_t)strlen(file_comment), MZ_BEST_COMPRESSION))
	{
		mz_zip_writer_end(zip);
		return "Failed to add "GLOBALTOMLPATH" to heap ZIP archive!";
	}

	// Add /etc/hosts to the ZIP archive
	file_comment = "System's HOSTS file";
	file_path = "/etc/hosts";
	if(!mz_zip_writer_add_file(zip, file_path+1, file_path, file_comment, (uint16_t)strlen(file_comment), MZ_BEST_COMPRESSION))
	{
		mz_zip_writer_end(zip);
		return "Failed to add /etc/hosts to heap ZIP archive!";
	}

	// Add /etc/pihole/dhcp.lease to the ZIP archive if it exists
	file_comment = "DHCP leases file";
	file_path = "/etc/pihole/dhcp.leases";
	if(file_exists(file_path) && !mz_zip_writer_add_file(zip, file_path+1, file_path, file_comment, (uint16_t)strlen(file_comment), MZ_BEST_COMPRESSION))
	{
		mz_zip_writer_end(zip);
		return "Failed to add /etc/hosts to heap ZIP archive!";
	}

	const char *directory = "/etc/dnsmasq.d";
	if(directory_exists(directory))
	{
		// Loop over all files and add them to the ZIP archive
		DIR *dir;
		if((dir = opendir(directory)) != NULL)
		{
			// Loop over all files in the directory
			struct dirent *ent;
			while((ent = readdir(dir)) != NULL)
			{
				// Skip "." and ".."
				if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
					continue;

				// Construct full path to file
				char fullpath[128] = "";
				snprintf(fullpath, 128, "%s/%s", directory, ent->d_name);

				// Add file to ZIP archive
				file_comment = "dnsmasq configuration file";
				file_path = fullpath;

				if(!mz_zip_writer_add_file(zip, file_path+1, file_path, file_comment, (uint16_t)strlen(file_comment), MZ_BEST_COMPRESSION))
					continue;
			}
			closedir(dir);
		}
	}

	// Add (a reduced version of) the gravity database to the ZIP archive
	void *dbbuf = NULL;
	size_t dbsize = 0u;
	if(create_teleporter_database(config.files.gravity.v.s, gravity_tables, ArraySize(gravity_tables), &dbbuf, &dbsize))
	{
		// Add gravity database to ZIP archive
		file_comment = "Pi-hole's gravity database";
		file_path = config.files.gravity.v.s;
		if(file_path[0] == '/')
			file_path++;
		if(!mz_zip_writer_add_mem_ex(zip, file_path, dbbuf, dbsize, file_comment, (uint16_t)strlen(file_comment), MZ_BEST_COMPRESSION, 0, 0))
		{
			sqlite3_free(dbbuf);
			mz_zip_writer_end(zip);
			return "Failed to add gravity database to heap ZIP archive!";
		}
		sqlite3_free(dbbuf);
	}
	else
	{
		mz_zip_writer_end(zip);
		return "Failed to create gravity database for heap ZIP archive!";
	}

	if(create_teleporter_database(config.files.database.v.s, ftl_tables, ArraySize(ftl_tables), &dbbuf, &dbsize))
	{
		// Add FTL database to ZIP archive
		file_comment = "Pi-hole's FTL database";
		file_path = config.files.database.v.s;
		if(file_path[0] == '/')
			file_path++;
		if(!mz_zip_writer_add_mem_ex(zip, file_path, dbbuf, dbsize, file_comment, (uint16_t)strlen(file_comment), MZ_BEST_COMPRESSION, 0, 0))
		{
			sqlite3_free(dbbuf);
			mz_zip_writer_end(zip);
			return "Failed to add FTL database to heap ZIP archive!";
		}
		sqlite3_free(dbbuf);
	}
	else
	{
		mz_zip_writer_end(zip);
		return "Failed to create FTL database for heap ZIP archive!";
	}

	// Get the heap data so we can send it to the requesting client
	if(!mz_zip_writer_finalize_heap_archive(zip, ptr, size))
	{
		mz_zip_writer_end(zip);
		return "Failed to finalize heap ZIP archive!";
	}

	// Verify that the ZIP archive is valid
	mz_zip_error pErr;
	if(!mz_zip_validate_mem_archive(*ptr, *size, MZ_ZIP_FLAG_VALIDATE_LOCATE_FILE_FLAG, &pErr))
	{
		log_err("Failed to validate generated Teleporter ZIP archive: %s",
		        mz_zip_get_error_string(pErr));
		return "Failed to validate generated Teleporter ZIP archive!";
	}

	// Generate filename for ZIP archive (it has both the hostname and the
	// current datetime)
	char timestr[TIMESTR_SIZE] = "";
	get_timestr(timestr, time(NULL), false, true);
	snprintf(filename, 128, "pi-hole_%s_teleporter_%s.zip", hostname(), timestr);

	// Everything worked well
	return NULL;
}

static const char *test_and_import_pihole_toml(void *ptr, size_t size, char * const hint)
{
	// Check if the file is empty
	if(size == 0)
		return "File etc/pihole/pihole.toml in ZIP archive is empty";

	// Create a memory copy that is null-terminated
	char *buffer = calloc(size+1, sizeof(char));
	if(buffer == NULL)
		return "Failed to allocate memory for null-terminated copy of etc/pihole/pihole.toml in ZIP archive";
	memcpy(buffer, ptr, size);
	buffer[size] = '\0';

	// Check if the file is a valid TOML file
	toml_table_t *toml = toml_parse(buffer, hint, ERRBUF_SIZE);
	if(toml == NULL)
	{
		free(buffer);
		return "File etc/pihole/pihole.toml in ZIP archive is not a valid TOML file";
	}
	free(buffer);

	// Check if the file contains a valid configuration for Pi-hole by parsing it into
	// a temporary config struct (teleporter_config)
	struct config teleporter_config = { 0 };
	duplicate_config(&teleporter_config, &config);
	if(!readFTLtoml(NULL, &teleporter_config, toml, true, NULL, 0))
		return "File etc/pihole/pihole.toml in ZIP archive contains invalid TOML configuration";

	// Test dnsmasq config in the imported configuration
	// The dnsmasq configuration will be overwritten if the test succeeds
	if(!write_dnsmasq_config(&teleporter_config, true, hint))
		return "File etc/pihole/pihole.toml in ZIP archive contains invalid dnsmasq configuration";

	// When we reach this point, we know that the file is a valid TOML file and contains
	// a valid configuration for Pi-hole. We can now safely overwrite the current
	// configuration with the one from the ZIP archive

	// Install new configuration
	replace_config(&teleporter_config);

	// Write new pihole.toml to disk, the dnsmaq config was already written above
	// Also write the custom list to disk
	rotate_files(GLOBALTOMLPATH, NULL);
	writeFTLtoml(true);
	write_custom_list();

	return NULL;
}

static const char *import_dhcp_leases(void *ptr, size_t size, char * const hint)
{
	// We do not check if the file is empty here, as an empty dhcp.leases file is valid

	// When we reach this point, we know that the file is a valid dhcp.leases file.
	// We can now safely overwrite the current dhcp.leases file with the one from the ZIP archive
	// Nevertheless, we rotate the current dhcp.leases file to keep a backup of the previous version

	// Rotate current dhcp.leases file
	rotate_files(DHCPLEASESFILE, NULL);

	// Write new dhcp.leases file to disk
	FILE *fp = fopen(DHCPLEASESFILE, "w");
	if(fp == NULL)
	{
		strncpy(hint, strerror(errno), ERRBUF_SIZE);
		return "Failed to open dhcp.leases file for writing";
	}
	if(fwrite(ptr, 1, size, fp) != size)
	{
		strncpy(hint, strerror(errno), ERRBUF_SIZE);
		fclose(fp);
		return "Failed to write to dhcp.leases file";
	}
	fclose(fp);

	return NULL;
}

static const char *test_and_import_database(void *ptr, size_t size, const char *destination,
                                            const char **tables, const size_t num_tables,
                                            char * const hint)
{
	// Check if the file is empty
	// The first 100 bytes of the database file comprise the database file header.
	// See https://www.sqlite.org/fileformat.html, section 1.3
	if(size < 100)
	{
		return "File etc/pihole/gravity.db in ZIP archive is empty";
	}

	// Check file header to see if this is a SQLite3 database file
	// Every valid SQLite database file begins with the following 16 bytes (in
	// hex): 53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00. This byte sequence
	// corresponds to the UTF-8 string "SQLite format 3" including the nul
	// terminator character at the end. The nul terminator character is not
	// included in the 16 bytes of the header.
	// See https://www.sqlite.org/fileformat.html, section 1.3.1
	if(memcmp(ptr, "SQLite format 3", 15) != 0)
	{
		return "File etc/pihole/gravity.db in ZIP archive is not a SQLite3 database file (no header)";
	}

	// Check if the file is a valid SQlite3 database
	// We do this by trying to deserialize the file into a SQLite3 database
	// object. If this fails, the file is not a valid SQlite3 database.
	sqlite3 *database = NULL;
	if(sqlite3_open_v2(":memory:", &database, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		strncpy(hint, sqlite3_errmsg(database), ERRBUF_SIZE);
		return "Failed to open temporary SQLite3 database";
	}
	if(sqlite3_deserialize(database, "main", ptr, size, size, SQLITE_DESERIALIZE_READONLY) != SQLITE_OK)
	{
		strncpy(hint, sqlite3_errmsg(database), ERRBUF_SIZE);
		return "File etc/pihole/gravity.db in ZIP archive is not a valid SQLite3 database file";
	}

	// Run PRAGMA integrity_check on the database to check if the database is
	// valid. If the database is valid, the result of the PRAGMA integrity_check
	// is "ok". If the database is invalid, the result of the PRAGMA
	// integrity_check is a string describing the error.
	// See https://www.sqlite.org/pragma.html#pragma_integrity_check
	sqlite3_stmt *statement = NULL;
	if(sqlite3_prepare_v2(database, "PRAGMA integrity_check;", -1, &statement, NULL) != SQLITE_OK)
	{
		strncpy(hint, sqlite3_errmsg(database), ERRBUF_SIZE);
		sqlite3_finalize(statement);
		sqlite3_close(database);
		return "Failed to prepare PRAGMA integrity_check statement";
	}
	if(sqlite3_step(statement) != SQLITE_ROW)
	{
		strncpy(hint, sqlite3_errmsg(database), ERRBUF_SIZE);
		sqlite3_finalize(statement);
		sqlite3_close(database);
		return "Failed to execute PRAGMA integrity_check statement";
	}
	if(strcmp((const char *)sqlite3_column_text(statement, 0), "ok") != 0)
	{
		strncpy(hint, (const char *)sqlite3_column_text(statement, 0), ERRBUF_SIZE);
		sqlite3_finalize(statement);
		sqlite3_close(database);
		return "Database file in ZIP archive is not a valid SQLite3 database (integrity check failed)";
	}
	// Finalize statement
	sqlite3_finalize(statement);

	// When we reach this point, we know that the file is a valid SQLite3 database

	// ATTACH the database file to the in-memory database
	char *err = NULL;
	char attach_stmt[128] = "";
	snprintf(attach_stmt, sizeof(attach_stmt), "ATTACH DATABASE '%s' AS disk;", destination);
	if(sqlite3_exec(database, attach_stmt, NULL, NULL, &err) != SQLITE_OK)
	{
		strncpy(hint, err, ERRBUF_SIZE);
		sqlite3_free(err);
		sqlite3_close(database);
		return "Failed to attach database file to in-memory SQLite3 database";
	}

	// Disable foreign key checks for import
	if(sqlite3_exec(database, "PRAGMA foreign_keys = 0;", NULL, NULL, &err) != SQLITE_OK)
	{
		strncpy(hint, err, ERRBUF_SIZE);
		sqlite3_free(err);
		sqlite3_close(database);
		return "Failed to disable foreign key checks for import";
	}

	// Start transaction
	if(sqlite3_exec(database, "BEGIN TRANSACTION;", NULL, NULL, &err) != SQLITE_OK)
	{
		strncpy(hint, err, ERRBUF_SIZE);
		sqlite3_free(err);
		sqlite3_close(database);
		return "Failed to start transaction";
	}

	// Loop over the tables
	for(unsigned int i = 0; i < num_tables; i++)
	{
		char stmt[256] = "";
		// Delete all rows in the disk table
		snprintf(stmt, sizeof(stmt), "DELETE FROM disk.\"%s\";", tables[i]);
		if(sqlite3_exec(database, stmt, NULL, NULL, &err) != SQLITE_OK)
		{
			strncpy(hint, err, ERRBUF_SIZE);
			sqlite3_free(err);
			sqlite3_close(database);
			return "Failed to delete from disk database table";
		}

		// Store the table in the disk database
		// We have to use INSERT OR REPLACE here, because the gravity database
		// has several triggers, e.g., immediately recreating the default group
		// on (accidental) deletion. This would cause the import to fail due to
		// a unique constraint violation.
		snprintf(stmt, sizeof(stmt), "INSERT OR REPLACE INTO disk.\"%s\" SELECT * FROM \"%s\";", tables[i], tables[i]);
		if(sqlite3_exec(database, stmt, NULL, NULL, &err) != SQLITE_OK)
		{
			strncpy(hint, err, ERRBUF_SIZE);
			sqlite3_free(err);
			sqlite3_close(database);
			return "Failed to insert into disk database table";
		}

		log_debug(DEBUG_DATABASE, "Replaced table %s in %s", tables[i], destination);
	}

	// End transaction
	if(sqlite3_exec(database, "END TRANSACTION;", NULL, NULL, &err) != SQLITE_OK)
	{
		strncpy(hint, err, ERRBUF_SIZE);
		sqlite3_free(err);
		sqlite3_close(database);
		return "Failed to end transaction";
	}

	// Detach the database file from the in-memory database
	if(sqlite3_exec(database, "DETACH DATABASE disk;", NULL, NULL, &err) != SQLITE_OK)
	{
		strncpy(hint, err, ERRBUF_SIZE);
		sqlite3_free(err);
		sqlite3_close(database);
		return "Failed to detach database file from in-memory SQLite3 database";
	}

	// Close the database
	sqlite3_close(database);

	// Add event to reload gravity database
	set_event(RELOAD_GRAVITY);

	return NULL;
}

const char *read_teleporter_zip(uint8_t *buffer, const size_t buflen, char * const hint, cJSON *import, cJSON *imported_files)
{
	// Initialize ZIP archive
	mz_zip_archive zip = { 0 };
	memset(&zip, 0, sizeof(zip));

	log_debug(DEBUG_CONFIG, "Reading ZIP archive from memory buffer (size %zu)", buflen);

	// Open ZIP archive from memory buffer
	if(!mz_zip_reader_init_mem(&zip, buffer, buflen, 0))
	{
		strncpy(hint, mz_zip_get_error_string(mz_zip_get_last_error(&zip)), ERRBUF_SIZE);
		return "Failed to parse received ZIP archive";
	}

	// Loop over all files in the ZIP archive
	for(mz_uint i = 0; i < mz_zip_reader_get_num_files(&zip); i++)
	{
		// Get file information
		mz_zip_archive_file_stat file_stat;
		if(!mz_zip_reader_file_stat(&zip, i, &file_stat))
		{
			log_warn("Failed to get file information for file %u in ZIP archive: %s",
			         i, mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
			continue;
		}

		// Check if this file is one of the files we want to extract and process
		bool extract = false;
		for(size_t j = 0; j < ArraySize(extract_files); j++)
		{
			if(strcmp(file_stat.m_filename, extract_files[j]) == 0)
			{
				extract = true;
				break;
			}
		}
		if(!extract)
			continue;

		// Read file into its dedicated memory buffer
		void *ptr = malloc(file_stat.m_uncomp_size);
		if(ptr == NULL)
		{
			log_warn("Failed to allocate memory for file %u (%s) in ZIP archive: %s",
			         i, file_stat.m_filename, mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
			continue;
		}
		if(!mz_zip_reader_extract_to_mem(&zip, i, ptr, file_stat.m_uncomp_size, 0))
		{
			log_warn("Failed to read file %u (%s) in ZIP archive: %s",
			         i, file_stat.m_filename, mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
			free(ptr);
			continue;
		}

		log_debug(DEBUG_CONFIG, "Processing file %u (%s) in ZIP archive (%zu/%zu bytes, comment: \"%s\", timestamp: %lu)",
		          i, file_stat.m_filename, (size_t)file_stat.m_comp_size, (size_t)file_stat.m_uncomp_size,
		          file_stat.m_comment, (unsigned long)file_stat.m_time);

		// Process file
		// Is this "etc/pihole/pihole.toml" ?
		if(strcmp(file_stat.m_filename, extract_files[0]) == 0)
		{
			// Check whether we should import this file
			if(import != NULL && !JSON_KEY_TRUE(import, "config"))
			{
				log_info("Ignoring file %s in Teleporter archive (not in import list)", file_stat.m_filename);
				free(ptr);
				continue;
			}

			// Import Pi-hole configuration
			memset(hint, 0, ERRBUF_SIZE);
			const char *err = test_and_import_pihole_toml(ptr, file_stat.m_uncomp_size, hint);
			if(err != NULL)
			{
				free(ptr);
				return err;
			}
			log_debug(DEBUG_CONFIG, "Imported Pi-hole configuration: %s", file_stat.m_filename);
		}
		// Is this "etc/pihole/dhcp.leases"?
		else if(strcmp(file_stat.m_filename, extract_files[1]) == 0)
		{
			// Check whether we should import this file
			if(import != NULL && !JSON_KEY_TRUE(import, "dhcp_leases"))
			{
				log_info("Ignoring file %s in Teleporter archive (not in import list)", file_stat.m_filename);
				free(ptr);
				continue;
			}

			// Import DHCP leases
			memset(hint, 0, ERRBUF_SIZE);
			const char *err = import_dhcp_leases(ptr, file_stat.m_uncomp_size, hint);
			if(err != NULL)
			{
				free(ptr);
				return err;
			}
			log_debug(DEBUG_CONFIG, "Imported DHCP leases: %s", file_stat.m_filename);
		}
		// Is this "etc/pihole/gravity.db"?
		else if(strcmp(file_stat.m_filename, extract_files[2]) == 0)
		{
			// Check whether we should import this file
			if(import != NULL && !cJSON_HasObjectItem(import, "gravity"))
			{
				log_info("Ignoring file %s in Teleporter archive (not in import list)", file_stat.m_filename);
				free(ptr);
				continue;
			}

			const char *import_tables[ArraySize(gravity_tables)] = { NULL };
			size_t num_tables = 0u;
			if(import == NULL)
			{
				// Import all tables
				num_tables = ArraySize(gravity_tables);
				memcpy(import_tables, gravity_tables, sizeof(gravity_tables));
			}
			else
			{
				// Get object at import.gravity
				cJSON *import_gravity = cJSON_GetObjectItem(import, "gravity");

				// Check if import.gravity is a JSON object
				if(import_gravity == NULL || !cJSON_IsObject(import_gravity))
				{
					log_warn("Ignoring file %s in Teleporter archive (import.gravity is not a JSON object)", file_stat.m_filename);
					free(ptr);
					continue;
				}

				// Import selected tables
				for(size_t j = 0; j < ArraySize(gravity_tables); j++)
				{
					if(JSON_KEY_TRUE(import, gravity_tables[j]))
						import_tables[num_tables++] = gravity_tables[j];
				}
			}

			// Import gravity database
			memset(hint, 0, ERRBUF_SIZE);
			const char *err = test_and_import_database(ptr, file_stat.m_uncomp_size, config.files.gravity.v.s,
			                                           import_tables, num_tables, hint);
			if(err != NULL)
			{
				free(ptr);
				return err;
			}
			log_debug(DEBUG_CONFIG, "Imported database: %s", file_stat.m_filename);
		}
		else
		{
			log_warn("Ignoring file %s in Teleporter archive", file_stat.m_filename);
			free(ptr);
			continue;
		}

		// Add filename of processed files to JSON array
		if(imported_files != NULL && !cJSON_AddItemToArray(imported_files, cJSON_CreateString(file_stat.m_filename)))
			log_warn("Failed to add file %s to JSON array", file_stat.m_filename);

		// Free allocated memory
		free(ptr);
	}

	// Close ZIP archive
	mz_zip_reader_end(&zip);

	// Everything worked well
	return NULL;
}

bool free_teleporter_zip(mz_zip_archive *zip)
{
	return mz_zip_writer_end(zip);
}

bool write_teleporter_zip_to_disk(void)
{
	// Generate in-memory ZIP file
	mz_zip_archive zip = { 0 };
	void *ptr = NULL;
	size_t size = 0u;
	char filename[128] = "";
	const char *error = generate_teleporter_zip(&zip, filename, &ptr, &size);
	if(error != NULL)
	{
		log_err("Failed to create Teleporter ZIP file: %s", error);
		return false;
	}

	// Write file to disk
	FILE *fp = fopen(filename, "w");
	if(fp == NULL)
	{
		log_err("Failed to open %s for writing: %s", filename, strerror(errno));
		free_teleporter_zip(&zip);
		return false;
	}
	if(fwrite(ptr, 1, size, fp) != size)
	{
		log_err("Failed to write %zu bytes to %s: %s", size, filename, strerror(errno));
		free_teleporter_zip(&zip);
		fclose(fp);
		return false;
	}
	fclose(fp);

	// Free allocated ZIP memory
	free_teleporter_zip(&zip);

	/* Output filename on successful creation */
	log_info("%s", filename);

	return true;
}

#define MAX_TELEPORTER_ZIP_SIZE (size_t)(128*1024*1024) // 128 MiB

bool read_teleporter_zip_from_disk(const char *filename)
{
	// Open ZIP archive
	FILE *fp = fopen(filename, "r");
	if(fp == NULL)
	{
		log_err("Failed to open %s for reading: %s",
		        filename, strerror(errno));
		return false;
	}

	// Get ZIP archive size
	fseek(fp, 0, SEEK_END);
	const size_t size = (size_t)ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if(size > MAX_TELEPORTER_ZIP_SIZE)
	{
		log_err("ZIP archive %s is too large (%zu bytes, max. %zu bytes)",
		        filename, size, MAX_TELEPORTER_ZIP_SIZE);
		fclose(fp);
		return false;
	}

	// Read ZIP archive to memory
	void *ptr = calloc(size, sizeof(char));
	if(fread(ptr, 1, size, fp) != size)
	{
		log_err("Failed to read %zu bytes from %s: %s",
		        size, filename, strerror(errno));
		fclose(fp);
		free(ptr);
		return false;
	}
	fclose(fp);

	// Process ZIP archive
	char hint[ERRBUF_SIZE] = "";
	cJSON *imported_files = cJSON_CreateArray();
	const char *error = read_teleporter_zip(ptr, size, hint, NULL, imported_files);

	if(error != NULL)
	{
		log_err("Failed to read Teleporter ZIP file: %s", error);
		log_err("Hint: %s", hint);
		cJSON_Delete(imported_files);
		free(ptr);
		return false;
	}

	// Output imported files
	for(cJSON *file = imported_files->child; file != NULL; file = file->next)
		log_info("Imported %s", file->valuestring);

	return true;
}
