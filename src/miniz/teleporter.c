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
#include "miniz/teleporter.h"
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

// Tables to copy from the gravity database to the Teleporter database
static const char *gravity_tables[] = {
	"info",
	"group",
	"adlist",
	"adlist_by_group",
	"domainlist",
	"domainlist_by_group",
	"client",
	"client_by_group",
	"domain_audit"
};

// Create a reduced gravity database in memory and return a memory pointer to it
static bool create_teleporter_gravity(void **buffer, size_t *size)
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

	snprintf(attach_stmt, sizeof(attach_stmt), "ATTACH DATABASE '%s' AS \"gravity\";", config.files.gravity.v.s);

	if(sqlite3_exec(db, attach_stmt, NULL, NULL, &err) != SQLITE_OK)
	{
		log_warn("Failed to attach FTL database to in-memory database: %s", err);
		sqlite3_free(err);
		sqlite3_close(db);
		return "Failed to attach FTL database to in-memory database!";
	}

	// Loop over the tables and copy them to the in-memory database
	for(unsigned int i = 0; i < ArraySize(gravity_tables); i++)
	{
		char *err = NULL;
		char create_stmt[128] = "";

		// Create in-memory table copy
		snprintf(create_stmt, sizeof(create_stmt), "CREATE TABLE \"%s\" AS SELECT * FROM gravity.\"%s\";", gravity_tables[i], gravity_tables[i]);
		if(sqlite3_exec(db, create_stmt, NULL, NULL, &err) != SQLITE_OK)
		{
			log_warn("Failed to create %s in in-memory database: %s", gravity_tables[i], err);
			sqlite3_free(err);
			sqlite3_close(db);
			return false;
		}
	}

	// Detach the FTL database from the in-memory database
	if(sqlite3_exec(db, "DETACH DATABASE 'gravity';", NULL, NULL, &err) != SQLITE_OK)
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

const char *generate_teleporter_zip(mz_zip_archive *zip, char filename[128], void *ptr, size_t *size)
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
		struct dirent *ent;
		if((dir = opendir(directory)) != NULL)
		{
			// Loop over all files in the directory
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
	if(create_teleporter_gravity(&dbbuf, &dbsize))
	{
		// Add gravity database to ZIP archive
		file_comment = "Pi-hole's gravity database";
		file_path = "/etc/pihole/gravity.db";
		if(!mz_zip_writer_add_mem(zip, file_path+1, dbbuf, dbsize, MZ_BEST_COMPRESSION))
		{
			sqlite3_free(dbbuf);
			mz_zip_writer_end(zip);
			return "Failed to add gravity.db to heap ZIP archive!";
		}

		sqlite3_free(dbbuf);
	}
	else
	{
		mz_zip_writer_end(zip);
		return "Failed to create gravity.db for heap ZIP archive!";
	}

	// Get the heap data so we can send it to the requesting client
	if(!mz_zip_writer_finalize_heap_archive(zip, ptr, size))
	{
		mz_zip_writer_end(zip);
		return "Failed to finalize heap ZIP archive!";
	}

	char timestr[TIMESTR_SIZE] = "";
	get_timestr(timestr, time(NULL), false, true);
	snprintf(filename, 128, "pi-hole_%s_teleporter_%s.zip", hostname(), timestr);

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
		return false;
	}
	fclose(fp);

	// Free allocated ZIP memory
	free_teleporter_zip(&zip);

	/* Output filename on successful creation */
	log_info("%s", filename);

	return true;
}