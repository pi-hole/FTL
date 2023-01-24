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