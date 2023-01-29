/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  File operation routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "files.h"
#include "config/config.h"
#include "setupVars.h"
#include "log.h"

// opendir(), readdir()
#include <dirent.h>
// getpwuid()
#include <pwd.h>
// getgrgid()
#include <grp.h>
// NAME_MAX
#include <limits.h>
// statvfs()
#include <sys/statvfs.h>
// dirname()
#include <libgen.h>
// compression functions
#include "zip/gzip.h"

#define BACKUP_DIR "/etc/pihole/config_backups"

// chmod_file() changes the file mode bits of a given file (relative
// to the directory file descriptor) according to mode. mode is an
// octal number representing the bit pattern for the new mode bits
bool chmod_file(const char *filename, const mode_t mode)
{
	if(chmod(filename, mode) < 0)
	{
		log_warn("chmod(%s, %u): chmod() failed: %s",
		         filename, mode, strerror(errno));
		return false;
	}

	struct stat st;
	if(stat(filename, &st) < 0)
	{
		log_warn("chmod(%s, %u): stat() failed: %s",
		         filename, mode, strerror(errno));
		return false;
	}

	// We need to apply a bitmask on st.st_mode as the upper bits may contain random data
	// 0x1FF = 0b111_111_111 corresponding to the three-digit octal mode number
	if((st.st_mode & 0x1FF) != mode)
	{
		log_warn("chmod(%s, %u): Verification failed, %u != %u",
		         filename, mode, st.st_mode, mode);
		return false;
	}

	return true;
}

/**
 * Function to check whether a file exists or not.
 * It returns true if given path is a file and exists
 * otherwise returns false.
 */
bool file_exists(const char *filename)
{
	struct stat stats = { 0 };
	if(stat(filename, &stats) != 0)
	{
		// Directory does not exist
		return false;
	}

	// Check if this is a directory
	return S_ISREG(stats.st_mode);
}

/**
 * Function to check whether a directory exists or not.
 * It returns true if given path is a directory and exists
 * otherwise returns false.
 */
bool directory_exists(const char *path)
{
	struct stat stats = { 0 };
	if(stat(path, &stats) != 0)
	{
		// Directory does not exist
		return false;
	}

	// Check if this is a directory
	return S_ISDIR(stats.st_mode);
}

bool get_database_stat(struct stat *st)
{
	if(stat(config.files.database.v.s, st) == 0)
		return true;

	log_err("Cannot stat %s: %s", config.files.database.v.s, strerror(errno));
	return false;
}

unsigned long long get_FTL_db_filesize(void)
{
	struct stat st;
	if(get_database_stat(&st))
		return st.st_size;
	return 0llu;
}

void get_permission_string(char permissions[10], struct stat *st)
{
	// Get human-readable format of permissions as known from ls
	snprintf(permissions, 10u,
	         "%s%s%s%s%s%s%s%s%s",
	         st->st_mode & S_IRUSR ? "r":"-",
	         st->st_mode & S_IWUSR ? "w":"-",
	         st->st_mode & S_IXUSR ? "x":"-",
	         st->st_mode & S_IRGRP ? "r":"-",
	         st->st_mode & S_IWGRP ? "w":"-",
	         st->st_mode & S_IXGRP ? "x":"-",
	         st->st_mode & S_IROTH ? "r":"-",
	         st->st_mode & S_IWOTH ? "w":"-",
	         st->st_mode & S_IXOTH ? "x":"-");
}

void ls_dir(const char* path)
{
	// Open directory stream
	DIR* dirp = opendir(path);
	if(dirp == NULL)
	{
		log_warn("opendir(\"%s\") failed with %s", path, strerror(errno));
		return;
	}

	// Stack space for full path (directory + "/" + filename + terminating \0)
	const size_t full_path_len = strlen(path) + NAME_MAX + 2;
	char *full_path = calloc(full_path_len, sizeof(char));

	log_info("------ Listing content of directory %s ------", path);
	log_info("File Mode User:Group      Size  Filename");

	struct dirent *dircontent = NULL;
	// Walk directory file by file
	while((dircontent = readdir(dirp)) != NULL)
	{
		// Get filename
		const char *filename = dircontent->d_name;

		// Construct full path
		snprintf(full_path, full_path_len, "%s/%s", path, filename);

		struct stat st;
		// Use stat to get file size, permissions, and ownership
		if(stat(full_path, &st) < 0)
		{
			log_warn("stat(\"%s\") failed with %s", filename, strerror(errno));
			continue;
		}

		// Get owner's name
		struct passwd *pwd;
		char user[256];
		if ((pwd = getpwuid(st.st_uid)) != NULL)
			snprintf(user, sizeof(user), "%s", pwd->pw_name);
		else
			snprintf(user, sizeof(user), "%u", st.st_uid);

		struct group *grp;
		char usergroup[256];
		// Get out group name
		if ((grp = getgrgid(st.st_gid)) != NULL)
			snprintf(usergroup, sizeof(usergroup), "%s:%s", user, grp->gr_name);
		else
			snprintf(usergroup, sizeof(usergroup), "%s:%u", user, st.st_gid);

		char permissions[10];
		get_permission_string(permissions, &st);

		char prefix[2] = { 0 };
		double formatted = 0.0;
		format_memory_size(prefix, (unsigned long long)st.st_size, &formatted);

		// Log output for this file
		log_info("%s %-15s %3.0f%s  %s", permissions, usergroup, formatted, prefix, filename);
	}

	log_info("---------------------------------------------------");

	// Free memory
	free(full_path);
	full_path = NULL;

	// Close directory stream
	closedir(dirp);
}

unsigned int get_path_usage(const char *path, char buffer[64])
{
	// Get filesystem information about /dev/shm (typically a tmpfs)
	struct statvfs f;
	if(statvfs(path, &f) != 0)
	{
		// If statvfs() failed, we return the error instead
		strncpy(buffer, strerror(errno), 64);
		buffer[63] = '\0';
		return 0;
	}

	// Explicitly cast the block counts to unsigned long long to avoid
	// overflowing with drives larger than 4 GB on 32bit systems
	const unsigned long long size = (unsigned long long)f.f_blocks * f.f_frsize;
	const unsigned long long free = (unsigned long long)f.f_bavail * f.f_bsize;
	const unsigned long long used = size - free;

	// Create human-readable total size
	char prefix_size[2] = { 0 };
	double formatted_size = 0.0;
	format_memory_size(prefix_size, size, &formatted_size);

	// Generate human-readable "total used" size
	char prefix_used[2] = { 0 };
	double formatted_used = 0.0;
	format_memory_size(prefix_used, used, &formatted_used);

	// Print result into buffer passed to this subroutine
	snprintf(buffer, 64, "%s: %.1f%sB used, %.1f%sB total", path,
	         formatted_used, prefix_used, formatted_size, prefix_size);

	// If size is 0, we return 0% to avoid division by zero below
	if(size == 0)
		return 0;
	// If used is larger than size, we return 100%
	if(used > size)
		return 100;
	// Return percentage of used memory at this path (rounded down)
	return (used*100)/(size + 1);
}

unsigned int get_filepath_usage(const char *file, char buffer[64])
{
	if(file == NULL || strlen(file) == 0)
		return -1;

	// Get path from file, we duplicate the string
	// here as dirname() modifies the string inplace
	char path[PATH_MAX] = { 0 };
	strncpy(path, file, sizeof(path)-1);
	path[sizeof(path)-1] = '\0';
	dirname(path);

	// Get percentage of disk usage at this path
	return get_path_usage(path, buffer);
}

// Credits: https://stackoverflow.com/a/55410469
static char *trim(char *str)
{
	char *start = str;
	char *end = str + strlen(str);

	while(*start && isspace(*start))
		start++;

	while(end > start && isspace(*(end - 1)))
		end--;

	*end = '\0';
	return start;
}

// Rotate files in a directory
void rotate_files(const char *path)
{
	// Check if file exists. If not, we don't need to rotate anything here
	if(!file_exists(path))
	{
		log_debug(DEBUG_CONFIG, "rotate_files(): File \"%s\" does not exist, not rotating", path);
		return;
	}

	// Try to create backup directory if it does not exist
	if(!directory_exists(BACKUP_DIR))
		mkdir(BACKUP_DIR, S_IRWXU | S_IRWXG); // mode 0770

	// Rename all files to one number higher
	for(unsigned int i = MAX_ROTATIONS; i > 0; i--)
	{
		// Construct old and new paths
		char *fname = strdup(path);
		const char *filename = basename(fname);
		// extra 6 bytes is enough space for up to 999 rotations ("/", ".", "\0", "999")
		const size_t buflen = strlen(filename) + MAX(strlen(BACKUP_DIR), strlen(path)) + 6;
		char *old_path = calloc(buflen, sizeof(char));
		if(i == 1)
			snprintf(old_path, buflen, "%s", path);
		else
			snprintf(old_path, buflen, BACKUP_DIR"/%s.%u", filename, i-1);
		char *new_path = calloc(buflen, sizeof(char));
		snprintf(new_path, buflen, BACKUP_DIR"/%s.%u", filename, i);
		free(fname);

		size_t old_path_len = strlen(old_path) + 4;
		char *old_path_compressed = calloc(old_path_len, sizeof(char));
		snprintf(old_path_compressed, old_path_len, "%s.gz", old_path);

		size_t new_path_len = strlen(new_path) + 4;
		char *new_path_compressed = calloc(new_path_len, sizeof(char));
		snprintf(new_path_compressed, new_path_len, "%s.gz", new_path);

		if(file_exists(old_path))
		{
			// Rename file
			if(rename(old_path, new_path) < 0)
			{
				log_warn("Rotation %s -> %s failed: %s",
				         old_path, new_path, strerror(errno));
			}
			else
			{
				// Log success if debug is enabled
				log_debug(DEBUG_CONFIG, "Rotated %s -> %s",
				          old_path, new_path);
			}

			// Compress file if we are rotating a sufficiently old file
			if(i > ZIP_ROTATIONS)
			{
				log_debug(DEBUG_CONFIG, "Compressing %s -> %s",
				          new_path, new_path_compressed);
				if(deflate_file(new_path, new_path_compressed, false))
				{
					// On success, we remove the uncompressed file
					remove(new_path);
				}
			}
		}
		else if(file_exists(old_path_compressed))
		{
			// Rename file
			if(rename(old_path_compressed, new_path_compressed) < 0)
			{
				log_warn("Rotation %s -> %s failed: %s",
				         old_path_compressed, new_path_compressed, strerror(errno));
			}
			else
			{
				// Log success if debug is enabled
				log_debug(DEBUG_CONFIG, "Rotated %s -> %s",
				          old_path_compressed, new_path_compressed);
			}
		}

		// Free memory
		free(old_path);
		free(new_path);
		free(old_path_compressed);
		free(new_path_compressed);
	}
}

// Credits: https://stackoverflow.com/a/55410469
int parse_line(char *line, char **key, char **value)
{
	char *ptr = strchr(line, '=');
	if (ptr == NULL)
		return -1;

	*ptr++ = '\0';
	*key = trim(line);
	*value = trim(ptr);

	return 0;
}
