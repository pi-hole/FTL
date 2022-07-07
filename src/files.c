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
#include "config.h"
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

// chmod_file() changes the file mode bits of a given file (relative
// to the directory file descriptor) according to mode. mode is an
// octal number representing the bit pattern for the new mode bits
bool chmod_file(const char *filename, const mode_t mode)
{
	if(chmod(filename, mode) < 0)
	{
		logg("WARNING: chmod(%s, %d): chmod() failed: %s (%d)", filename, mode, strerror(errno), errno);
		return false;
	}

	struct stat st;
	if(stat(filename, &st) < 0)
	{
		logg("WARNING: chmod(%s, %d): stat() failed: %s (%d)", filename, mode, strerror(errno), errno);
		return false;
	}

	// We need to apply a bitmask on st.st_mode as the upper bits may contain random data
	// 0x1FF = 0b111_111_111 corresponding to the three-digit octal mode number
	if((st.st_mode & 0x1FF) != mode)
	{
		logg("WARNING: chmod(%s, %d): Verification failed, %d != %d", filename, mode, st.st_mode, mode);
		return false;
	}

	return true;
}

bool file_exists(const char *filename)
{
	struct stat st;
	return stat(filename, &st) == 0;
}

unsigned long long get_FTL_db_filesize(void)
{
	struct stat st;
	if(stat(FTLfiles.FTL_db, &st) != 0)
	{
		// stat() failed (maybe the DB file does not exist?)
		return 0;
	}
	return st.st_size;
}

void ls_dir(const char* path)
{
	// Open directory stream
	DIR* dirp = opendir(path);
	if(dirp == NULL)
	{
		logg("opendir(\"%s\") failed with %s (%d)", path, strerror(errno), errno);
		return;
	}

	// Stack space for full path (directory + "/" + filename + terminating \0)
	char full_path[strlen(path)+NAME_MAX+2];

	logg("------ Listing content of directory %s ------", path);
	logg("File Mode User:Group      Size  Filename");

	struct dirent *dircontent = NULL;
	// Walk directory file by file
	while((dircontent = readdir(dirp)) != NULL)
	{
		// Get filename
		const char *filename = dircontent->d_name;

		// Construct full path
		snprintf(full_path, sizeof(full_path), "%s/%s", path, filename);

		struct stat st;
		// Use stat to get file size, permissions, and ownership
		if(stat(full_path, &st) < 0)
		{
			logg("%s failed with %s (%d)", filename, strerror(errno), errno);
			continue;
		}

		// Get owner's name
		struct passwd *pwd;
		char user[256];
		if ((pwd = getpwuid(st.st_uid)) != NULL)
			snprintf(user, sizeof(user), "%s", pwd->pw_name);
		else
			snprintf(user, sizeof(user), "%d", st.st_uid);

		struct group *grp;
		char usergroup[256];
		// Get out group name
		if ((grp = getgrgid(st.st_gid)) != NULL)
			snprintf(usergroup, sizeof(usergroup), "%s:%s", user, grp->gr_name);
		else
			snprintf(usergroup, sizeof(usergroup), "%s:%d", user, st.st_gid);

		char permissions[10];
		// Get human-readable format of permissions as known from ls
		snprintf(permissions, sizeof(permissions),
		         "%s%s%s%s%s%s%s%s%s",
		         st.st_mode & S_IRUSR ? "r":"-",
		         st.st_mode & S_IWUSR ? "w":"-",
		         st.st_mode & S_IXUSR ? "x":"-",
		         st.st_mode & S_IRGRP ? "r":"-",
		         st.st_mode & S_IWGRP ? "w":"-",
		         st.st_mode & S_IXGRP ? "x":"-",
		         st.st_mode & S_IROTH ? "r":"-",
		         st.st_mode & S_IWOTH ? "w":"-",
		         st.st_mode & S_IXOTH ? "x":"-");

		char prefix[2] = { 0 };
		double formatted = 0.0;
		format_memory_size(prefix, (unsigned long long)st.st_size, &formatted);

		// Log output for this file
		logg("%s %-15s %3.0f%s  %s", permissions, usergroup, formatted, prefix, filename);
	}

	logg("---------------------------------------------------");

	// Close directory stream
	closedir(dirp);
}

int get_path_usage(const char *path, char buffer[64])
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

	// Return percentage of used shared memory
	// Adding 1 avoids FPE if the size turns out to be zero
	return (used*100)/(size + 1);
}

int get_filepath_usage(const char *file, char buffer[64])
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
