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
#include "miniz/miniz.h"

static bool compress_file(const char *in, const char* out);

// chmod_file() changes the file mode bits of a given file (relative
// to the directory file descriptor) according to mode. mode is an
// octal number representing the bit pattern for the new mode bits
bool chmod_file(const char *filename, const mode_t mode)
{
	if(chmod(filename, mode) < 0)
	{
		log_warn("chmod(%s, %d): chmod() failed: %s",
		         filename, mode, strerror(errno));
		return false;
	}

	struct stat st;
	if(stat(filename, &st) < 0)
	{
		log_warn("chmod(%s, %d): stat() failed: %s",
		         filename, mode, strerror(errno));
		return false;
	}

	// We need to apply a bitmask on st.st_mode as the upper bits may contain random data
	// 0x1FF = 0b111_111_111 corresponding to the three-digit octal mode number
	if((st.st_mode & 0x1FF) != mode)
	{
		log_warn("chmod(%s, %d): Verification failed, %d != %d",
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
	char full_path[strlen(path)+NAME_MAX+2];

	log_info("------ Listing content of directory %s ------", path);
	log_info("File Mode User:Group      Size  Filename");

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
			log_warn("stat(\"%s\") failed with %s", filename, strerror(errno));
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
		get_permission_string(permissions, &st);

		char prefix[2] = { 0 };
		double formatted = 0.0;
		format_memory_size(prefix, (unsigned long long)st.st_size, &formatted);

		// Log output for this file
		log_info("%s %-15s %3.0f%s  %s", permissions, usergroup, formatted, prefix, filename);
	}

	log_info("---------------------------------------------------");

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
	// Rename all files to one number higher
	for(unsigned int i = MAX_ROTATIONS; i > 0; i--)
	{
		// Construct old and new paths
		char old_path[strlen(path) + 4];
		if(i == 1)
			snprintf(old_path, sizeof(old_path), "%s", path);
		else
			snprintf(old_path, sizeof(old_path), "%s.%u", path, i-1);
		char new_path[strlen(old_path) + 4];
		snprintf(new_path, sizeof(new_path), "%s.%u", path, i);

		char old_path_compressed[strlen(old_path) + 4];
		snprintf(old_path_compressed, sizeof(old_path_compressed), "%s.gz", old_path);

		char new_path_compressed[strlen(new_path) + 4];
		snprintf(new_path_compressed, sizeof(new_path_compressed), "%s.gz", new_path);

		if(file_exists(old_path))
		{
			// Rename file
			if(rename(old_path, new_path) < 0)
			{
				if(i == 1)
					log_warn("Rotation %s{ -> .%u} failed: %s (%d)",
					         path, i, strerror(errno), errno);
				else
					log_warn("Rotation %s.{%u -> %u} failed: %s (%d)",
					         path, i-1, i, strerror(errno), errno);
			}
			else
			{
				// Log success if debug is enabled
				if(i == 1)
					log_debug(DEBUG_CONFIG, "Rotated %s{ -> .%u}",
					          path, i);
				else
					log_debug(DEBUG_CONFIG, "Rotated %s.{%u -> %u}",
					          path, i-1, i);
			}

			// Compress file if we are rotating a sufficiently old file
			if(i > ZIP_ROTATIONS)
			{
				if(i == 1)
					log_debug(DEBUG_CONFIG, "Compressing %s{ -> .%u.gz}",
					          path, i);
				else
					log_debug(DEBUG_CONFIG, "Compressing %s.{%u -> %u.gz}",
					          path, i-1, i);
				if(compress_file(new_path, new_path_compressed))
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
				if(i == 1)
					log_warn("Rotation %s{ -> .%u}.gz failed: %s (%d)",
					         path, i, strerror(errno), errno);
				else
					log_warn("Rotation %s.{%u -> %u}.gz failed: %s (%d)",
					         path, i-1, i, strerror(errno), errno);
			}
			else
			{
				// Log success if debug is enabled
				if(i == 1)
					log_debug(DEBUG_CONFIG, "Rotated %s{ -> .%u}.gz",
					          path, i);
				else
					log_debug(DEBUG_CONFIG, "Rotated %s.{%u -> %u}.gz",
					          path, i-1, i);
			}
		}
	}
}

static bool compress_file(const char *in, const char *out)
{
	// Read entire file into memory
	FILE *fp = fopen(in, "rb");
	if(fp == NULL)
	{
		log_warn("compress_file(): failed to open %s: %s (%d)", in, strerror(errno), errno);
		return false;
	}

	// Get file size
	fseek(fp, 0, SEEK_END);
	const mz_ulong size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Read file into memory
	unsigned char *buffer = malloc(size);
	if(buffer == NULL)
	{
		log_warn("compress_file(): failed to allocate %lu bytes of memory", (unsigned long)size);
		fclose(fp);
		return false;
	}
	if(fread(buffer, 1, size, fp) != size)
	{
		log_warn("compress_file(): failed to read %lu bytes from %s", (unsigned long)size, in);
		fclose(fp);
		free(buffer);
		return false;
	}
	fclose(fp);

	// Allocate memory for compressed file
	// (compressBound() returns the maximum size of the compressed data)
	mz_ulong size_compressed = compressBound(size);
	unsigned char *buffer_compressed = malloc(size_compressed);
	if(buffer_compressed == NULL)
	{
		log_warn("compress_file(): failed to allocate %lu bytes of memory", (unsigned long)size_compressed);
		free(buffer);
		return false;
	}

	// Compress file (ZLIB stream format - not GZIP! - see https://tools.ietf.org/html/rfc1950)
	int ret = compress2(buffer_compressed, &size_compressed, buffer, size, Z_BEST_COMPRESSION);
	if(ret != Z_OK)
	{
		log_warn("compress_file(): failed to compress %s: %s (%d)", in, zError(ret), ret);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Create compressed file
	fp = fopen(out, "wb");
	if(fp == NULL)
	{
		log_warn("compress_file(): failed to open %s: %s (%d)", out, strerror(errno), errno);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Generate GZIP header (without timestamp and extra flags)
	// (see https://tools.ietf.org/html/rfc1952#section-2.3)
	//
	//   0   1   2   3   4   5   6   7   8   9
	// +---+---+---+---+---+---+---+---+---+---+
	// |ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
	// +---+---+---+---+---+---+---+---+---+---+
	//
	// 1F8B: magic number
	// 08: compression method (deflate)
	// 01: flags (FTEXT is set)
	// 00000000: timestamp (set later). For simplicity, we set it to the current time
	// 02: extra flags (maximum compression)
	// 03: operating system (Unix)
	const unsigned char gzip_header[] = { 0x1F, 0x8B, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03 };
	// Set timestamp
	uint32_t now = htole32(time(NULL));
	memcpy((void*)(gzip_header+4), &now, sizeof(now));
	// Write header
	if(fwrite(gzip_header, 1, sizeof(gzip_header), fp) != sizeof(gzip_header))
	{
		log_warn("compress_file(): failed to write GZIP header to %s", out);
		fclose(fp);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Write compressed data, strip ZLIB header (first two bytes) and footer (last four bytes)
	// +=======================+
	// |...compressed blocks...| (more-->)
	// +=======================+
	if(fwrite(buffer_compressed + 2, 1, size_compressed - (2 + 4), fp) != size_compressed-6)
	{
		log_warn("compress_file(): failed to write %lu bytes to %s", (unsigned long)size_compressed, out);
		fclose(fp);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Write GZIP footer (CRC32 and uncompressed size)
	// (see https://tools.ietf.org/html/rfc1952#section-2.3)
	//
	//   0   1   2   3   4   5   6   7
	// +---+---+---+---+---+---+---+---+
	// |     CRC32     |     ISIZE     |
	// +---+---+---+---+---+---+---+---+
	//
	// CRC32: This contains a Cyclic Redundancy Check value of the
	//        uncompressed data computed according to CRC-32 algorithm used in
	//        the ISO 3309 standard and in section 8.1.1.6.2 of ITU-T
	//        recommendation V.42.  (See http://www.iso.ch for ordering ISO
	//        documents. See gopher://info.itu.ch for an online version of
	//        ITU-T V.42.)
	// isize: This contains the size of the original (uncompressed) input
	//        data modulo 2^32 (little endian).
	uint32_t crc = mz_crc32(MZ_CRC32_INIT, buffer, size);
	uint32_t isize = htole32(size);
	free(buffer);
	if(fwrite(&crc, 1, sizeof(crc), fp) != sizeof(crc))
	{
		log_warn("compress_file(): failed to write CRC32 to %s", out);
		fclose(fp);
		free(buffer_compressed);
		return false;
	}
	if(fwrite(&isize, 1, sizeof(isize), fp) != sizeof(isize))
	{
		log_warn("compress_file(): failed to write isize to %s", out);
		fclose(fp);
		free(buffer_compressed);
		return false;
	}

	fclose(fp);
	free(buffer_compressed);
	return true;
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
