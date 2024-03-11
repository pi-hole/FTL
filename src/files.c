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
#include "config/setupVars.h"
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
// sendfile()
#include <fcntl.h>
#include <sys/sendfile.h>

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

	// Check if this is a regular file
	return S_ISREG(stats.st_mode);
}

/**
 * Function to check whether a file exists and is readable or not.
 */
bool file_readable(const char *filename)
{
	// Check if file exists and is readable
	return access(filename, R_OK) == 0;
}

/**
 * Function to check whether a file is writable or not.
 * This function also returns success when a file does not exist yet but could
 * be created and written to.
 */
bool file_writeable(const char *filename)
{
	// Check if file is writable
	FILE *fp = fopen(filename, "ab");
	if(fp == NULL)
	{
		// File is not writable
		return false;
	}

	// Close file
	fclose(fp);

	// File is writable
	return true;
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
		log_info("%s %-15s %3.0f%s  %s", permissions, usergroup, formatted, strlen(prefix) > 0 ? prefix : " ", filename);
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
	snprintf(buffer, 64, "%.1f%sB used, %.1f%sB total",
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

// Get the filesystem where the given path is located
struct mntent *get_filesystem_details(const char *path)
{
	/* stat the file in question */
	struct stat path_stat;
	stat(path, &path_stat);

	/* iterate through the list of devices */
	FILE *file = setmntent("/proc/mounts", "r");
	struct mntent *ent = NULL;
	while(file != NULL && (ent = getmntent(file)) != NULL)
	{
		/* stat the mount point */
		struct stat dev_stat;
		stat(ent->mnt_dir, &dev_stat);

		/* check if our file and the mount point are on the same device */
		if(dev_stat.st_dev == path_stat.st_dev)
			break;
	}

	endmntent(file);

	return ent;
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

// Credits: https://stackoverflow.com/a/2180157 (modified) for the fallback solution
static int copy_file(const char *source, const char *destination)
{
// Check glibc >= 2.27 for copy_file_range()
#if __GLIBC__ > 2 ||  (__GLIBC__ == 2 && (__GLIBC_MINOR__ >= 27 ))
	int fd_in, fd_out;
	struct stat stat;
	size_t len;
	ssize_t ret;

	fd_in = open(source, O_RDONLY);
	if (fd_in == -1)
	{
		log_warn("copy_file(): Failed to open \"%s\" read-only: %s", source, strerror(errno));
		return -1;
	}

	if (fstat(fd_in, &stat) == -1) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	len = stat.st_size;

	fd_out = open(destination, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd_out == -1)
	{
		log_warn("copy_file(): Failed to open \"%s\" for writing: %s", destination, strerror(errno));
		close(fd_in);
		return -1;
	}

	do {
		ret = copy_file_range(fd_in, NULL, fd_out, NULL, len, 0);
		if (ret == -1) {
			log_warn("copy_file(): Failed to copy file after %zu of %zu bytes: %s", (size_t)stat.st_size - len, (size_t)stat.st_size, strerror(errno));
			close(fd_in);
			close(fd_out);
			return -1;
		}

		len -= ret;
	} while (len > 0 && ret > 0);

	close(fd_in);
	close(fd_out);

	return 0;
#else
	int input, output;
	if ((input = open(source, O_RDONLY)) == -1)
	{
			log_warn("copy_file(): Failed to open \"%s\" read-only: %s", source, strerror(errno));
			return -1;
	}
	if ((output = creat(destination, 0660)) == -1)
	{
			log_warn("copy_file(): Failed to open \"%s\" for writing: %s", destination, strerror(errno));
			close(input);
			return -1;
	}
	// Use sendfile (kernel-space copying as fallback)
	off_t bytesCopied = 0;
	struct stat fileinfo = {0};
	fstat(input, &fileinfo);
	errno = 0;
	const int result = sendfile(output, input, &bytesCopied, fileinfo.st_size);
	if(result == -1)
			log_warn("copy_file(): Failed to copy \"%s\" to \"%s\": %s", source, destination, strerror(errno));
	close(input);
	close(output);

	return result;
#endif
}

// Change ownership of file to pihole user
static bool chown_pihole(const char *path)
{
	// Get pihole user's uid and gid
	struct passwd *pwd = getpwnam("pihole");
	if(pwd == NULL)
	{
		log_warn("chown_pihole(): Failed to get pihole user's uid: %s", strerror(errno));
		return false;
	}
	struct group *grp = getgrnam("pihole");
	if(grp == NULL)
	{
		log_warn("chown_pihole(): Failed to get pihole user's gid: %s", strerror(errno));
		return false;
	}

	// Change ownership of file to pihole user
	if(chown(path, pwd->pw_uid, grp->gr_gid) < 0)
	{
		log_warn("chown_pihole(): Failed to change ownership of \"%s\" to %u:%u: %s",
		         path, pwd->pw_uid, grp->gr_gid, strerror(errno));
		return false;
	}

	return true;
}

// Rotate files in a directory
void rotate_files(const char *path, char **first_file)
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

	// Rename all files to one number higher, except for the original file
	// The original file is *copied* to the backup directory to avoid possible
	// issues with file permissions if the new config cannot be written after
	// the old file has already been moved away
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

		// If this is the first file, export the path to the caller (if
		// requested)
		if(i == 1 && first_file != NULL)
			*first_file = strdup(new_path);

		if(file_exists(old_path))
		{
			// Copy file to backup directory
			if(i == 1)
			{
				// Copy file to backup directory
				log_debug(DEBUG_CONFIG, "Copying %s -> %s", old_path, new_path);
				if(copy_file(old_path, new_path) < 0)
				{
					log_warn("Rotation %s -(COPY)> %s failed",
					         old_path, new_path);
				}
				else
				{
					// Log success if debug is enabled
					log_debug(DEBUG_CONFIG, "Copied %s -> %s",
					          old_path, new_path);
				}
			}
			// Rename file to backup directory
			else if(rename(old_path, new_path) < 0)
			{
				log_warn("Rotation %s -(MOVE)> %s failed: %s",
				         old_path, new_path, strerror(errno));
			}
			else
			{
				// Log success if debug is enabled
				log_debug(DEBUG_CONFIG, "Rotated %s -> %s",
				          old_path, new_path);
			}

			// Change ownership of file to pihole user
			chown_pihole(new_path);
		}

		// Free memory
		free(old_path);
		free(new_path);
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

// Get symlink target
char * __attribute__((malloc)) get_hwmon_target(const char *path)
{
	struct stat sb;

	// Get symlink status
	if(lstat(path, &sb) == -1)
		return NULL;

	// Check if path is a symlink
	if(!S_ISLNK(sb.st_mode))
		return NULL;

	// Allocate buffer
	off_t bufsize = sb.st_size + 1;

	// Some systems do not set st_size for symlinks
	// In this case, we use PATH_MAX
	if(bufsize == 1)
		bufsize = PATH_MAX;

	// Allocate buffer
	char *target = calloc(bufsize, sizeof(char));
	if(target == NULL)
		return NULL;

	// Read symlink target
	const ssize_t nbytes = readlink(path, target, bufsize);
	if(nbytes == -1)
	{
		free(target);
		return NULL;
	}

	// The link target may be relative to the link's parent directory
	// It typically looks like, e.g.
	//
	//   ../../devices/pci0000:00/0000:00:1f.3/hwmon/hwmon0
	//
	// We remove the "../" and "/hwmon/hwmonX" parts so it becomes
	//
	//   devices/pci0000:00/0000:00:1f.3


	// Strip "../" from beginning of string (if present)
	while(nbytes >= 3 && strncmp(target, "../", 3) == 0)
	{
		memmove(target, target + 3, nbytes - 3);
		target[nbytes - 3] = '\0';
	}

	// Strip "/hwmon[...]" from end of string (if present)
	char *hwmon = strstr(target, "/hwmon");
	if(hwmon != NULL)
		*hwmon = '\0';

	// Ensure that the string is null-terminated
	target[nbytes] = '\0';

	return target;
}

// Returns true if the files have different contents
// from specifies from which line number the files should be compared
bool files_different(const char *pathA, const char* pathB, unsigned int from)
{
	// Check if both files exist
	if(!file_exists(pathA) || !file_exists(pathB))
		return true;

	// Check if both files are identical
	if(strcmp(pathA, pathB) == 0)
		return false;

	// Open both files
	FILE *fpA = fopen(pathA, "r");
	if(fpA == NULL)
	{
		log_warn("files_different(): Failed to open \"%s\" for reading: %s", pathA, strerror(errno));
		return true;
	}
	FILE *fpB = fopen(pathB, "r");
	if(fpB == NULL)
	{
		log_warn("files_different(): Failed to open \"%s\" for reading: %s", pathB, strerror(errno));
		fclose(fpA);
		return true;
	}

	// Compare both files line by line
	char *lineA = NULL, *lineB = NULL;
	size_t lenA = 0, lenB = 0;
	ssize_t readA = 0, readB = 0;
	bool different = false;
	unsigned int lineno = 0;
	while(true)
	{
		// Read lines from both files
		readA = getline(&lineA, &lenA, fpA);
		readB = getline(&lineB, &lenB, fpB);

		// Check if we reached the end of any of the files
		if(readA < 0 || readB < 0)
			break;

		// Skip lines until we reach the requested line number
		if(from > ++lineno)
			continue;

		// Remove possible trailing newline characters
		if(lineA[readA - 1] == '\n')
			lineA[readA - 1] = '\0';
		if(lineB[readB - 1] == '\n')
			lineB[readB - 1] = '\0';

		// Compare lines
		if(strcmp(lineA, lineB) != 0)
		{
			different = true;
			log_debug(DEBUG_CONFIG, "Files %s and %s differ at line %u",
			          pathA, pathB, lineno);
			log_debug(DEBUG_CONFIG, "-> %s:%u = '%s'", pathA, lineno, readA < 0 ? "<EOF>" : lineA);
			log_debug(DEBUG_CONFIG, "-> %s:%u = '%s'", pathB, lineno, readB < 0 ? "<EOF>" : lineB);
			break;
		}
	}

	// Check if one file has more lines than the other
	if(!different && readA != readB)
	{
		different = true;
		log_debug(DEBUG_CONFIG, "Files %s and %s differ at the final line %u",
		          pathA, pathB, lineno);
		log_debug(DEBUG_CONFIG, "-> %s:%u = '%s'", pathA, lineno, readA < 0 ? "<EOF>" : lineA);
		log_debug(DEBUG_CONFIG, "-> %s:%u = '%s'", pathB, lineno, readB < 0 ? "<EOF>" : lineB);
	}

	// Free memory
	free(lineA);
	free(lineB);

	// Close files
	fclose(fpA);
	fclose(fpB);

	// Log result (if not already done above)
	if(!different)
		log_debug(DEBUG_CONFIG, "Files %s and %s are identical (skipped the first %u line%s)",
		          pathA, pathB, from, from == 1 ? "" : "s");

	return different;
}

// Create SHA256 checksum of a file
bool sha256sum(const char *path, uint8_t checksum[SHA256_DIGEST_SIZE])
{
	// Open file
	FILE *fp = fopen(path, "rb");
	if(fp == NULL)
	{
		log_warn("sha256_file(): Failed to open \"%s\" for reading: %s", path, strerror(errno));
		return false;
	}

	// Initialize SHA2-256 context
	struct sha256_ctx ctx;
	sha256_init(&ctx);

	// Read file in chunks of <pagesize> bytes
	const size_t pagesize = getpagesize();
	unsigned char *buf = calloc(pagesize, sizeof(char));
	size_t len;
	while((len = fread(buf, sizeof(char), pagesize, fp)) > 0)
	{
		// Update SHA256 context
		sha256_update(&ctx, len, buf);
	}

	// Finalize SHA256 context
	sha256_digest(&ctx, SHA256_DIGEST_SIZE, checksum);

	// Close file
	fclose(fp);

	// Free memory
	free(buf);

	return true;
}
