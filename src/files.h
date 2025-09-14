/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  File prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FILE_H
#define FILE_H

#include <stdbool.h>
#include <sys/stat.h>
// setmntent()
#include <mntent.h>
// SHA256_DIGEST_SIZE
#include <nettle/sha2.h>
// getpwuid()
#include <pwd.h>

#define MAX_ROTATIONS 15
#define BACKUP_DIR "/etc/pihole/config_backups"

bool chmod_file(const char *filename, const mode_t mode);
bool file_exists(const char *filename);
bool file_readable(const char *filename);
bool file_writeable(const char *filename);
bool get_database_stat(struct stat *st);
unsigned long long get_FTL_db_filesize(void);
void get_permission_string(char permissions[10], struct stat *st);
void ls_dir(const char *path);
unsigned int get_path_usage(const char *path, char buffer[64]);
struct mntent *get_filesystem_details(const char *path);
bool directory_exists(const char *path);
bool chown_pihole(const char *path, struct passwd *pwd);
void rotate_files(const char *path, char **first_file);
bool files_different(const char *pathA, const char *pathB, unsigned int from);
bool sha256sum(const char *path, uint8_t checksum[SHA256_DIGEST_SIZE], const bool skip_end);
enum verify_result verify_FTL(bool verbose);

bool parse_line(char *line, char **key, char **value);

char *get_hwmon_target(const char *path) __attribute__((malloc));

bool lock_file(FILE *fp, const char *filename);
bool unlock_file(FILE *fp, const char *filename);

#endif //FILE_H
