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

bool chmod_file(const char *filename, const mode_t mode);
bool file_exists(const char *filename);
bool get_database_stat(struct stat *st);
unsigned long long get_FTL_db_filesize(void);
void get_permission_string(char permissions[10], struct stat *st);
void ls_dir(const char* path);
const char *short_path(const char *full_path) __attribute__ ((pure));

#endif //FILE_H
