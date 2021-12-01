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
unsigned long long get_FTL_db_filesize(void);
void ls_dir(const char* path);
int get_path_usage(const char *path, char buffer[64]);
int get_filepath_usage(const char *file, char buffer[64]);

#endif //FILE_H
