/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Logging prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LOG_H
#define LOG_H

#include <stdbool.h>

void open_FTL_log(const bool test);
void logg(const char* format, ...) __attribute__ ((format (gnu_printf, 1, 2)));
void log_counter_info(void);
void format_memory_size(char *prefix, unsigned long long int bytes, double *formated);
const char *get_FTL_version(void) __attribute__ ((malloc));
void log_FTL_version(bool crashreport);
void get_timestr(char *timestring, const time_t timein);

#endif //LOG_H
