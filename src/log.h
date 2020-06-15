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
#include <time.h>

enum web_code { HTTP_INFO, PH7_ERROR };

void open_FTL_log(const bool test);
void logg(const char* format, ...) __attribute__ ((format (gnu_printf, 1, 2)));
void log_counter_info(void);
void format_memory_size(char *prefix, unsigned long long int bytes, double *formated);
char *get_FTL_version(void) __attribute__ ((malloc));
void log_FTL_version(bool crashreport);
void get_timestr(char *timestring, const time_t timein);
void logg_web(enum web_code code, const char* format, ...) __attribute__ ((format (gnu_printf, 2, 3)));

#endif //LOG_H
