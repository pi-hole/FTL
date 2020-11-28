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

void init_FTL_log(void);
void open_FTL_log(const bool test);
void log_counter_info(void);
void format_memory_size(char * const prefix, unsigned long long int bytes,
                        double * const formated);
void format_time(char buffer[42], unsigned long seconds, double milliseconds);
const char *get_FTL_version(void) __attribute__ ((malloc));
void log_FTL_version(bool crashreport);
void get_timestr(char * const timestring, const time_t timein);
const char *get_ordinal_suffix(unsigned int number) __attribute__ ((const));

// The actual logging routine can take extra options for specialized logging
// The more general interfaces can be defined here as appropriate shortcuts
#define logg(format, ...) _FTL_log(true, format, ## __VA_ARGS__)
#define logg_sameline(format, ...) _FTL_log(false, format, ## __VA_ARGS__)
void _FTL_log(const bool newline, const char* format, ...) __attribute__ ((format (gnu_printf, 2, 3)));
void FTL_log_dnsmasq_fatal(const char *format, ...) __attribute__ ((format (gnu_printf, 1, 2)));
void log_ctrl(bool vlog, bool vstdout);
void FTL_log_helper(const unsigned char n, ...);

#endif //LOG_H
