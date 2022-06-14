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
// enums
#include "enums.h"
#include <sys/syslog.h>

#define DEBUG_ANY 0

void init_FTL_log(const char *name);
void log_counter_info(void);
void format_memory_size(char prefix[2], unsigned long long int bytes,
                        double * const formatted);
void format_time(char buffer[42], unsigned long seconds, double milliseconds);
const char *get_FTL_version(void) __attribute__ ((malloc));
void log_FTL_version(bool crashreport);
double double_time(void);
void get_timestr(char * const timestring, const time_t timein, const bool millis);
void debugstr(const enum debug_flag flag, const char **name, const char **desc);
void logg_web(enum web_code code, const char *format, ...) __attribute__ ((format (gnu_printf, 2, 3)));
const char *get_ordinal_suffix(unsigned int number) __attribute__ ((const));
void print_FTL_version(void);
void dnsmasq_diagnosis_warning(char *message);

// The actual logging routine can take extra options for specialized logging
// The more general interfaces can be defined here as appropriate shortcuts
#define log_crit(format, ...) _FTL_log(LOG_CRIT, 0, format, ## __VA_ARGS__)
#define log_err(format, ...) _FTL_log(LOG_ERR, 0, format, ## __VA_ARGS__)
#define log_warn(format, ...) _FTL_log(LOG_WARNING, 0, format, ## __VA_ARGS__)
#define log_notice(format, ...) _FTL_log(LOG_NOTICE, 0, format, ## __VA_ARGS__)
#define log_info(format, ...) _FTL_log(LOG_INFO, 0, format, ## __VA_ARGS__)
#define log_debug(flag, format, ...) _FTL_log(LOG_DEBUG, flag, format, ## __VA_ARGS__)
void _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...) __attribute__ ((format (gnu_printf, 3, 4)));
void FTL_log_dnsmasq_fatal(const char *format, ...) __attribute__ ((format (gnu_printf, 1, 2)));
void log_ctrl(bool vlog, bool vstdout);
void FTL_log_helper(const unsigned char n, ...);

int binbuf_to_escaped_C_literal(const char *src_buf, size_t src_sz, char *dst_str, size_t dst_sz);

int forwarded_queries(void)  __attribute__ ((pure));
int cached_queries(void)  __attribute__ ((pure));
int blocked_queries(void)  __attribute__ ((pure));

const char *short_path(const char *full_path) __attribute__ ((pure));

#endif //LOG_H
