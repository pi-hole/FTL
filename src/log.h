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
#define TIMESTR_SIZE 84

// Credit: https://stackoverflow.com/a/75116514
#define LEFT(str, w) \
    ({int m = w + strlen(str); m % 2 ? (m + 1) / 2 : m / 2;})
#define RIGHT(str, w) \
({ int m = w - strlen(str); m % 2 ? (m - 1) / 2 : m / 2; })
#define STR_CENTER(str, width) \
    LEFT(str, width), str, RIGHT(str, width), ""
#define FPRINTF_CENTER(fp, width, start, fmt, end, ...) ({ \
    int n = snprintf(NULL, 0, fmt, __VA_ARGS__);     \
    int m = width - n;                               \
    int left = m % 2 ? (m + 1) / 2 : m / 2;          \
    int right = m % 2 ? (m - 1) / 2 : m / 2;         \
    fprintf(fp, start "%*s" fmt "%*s" end, left, "",      \
            __VA_ARGS__, right, "");                  \
})
#define CONFIG_CENTER(fp, width, fmt, ...)  \
    FPRINTF_CENTER(fp, width, "#", fmt  , "#\n", __VA_ARGS__)

extern bool debug_flags[DEBUG_MAX];
extern bool only_testing;

void clear_debug_flags(void);
void init_FTL_log(const char *name);
void log_counter_info(void);
void format_memory_size(char prefix[2], unsigned long long int bytes,
                        double * const formatted);
void format_time(char buffer[42], unsigned long seconds, double milliseconds);
unsigned int get_year(const time_t timein);
const char *get_FTL_version(void);
void log_FTL_version(bool crashreport);
double double_time(void);
void get_timestr(char timestring[TIMESTR_SIZE], const time_t timein, const bool millis, const bool uri_compatible);
const char *debugstr(const enum debug_flag flag) __attribute__((const));
void log_web(const char *format, ...) __attribute__ ((format (gnu_printf, 1, 2)));
const char *get_ordinal_suffix(unsigned int number) __attribute__ ((const));
void print_FTL_version(void);
unsigned int countchar(const char *str, const char c) __attribute__ ((pure));
void dnsmasq_diagnosis_warning(char *message);

// The actual logging routine can take extra options for specialized logging
// The more general interfaces can be defined here as appropriate shortcuts
#define log_crit(format, ...) _FTL_log(LOG_CRIT, 0, format, ## __VA_ARGS__)
#define log_err(format, ...) _FTL_log(LOG_ERR, 0, format, ## __VA_ARGS__)
#define log_warn(format, ...) _FTL_log(LOG_WARNING, 0, format, ## __VA_ARGS__)
#define log_notice(format, ...) _FTL_log(LOG_NOTICE, 0, format, ## __VA_ARGS__)
#define log_info(format, ...) _FTL_log(LOG_INFO, 0, format, ## __VA_ARGS__)
#define log_debug(flag, format, ...)({ \
	if(flag > -1 && flag < DEBUG_MAX && debug_flags[flag]) \
		_FTL_log(LOG_DEBUG, flag, format, ## __VA_ARGS__); \
})
void _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...) __attribute__ ((format (gnu_printf, 3, 4)));
void FTL_log_dnsmasq_fatal(const char *format, ...) __attribute__ ((format (gnu_printf, 1, 2)));
void log_ctrl(bool vlog, bool vstdout);
void FTL_log_helper(const unsigned char n, ...);

int binbuf_to_escaped_C_literal(const char *src_buf, size_t src_sz, char *dst_str, size_t dst_sz);

int forwarded_queries(void)  __attribute__ ((pure));
int cached_queries(void)  __attribute__ ((pure));
int blocked_queries(void)  __attribute__ ((pure));

const char *short_path(const char *full_path) __attribute__ ((pure));

// How long is each line in the FIFO buffer allowed to be?
#define MAX_MSG_FIFO 256u

// How many messages do we keep in memory (FIFO message buffer)?
// This number multiplied by MAX_MSG_FIFO (see above) gives the total buffer size
// Defaults to 512 [512 * 256 above = use 128 KB of memory for the log]
#define LOG_SIZE 515u

void add_to_fifo_buffer(const enum fifo_logs which, const char *payload, const char *prio, const size_t length);

bool flush_dnsmasq_log(void);

typedef struct {
	struct {
		unsigned int next_id;
		double timestamp[LOG_SIZE];
		char message[LOG_SIZE][MAX_MSG_FIFO];
		const char *prio[LOG_SIZE];
	} logs[FIFO_MAX];
} fifologData;

extern fifologData *fifo_log;

#endif //LOG_H
