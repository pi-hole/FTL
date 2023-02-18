/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Logging routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "version.h"
// is_fork()
#include "daemon.h"
#include "config/config.h"
#include "log.h"
// global variable username
#include "main.h"
// global variable daemonmode
#include "args.h"
// global counters variable
#include "shmem.h"
// main_pid()
#include "signals.h"
// logg_fatal_dnsmasq_message()
#include "database/message-table.h"

static bool print_log = true, print_stdout = true;
static const char *process = "";
bool debug_flags[DEBUG_MAX] = { false };

void clear_debug_flags(void)
{
	for(unsigned int i = 0; i < DEBUG_MAX; i++)
		debug_flags[i] = false;
}

void log_ctrl(bool plog, bool pstdout)
{
	print_log = plog;
	print_stdout = pstdout;
}

void init_FTL_log(const char *name)
{
	// Open the log file in append/create mode
	if(config.files.log.ftl.v.s != NULL)
	{
		FILE *logfile = NULL;
		if((logfile = fopen(config.files.log.ftl.v.s, "a+")) == NULL)
		{
			syslog(LOG_ERR, "Opening of FTL\'s log file failed, using syslog instead!");
			printf("ERR: Opening of FTL log (%s) failed!\n",config.files.log.ftl.v.s);
			config.files.log.ftl.v.s = NULL;
		}

		// Close log file
		if(logfile != NULL)
			fclose(logfile);
	}

	// Store process name (if available), strip path if found
	if(name != NULL)
	{
		if(strrchr(name, '/') != NULL)
			process = strrchr(name, '/')+1;
		else
			process = name;
	}
}

// Return time(NULL) but with (up to) nanosecond accuracy
// The resolution of clock depends on the hardware implementation and cannot be
// changed by a particular process
double double_time(void)
{
	struct timespec tp;
	// POSIX.1-2008: "Applications should use the clock_gettime() function instead
	// of the obsolescent gettimeofday() function"
	clock_gettime(CLOCK_REALTIME, &tp);
	return tp.tv_sec + 1e-9*tp.tv_nsec;
}

// The size of 84 bytes has been carefully selected for all possible timestamps
// to always fit into the available space without buffer overflows
void get_timestr(char timestring[TIMESTR_SIZE], const time_t timein, const bool millis, const bool uri_compatible)
{
	struct tm tm;
	localtime_r(&timein, &tm);
	char space = ' ';
	char colon = ':';
	if(uri_compatible)
	{
		space = '_';
		colon = '-';
	}

	if(millis)
	{
		struct timeval tv;
		gettimeofday(&tv, NULL);
		const int millisec = tv.tv_usec/1000;

		sprintf(timestring,"%d-%02d-%02d%c%02d%c%02d%c%02d.%03i",
		        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, space,
		        tm.tm_hour, colon, tm.tm_min, colon, tm.tm_sec, millisec);
	}
	else
	{
		sprintf(timestring,"%d-%02d-%02d%c%02d%c%02d%c%02d",
		        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, space,
		        tm.tm_hour, colon, tm.tm_min, colon, tm.tm_sec);
	}
}

// Return the current year
unsigned int get_year(const time_t timein)
{
	struct tm tm;
	localtime_r(&timein, &tm);
	return tm.tm_year + 1900;
}

static const char *priostr(const int priority, const enum debug_flag flag)
{
	const char *name;
	switch (priority)
	{
		// system is unusable
		case LOG_EMERG:
			return "EMERG";
		// action must be taken immediately
		case LOG_ALERT:
			return "ALERT";
		// critical conditions
		case LOG_CRIT:
			return "CRIT";
		// error conditions
		case LOG_ERR:
			return "ERR";
		// warning conditions
		case LOG_WARNING:
			return "WARNING";
		// normal but significant condition
		case LOG_NOTICE:
			return "NOTICE";
		// informational
		case LOG_INFO:
			return "INFO";
		// debug-level messages
		case LOG_DEBUG:
			debugstr(flag, &name);
			return name;
		// invalid option
		default:
			return "UNKNOWN";
	}
}

void debugstr(const enum debug_flag flag, const char **name)
{
	switch (flag)
	{
		case DEBUG_DATABASE:
			*name = "DEBUG_DATABASE";
			return;
		case DEBUG_NETWORKING:
			*name = "DEBUG_NETWORKING";
			return;
		case DEBUG_LOCKS:
			*name = "DEBUG_LOCKS";
			return;
		case DEBUG_QUERIES:
			*name = "DEBUG_QUERIES";
			return;
		case DEBUG_FLAGS:
			*name = "DEBUG_FLAGS";
			return;
		case DEBUG_SHMEM:
			*name = "DEBUG_SHMEM";
			return;
		case DEBUG_GC:
			*name = "DEBUG_GC";
			return;
		case DEBUG_ARP:
			*name = "DEBUG_ARP";
			return;
		case DEBUG_REGEX:
			*name = "DEBUG_REGEX";
			return;
		case DEBUG_API:
			*name = "DEBUG_API";
			return;
		case DEBUG_OVERTIME:
			*name = "DEBUG_OVERTIME";
			return;
		case DEBUG_STATUS:
			*name = "DEBUG_STATUS";
			return;
		case DEBUG_CAPS:
			*name = "DEBUG_CAPS";
			return;
		case DEBUG_DNSSEC:
			*name = "DEBUG_DNSSEC";
			return;
		case DEBUG_VECTORS:
			*name = "DEBUG_VECTORS";
			return;
		case DEBUG_RESOLVER:
			*name = "DEBUG_RESOLVER";
			return;
		case DEBUG_EDNS0:
			*name = "DEBUG_EDNS0";
			return;
		case DEBUG_CLIENTS:
			*name = "DEBUG_CLIENTS";
			return;
		case DEBUG_ALIASCLIENTS:
			*name = "DEBUG_ALIASCLIENTS";
			return;
		case DEBUG_EVENTS:
			*name = "DEBUG_EVENTS";
			return;
		case DEBUG_HELPER:
			*name = "DEBUG_HELPER";
			return;
		case DEBUG_EXTRA:
			*name = "DEBUG_EXTRA";
			return;
		case DEBUG_CONFIG:
			*name = "DEBUG_CONFIG";
			return;
		case DEBUG_INOTIFY:
			*name = "DEBUG_INOTIFY";
			return;
		case DEBUG_RESERVED:
			*name = "DEBUG_RESERVED";
			return;
		case DEBUG_MAX:
			*name = "DEBUG_MAX";
			return;
		default:
			*name = "DEBUG_ANY";
			return;
	}
}

void __attribute__ ((format (gnu_printf, 3, 4))) _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...)
{
	char timestring[TIMESTR_SIZE] = "";
	va_list args;

	// We have been explicitly asked to not print anything to the log
	if(!print_log && !print_stdout)
		return;

	// Get human-readable time
	get_timestr(timestring, time(NULL), true, false);

	// Get and log PID of current process to avoid ambiguities when more than one
	// pihole-FTL instance is logging into the same file
	char idstr[42];
	const int pid = getpid(); // Get the process ID of the calling process
	const int mpid = main_pid(); // Get the process ID of the main FTL process
	const int tid = gettid(); // Get the thread ID of the calling process

	// There are four cases we have to differentiate here:
	if(pid == tid)
		if(is_fork(mpid, pid))
			// Fork of the main process
			snprintf(idstr, sizeof(idstr)-1, "%i/F%i", pid, mpid);
		else
			// Main process
			snprintf(idstr, sizeof(idstr)-1, "%iM", pid);
	else
		if(is_fork(mpid, pid))
			// Thread of a fork of the main process
			snprintf(idstr, sizeof(idstr)-1, "%i/F%i/T%i", pid, mpid, tid);
		else
			// Thread of the main process
			snprintf(idstr, sizeof(idstr)-1, "%i/T%i", pid, tid);

	// Print to stdout before writing to file
	if((!daemonmode || cli_mode) && print_stdout)
	{
		// Only print time/ID string when not in direct user interaction (CLI mode)
		if(!cli_mode)
			printf("%s [%s] %s: ", timestring, idstr, priostr(priority, flag));
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
		printf("\n");
	}

	// Print to log file or syslog
	if(print_log)
	{
		// Add line to FIFO buffer
		char buffer[MAX_MSG_FIFO + 1u];
		va_start(args, format);
		const size_t len = vsnprintf(buffer, MAX_MSG_FIFO, format, args) + 1u; /* include zero-terminator */
		va_end(args);
		add_to_fifo_buffer(FIFO_FTL, buffer, len > MAX_MSG_FIFO ? MAX_MSG_FIFO : len);

		if(config.files.log.ftl.v.s != NULL)
		{
			// Open log file
			FILE *logfile = fopen(config.files.log.ftl.v.s, "a+");

			// Write to log file
			if(logfile != NULL)
			{
				// Prepend message with identification string and priority
				fprintf(logfile, "%s [%s] %s: ", timestring, idstr, priostr(priority, flag));

				// Log message
				va_start(args, format);
				vfprintf(logfile, format, args);
				va_end(args);

				// Append newline character to the end of the file
				fputc('\n', logfile);

				// Close file after writing
				fclose(logfile);
			}
			else if(!daemonmode)
			{
				printf("!!! WARNING: Writing to FTL\'s log file failed!\n");
				syslog(LOG_ERR, "Writing to FTL\'s log file failed!");
			}
		}
		else
		{
			// Syslog logging
			va_start(args, format);
			vsyslog(priority, format, args);
			va_end(args);
		}
	}
}

static FILE * __attribute__((malloc, warn_unused_result)) open_web_log(const enum fifo_logs which)
{
	// Open the log file in append/create mode
	char *file = NULL;
	switch (which)
	{
		case FIFO_CIVETWEB:
			file = config.files.http_info.v.s;
			break;
		case FIFO_PH7:
			file = config.files.ph7_error.v.s;
			break;
		case FIFO_FTL:
		case FIFO_DNSMASQ:
		case FIFO_MAX:
		default:
			log_err("Invalid logging requested");
			return NULL;
	}

	return fopen(file, "a+");
}

void __attribute__ ((format (gnu_printf, 2, 3))) logg_web(enum fifo_logs which, const char *format, ...)
{
	char timestring[TIMESTR_SIZE] = "";
	const time_t now = time(NULL);
	va_list args;

	// Add line to FIFO buffer
	char buffer[MAX_MSG_FIFO + 1u];
	va_start(args, format);
	const size_t len = vsnprintf(buffer, MAX_MSG_FIFO, format, args) + 1u; /* include zero-terminator */
	va_end(args);
	add_to_fifo_buffer(which, buffer, len > MAX_MSG_FIFO ? MAX_MSG_FIFO : len);

	// Get human-readable time
	get_timestr(timestring, now, true, false);

	// Get and log PID of current process to avoid ambiguities when more than one
	// pihole-FTL instance is logging into the same file
	const long pid = (long)getpid();

	// Open web log file
	FILE *weblog = open_web_log(which);

	// Write to web log file
	if(weblog != NULL)
	{
		fprintf(weblog, "[%s %ld] ", timestring, pid);
		va_start(args, format);
		vfprintf(weblog, format, args);
		va_end(args);
		fputc('\n',weblog);
		fclose(weblog);
	}
	else if(!daemonmode)
	{
		printf("!!! WARNING: Writing to web log file failed!\n");
		syslog(LOG_ERR, "Writing to web log file failed!");
	}
}

// Log helper activity (may be script or lua)
void FTL_log_helper(const unsigned char n, ...)
{
	// Only log helper debug messages if enabled
	if(!(config.debug.helper.v.b))
		return;

	// Extract all variable arguments
	va_list args;
	char **arg = calloc(n, sizeof(char*));
	va_start(args, n);
	for(unsigned char i = 0; i < n; i++)
	{
		const char *argin = va_arg(args, char*);
		if(argin == NULL)
			arg[i] = NULL;
		else
			arg[i] = strdup(argin);
	}
	va_end(args);

	// Select appropriate logging format
	switch (n)
	{
		case 1:
			log_debug(DEBUG_HELPER, "Script: Starting helper for action \"%s\"", arg[0]);
			break;
		case 2:
			log_debug(DEBUG_HELPER, "Script: FAILED to execute \"%s\": %s", arg[0], arg[1]);
			break;
		case 5:
			log_debug(DEBUG_HELPER, "Script: Executing \"%s\" with arguments: \"%s %s %s %s\"",
			          arg[0], arg[1], arg[2], arg[3], arg[4]);
			break;
		default:
			log_debug(DEBUG_HELPER, "ERROR: Unsupported number of arguments passed to FTL_log_helper(): %u", n);
			break;
	}

	// Free allocated memory
	for(unsigned char i = 0; i < n; i++)
		if(arg[i] != NULL)
			free(arg[i]);
	free(arg);
}

void format_memory_size(char prefix[2], const unsigned long long int bytes,
                        double * const formatted)
{
	unsigned int i;
	*formatted = bytes;
	// Determine exponent for human-readable display
	for(i = 0; i < 7; i++)
	{
		if(*formatted <= 1e3)
			break;
		*formatted /= 1e3;
	}
	const char prefixes[8] = { '\0', 'K', 'M', 'G', 'T', 'P', 'E', '?' };
	// Chose matching SI prefix
	prefix[0] = prefixes[i];
	prefix[1] = '\0';
}

// Human-readable time
void format_time(char buffer[42], unsigned long seconds, double milliseconds)
{
	unsigned long umilliseconds = 0;
	if(milliseconds > 0)
	{
		seconds = milliseconds / 1000;
		umilliseconds = (unsigned long)milliseconds % 1000;
	}
	const unsigned int days = seconds / (60 * 60 * 24);
	seconds -= days * (60 * 60 * 24);
	const unsigned int hours = seconds / (60 * 60);
	seconds -= hours * (60 * 60);
	const unsigned int minutes = seconds / 60;
	seconds %= 60;

	buffer[0] = ' ';
	buffer[1] = '\0';
	if(days > 0)
		sprintf(buffer + strlen(buffer), "%ud ", days);
	if(hours > 0)
		sprintf(buffer + strlen(buffer), "%uh ", hours);
	if(minutes > 0)
		sprintf(buffer + strlen(buffer), "%um ", minutes);
	if(seconds > 0)
		sprintf(buffer + strlen(buffer), "%lus ", seconds);

	// Only append milliseconds when the timer value is less than 10 seconds
	if((days + hours + minutes) == 0 && seconds < 10 && umilliseconds > 0)
		sprintf(buffer + strlen(buffer), "%lums ", umilliseconds);
}

void FTL_log_dnsmasq_fatal(const char *format, ...)
{
	if(!print_log)
		return;
	// Build a complete string from possible multi-part string passed from dnsmasq
	char message[256] = { 0 };
	va_list args;
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	message[255] = '\0';

	// Log error into FTL's log + message table
	logg_fatal_dnsmasq_message(message);
}

void log_counter_info(void)
{
	log_info(" -> Total DNS queries: %i", counters->queries);
	log_info(" -> Cached DNS queries: %i", get_cached_count());
	log_info(" -> Forwarded DNS queries: %i", get_forwarded_count());
	log_info(" -> Blocked DNS queries: %i", get_blocked_count());
	log_info(" -> Unknown DNS queries: %i", counters->status[QUERY_UNKNOWN]);
	log_info(" -> Unique domains: %i", counters->domains);
	log_info(" -> Unique clients: %i", counters->clients);
	log_info(" -> Known forward destinations: %i", counters->upstreams);
}

void log_FTL_version(const bool crashreport)
{
	log_info("FTL branch: %s", GIT_BRANCH);
	log_info("FTL version: %s", get_FTL_version());
	log_info("FTL commit: %s", GIT_HASH);
	log_info("FTL date: %s", GIT_DATE);
	if(crashreport)
	{
		char *username_now = getUserName();
		log_info("FTL user: started as %s, ended as %s", username, username_now);
		free(username_now);
	}
	else
		log_info("FTL user: %s", username);
	log_info("Compiled for %s using %s", FTL_ARCH, FTL_CC);
}

static char *FTLversion = NULL;
const char __attribute__ ((malloc)) *get_FTL_version(void)
{
	// Obtain FTL version if not already determined
	if(FTLversion == NULL)
	{
		if(strlen(GIT_TAG) > 1 )
		{
			if (strlen(GIT_VERSION) > 1)
			{
				// Copy version string if this is a tagged release
				FTLversion = strdup(GIT_VERSION);
			}

		}
		else if(strlen(GIT_HASH) > 0)
		{
			// Build special version string when there is a hash
			FTLversion = calloc(13, sizeof(char));
			// Build version by appending 7 characters of the hash to "vDev-"
			snprintf(FTLversion, 13, "vDev-%.7s", GIT_HASH);
		}
		else
		{
			// Fallback for tarball build, etc. without any GIT subsystem
			FTLversion = strdup("UNKNOWN (not a GIT build)");
		}
	}

	return FTLversion;
}

const char __attribute__ ((const)) *get_ordinal_suffix(unsigned int number)
{
	if((number % 100) > 9 && (number % 100) < 20)
	{
		// If the tens digit of a number is 1, then "th" is written
		// after the number. For example: 13th, 19th, 112th, 9,311th.
		return "th";
	}

	// If the tens digit is not equal to 1, then the following table could be used:
	switch (number % 10)
	{
	case 1: // If the units digit is 1: This is written after the number "st"
		return "st";
	case 2: // If the units digit is 2: This is written after the number "nd"
		return "nd";
	case 3: // If the units digit is 3: This is written after the number "rd"
		return "rd";
	default: // If the units digit is 0 or 4-9: This is written after the number "th"
		return "th";
	}
	// For example: 2nd, 7th, 20th, 23rd, 52nd, 135th, 301st BUT 311th (covered above)
}

// Converts a buffer of specified length to ASCII representation as it was a C
// string literal. Returns how much bytes from source was processed
// Inspired by https://stackoverflow.com/a/56123950
int binbuf_to_escaped_C_literal(const char *src_buf, size_t src_sz,
                                      char *dst_str, size_t dst_sz)
{
	const char *src = src_buf;
	char *dst = dst_str;

	// Special handling for empty strings
	if(src_sz == 0)
	{
		strncpy(dst_str, "(empty)", dst_sz);
		dst_str[dst_sz-1] = '\0';
		return 0;
	}

	while (src < src_buf + src_sz)
	{
		if (isprint(*src))
		{
			// The printable characters are:
			// ! " # $ % & ' ( ) * + , - . / 0 1 2 3 4 5 6 7 8 9 : ;
			// < = > ? @ A B C D E F G H I J K L M N O P Q R S T U V
			// W X Y Z [ \ ] ^ _ ` a b c d e f g h i j k l m n o p q
			// r s t u v w x y z { | } ~
			*dst++ = *src++;
		}
		else if (*src == '\\')
		{
			// Backslash isn't included above but isn't harmful
			*dst++ = '\\';
			*dst++ = *src++;
		}
		else
		{
			// Handle other characters more specifically
			switch(*src)
			{
				case '\n':
					*dst++ = '\\';
					*dst++ = 'n';
					break;
				case '\r':
					*dst++ = '\\';
					*dst++ = 'r';
					break;
				case '\t':
					*dst++ = '\\';
					*dst++ = 't';
					break;
				case '\0':
					*dst++ = '\\';
					*dst++ = '0';
					break;
				default:
					sprintf(dst, "0x%X", *(unsigned char*)src);
					dst += 4;
			}

			// Advance reading counter by one character
			src++;
		}

		// next iteration requires up to 5 chars in dst buffer, for ex.
		// "0x04" + terminating zero (see below)
		if (dst > (dst_str + dst_sz - 5))
			break;
	}

	// Zero-terminate buffer
	*dst = '\0';

	return src - src_buf;
}

// Find number of occurrences of a character in a string
unsigned int __attribute__ ((pure)) countchar(const char *str, const char c)
{
	unsigned int count = 0;
	for(const char *p = str; *p != '\0'; p++)
		if(*p == c)
			count++;
	return count;
}

int __attribute__ ((pure)) forwarded_queries(void)
{
	return counters->status[QUERY_FORWARDED] +
	       counters->status[QUERY_RETRIED] +
	       counters->status[QUERY_RETRIED_DNSSEC];
}

int __attribute__ ((pure)) cached_queries(void)
{
	return counters->status[QUERY_CACHE];
}

int __attribute__ ((pure)) blocked_queries(void)
{
	int num = 0;
	for(enum query_status status = 0; status < QUERY_STATUS_MAX; status++)
		if(is_blocked(status))
			num += counters->status[status];
	return num;
}

const char * __attribute__ ((pure)) short_path(const char *full_path)
{
	const char *shorter = strstr(full_path, "src/");
	return shorter != NULL ? shorter : full_path;
}

void print_FTL_version(void)
{
    printf("Pi-hole FTL %s\n", get_FTL_version());
}

// Skip leading string if found
static char *skipStr(const char *startstr, char *message)
{
	const size_t startlen = strlen(startstr);
	if(strncmp(startstr, message, startlen) == 0)
		return message + startlen;
	else
		return message;
}

void dnsmasq_diagnosis_warning(char *message)
{
	// Crop away any existing initial "warning: "
	logg_warn_dnsmasq_message(skipStr("warning: ", message));
}

void add_to_fifo_buffer(const enum fifo_logs which, const char *payload, const size_t length)
{
	const double now = double_time();

	// Do not try to log when shared memory isn't initialized yet
	if(!fifo_log)
		return;

	unsigned int idx = fifo_log->logs[which].next_id++;
	if(idx >= LOG_SIZE)
	{
		// Log is full, move everything one slot forward to make space for a new record at the end
		// This pruges the oldest message from the list (it is overwritten by the second message)
		memmove(&fifo_log->logs[which].message[0][0], &fifo_log->logs[which].message[1][0], (LOG_SIZE - 1u) * MAX_MSG_FIFO);
		memmove(&fifo_log->logs[which].timestamp[0], &fifo_log->logs[which].timestamp[1], (LOG_SIZE - 1u) * sizeof(fifo_log->logs[which].timestamp[0]));
		idx = LOG_SIZE - 1u;
	}

	// Copy relevant string into temporary buffer
	size_t copybytes = length < MAX_MSG_FIFO ? length : MAX_MSG_FIFO;
	memcpy(fifo_log->logs[which].message[idx], payload, copybytes);

	// Zero-terminate buffer, truncate newline if found
	if(fifo_log->logs[which].message[idx][copybytes - 1u] == '\n')
	{
		fifo_log->logs[which].message[idx][copybytes - 1u] = '\0';
	}
	else
	{
		fifo_log->logs[which].message[idx][copybytes] = '\0';
	}

	// Set timestamp
	fifo_log->logs[which].timestamp[idx] = now;
}
