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
// delete_old_queries_from_db()
#include "database/query-table.h"
// runGC()
#include "gc.h"
// open(), O_WRONLY, O_CREAT, O_APPEND, O_CLOEXEC
#include <fcntl.h>
// cJSON_CreateObject(), ...
#include "webserver/cJSON/cJSON.h"

static bool print_log = true, print_stdout = true;
bool debug_flags[DEBUG_MAX] = { false };

// Per-file log state: fd, path (owned copy), writer-preferenced lock, reopen flag
struct log_fd {
	int fd;
	char *path;
	pthread_mutex_t lock;
	volatile sig_atomic_t reopen_needed;
};

static struct log_fd ftl_log = { .fd = -1, .lock = PTHREAD_MUTEX_INITIALIZER };
static struct log_fd webserver_log = { .fd = -1, .lock = PTHREAD_MUTEX_INITIALIZER };
static struct log_fd dnsmasq_log = { .fd = -1, .lock = PTHREAD_MUTEX_INITIALIZER };

// dnsmasq forks per TCP query while FTL threads may be mid-write.  Without
// atfork handling the child would inherit one of the per-file mutexes locked
// and the first my_syslog() there would block forever, hanging that query.
// Lock all log mutexes before fork() and release them in both parent and child.
static void log_atfork_prepare(void)
{
	pthread_mutex_lock(&ftl_log.lock);
	pthread_mutex_lock(&webserver_log.lock);
	pthread_mutex_lock(&dnsmasq_log.lock);
}
static void log_atfork_parent(void)
{
	pthread_mutex_unlock(&ftl_log.lock);
	pthread_mutex_unlock(&webserver_log.lock);
	pthread_mutex_unlock(&dnsmasq_log.lock);
}
static void log_atfork_child(void)
{
	pthread_mutex_unlock(&ftl_log.lock);
	pthread_mutex_unlock(&webserver_log.lock);
	pthread_mutex_unlock(&dnsmasq_log.lock);
}

// Return 1 if this fd is associated with any logfile to avoid
// dnsmasq closing it during initialization
int __attribute__((pure)) is_log_fd(const int fd)
{
	return fd == ftl_log.fd || fd == webserver_log.fd || fd == dnsmasq_log.fd;
}

// Writer-preferenced per-file lock: only the fd for this specific log is
// held, so writes to different files never contend.  The reopen flag is
// per-file so SIGUSR2 only touches the fd that actually needs it.
static bool write_log_line(struct log_fd *log, const char *line, size_t len)
{
	// Do not try to write when the path is unknown
	if(log->path == NULL)
		return false;

	// log->fd and log->reopen_needed are only accessed under the lock so a
	// reopen (e.g. from flush_dnsmasq_log()) can never race a concurrent write
	pthread_mutex_lock(&log->lock);

	// Reopen the log if requested.  This must be tested before the fd == -1
	// check so that SIGUSR2 can revive a log whose initial open failed (missing
	// directory, transient EACCES, ...).
	if(log->reopen_needed)
	{
		log->reopen_needed = 0;
		if(log->fd != -1)
			close(log->fd);
		log->fd = open(log->path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, S_IRUSR|S_IWUSR|S_IRGRP);
	}

	// No usable descriptor: let the caller fall back to another channel
	if(log->fd == -1)
	{
		pthread_mutex_unlock(&log->lock);
		return false;
	}

	ssize_t written = 0;
	while(written < (ssize_t)len)
	{
		ssize_t rc = write(log->fd, line + written, len - written);
		if(rc == -1)
		{
			if(errno == EINTR)
				continue;
			pthread_mutex_unlock(&log->lock);
			return false;
		}
		written += rc;
	}

	pthread_mutex_unlock(&log->lock);
	return true;
}

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

// Set a log_fd path from a config string.  The path is duplicated so
// that a config replacement (free_config + memcpy) cannot leave a
// dangling pointer in the reopen path.
static void set_log_path(struct log_fd *log, const char *path)
{
	if(log->path != NULL && path != NULL && strcmp(log->path, path) == 0)
		return; // unchanged
	if(log->path != NULL)
		free(log->path);
	log->path = path != NULL ? strdup(path) : NULL;
}

// Open cached log fds from config paths.
// open_log_fds(true):  open FTL.log only (called early, before full config)
// open_log_fds(false): open webserver.log + pihole.log (called after config)
void open_log_fds(bool ftl)
{
	// Only open log files when file logging is explicitly selected
	if(config.files.log.destination.v.log_destination != LOG_DEST_FILE)
		return;

	if(ftl)
	{
		// FTL.log - path is known from getLogFilePath()
		if(config.files.log.ftl.v.s != NULL)
		{
			set_log_path(&ftl_log, config.files.log.ftl.v.s);
			ftl_log.fd = open(ftl_log.path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, S_IRUSR|S_IWUSR|S_IRGRP);
			if(ftl_log.fd == -1)
			{
				printf("ERROR: Opening of FTL log (%s) failed: %s\nUsing syslog instead!\n",
				       ftl_log.path, strerror(errno));
				syslog(LOG_ERR, "Opening of FTL\'s log file failed, using syslog instead!");
			}
		}
		return;
	}

	// webserver.log + pihole.log - paths are known after readFTLconf()
	if(config.files.log.webserver.v.s != NULL)
	{
		set_log_path(&webserver_log, config.files.log.webserver.v.s);
		if(webserver_log.fd >= 0)
			close(webserver_log.fd);
		webserver_log.fd = open(webserver_log.path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, S_IRUSR|S_IWUSR|S_IRGRP);
		if(webserver_log.fd == -1)
		{
			log_warn("webserver.log is unavailable (%s); warnings are still relayed to the FTL log",
			         strerror(errno));
		}
	}

	// pihole.log (dnsmasq) - FTL owns this file from now on
	if(config.files.log.dnsmasq.v.s != NULL)
	{
		set_log_path(&dnsmasq_log, config.files.log.dnsmasq.v.s);
		if(dnsmasq_log.fd >= 0)
			close(dnsmasq_log.fd);
		dnsmasq_log.fd = open(dnsmasq_log.path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, S_IRUSR|S_IWUSR|S_IRGRP);
		if(dnsmasq_log.fd == -1)
		{
			// Warn regardless - the hide_dnsmasq_warn setting only controls
			// whether the warnings themselves are shown, not this notice
			if(config.misc.hide_dnsmasq_warn.v.b)
				log_warn("pihole.log is unavailable (%s); dnsmasq warnings are hidden (misc.hide_dnsmasq_warn)",
				         strerror(errno));
			else
				log_warn("pihole.log is unavailable (%s); dnsmasq warnings are still relayed to the FTL log",
				         strerror(errno));
		}
	}

	// Register atfork handlers once, before any threads or dnsmasq forks
	// exist, so a TCP-query fork can never inherit a locked log mutex.
	// Invariant: fork() is never called from inside a log write, so the
	// atfork prepare/parent/child handlers only need to cover the case
	// where a thread holds a log mutex at the moment of the fork.
	static bool atfork_registered = false;
	if(!atfork_registered)
	{
		atfork_registered = true;
		pthread_atfork(log_atfork_prepare, log_atfork_parent, log_atfork_child);
	}
}

// Signal that log fds need to be reopened (called from SIGUSR2 handler path)
void mark_log_reopen(void)
{
	ftl_log.reopen_needed = 1;
	webserver_log.reopen_needed = 1;
	dnsmasq_log.reopen_needed = 1;
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

// Get a human-readable time string
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

		snprintf(timestring, TIMESTR_SIZE, "%d-%02d-%02d%c%02d%c%02d%c%02d.%03i%c%s",
		        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, space,
		        tm.tm_hour, colon, tm.tm_min, colon, tm.tm_sec, millisec, space, tm.tm_zone);
	}
	else
	{
		snprintf(timestring, TIMESTR_SIZE, "%d-%02d-%02d%c%02d%c%02d%c%02d%c%s",
		        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, space,
		        tm.tm_hour, colon, tm.tm_min, colon, tm.tm_sec, space, tm.tm_zone);
	}

	// Ensure that the string is zero-terminated
	timestring[TIMESTR_SIZE - 1] = '\0';
}

// Return the current year
unsigned int get_year(const time_t timein)
{
	struct tm tm;
	localtime_r(&timein, &tm);
	return tm.tm_year + 1900;
}

static void get_timestr_iso8601(char timestring[TIMESTR_SIZE], const time_t timein)
{
	struct tm tm;
	gmtime_r(&timein, &tm);

	struct timeval tv;
	gettimeofday(&tv, NULL);

	int millisec = 0;
	if(tv.tv_sec == timein)
		millisec = tv.tv_usec / 1000;

	snprintf(timestring, TIMESTR_SIZE,
	         "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
	         tm.tm_year + 1900,
	         tm.tm_mon + 1,
	         tm.tm_mday,
	         tm.tm_hour,
	         tm.tm_min,
	         tm.tm_sec,
	         millisec);

	// Ensure null termination
	timestring[TIMESTR_SIZE - 1] = '\0';
}

void log_to_json(const time_t now, const char *log_level, const char *component, const char *pid, const char *msg)
{
	char timestring_iso8601[TIMESTR_SIZE];
	get_timestr_iso8601(timestring_iso8601, now);

	cJSON *root = cJSON_CreateObject();
	if (!root) return;

	cJSON_AddStringToObject(root, "timestamp", timestring_iso8601);
	cJSON_AddStringToObject(root, "log_level", log_level);
	cJSON_AddStringToObject(root, "service", "pihole-FTL");
	cJSON_AddStringToObject(root, "component", component);
	cJSON_AddStringToObject(root, "pid", pid);
	cJSON_AddStringToObject(root, "message", msg);

	char *out = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);

	if (!out) return;
	printf("%s\n", out);
	free(out);
}

void get_idstr(char *idstr, size_t size)
{
	const int pid = getpid(); // Get the process ID of the calling process
	const int mpid = main_pid(); // Get the process ID of the main FTL process
	const int tid = gettid(); // Get the thread ID of the calling process

	// There are four cases we have to differentiate here:
	if(pid == tid)
		if(is_fork(mpid, pid))
			// Fork of the main process
			snprintf(idstr, size, "%i/F%i", pid, mpid);
		else
			// Main process
			snprintf(idstr, size, "%iM", pid);
	else
		if(is_fork(mpid, pid))
			// Thread of a fork of the main process
			snprintf(idstr, size, "%i/F%i/T%i", pid, mpid, tid);
		else
			// Thread of the main process
			snprintf(idstr, size, "%i/T%i", pid, tid);
}

const char * __attribute__((const)) priostr(const int priority, const enum debug_flag flag)
{
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
			return "ERROR";
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
			return debugstr(flag);
		// invalid option
		default:
			return "UNKNOWN";
	}
}

const char *debugstr(const enum debug_flag flag)
{
	switch (flag)
	{
		case DEBUG_DATABASE:
			return "DEBUG_DATABASE";
		case DEBUG_NETWORKING:
			return "DEBUG_NETWORKING";
		case DEBUG_LOCKS:
			return "DEBUG_LOCKS";
		case DEBUG_QUERIES:
			return "DEBUG_QUERIES";
		case DEBUG_FLAGS:
			return "DEBUG_FLAGS";
		case DEBUG_SHMEM:
			return "DEBUG_SHMEM";
		case DEBUG_GC:
			return "DEBUG_GC";
		case DEBUG_ARP:
			return "DEBUG_ARP";
		case DEBUG_REGEX:
			return "DEBUG_REGEX";
		case DEBUG_API:
			return "DEBUG_API";
		case DEBUG_TLS:
			return "DEBUG_TLS";
		case DEBUG_OVERTIME:
			return "DEBUG_OVERTIME";
		case DEBUG_STATUS:
			return "DEBUG_STATUS";
		case DEBUG_CAPS:
			return "DEBUG_CAPS";
		case DEBUG_DNSSEC:
			return "DEBUG_DNSSEC";
		case DEBUG_VECTORS:
			return "DEBUG_VECTORS";
		case DEBUG_RESOLVER:
			return "DEBUG_RESOLVER";
		case DEBUG_EDNS0:
			return "DEBUG_EDNS0";
		case DEBUG_CLIENTS:
			return "DEBUG_CLIENTS";
		case DEBUG_ALIASCLIENTS:
			return "DEBUG_ALIASCLIENTS";
		case DEBUG_EVENTS:
			return "DEBUG_EVENTS";
		case DEBUG_HELPER:
			return "DEBUG_HELPER";
		case DEBUG_EXTRA:
			return "DEBUG_EXTRA";
		case DEBUG_CONFIG:
			return "DEBUG_CONFIG";
		case DEBUG_INOTIFY:
			return "DEBUG_INOTIFY";
		case DEBUG_WEBSERVER:
			return "DEBUG_WEBSERVER";
		case DEBUG_RESERVED:
			return "DEBUG_RESERVED";
		case DEBUG_NTP:
			return "DEBUG_NTP";
		case DEBUG_NETLINK:
			return "DEBUG_NETLINK";
		case DEBUG_TIMING:
			return "DEBUG_TIMING";
		case DEBUG_PERFORMANCE:
			return "DEBUG_PERFORMANCE";
		case DEBUG_DOTDOH:
			return "DEBUG_DOTDOH";
		case DEBUG_MAX:
			return "DEBUG_MAX";
		case DEBUG_NONE: // fall through
		default:
			return "DEBUG_ANY";
	}
}

// Write a dnsmasq log line to pihole.log in dnsmasq's exact on-disk format.
// The message is the bare body (no timestamp, no prefix) as handed to
// FTL_dnsmasq_log() from my_syslog().  We reproduce dnsmasq's format:
//   "Jan  1 12:00:00 dnsmasq-dhcp[12345]: <message>\n"
// where the func suffix (e.g. "-dhcp", "-tftp") comes from the priority
// bits extracted in my_syslog().
bool FTL_write_dnsmasq_log(const char *message, const char *func)
{
	// Locale-independent timestamp: ctime_r() renders the month/day in the
	// C locale regardless of setlocale(LC_ALL, ""), so the buffer cannot
	// overflow with non-English month names (strftime("%b") would emit
	// e.g. six bytes for ru_RU). ctime_r() is reentrant, unlike ctime()
	// which returns a pointer to a static buffer shared with localtime()
	// and asctime() - critical since FTL_write_dnsmasq_log() runs on the
	// DNS thread while the webserver, database and NTP threads format their
	// own timestamps. This is dnsmasq's own idiom and keeps the on-disk
	// format byte-identical to what we wrote before.
	time_t now = time(NULL);
	char ctime_buf[26];
	const char *ctime_str = ctime_r(&now, ctime_buf);
	if(ctime_str == NULL)
		ctime_str = "Thu Jan  1 00:00:00 1970\n";
	char ts_buf[16];
	snprintf(ts_buf, sizeof(ts_buf), "%.15s", ctime_str + 4);

	char line[2048];
	int off = snprintf(line, sizeof(line), "%s dnsmasq%s[%d]: ", ts_buf, func ? func : "", getpid());

	// Clamp before using off as an offset - snprintf returns the would-be
	// length on truncation and sizeof(line) - off would underflow otherwise;
	// it may also return negative on an encoding error
	if(off < 0 || off >= (int)sizeof(line))
		off = sizeof(line) - 1;

	const char *msg = message ? message : "";
	off += snprintf(line + off, sizeof(line) - off, "%s", msg);

	// Clamp to buffer end - snprintf returns would-be length on truncation
	if(off < 0 || off >= (int)sizeof(line))
		off = sizeof(line) - 1;

	if(off > 0 && line[off - 1] != '\n')
		line[off++] = '\n';

	return write_log_line(&dnsmasq_log, line, off);
}

void __attribute__ ((format (printf, 3, 4))) _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...)
{
	char timestring[TIMESTR_SIZE];
	const time_t now = time(NULL);
	va_list args;

	// We have been explicitly asked to not print anything to the log
	if(!print_log && !print_stdout)
		return;

	// Get human-readable time
	get_timestr(timestring, now, true, false);

	// Get and log PID of current process to avoid ambiguities when more than one
	// pihole-FTL instance is logging into the same file
	char idstr[42];
	get_idstr(idstr, sizeof(idstr));
	const char *prio = priostr(priority, flag);

	// Print to stdout before writing to file
	// Skip human-readable output when structured logging (JSON) is active
	if((!daemonmode || cli_mode) && print_stdout && config.files.log.destination.v.log_destination != LOG_DEST_JSON)
	{
		// Only print time/ID string when not in direct user interaction (CLI mode)
		if(!cli_mode)
			printf("%s [%s] %s: ", timestring, idstr, prio);
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
		add_to_fifo_buffer(FIFO_FTL, buffer, prio, len > MAX_MSG_FIFO ? MAX_MSG_FIFO : len);

		// Route to JSON output (in addition to file logging)
		if(config.files.log.destination.v.log_destination == LOG_DEST_JSON && !daemonmode)
		{
			char json_buffer[8192];
			va_start(args, format);
			vsnprintf(json_buffer, sizeof(json_buffer), format, args);
			va_end(args);

			log_to_json(now, prio, "FTL", idstr, json_buffer);
		}

		// Write to log file only when file logging is explicitly selected
		if(config.files.log.destination.v.log_destination == LOG_DEST_FILE)
		{
			// Format full line and write to cached fd
			char line[2048];
			int off = snprintf(line, sizeof(line), "%s [%s] %s: ", timestring, idstr, prio);

			// Clamp before using off as an offset - snprintf returns the would-be
			// length on truncation and sizeof(line) - off would underflow otherwise;
			// it may also return negative on an encoding error
			if(off < 0 || off >= (int)sizeof(line))
				off = sizeof(line) - 1;

			va_start(args, format);
			off += vsnprintf(line + off, sizeof(line) - off, format, args);
			va_end(args);

			// Clamp to buffer end - snprintf returns would-be length on truncation
			if(off < 0 || off >= (int)sizeof(line))
				off = sizeof(line) - 1;

			line[off++] = '\n';

			if(!write_log_line(&ftl_log, line, off))
			{
				// Fallback: syslog if fd is unavailable or write failed
				va_start(args, format);
				vsyslog(priority, format, args);
				va_end(args);
			}
		}
	}
}

void __attribute__ ((format (printf, 3, 4))) _log_web(const int priority, const enum debug_flag flag, const char *format, ...)
{
	// We have been explicitly asked to not print anything to the log
	if(!print_log && !print_stdout)
		return;

	char timestring[TIMESTR_SIZE];
	const time_t now = time(NULL);
	va_list args;

	// Get human-readable time
	get_timestr(timestring, now, true, false);

	// Get and log PID of current process to avoid ambiguities when more than one
	// pihole-FTL instance is logging into the same file
	char idstr[42];
	get_idstr(idstr, sizeof(idstr));
	const char *prio = priostr(priority, flag);

	// Print to stdout before writing to file
	if((!daemonmode || cli_mode) && print_stdout)
	{
		// Only print time/ID string when not in direct user interaction (CLI mode)
		if(!cli_mode)
			printf("%s [%s] %s: ", timestring, idstr, prio);
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
		printf("\n");
	}

	// Print to log file or FIFO
	if(print_log)
	{
		// Add line to FIFO buffer
		char buffer[MAX_MSG_FIFO + 1u];
		va_start(args, format);
		const size_t len = vsnprintf(buffer, MAX_MSG_FIFO, format, args) + 1u; /* include zero-terminator */
		va_end(args);
		add_to_fifo_buffer(FIFO_WEBSERVER, buffer, prio, len > MAX_MSG_FIFO ? MAX_MSG_FIFO : len);

		// Route to JSON output (in addition to file logging)
		if(config.files.log.destination.v.log_destination == LOG_DEST_JSON && !daemonmode)
		{
			char json_buffer[8192];
			va_start(args, format);
			vsnprintf(json_buffer, sizeof(json_buffer), format, args);
			va_end(args);

			log_to_json(now, prio, "webserver", idstr, json_buffer);
		}

		// Write to log file only when file logging is explicitly selected
		if(config.files.log.destination.v.log_destination == LOG_DEST_FILE)
		{
			// Format full line and write to cached fd
			char line[2048];
			int off = snprintf(line, sizeof(line), "%s [%s] %s: ", timestring, idstr, prio);
			va_start(args, format);
			off += vsnprintf(line + off, sizeof(line) - off, format, args);
			va_end(args);

			// Clamp to buffer end - snprintf returns would-be length on truncation
			if(off < 0 || off >= (int)sizeof(line))
				off = sizeof(line) - 1;

			line[off++] = '\n';

			if(!write_log_line(&webserver_log, line, off) && priority <= LOG_WARNING)
			{
				// No web log available - keep severe messages durable
				_FTL_log(priority, flag, "%s", buffer);
			}
		}
	}
}

// Log helper activity (may be script or lua)
void FTL_log_helper(const unsigned int n, ...)
{
	// Only log helper debug messages if enabled
	if(!(config.debug.helper.v.b))
		return;

	// Extract all variable arguments
	va_list args;
	char **arg = calloc(n, sizeof(char*));
	va_start(args, n);
	for(unsigned int i = 0; i < n; i++)
	{
		char *argin = va_arg(args, char*);
		if(argin == NULL)
			arg[i] = NULL;
		else
			arg[i] = argin;
	}

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
	va_end(args);
	free(arg);
}

void format_memory_size(char prefix[2], const off_t bytes, double * const formatted)
{
	unsigned int i;
	*formatted = bytes;
	// Determine exponent for human-readable display
	const char prefixes[] = { '\0', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y', 'R', '?' };
	for(i = 0; i < sizeof(prefixes)/sizeof(*prefixes) - 1; i++)
	{
		if(*formatted <= 1024.0)
			break;
		*formatted /= 1024.0;
	}
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
	log_info(" -> Total DNS queries: %u", counters->queries);
	log_info(" -> Cached DNS queries: %u", get_cached_count());
	log_info(" -> Forwarded DNS queries: %u", get_forwarded_count());
	log_info(" -> Blocked DNS queries: %u", get_blocked_count());
	log_info(" -> Unknown DNS queries: %u", counters->status[QUERY_UNKNOWN]);
	log_info(" -> Unique domains: %u", counters->domains);
	log_info(" -> Unique clients: %u", counters->clients);
	log_info(" -> DNS cache records: %u", counters->dns_cache_size);
	log_info(" -> Known forward destinations: %u", counters->upstreams);
}

void log_FTL_version(const bool crashreport)
{
	log_info("FTL branch: %s", git_branch());
	log_info("FTL version: %s", get_FTL_version());
	log_info("FTL commit: %s", git_hash());
	log_info("FTL date: %s", git_date());
	if(crashreport)
	{
		char *username_now = getUserName();
		log_info("FTL user: started as %s, ended as %s", username, username_now);
		free(username_now);
	}
	else
		log_info("FTL user: %s", username);
	log_info("Compiled for %s using %s", ftl_arch(), ftl_cc());
}

static char *FTLversion = NULL;
const char __attribute__ ((malloc)) *get_FTL_version(void)
{
	// Obtain FTL version if not already determined
	if(FTLversion == NULL)
	{
		if(strlen(git_tag()) > 1 )
		{
			if (strlen(git_version()) > 1)
			{
				// Copy version string if this is a tagged release
				FTLversion = strdup(git_version());
			}

		}
		else if(strlen(git_hash()) > 0)
		{
			// Build special version string when there is a hash
			FTLversion = calloc(13, sizeof(char));
			// Build version by appending 7 characters of the hash to "vDev-"
			snprintf(FTLversion, 13, "vDev-%.7s", git_hash());
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
	case 1: // If the units digit is 1: This is written after the number "1st"
		return "st";
	case 2: // If the units digit is 2: This is written after the number "2nd"
		return "nd";
	case 3: // If the units digit is 3: This is written after the number "3rd"
		return "rd";
	default: // If the units digit is 0 or 4-9: This is written after the number "9th"
		return "th";
	}
	// For example: 2nd, 7th, 20th, 23rd, 52nd, 135th, 301st BUT 311th (covered above)
}

// Converts a buffer of specified length to ASCII representation as it was a C
// string literal. Returns how much bytes from source was processed
// Inspired by https://stackoverflow.com/a/56123950
static int binbuf_to_escaped_C_literal(const char *src_buf, size_t src_sz,
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
		// Check if we have enough space before writing
		// Worst case: we need 4 chars for "0x00" + null terminator for
		// one byte of input
		if (dst > dst_str + dst_sz - 5)
			break;

		if (isprint(*src))
		{
			// The printable characters are:
			// ! " # $ % & ' ( ) * + , - . / 0 1 2 3 4 5 6 7 8 9 : ;
			// < = > ? @ A B C D E F G H I J K L M N O P Q R S T U V
			// W X Y Z [ \ ] ^ _ ` a b c d e f g h i j k l m n o p q
			// r s t u v w x y z { | } ~
			*dst++ = *src++;
		}
		else
		{
			// Handle special characters
			switch(*src)
			{
				case '\\':
					*dst++ = '\\';
					*dst++ = '\\';
					break;
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
					sprintf(dst, "\\x%02X", (unsigned char)*src);
					dst += 4;
					break;
			}
			src++;
		}
	}

	// Zero-terminate buffer
	*dst = '\0';

	return src - src_buf;
}

/**
 * @brief Escapes a given input string into a C-style escaped string literal.
 *
 * This function takes an input string and returns a newly allocated string
 * where all characters are escaped as necessary to form a valid C string literal.
 * The returned string must be freed by the caller.
 *
 * @param input The input string to escape. May be NULL.
 * @return A pointer to the newly allocated escaped string, or NULL if input is NULL
 *         or memory allocation fails.
 *
 * @note The returned string is allocated with calloc and must be freed by the caller.
 * @note Uses binbuf_to_escaped_C_literal to perform the actual escaping.
 */
char * __attribute__ ((malloc)) escape_string(const char *input)
{
	return input == NULL ? NULL : escape_data(input, strlen(input));
}

/**
 * @brief Escapes binary data to be printable as a C string literal.
 *
 * This function allocates a new string and converts the input buffer into an escaped
 * C string literal, suitable for safe printing or logging. Each character in the source
 * buffer may be escaped, so the output buffer is allocated with enough space for the
 * worst-case scenario (every character is escaped as \xNN).
 *
 * @param src_buf Pointer to the source buffer to escape.
 * @param src_sz  Size of the source buffer in bytes.
 * @return Pointer to the newly allocated escaped string, or NULL on allocation or conversion failure.
 *         The returned string must be freed by the caller.
 */
char * __attribute__((malloc)) escape_data(const char *src_buf, size_t src_sz)
{
	// Allocate memory for the escaped string
	char *escaped_str = malloc(src_sz * 4 + 1); // Worst case: every char is escaped
	if(!escaped_str)
		return NULL;

	// Convert buffer to escaped C literal
	const int processed = binbuf_to_escaped_C_literal(src_buf, src_sz, escaped_str, src_sz * 4 + 1);
	if(processed < 0)
	{
		free(escaped_str);
		return NULL;
	}

	return escaped_str;
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
static const char *skipStr(const char *startstr, const char *message)
{
	const size_t startlen = strlen(startstr);
	if(strncmp(startstr, message, startlen) == 0)
		return message + startlen;
	else
		return message;
}

void dnsmasq_diagnosis_warning(const char *message)
{
	// Crop away any existing initial "warning: "
	logg_warn_dnsmasq_message(skipStr("warning: ", message));
}

void add_to_fifo_buffer(const enum fifo_logs which, const char *payload, const char *prio, const size_t length)
{
	const double now = double_time();

	// Do not try to log when shared memory isn't initialized yet
	if(!fifo_log)
		return;

	// Nothing to store. A zero length would index message[idx][-1] when
	// looking for a trailing newline below, so drop the record entirely
	// rather than consuming a slot for it
	if(payload == NULL || length == 0)
		return;

	unsigned int idx = fifo_log->logs[which].next_id++;
	if(idx >= LOG_SIZE)
	{
		// Log is full, move everything one slot forward to make space for a new record at the end
		// This pruges the oldest message from the list (it is overwritten by the second message)
		memmove(&fifo_log->logs[which].message[0][0], &fifo_log->logs[which].message[1][0], (LOG_SIZE - 1u) * MAX_MSG_FIFO);
		memmove(&fifo_log->logs[which].prio[0], &fifo_log->logs[which].prio[1], (LOG_SIZE - 1u) * sizeof(fifo_log->logs[which].prio[0]));
		memmove(&fifo_log->logs[which].timestamp[0], &fifo_log->logs[which].timestamp[1], (LOG_SIZE - 1u) * sizeof(fifo_log->logs[which].timestamp[0]));
		idx = LOG_SIZE - 1u;
	}

	// Copy string
	// We need to use the pre-allocated buffer in shared memory as we share
	// this FIFO with forks and friends, so we can't use strdup()
	// Reserve one byte for the NUL terminator so we never write past the end
	// of message[idx] (which is MAX_MSG_FIFO bytes, indices 0..MAX_MSG_FIFO-1)
	size_t copybytes = length < (MAX_MSG_FIFO - 1u) ? length : (MAX_MSG_FIFO - 1u);
	memcpy(fifo_log->logs[which].message[idx], payload, copybytes);

	// Zero-terminate buffer, truncate newline if found
	if(fifo_log->logs[which].message[idx][copybytes - 1u] == '\n')
		fifo_log->logs[which].message[idx][copybytes - 1u] = '\0';
	else
		fifo_log->logs[which].message[idx][copybytes] = '\0';

	// Replace last bytes by "...\0" if we truncated the message
	if(length >= MAX_MSG_FIFO)
	{
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 4] = '.';
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 3] = '.';
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 2] = '.';
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 1] = '\0';
	}

	// Set timestamp
	fifo_log->logs[which].timestamp[idx] = now;

	// Set prio (if available)
	fifo_log->logs[which].prio[idx] = prio;
}

bool flush_dnsmasq_log(void)
{
	const double mintime = double_time();
	int trunc_err = 0;

	// Lock shared memory
	lock_shm();

	// Truncate pihole.log via its cached fd; O_APPEND appends future writes
	// to the empty file.  Lock order stays SHM first, then the per-file lock.
	pthread_mutex_lock(&dnsmasq_log.lock);
	if(dnsmasq_log.fd == -1)
		trunc_err = -1;          // no log file open
	else if(ftruncate(dnsmasq_log.fd, 0) == -1)
		trunc_err = errno;       // the fd stays usable for future writes
	pthread_mutex_unlock(&dnsmasq_log.lock);

	// Flush the FIFO, in-memory datastructure and database even if the
	// truncation above failed; the log file is then just left non-empty
	if(fifo_log)
		memset(&fifo_log->logs[FIFO_DNSMASQ], 0, sizeof(fifo_log->logs[FIFO_DNSMASQ]));

	// Clean internal datastructure
	runGC(time(NULL), NULL, true);

	// Unlock shared memory
	unlock_shm();

	// Report a failed truncation now that the SHM lock is released
	if(trunc_err == -1)
		log_warn("Could not truncate pihole.log: no log file is open");
	else if(trunc_err > 0)
		log_err("Could not truncate log file %s: %s", dnsmasq_log.path, strerror(trunc_err));

	// Flush last 24 hours of on-disk database
	if(!delete_old_queries_from_db(false, mintime))
	{
		log_err("Could not flush on-disk database");
		return false;
	}

	if(trunc_err != 0)
		return false;

	log_info("Log has been flushed due to API request");

	return true;
}
