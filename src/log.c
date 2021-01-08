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
#include "config.h"
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

static bool locks_initialized = false;
static pthread_mutex_t FTL_log_lock, web_log_lock;
static FILE *logfile = NULL;
static bool FTL_log_ready = false;
static bool print_log = true, print_stdout = true;

void log_ctrl(bool plog, bool pstdout)
{
	print_log = plog;
	print_stdout = pstdout;
}

static void close_FTL_log(void)
{
	if(logfile != NULL)
		fclose(logfile);
}

static void initialize_locks(void)
{
	// Initialize logging mutex
	if (pthread_mutex_init(&FTL_log_lock, NULL) != 0)
	{
		printf("FATAL: Log mutex init for FTL failed\n");
		// Return failure
		exit(EXIT_FAILURE);
	}

	if (pthread_mutex_init(&web_log_lock, NULL) != 0)
	{
		printf("FATAL: Log mutex init for web failed\n");
		// Return failure
		exit(EXIT_FAILURE);
	}
}

void open_FTL_log(const bool init)
{
	if(!locks_initialized)
		initialize_locks();

	if(init)
		// Obtain log file location
		getLogFilePath();

	// Open the log file in append/create mode
	logfile = fopen(FTLfiles.log, "a+");
	if((logfile == NULL) && init){
		syslog(LOG_ERR, "Opening of FTL\'s log file failed!");
		printf("FATAL: Opening of FTL log (%s) failed!\n",FTLfiles.log);
		printf("       Make sure it exists and is writeable by user %s\n", username);
		// Return failure
		exit(EXIT_FAILURE);
	}

	// Set log as ready (we were able to open it)
	FTL_log_ready = true;

	if(init)
	{
		close_FTL_log();
	}
}

// The size of 84 bytes has been carefully selected for all possible timestamps
// to always fit into the available space without buffer overflows
void get_timestr(char * const timestring, const time_t timein)
{
	struct tm tm;
	localtime_r(&timein, &tm);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	const int millisec = tv.tv_usec/1000;

	sprintf(timestring,"%d-%02d-%02d %02d:%02d:%02d.%03i",
	        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	        tm.tm_hour, tm.tm_min, tm.tm_sec, millisec);
}

static void open_web_log(const enum web_code code)
{
	if(!locks_initialized)
		initialize_locks();

	// Open the log file in append/create mode
	char *file = NULL;
	switch (code)
	{
	case HTTP_INFO:
		file = httpsettings.log_info;
		break;
	case PH7_ERROR:
		file = httpsettings.log_error;
		break;
	default:
		file = httpsettings.log_error;
		break;
	}

	logfile = fopen(file, "a+");
}

void _FTL_log(const bool newline, const char *format, ...)
{
	char timestring[84] = "";
	va_list args;

	// We have been explicitly asked to not print anything to the log
	if(!print_log && !print_stdout)
		return;

	pthread_mutex_lock(&FTL_log_lock);

	get_timestr(timestring, time(NULL));

	// Get and log PID of current process to avoid ambiguities when more than one
	// pihole-FTL instance is logging into the same file
	char idstr[42];
	const int pid = getpid(); // Get the process ID of the calling process
	const int mpid = main_pid(); // Get the process ID of the main FTL process
	const int tid = gettid(); // Get the thread ID of the callig process

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
			printf("[%s %s] ", timestring, idstr);
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
		if(newline)
			printf("\n");
	}

	if(print_log && FTL_log_ready)
	{
		// Open log file
		open_FTL_log(false);

		// Write to log file
		if(logfile != NULL)
		{
			fprintf(logfile, "[%s %s] ", timestring, idstr);
			va_start(args, format);
			vfprintf(logfile, format, args);
			va_end(args);
			fputc('\n',logfile);
		}
		else if(!daemonmode)
		{
			printf("!!! WARNING: Writing to FTL\'s log file failed!\n");
			syslog(LOG_ERR, "Writing to FTL\'s log file failed!");
		}
	}

	// Close log file
	close_FTL_log();
	pthread_mutex_unlock(&FTL_log_lock);
}

void __attribute__ ((format (gnu_printf, 2, 3))) logg_web(enum web_code code, const char *format, ...)
{
	char timestring[84] = "";
	va_list args;

	pthread_mutex_lock(&web_log_lock);

	get_timestr(timestring, time(NULL));

	// Get and log PID of current process to avoid ambiguities when more than one
	// pihole-FTL instance is logging into the same file
	const long pid = (long)getpid();

	// Open log file
	open_web_log(code);

	// Write to log file
	if(logfile != NULL)
	{
		fprintf(logfile, "[%s %ld] ", timestring, pid);
		va_start(args, format);
		vfprintf(logfile, format, args);
		va_end(args);
		fputc('\n',logfile);
	}
	else if(!daemonmode)
	{
		printf("!!! WARNING: Writing to web log file failed!\n");
		syslog(LOG_ERR, "Writing to web log file failed!");
	}

	// Close FTL log file
	close_FTL_log();
	pthread_mutex_unlock(&web_log_lock);
}

// Log helper activity (may be script or lua)
void FTL_log_helper(const unsigned char n, ...)
{
	// Only log helper debug messages if enabled
	if(!(config.debug & DEBUG_HELPER))
		return;

	// Extract all variable arguments
	va_list args;
	char *arg[n];
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
			logg("Script: Starting helper for action \"%s\"", arg[0]);
			break;
		case 2:
			logg("Script: FAILED to execute \"%s\": %s", arg[0], arg[1]);
			break;
		case 5:
			logg("Script: Executing \"%s\" with arguments: \"%s %s %s %s\"",
			     arg[0], arg[1], arg[2], arg[3], arg[4]);
			break;
		default:
			logg("ERROR: Unsupported number of arguments passed to FTL_log_helper(): %u", n);
			break;
	}

	// Free allocated memory
	for(unsigned char i = 0; i < n; i++)
		if(arg[i] != NULL)
			free(arg[i]);
}

void format_memory_size(char * const prefix, const unsigned long long int bytes,
                        double * const formated)
{
	unsigned int i;
	*formated = bytes;
	// Determine exponent for human-readable display
	for(i = 0; i < 7; i++)
	{
		if(*formated <= 1e3)
			break;
		*formated /= 1e3;
	}
	const char* prefixes[8] = { "", "K", "M", "G", "T", "P", "E", "?" };
	// Chose matching SI prefix
	strcpy(prefix, prefixes[i]);
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
	logg(" -> Total DNS queries: %i", counters->queries);
	logg(" -> Cached DNS queries: %i", counters->cached);
	logg(" -> Forwarded DNS queries: %i", counters->forwarded);
	logg(" -> Blocked DNS queries: %i", counters->blocked);
	logg(" -> Unknown DNS queries: %i", counters->unknown);
	logg(" -> Unique domains: %i", counters->domains);
	logg(" -> Unique clients: %i", counters->clients);
	logg(" -> Known forward destinations: %i", counters->upstreams);
}

void log_FTL_version(const bool crashreport)
{
	logg("FTL branch: %s", GIT_BRANCH);
	logg("FTL version: %s", get_FTL_version());
	logg("FTL commit: %s", GIT_HASH);
	logg("FTL date: %s", GIT_DATE);
	if(crashreport)
		logg("FTL user: started as %s, ended as %s", username, getUserName());
	else
		logg("FTL user: %s", username);
	logg("Compiled for %s using %s", FTL_ARCH, FTL_CC);
}

static char *FTLversion = NULL;
const char __attribute__ ((malloc)) *get_FTL_version(void)
{
	// Obtain FTL version if not already determined
	if(FTLversion == NULL)
	{
		if(strlen(GIT_TAG) > 1)
		{
			FTLversion = strdup(GIT_VERSION);
		}
		else
		{
			FTLversion = calloc(13, sizeof(char));
			// Build version by appending 7 characters of the hash to "vDev-"
			snprintf(FTLversion, 13, "vDev-%.7s", GIT_HASH);
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
