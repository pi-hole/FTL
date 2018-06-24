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

pthread_mutex_t lock;
FILE *logfile = NULL;

void close_FTL_log(void)
{
	if(logfile != NULL)
		fclose(logfile);
}

void open_FTL_log(bool test)
{
	// Open a log file in append/create mode
	logfile = fopen(FTLfiles.log, "a+");
	if((logfile == NULL) && test){
		syslog(LOG_ERR, "Opening of FTL\'s log file failed!");
		printf("FATAL: Opening of FTL log (%s) failed!\n",FTLfiles.log);
		printf("       Make sure it exists and is writeable by user %s\n", username);
		// Return failure
		exit(EXIT_FAILURE);
	}

	if(test)
	{
		if (pthread_mutex_init(&lock, NULL) != 0)
		{
			printf("FATAL: Log mutex init failed\n");
			// Return failure
			exit(EXIT_FAILURE);
		}
		close_FTL_log();
	}
}

void get_timestr(char *timestring)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int millisec = tv.tv_usec/1000;

	sprintf(timestring,"%d-%02d-%02d %02d:%02d:%02d.%03i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec);
}

void logg(const char *format, ...)
{
	char timestring[32] = "";
	va_list args;

	pthread_mutex_lock(&lock);

	get_timestr(timestring);

	// Print to stdout before writing to file
	if(debug)
	{
		printf("[%s] ", timestring);
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
		printf("\n");
	}

	// Open log file
	open_FTL_log(false);

	// Write to log file
	if(logfile != NULL)
	{
		fprintf(logfile, "[%s] ", timestring);
		va_start(args, format);
		vfprintf(logfile, format, args);
		va_end(args);
		fputc('\n',logfile);
	}
	else if(debug)
	{
		printf("!!! WARNING: Writing to FTL\'s log file failed!\n");
		syslog(LOG_ERR, "Writing to FTL\'s log file failed!");
	}

	// Close log file
	close_FTL_log();

	pthread_mutex_unlock(&lock);
}

void format_memory_size(char *prefix, unsigned long int bytes, double *formated)
{
	int i;
	*formated = bytes;
	// Determine exponent for human-readable display
	for(i=0; i < 7; i++)
	{
		if(*formated <= 1e3)
			break;
		*formated /= 1e3;
	}
	const char* prefixes[8] = { "", "K", "M", "G", "T", "P", "E", "?" };
	// Chose matching SI prefix
	strcpy(prefix, prefixes[i]);
}

void logg_struct_resize(const char* str, int to, int step)
{
	logg("Notice: Increasing %s struct size from %i to %i", str, (to-step), to);
}

void log_counter_info(void)
{
	logg(" -> Total DNS queries: %i", counters.queries);
	logg(" -> Cached DNS queries: %i", counters.cached);
	logg(" -> Forwarded DNS queries: %i", counters.forwardedqueries);
	logg(" -> Exactly blocked DNS queries: %i", counters.blocked);
	logg(" -> Unknown DNS queries: %i", counters.unknown);
	logg(" -> Unique domains: %i", counters.domains);
	logg(" -> Unique clients: %i", counters.clients);
	logg(" -> Known forward destinations: %i", counters.forwarded);
}

void log_FTL_version(void)
{
	logg("FTL branch: %s", GIT_BRANCH);
	logg("FTL version: %s", GIT_TAG);
	logg("FTL commit: %s", GIT_HASH);
	logg("FTL date: %s", GIT_DATE);
	logg("FTL user: %s", username);
}
