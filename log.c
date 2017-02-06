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

void open_FTL_log(void)
{
	// Open a log file in write mode.
	if((logfile = fopen(FTLfiles.log, "a+")) == NULL) {;
		printf("FATAL: Opening of FTL log (%s) failed!\n",FTLfiles.log);
		printf("       Make sure it exists and is writable using\n");
		// Return failure in exit status
		exit(1);
	}
}

void logg(const char* str)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int millisec = tv.tv_usec/1000;
	fprintf(logfile, "[%d-%02d-%02d %02d:%02d:%02d.%03i] %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str);
	fflush(logfile);
	if(debug)
		printf("[%d-%02d-%02d %02d:%02d:%02d.%03i] %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str);
}

void logg_int(const char* str, int i)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int millisec = tv.tv_usec/1000;
	fprintf(logfile, "[%d-%02d-%02d %02d:%02d:%02d.%03i] %s%i\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, i);
	fflush(logfile);
	if(debug)
		printf("[%d-%02d-%02d %02d:%02d:%02d.%03i] %s%i\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, i);
}

void logg_str(const char* str, char* str2)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int millisec = tv.tv_usec/1000;
	fprintf(logfile, "[%d-%02d-%02d %02d:%02d:%02d.%03i] %s%s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, str2);
	fflush(logfile);
	if(debug)
		printf("[%d-%02d-%02d %02d:%02d:%02d.%03i] %s%s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, str2);
}

void logg_str_str(const char* str, char* str2, char* str3)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int millisec = tv.tv_usec/1000;
	fprintf(logfile, "[%d-%02d-%02d %02d:%02d:%02d.%03i] %s%s (%s)\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, str2, str3);
	fflush(logfile);
	if(debug)
		printf("[%d-%02d-%02d %02d:%02d:%02d.%03i] %s%s (%s)\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, str2, str3);
}

void logg_struct_resize(const char* str, int from, int to)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int millisec = tv.tv_usec/1000;
	fprintf(logfile, "[%d-%02d-%02d %02d:%02d:%02d.%03i] Notice: Increasing %s struct size from %i to %i\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, from, to);
	fflush(logfile);
	if(debug)
		printf("[%d-%02d-%02d %02d:%02d:%02d.%03i] Notice: Increasing %s struct size from %i to %i\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec, str, from, to);
}

void log_counter_info(void)
{
	logg_int(" -> Total DNS queries: ", counters.queries);
	logg_int(" -> Cached DNS queries: ", counters.cached);
	logg_int(" -> Blocked DNS queries: ", counters.blocked);
	logg_int(" -> Unknown DNS queries: ", counters.unknown);
	logg_int(" -> Unique domains: ", counters.domains);
	logg_int(" -> Unique clients: ", counters.clients);
}
