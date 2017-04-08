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
		close_FTL_log();
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
}

void format_memory_size(char *prefix, unsigned long int bytes, double *formated)
{
	int exponent = floor(log10(bytes)/3.);
	if(exponent > 0 && exponent < 7)
	{
		const char* prefixes[7] = { "", "K", "M", "G", "T", "P", "E" };
		strcpy(prefix, prefixes[exponent]);
		*formated = (double)bytes/pow(10.0,exponent*3.0);
	}
	else
	{
		strcpy(prefix, "");
		*formated = (double)bytes;
	}
}

void logg_struct_resize(const char* str, int to, int step)
{
	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata + memory.querytypedata;

	unsigned long int bytes = structbytes + dynamicbytes;
	char *prefix = calloc(2, sizeof(char));
	double formated = 0.0;
	format_memory_size(prefix, bytes, &formated);

	logg("Notice: Increasing %s struct size from %i to %i (%.2f %sB)", str, (to-step), to, formated, prefix);
	if(debug)
	{
		logg("        at query time: %s", timestamp);
	}
	free(prefix);
}

void log_counter_info(void)
{
	logg(" -> Total DNS queries: %i", counters.queries);
	logg(" -> Cached DNS queries: %i", counters.cached);
	logg(" -> Blocked DNS queries: %i", counters.blocked);
	logg(" -> Unknown DNS queries: %i", counters.unknown);
	logg(" -> Unique domains: %i", counters.domains);
	logg(" -> Unique clients: %i", counters.clients);
}
