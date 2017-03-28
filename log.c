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
		printf("       Make sure it exists\n");
		// Return failure in exit status
		exit(1);
	}
}

char timestring[32];
void get_timestr(void)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int millisec = tv.tv_usec/1000;

	sprintf(timestring,"%d-%02d-%02d %02d:%02d:%02d.%03i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millisec);
}

void logg(const char* str)
{
	get_timestr();

	fprintf(logfile, "[%s] %s\n", timestring, str);
	fflush(logfile);
	if(debug)
		printf("[%s] %s\n", timestring, str);
}

void logg_int(const char* str, int i)
{
	get_timestr();

	fprintf(logfile, "[%s] %s%i\n", timestring, str, i);
	fflush(logfile);
	if(debug)
		printf("[%s] %s%i\n", timestring, str, i);
}

void logg_str(const char* str, char* str2)
{
	get_timestr();

	fprintf(logfile, "[%s] %s%s\n", timestring, str, str2);
	fflush(logfile);
	if(debug)
		printf("[%s] %s%s\n", timestring, str, str2);
}

void logg_const_str(const char* str, const char* str2)
{
	get_timestr();

	fprintf(logfile, "[%s] %s%s\n", timestring, str, str2);
	fflush(logfile);
	if(debug)
		printf("[%s] %s%s\n", timestring, str, str2);
}

void logg_str_str(const char* str, char* str2, char* str3)
{
	get_timestr();

	fprintf(logfile, "[%s] %s%s (%s)\n", timestring, str, str2, str3);
	fflush(logfile);
	if(debug)
		printf("[%s] %s%s (%s)\n", timestring, str, str2, str3);
}

void logg_str_str_int(const char* str, char* str2, char* str3, int i)
{
	get_timestr();

	fprintf(logfile, "[%s] %s%s%s%i\n", timestring, str, str2, str3, i);
	fflush(logfile);
	if(debug)
		printf("[%s] %s%s%s%i\n", timestring, str, str2, str3, i);
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
	get_timestr();

	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata + memory.querytypedata;

	unsigned long int bytes = structbytes + dynamicbytes;
	char *prefix = calloc(2, sizeof(char));
	double formated = 0.0;
	format_memory_size(prefix, bytes, &formated);

	fprintf(logfile, "[%s] Notice: Increasing %s struct size from %i to %i (%.2f %sB)\n", timestring, str, (to-step), to, formated, prefix);
	fflush(logfile);
	if(debug)
		printf("[%s] Notice: Increasing %s struct size from %i to %i (%.2f %sB)\n", timestring, str, (to-step), to, formated, prefix);

	free(prefix);
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

void logg_bool(const char* str, bool b)
{
	get_timestr();
	fprintf(logfile, "[%s] %s: %s\n", timestring, str, b ? "true" : "false");
	fflush(logfile);
	if(debug)
		printf("[%s] %s: %s\n", timestring, str, b ? "true" : "false");
}
