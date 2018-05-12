/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Daemon routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include <dirent.h>

struct timeval t0[NUMTIMERS];

void timer_start(int i)
{
	if(i >= NUMTIMERS)
	{
		logg("Code error: Timer %i not defined in timer_start().", i);
		exit(EXIT_FAILURE);
	}
	gettimeofday(&t0[i], 0);
}

double timer_elapsed_msec(int i)
{
	if(i >= NUMTIMERS)
	{
		logg("Code error: Timer %i not defined in timer_elapsed_msec().", i);
		exit(EXIT_FAILURE);
	}
	struct timeval t1;
	gettimeofday(&t1, 0);
	return (t1.tv_sec - t0[i].tv_sec) * 1000.0f + (t1.tv_usec - t0[i].tv_usec) / 1000.0f;
}

void sleepms(int milliseconds)
{
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	select(0, NULL, NULL, NULL, &tv);
}

void savepid(void)
{
	FILE *f;
	pid_t pid = getpid();
	if((f = fopen(FTLfiles.pid, "w+")) == NULL)
	{
		logg("WARNING: Unable to write PID to file.");
		logg("         Continuing anyway...");
	}
	else
	{
		fprintf(f, "%i", (int)pid);
		fclose(f);
	}
	logg("PID of FTL process: %i", (int)pid);
}

void removepid(void)
{
	FILE *f;
	if((f = fopen(FTLfiles.pid, "w+")) == NULL)
	{
		logg("WARNING: Unable to empty PID file");
		return;
	}
	fclose(f);
}

char *getUserName(void)
{
	char * username;
	// the getpwuid() function shall search the user database for an entry with a matching uid
	// the geteuid() function shall return the effective user ID of the calling process - this is used as the search criteria for the getpwuid() function
	uid_t euid = geteuid();
	struct passwd *pw = getpwuid(euid);
	if(pw)
	{
		username = strdup(pw->pw_name);
	}
	else
	{
		if(asprintf(&username, "%i", euid) < 0)
			return NULL;
	}

	return username;
}
