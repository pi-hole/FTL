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

void test_singularity(void)
{
	FILE *f;
	if((f = fopen(FTLfiles.pid, "r")) == NULL)
	{
		if(!runtest)
		{
			logg("WARNING: Unable to read PID from file (cannot open file).");
			logg("         Cannot test if another FTL process is running!");
			return;
		}
		else
		{
			printf("Unknown: Unable to open PID file\n");
			exit(EXIT_FAILURE);
		}
	}
	// Test if any process has the given PID
	// We use getpgid() since we are allowed to inspect the
	// process group ID even for processes that don't belong to us
	int pid;
	if(fscanf(f,"%d",&pid) != 1)
	{
		if(!runtest)
		{
			logg("WARNING: Unable to read PID from file (cannot read PID from file).");
			logg("         Cannot test if another FTL process is running!");
			fclose(f);
			return;
		}
		else
		{
			printf("Unknown: Unable to read PID from file\n");
			exit(EXIT_FAILURE);
		}
	}
	fclose(f);

	// Test if another process is running
	if (getpgid(pid) >= 0) {
		if(!runtest)
		{
			printf("FATAL: Another FTL process is already running (PID %i)! Exiting...\n",pid);
			logg_int("FATAL: Another FTL process is already running: ",pid);
			exit(EXIT_FAILURE);
		}
		else
		{
			printf("Yes: Found a running FTL process\n");
			exit(EXIT_FAILURE);
		}
	}
	// No other process found
	if(!runtest)
	{
		return;
	}
	else
	{
		printf("No: Did not find a running FTL process\n");
		exit(EXIT_SUCCESS);
	}
}

void go_daemon(void)
{
	pid_t process_id = 0;
	pid_t sid = 0;

	test_singularity();

	// Create child process
	process_id = fork();

	// Indication of fork() failure
	if (process_id < 0)
	{
		logg("fork failed!\n");
		// Return failure in exit status
		exit(EXIT_FAILURE);
	}

	// PARENT PROCESS. Need to kill it.
	if (process_id > 0)
	{
		printf("FTL started!\n");
		// return success in exit status
		exit(EXIT_SUCCESS);
	}

	//unmask the file mode
	umask(0);

	//set new session
	// creates a session and sets the process group ID
	sid = setsid();
	if(sid < 0)
	{
		// Return failure
		logg("setsid failed!\n");
		exit(EXIT_FAILURE);
	}
	savepid(sid);

	// Change the current working directory
	if(chdir("/etc/pihole") != 0)
	{
		logg_int("FATAL: Cannot change directory to /etc/pihole. Error code ",errno);
		// Return failure
		exit(EXIT_FAILURE);
	}

	// Close stdin, stdout and stderr
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

struct timeval t0, t1;

void timer_start(void)
{
	gettimeofday(&t0, 0);
}

float timer_elapsed_msec(void)
{
	gettimeofday(&t1, 0);
	return (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
}

void sleepms(int milliseconds)
{
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	select(0, NULL, NULL, NULL, &tv);
}

void savepid(pid_t sid)
{
	FILE *f;
	if((f = fopen(FTLfiles.pid, "w+")) == NULL)
	{
		logg("WARNING: Unable to write PID to file.");
		logg("         Continuing anyway...");
	}
	else
	{
		fprintf(f, "%i", (int)sid);
		fclose(f);
	}
	logg_int("PID of FTL process: ", (int)sid);
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
		username = calloc(strlen(pw->pw_name)+1, sizeof(char));
		strcpy(username, pw->pw_name);
	}
	else
	{
		username = calloc(12, sizeof(char));
		sprintf(username, "%i", euid);
	}

	return username;
}
