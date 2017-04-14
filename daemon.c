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

int detect_FTL_process(void)
{
	DIR* dir = opendir("/proc");

	if(dir)
	{
		struct dirent* de = 0;
		while((de = readdir(dir)) != 0)
		{
			// Skip "." and ".."
			if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
				continue;

			int pid = -1;
			if(sscanf(de->d_name, "%d", &pid) == 1)
			{
				// Test if that is our own process
				if(pid == getpid())
					continue;

				char buffer[512] = { 0 };
				sprintf(buffer, "/proc/%d/cmdline", pid);

				FILE* fp;
				if((fp = fopen(buffer, "r")) != NULL)
				{
					if (fgets(buffer, sizeof(buffer), fp) != NULL)
					{
						if (strstr(buffer, "pihole-FTL") != 0)
						{
							fclose(fp);
							logg("%i - %s", pid, buffer);
							return pid;
						}
					}
					fclose(fp);
				}
			}
		}
		closedir(dir);
	}
	return -1;
}

void test_singularity(void)
{
	if(runtest)
	{
		if(detect_FTL_process() > -1)
		{
			printf("Yes: Found a running FTL process\n");
			exit(EXIT_FAILURE);
		}
		else
		{
			printf("No: Did not find a running FTL process\n");
			exit(EXIT_SUCCESS);
		}
	}

	int pid;
	while((pid = detect_FTL_process()) > -1)
	{
		printf("Found pihole-FTL process with PID %i (my PID %i) - killing it ...\n", pid, getpid());
		logg("Found pihole-FTL process with PID %i (my PID %i) - killing it ...", pid, getpid());
		if(kill(pid, SIGTERM) != 0)
		{
			printf("Killing failed (%s) ... Exiting now ...\n", strerror(errno));
			logg("Killing failed (%s) ... Exiting now ...", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	logg("Found no other running pihole-FTL process");
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

	// Create grandchild process
	// Fork a second child and exit immediately to prevent zombies.  This
	// causes the second child process to be orphaned, making the init
	// process responsible for its cleanup.  And, since the first child is
	// a session leader without a controlling terminal, it's possible for
	// it to acquire one by opening a terminal in the future (System V-
	// based systems).  This second fork guarantees that the child is no
	// longer a session leader, preventing the daemon from ever acquiring
	// a controlling terminal.
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
		// return success in exit status
		exit(EXIT_SUCCESS);
	}

	savepid();

	// Change the current working directory
	if(chdir("/etc/pihole") != 0)
	{
		logg("FATAL: Cannot change directory to /etc/pihole. Error code: %i",errno);
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
