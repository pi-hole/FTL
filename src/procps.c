/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  /proc system subroutines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "procps.h"
#include "log.h"
#include <dirent.h>
// getpid()
#include <unistd.h>

#define PROCESS_NAME   "pihole-FTL"

static bool get_process_name(const pid_t pid, char name[128])
{
	if(pid == 0)
	{
		strcpy(name, "init");
		return true;
	}

	// Try to open comm file
	char filename[sizeof("/proc/%u/task/%u/comm") + sizeof(int)*3 * 2];
	snprintf(filename, sizeof(filename), "/proc/%d/comm", pid);
	FILE *f = fopen(filename, "r");
	if(f == NULL)
		return false;

	// Read name from opened file
	if(fscanf(f, "%128s", name) != 1)
		false;
	fclose(f);

	return true;
}


static bool get_process_ppid(const pid_t pid, pid_t *ppid)
{
	// Try to open status file
	char filename[sizeof("/proc/%u/task/%u/comm") + sizeof(int)*3 * 2];
	snprintf(filename, sizeof(filename), "/proc/%d/status", pid);
	FILE *f = fopen(filename, "r");
	if(f == NULL)
		return false;

	// Read comm from opened file
	char buffer[128];
	while(fgets(buffer, sizeof(buffer), f) != NULL)
	{
		if(sscanf(buffer, "PPid: %d\n", ppid) == 1)
			break;
	}
	fclose(f);

	return true;
}

static bool get_process_creation_time(const pid_t pid, char timestr[84])
{
	// Try to open comm file
	char filename[sizeof("/proc/%u/task/%u/comm") + sizeof(int)*3 * 2];
	snprintf(filename, sizeof(filename), "/proc/%d/comm", pid);
	struct stat st;
	if(stat(filename, &st) < 0)
		return false;
	get_timestr(timestr, st.st_ctim.tv_sec, false);

	return true;
}

void check_running_FTL(void)
{
	//pid_t pid;
	DIR *dirPos;
	struct dirent *entry;

	// Open /proc
	errno = 0;
	if ((dirPos = opendir("/proc")) == NULL)
	{
		logg("Dailed to access /proc: %s", strerror(errno));
		return;
	}

	// Loop over entries in /proc
	// This is much more efficient than iterating over all possible PIDs
	while ((entry = readdir(dirPos)) != NULL)
	{
		// We are only interested in subdirectories of /proc
		if(entry->d_type != DT_DIR)
			continue;
		// We are only interested in PID subdirectories
		if(entry->d_name[0] < '0' || entry->d_name[0] > '9')
			continue;

		// Extract PID
		const pid_t pid = strtol(entry->d_name, NULL, 10);

		// Skip our own process
		if(pid == getpid())
			continue;

		// Get process name
		char name[128] = { 0 };
		if(!get_process_name(pid, name))
			continue;

		// Get parent process ID (PPID)
		pid_t ppid;
		if(!get_process_ppid(pid, &ppid))
			continue;
		char ppid_name[128] = { 0 };
		if(!get_process_name(ppid, ppid_name))
			continue;

		char timestr[84] = { 0 };
		get_process_creation_time(pid, timestr);

		// Log this process if it is a duplicate of us
		if(strcasecmp(name, PROCESS_NAME) == 0)
			logg("---> %s is already running as PID %d (started %s, child of PID %i (%s))",
			     PROCESS_NAME, pid, timestr, ppid, ppid_name);
	}

	closedir(dirPos);
}
