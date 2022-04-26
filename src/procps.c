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

static bool get_process_name(const pid_t pid, char name[16])
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
	if(fscanf(f, "%15s", name) != 1)
		false;
	fclose(f);

	return true;
}


static bool get_process_ppid(const pid_t pid, pid_t *ppid)
{
	// Try to open status file
	char filename[sizeof("/proc/%u/task/%u/status") + sizeof(int)*3 * 2];
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

bool check_running_FTL(void)
{
	DIR *dirPos;
	struct dirent *entry;
	const pid_t ourselves = getpid();
	bool process_running = false;

	// Open /proc
	errno = 0;
	if ((dirPos = opendir("/proc")) == NULL)
	{
		logg("Failed to access /proc: %s", strerror(errno));
		return false;
	}

	// Loop over entries in /proc
	// This is much more efficient than iterating over all possible PIDs
	pid_t last_pid = 0;
	size_t last_len = 0u;
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
		if(pid == ourselves)
			continue;

		// Get process name
		char name[16] = { 0 };
		if(!get_process_name(pid, name))
			continue;

		// Only process this is this is our own process
		if(strcasecmp(name, PROCESS_NAME) != 0)
			continue;

		// Get parent process ID (PPID)
		pid_t ppid;
		if(!get_process_ppid(pid, &ppid))
			continue;
		char ppid_name[16] = { 0 };
		if(!get_process_name(ppid, ppid_name))
			continue;

		char timestr[84] = { 0 };
		get_process_creation_time(pid, timestr);

		// If this is the first process we log, add a header
		if(!process_running)
		{
			process_running = true;
			logg("HINT: %s is already running!", PROCESS_NAME);
		}

		if(last_pid != ppid)
		{
			// Independent process, may be child of init/systemd
			logg("%s (%d) ──> %s (PID %d, started %s)",
			     ppid_name, ppid, name, pid, timestr);
			last_pid = pid;
			last_len = snprintf(NULL, 0, "%s (%d) ──> ", ppid_name, ppid);
		}
		else
		{
			// Process parented by the one we analyzed before,
			// highlight their relationship
			logg("%*s └─> %s (PID %d, started %s)",
			     (int)last_len, "", name, pid, timestr);
		}
	}

	closedir(dirPos);
	return process_running;
}
