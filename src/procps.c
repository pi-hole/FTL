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
#include <sys/times.h>

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
		log_warn("Failed to access /proc: %s", strerror(errno));
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
			log_info("%s is already running!", PROCESS_NAME);
		}

		if(last_pid != ppid)
		{
			// Independent process, may be child of init/systemd
			log_info("%s (%d) ──> %s (PID %d, started %s)",
			         ppid_name, ppid, name, pid, timestr);
			last_pid = pid;
			last_len = snprintf(NULL, 0, "%s (%d) ──> ", ppid_name, ppid);
		}
		else
		{
			// Process parented by the one we analyzed before,
			// highlight their relationship
			log_info("%*s └─> %s (PID %d, started %s)",
			         (int)last_len, "", name, pid, timestr);
		}
	}

	closedir(dirPos);
	return process_running;
}

bool read_self_memory_status(struct statm_t *result)
{
	const char* statm_path = "/proc/self/statm";

	FILE *f = fopen(statm_path,"r");
	if(!f){
		perror(statm_path);
		return false;
	}
	if(fscanf(f,"%lu %lu %lu %lu %lu %lu %lu",
	   &result->size, &result->resident, &result->shared,
	   &result->text, &result->lib, &result->data,
	   &result->dirty) != 7)
	{
		perror(statm_path);
		return false;
	}
	fclose(f);

	return true;
}

bool getProcessMemory(struct proc_mem *mem, const unsigned long total_memory)
{
	// Open /proc/self/status
	FILE *file = fopen("/proc/self/status", "r");
	if(file == NULL)
		return false;

	// Parse the entire file
	char line[256];
	while(fgets(line, sizeof(line), file))
	{
		sscanf(line, "VmRSS: %lu", &mem->VmRSS);
		sscanf(line, "VmHWM: %lu", &mem->VmHWM);
		sscanf(line, "VmSize: %lu", &mem->VmSize);
		sscanf(line, "VmPeak: %lu", &mem->VmPeak);
	}
	fclose(file);

	mem->VmRSS_percent = 100.0f * mem->VmRSS / total_memory;
	if(mem->VmRSS_percent > 99.9f)
		mem->VmRSS_percent = 99.9f;

	return true;
}

// Get RAM information in units of kB
// This is implemented similar to how free (procps) does it
bool parse_proc_meminfo(struct proc_meminfo *mem)
{
	long page_cached = -1, buffers = -1, slab_reclaimable = -1;
	FILE *meminfo = fopen("/proc/meminfo", "r");
	if(meminfo == NULL)
		return false;

	char line[256];
	while(fgets(line, sizeof(line), meminfo))
	{
		sscanf(line, "MemTotal: %lu kB", &mem->total);
		sscanf(line, "MemFree: %lu kB", &mem->mfree);
		sscanf(line, "MemAvailable: %lu kB", &mem->avail);
		sscanf(line, "Cached: %lu kB", &page_cached);
		sscanf(line, "Buffers: %lu kB", &buffers);
		sscanf(line, "SReclaimable: %lu kB", &slab_reclaimable);
	}
	fclose(meminfo);

	// Compute actual memory numbers
	mem->cached = page_cached + slab_reclaimable;

	// This logic is copied from procps (meminfo.c)
	// if mem->avail is greater than mem->total or our calculation of used
	// overflows, that's symptomatic of running within a lxc container where
	// such values will be dramatically distorted over those of the host.
	if (mem->avail > mem->total)
		mem->avail = mem->mfree;
	if (mem->total >= mem->mfree + mem->cached + buffers)
		mem->used = mem->total - mem->mfree - mem->cached - buffers;
	else
		mem->used = mem->total - mem->mfree;

	// Return success
	return true;
}
