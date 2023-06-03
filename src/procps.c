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
// config
#include "config/config.h"

#define PROCESS_NAME   "pihole-FTL"
#define PROC_PATH_SIZ  32

// This function tries to obtain the process name of a given PID
// It returns true on success, false otherwise and stores the process name in
// the given buffer
// The preferred mechanism is to use /proc/<pid>/exe, but if that fails, we try
// to parse /proc/<pid>/comm. The latter is not guaranteed to be correct (e.g.
// processes can easily change it themselves using prctl with PR_SET_NAME), but
// it is better than nothing.
static bool get_process_name(const pid_t pid, char name[PROC_PATH_SIZ])
{
	if(pid == 0)
	{
		strcpy(name, "init");
		return true;
	}

	// Try to open comm file
	char filename[sizeof("/proc/%d/exe") + sizeof(int)*3];
	snprintf(filename, sizeof(filename), "/proc/%d/exe", pid);

	// Read link destination
	ssize_t len = readlink(filename, name, PROC_PATH_SIZ);
	if(len > 0)
	{
		// If readlink() succeeded, terminate string
		name[len] = '\0';

		// Strip path from name
		char *ptr = strrchr(name, '/');
		if(ptr != NULL)
			memmove(name, ptr+1, len - (ptr - name));

		return true;
	}

	// If readlink() failed, try to open comm file
	snprintf(filename, sizeof(filename), "/proc/%d/comm", pid);
	FILE *f = fopen(filename, "r");
	if(f == NULL)
		return false;

	// Read name from opened file
	if(fscanf(f, "%15s", name) != 1)
	{
		fclose(f);
		return false;
	}

	// Close file
	fclose(f);

	return true;
}

// This function tries to obtain the parent process ID of a given PID
// It returns true on success, false otherwise and stores the parent PID in
// the given pid_t pointer
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

// This function tries to obtain the process creation time of a given PID
// It returns true on success, false otherwise and stores the creation time in
// the given buffer
static bool get_process_creation_time(const pid_t pid, char timestr[TIMESTR_SIZE])
{
	// Try to open comm file
	char filename[sizeof("/proc/%u/task/%u/comm") + sizeof(int)*3 * 2];
	snprintf(filename, sizeof(filename), "/proc/%d/comm", pid);
	struct stat st;
	if(stat(filename, &st) < 0)
		return false;
	get_timestr(timestr, st.st_ctim.tv_sec, false, false);

	return true;
}

// This function prints an info message about if another FTL process is already
// running. It returns true if another FTL process is already running, false
// otherwise.
bool check_running_FTL(void)
{
	DIR *dirPos;
	struct dirent *entry;
	const pid_t ourselves = getpid();
	bool already_running = false;
	pid_t pid = 0;

	// First we try to read the PID file and compare the PID in there with
	// our own PID. If the PID file does not exist or does not contain our
	// PID, we try to find another FTL process by looking at the process
	// list further down.
	if(config.files.pid.v.s != NULL)
	{
		FILE *pidFile = fopen(config.files.pid.v.s, "r");
		if(pidFile != NULL)
		{
			if(fscanf(pidFile, "%d", &pid) == 1)
			{
				if(pid == ourselves)
				{
					log_debug(DEBUG_SHMEM, "PID file contains our own PID");
				}
				else
				{
					// Note: kill(pid, 0) does not send a
					// signal, but merely checks if the
					// process exists If the process does
					// not exist, kill() returns -1 and sets
					// errno to ESRCH. However, if the
					// process exists, but security
					// restrictions tell the system to deny
					// its existence, we cannot distinguish
					// between the process not existing and
					// the process existing but being denied
					// to us. In that case, our fallback
					// solution below kicks in and iterates
					// over /proc instead.
					already_running = kill(pid, 0) == 0;
					log_debug(DEBUG_SHMEM, "PID file contains PID %d (%s), we are %d",
					          pid, already_running ? "running" : "dead", ourselves);
				}
			}
			else
			{
				log_debug(DEBUG_SHMEM, "Failed to parse PID in PID file");
			}
			fclose(pidFile);
		}
		else
		{
			log_debug(DEBUG_SHMEM, "Failed to open PID file");
		}
	}

	// If already_running is true, we are done
	if(already_running)
	{
		log_info("%s is already running (PID %d)!", PROCESS_NAME, pid);
		return true;
	}

	// If the PID file does not contain our own PID, we try to find a running
	// process with the same name as our own process
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
	log_debug(DEBUG_SHMEM, "Reading /proc/[0-9]*");
	while ((entry = readdir(dirPos)) != NULL)
	{
		// We are only interested in subdirectories of /proc
		if(entry->d_type != DT_DIR)
			continue;
		// We are only interested in PID subdirectories
		if(entry->d_name[0] < '0' || entry->d_name[0] > '9')
			continue;

		// Extract PID
		pid = strtol(entry->d_name, NULL, 10);

		// Get process name
		char name[PROC_PATH_SIZ] = { 0 };
		if(!get_process_name(pid, name))
			continue;

		log_debug(DEBUG_SHMEM, "PID: %d -> name: %s%s", pid, name, pid == ourselves ? " (us)" : "");

		// Skip our own process
		if(pid == ourselves)
			continue;

		// Only process this is this is our own process
		if(strcasecmp(name, PROCESS_NAME) != 0)
			continue;

		// Get parent process ID (PPID)
		pid_t ppid;
		if(!get_process_ppid(pid, &ppid))
			continue;
		char ppid_name[PROC_PATH_SIZ] = { 0 };
		if(!get_process_name(ppid, ppid_name))
			continue;

		log_debug(DEBUG_SHMEM, " └ PPID: %d -> name: %s", ppid, ppid_name);

		char timestr[TIMESTR_SIZE] = { 0 };
		get_process_creation_time(pid, timestr);

		// If this is the first process we log, add a header
		if(!already_running)
		{
			already_running = true;
			log_info("%s is already running!", PROCESS_NAME);
		}

		if(last_pid != ppid)
		{
			// Independent process, may be child of init/systemd
			log_info("%s (PID %d) ──> %s (PID %d, started %s)",
			         ppid_name, ppid, name, pid, timestr);
			last_pid = pid;
			last_len = snprintf(NULL, 0, "%s (PID %d) ──> ", ppid_name, ppid);
		}
		else
		{
			// Process parented by the one we analyzed before,
			// highlight their relationship
			log_info("%*s └─> %s (PID %d, started %s)",
			         (int)last_len, "", name, pid, timestr);
		}
	}
	log_debug(DEBUG_SHMEM, "Done reading /proc/[0-9]*");

	closedir(dirPos);
	return already_running;
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
		sscanf(line, "Cached: %ld kB", &page_cached);
		sscanf(line, "Buffers: %ld kB", &buffers);
		sscanf(line, "SReclaimable: %ld kB", &slab_reclaimable);
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
