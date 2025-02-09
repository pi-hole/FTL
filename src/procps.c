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
// readpid()
#include "daemon.h"

#define PROCESS_NAME   "pihole-FTL"

// This function tries to obtain the process name of a given PID
// It returns true on success, false otherwise and stores the process name in
// the given buffer
// The preferred mechanism is to use /proc/<pid>/exe, but if that fails, we try
// to parse /proc/<pid>/comm. The latter is not guaranteed to be correct (e.g.
// processes can easily change it themselves using prctl with PR_SET_NAME), but
// it is better than nothing.
bool get_process_name(const pid_t pid, char name[PROC_PATH_SIZ])
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

// This function prints an info message about if another FTL process is already
// running. It returns true if another FTL process is already running, false
// otherwise.
bool another_FTL(void)
{
	const pid_t ourselves = getpid();
	bool already_running = false;
	pid_t pid = readpid();

	if(pid == ourselves)
	{
		log_info("PID file contains our own PID");
	}
	else if(pid < 0)
	{
		log_info("PID file does not exist or not readable");
	}
	else
	{
		// Note: kill(pid, 0) does not send a signal, but merely checks
		// if the process exists. If the process does not exist, kill()
		// returns -1 and sets errno to ESRCH. However, if the process
		// exists, but security restrictions tell the system to deny its
		// existence, we cannot distinguish between the process not
		// existing and the process existing but being denied to us. In
		// that case, our fallback solution below kicks in and iterates
		// over /proc instead.
		already_running = kill(pid, 0) == 0;
		log_info("PID file contains PID %d (%s), we are %d",
		         pid, already_running ? "running" : "dead", ourselves);
	}

	// If already_running is true, we are done
	if(already_running)
	{
		log_crit("%s is already running (PID %d)!", PROCESS_NAME, pid);
		return true;
	}

	// If we did not find another FTL process by looking at the PID file, we assume
	// no other FTL process is running. We write our own PID to the file later after
	// we have successfully started up (and possibly forked).
	return false;
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
