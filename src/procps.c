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
// readPID()
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

/**
 * @brief Reads the process ID (PID) from a file.
 *
 * This function attempts to open a file specified by the configuration
 * and read the PID from it. If the file cannot be opened or the PID
 * cannot be parsed, appropriate warnings are logged and the function
 * returns -1.
 *
 * @return pid_t The PID read from the file on success, or -1 on failure.
 */
static pid_t readPID(void)
{
	pid_t pid = -1;
	FILE *f = NULL;
	// Open file for reading
	if((f = fopen(config.files.pid.v.s, "r")) == NULL)
	{
		// Log error
		log_warn("Unable to read PID from file: %s", strerror(errno));
		return -1;
	}

	// Try to read PID from file if it is not empty
	if(fscanf(f, "%d", &pid) != 1)
		log_debug(DEBUG_SHMEM, "Unable to parse PID in PID file");

	// Close file
	fclose(f);

	return pid;
}

/**
 * @brief Checks if a process with the given PID is alive.
 *
 * This function determines if a process is alive by checking the
 * /proc/<pid>/status file. If the file cannot be opened, it is assumed that the
 * process is dead. The function reads the status file to check the state of the
 * process. If the process is in zombie state, it is considered not running.
 *
 * @param pid The process ID to check.
 * @return true if the process is alive and not a zombie, false otherwise.
 */
static bool process_alive(const pid_t pid)
{
	// Create /proc/<pid>/status filename
	char filename[64] = { 0 };
	snprintf(filename, sizeof(filename), "/proc/%d/status", pid);

	FILE *file = fopen(filename, "r");
	// If we cannot open the file, we assume the process is dead as
	// /proc/<pid> does not exist anymore
	if(file == NULL)
		return false;

	// Parse the entire file
	char line[256];
	bool running = true;
	while(fgets(line, sizeof(line), file))
	{
		// Search for state
		if(strncmp(line, "State:", 6) == 0)
		{
			// Check if process is a zombie
			// On Linux operating systems, a zombie process is a
			// process that has completed execution (via the exit
			// system call) but still has an entry in the process
			// table: it is a process in the "Terminated state".
			// It typically happens when the parent (calling)
			// program properly has not yet fetched the return
			// status of the sub-process.
			if(strcmp(line, "State:\tZ") == 0)
				running = false;

			log_debug(DEBUG_SHMEM, "Process state: \"%s\"", line);
			break;
		}
	}

	// Close file
	fclose(file);

	// Process is still alive if the running flag is still true
	return running;
}

// This function prints an info message about if another FTL process is already
// running. It returns true if another FTL process is already running, false
// otherwise.
bool another_FTL(void)
{
	// The PID in the PID file
	const pid_t pid = readPID();
	// Our own PID from the current process
	const pid_t ourselves = getpid();

	if(pid == ourselves)
	{
		// This should not happen, as we store our own PID in the PID
		// file only after we have successfully started up (and possibly
		// forked). However, if it does happen, we log an info message
		log_info("PID file contains our own PID");
	}
	else if(pid < 0)
	{
		// If we cannot read the PID file, we assume no other FTL process is
		// running. We write our own PID to the file later after we have
		// successfully started up (and possibly forked).
		log_info("PID file does not exist or not readable");
	}
	else if(process_alive(pid))
	{
		// If we found another FTL process by looking at the PID file, we
		// check if it is still alive. If it is, we log a critical message
		// and return true. This will terminate the current process.
		log_crit("%s is already running (PID %d)!", PROCESS_NAME, pid);
		return true;
	}

	// If we did not find another FTL process by looking at the PID file, we assume
	// no other FTL process is running. We write our own PID to the file later after
	// we have successfully started up (and possibly forked).
	log_info("No other running FTL process found.");
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
