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
		char pname[PROC_PATH_SIZ + 1] = { 0 };
		if(get_process_name(pid, pname) && strcasecmp(pname, PROCESS_NAME) == 0)
		{
			// If we found another FTL process by looking at the PID
			// file, we log an info message and return true. This
			// will terminate the current process.
			log_crit("%s is already running (PID %d)!", PROCESS_NAME, pid);
			return true;
		}
		// If we found another process by looking at the PID file, which
		// is, however, not FTL, we log this and continue.
		log_warn("Found process \"%s\" at PID %d suggested by PID file, ignoring", pname, pid);
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


/**
 * @brief Parses the /proc/stat file to extract total CPU usage statistics.
 *
 * @return The total CPU time (in seconds) spent in user, nice, and system modes,
 *         or -1.0 if an error occurs (e.g., file cannot be opened or parsed).
 */
double parse_proc_stat(void)
{
	FILE *statfile = fopen("/proc/stat", "r");
	if(statfile == NULL)
		return -1.0;

	unsigned long user, nice, system;
	/*
	    user   (1) Time spent in user mode. (includes guest and guest_nice time)

	    nice   (2) Time spent in user mode with low priority (nice).

	    system (3) Time spent in system mode.

	    idle   (4) Time spent in the idle task.  This value should be USER_HZ  times
	           the second entry in the /proc/uptime pseudo-file.

	    iowait (since Linux 2.5.41)
	           (5) Time waiting for I/O to complete.

	    irq (since Linux 2.6.0-test4)
	           (6) Time servicing interrupts.

	    softirq (since Linux 2.6.0-test4)
	           (7) Time servicing softirqs.

	    steal (since Linux 2.6.11)
	           (8)  Stolen  time, which is the time spent in other operating systems
	           when running in a virtualized environment

	    guest (since Linux 2.6.24)
	           (9) Time spent running a virtual  CPU  for  guest  operating  systems
	           under the control of the Linux kernel.

	    guest_nice (since Linux 2.6.33)
	           (10)  Time spent running a niced guest (virtual CPU for guest operat-
	           ing systems under the control of the Linux kernel).
	*/

	// Read the file until we find the first line starting with "cpu "
	char line[256];
	bool found = false;
	while(fgets(line, sizeof(line), statfile))
	{
		if(strncmp(line, "cpu ", 4) == 0)
		{
			if(sscanf(line, "cpu %lu %lu %lu",
			       &user, &nice, &system) != 3)
			{
				log_debug(DEBUG_ANY, "Failed to parse CPU line in /proc/stat");
				fclose(statfile);
				return -1.0;
			}
			found = true;
			break;
		}
	}

	if(!found) {
		log_warn("No CPU line found in /proc/stat");
		fclose(statfile);
		return -1.0;
	}

	fclose(statfile);

	const long ticks = sysconf(_SC_CLK_TCK);
	return (user + nice + system) / (double)ticks;
}

/**
 * @brief Parses the /proc/self/stat file to retrieve the used CPU time for the
 * current process.
 *
 * This function opens the /proc/self/stat file, skips the first 13 fields, and
 * reads the user mode (utime) and kernel mode (stime) CPU times. It then
 * converts the sum of these times from clock ticks to seconds using the
 * system's clock tick rate.
 *
 * @return The total CPU time (user + system) in seconds for the current
 *         process, or -1.0 if an error occurs (e.g., file cannot be opened,
 *         parsing fails, or invalid clock tick rate).
 */
double parse_proc_self_stat(void)
{
	// Open /proc/self/stat
	FILE *file = fopen("/proc/self/stat", "r");
	if(file == NULL)
		return -1.0;

	// Read utime and stime
	unsigned long utime = 0, stime = 0;
	const bool parsed = fscanf(file, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &utime, &stime) == 2;
	fclose(file);

	// If we could not parse the file, return -1.0
	if(!parsed)
		return -1.0;

	// Convert clock ticks to seconds
	const long ticks = sysconf(_SC_CLK_TCK);
	if(ticks <= 0)
		return -1.0;

	return (utime + stime) / (double)ticks;
}

/**
 * @brief Searches for a process by its name in the /proc filesystem.
 *
 * This function iterates through the directories in /proc, which represent
 * process IDs (PIDs), and checks the "comm" file in each directory to find
 * a process with a matching name.
 *
 * @param name The name of the process to search for.
 *
 * @return The PID of the process if found, or -1 if no matching process is found
 *         or if an error occurs (e.g., unable to open /proc or a file).
 *
 * @note This function assumes the /proc filesystem is available and accessible.
 *       It also assumes that the "comm" file in each process directory contains
 *       the name of the process.
 */
pid_t search_proc(const char *name)
{
	DIR *dir = opendir("/proc");
	if(dir == NULL)
		return -1;

	struct dirent *entry;
	while((entry = readdir(dir)) != NULL)
	{
		// Check if the entry is a directory and contains only digits
		// We skip ".", "..", "self", and friends
		if(entry->d_type == DT_DIR && isdigit(entry->d_name[0]))
		{
			char filename[64];
			snprintf(filename, sizeof(filename), "/proc/%s/comm", entry->d_name);
			FILE *file = fopen(filename, "r");
			if(file != NULL)
			{
				char comm[PROC_PATH_SIZ + 1] = { 0 };
				// Read the command name from the file
				if(fscanf(file, "%"xstr(PROC_PATH_SIZ)"s", comm) == 1)
				{
					if(strncmp(comm, name, PROC_PATH_SIZ) == 0)
					{
						// Found a matching process
						fclose(file);
						const int pid = atoi(entry->d_name);
						closedir(dir);
						return pid;
					}
				}
				fclose(file);
			}
		}
	}

	// No process found with the given name
	closedir(dir);
	return -1;
}
