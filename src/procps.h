/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  /proc system prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef PROCPS_H
#define PROCPS_H

#include <stdbool.h>
#include <sys/types.h>

#define PROC_PATH_SIZ  32

bool get_process_name(const pid_t pid, char name[PROC_PATH_SIZ]);
bool another_FTL(void);

struct proc_mem {
	// Memory currently resident in RAM (in kB)
	unsigned long VmRSS;
	unsigned long VmSize;
	unsigned long VmPeak;
	unsigned long VmHWM;
	float VmRSS_percent;
};

struct statm_t {
	unsigned long size;
	unsigned long resident;
	unsigned long shared;
	unsigned long text;
	unsigned long lib;
	unsigned long data;
	unsigned long dirty;
};

struct proc_meminfo {
	unsigned long total;
	unsigned long used;
	unsigned long mfree;
	unsigned long avail;
	unsigned long cached;
};

bool getProcessMemory(struct proc_mem *mem, const unsigned long total_memory);
double parse_proc_self_stat(void);
bool parse_proc_meminfo(struct proc_meminfo *mem);
double parse_proc_stat(void);
pid_t search_proc(const char *name);

#endif // PROCPS_H
