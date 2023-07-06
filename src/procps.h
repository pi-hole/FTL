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
bool check_running_FTL(void);

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

bool read_self_memory_status(struct statm_t *result);
bool getProcessMemory(struct proc_mem *mem, const unsigned long total_memory);
bool parse_proc_meminfo(struct proc_meminfo *mem);

#endif // PROCPS_H