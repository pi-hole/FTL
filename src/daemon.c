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
#include "daemon.h"
#include "config/config.h"
#include "log.h"
// sleepms()
#include "timers.h"
// gravityDB_close()
#include "database/gravity-db.h"
// destroy_shmem()
#include "shmem.h"
// uname()
#include <sys/utsname.h>
// killed
#include "signals.h"
// sysinfo()
#include <sys/sysinfo.h>
#include <errno.h>
// getprio(), setprio()
#include <sys/resource.h>
// free_regex()
#include "regex_r.h"
// close_memory_database()
#include "database/query-table.h"
// http_terminate()
#include "webserver/webserver.h"
// free_api()
#include "api/api.h"
// setlocale()
#include <locale.h>
// freeEnvVars()
#include "config/env.h"

pthread_t threads[THREADS_MAX] = { 0 };
bool resolver_ready = false;
bool dnsmasq_failed = false;

void go_daemon(void)
{
	// Create child process
	pid_t process_id = fork();

	// Indication of fork() failure
	if (process_id < 0)
	{
		log_crit("fork failed!");
		// Return failure in exit status
		exit(EXIT_FAILURE);
	}

	// PARENT PROCESS. Need to kill it.
	if (process_id > 0)
	{
		printf("FTL started!\n");
		// Return success in exit status
		exit(EXIT_SUCCESS);
	}

	// Unmask the file mode
	umask(0);

	// Set new session to ensure we have no controlling terminal
	// creates a session and sets the process group ID
	const pid_t sid = setsid();
	if(sid < 0)
	{
		// Return failure
		log_crit("setsid failed: %s", strerror(errno));
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
		log_crit("fork failed: %s", strerror(errno));
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

	// Closing stdin, stdout and stderr is handled by dnsmasq
}

void savepid(void)
{
	FILE *f;
	// Get PID of the current process
	const pid_t pid = getpid();
	// Open file for writing
	if((f = fopen(config.files.pid.v.s, "w+")) == NULL)
	{
		// Log error
		log_warn("Unable to write PID to file: %s", strerror(errno));
	}
	else
	{
		// Write PID to file
		fprintf(f, "%i", (int)pid);
		fclose(f);
	}
	log_info("PID of FTL process: %i", (int)pid);
}

static void removepid(void)
{
	// Note that this function is not really removing the PID file but
	// rather emptying it
	FILE *f;
	// Open file for writing (emptying it)
	if((f = fopen(config.files.pid.v.s, "w")) == NULL)
	{
		log_warn("Unable to empty PID file: %s", strerror(errno));
		return;
	}
	fclose(f);
}

char *getUserName(void)
{
	char *name;
	// the getpwuid() function shall search the user database for an entry with a matching uid
	// the geteuid() function shall return the effective user ID of the calling process - this is used as the search criteria for the getpwuid() function
	const uid_t euid = geteuid();
	errno = 0;
	const struct passwd *pw = getpwuid(euid);
	if(pw)
	{
		// If the user is found, we return the username
		name = strdup(pw->pw_name);
	}
	else
	{
		// If there was an error, we log it
		if(errno != 0)
			log_warn("getpwuid(%u) failed: %s", euid, strerror(errno));

		// If the user is not found, we return the UID as string
		if(asprintf(&name, "%u", euid) < 0)
			return NULL;
	}

	return name;
}

// "man 7 hostname" says:
//
//     Each element of the hostname must be from 1 to 63 characters long and the
//     entire hostname, including the dots, can be at most 253 characters long.
//
//     Valid characters for hostnames are ASCII(7) letters from a to z, the
//     digits from 0 to 9, and the hyphen (-). A hostname may not start with a
//     hyphen.
#define HOSTNAMESIZE 256
static char nodename[HOSTNAMESIZE] = { 0 };
static char dname[HOSTNAMESIZE] = { 0 };

// Returns the hostname of the system
const char *hostname(void)
{
	// Ask kernel for node name if not known
	// This is equivalent to "uname -n"
	//
	// According to man gethostname(2), this is exactly the same as calling
	// getdomainname() just with one step less
	if(nodename[0] == '\0')
	{
		struct utsname buf;
		if(uname(&buf) == 0)
		{
			strncpy(nodename, buf.nodename, HOSTNAMESIZE);
			strncpy(dname, buf.domainname, HOSTNAMESIZE);
		}
		nodename[HOSTNAMESIZE - 1] = '\0';
		dname[HOSTNAMESIZE - 1] = '\0';
	}
	return nodename;
}

// Returns the domain name of the system
const char *domainname(void)
{
	if(dname[0] == '\0')
		hostname();

	return dname;
}

void delay_startup(void)
{
	// Exit early if not sleeping
	if(config.misc.delay_startup.v.ui == 0u)
		return;

	// Get uptime of system
	struct sysinfo info = { 0 };
	if(sysinfo(&info) == 0)
	{
		// Exit early if system has already been running for a while
		if(info.uptime > DELAY_UPTIME)
		{
			log_info("Not sleeping as system has finished booting");
			return;
		}
	}
	else
	{
		// Log error but continue
		log_err("Unable to obtain sysinfo: %s (%i)", strerror(errno), errno);
	}

	// Sleep if requested by DELAY_STARTUP
	log_info("Sleeping for %u seconds as requested by configuration ...", config.misc.delay_startup.v.ui);
	if(sleep(config.misc.delay_startup.v.ui) != 0)
	{
		log_crit("Sleeping was interrupted by an external signal");
		cleanup(EXIT_FAILURE);
		exit(EXIT_FAILURE);
	}
	log_info("Done sleeping, continuing startup of resolver...");
}

// Is this a fork?
bool __attribute__ ((const)) is_fork(const pid_t mpid, const pid_t pid)
{
	return mpid > -1 && mpid != pid;
}

pid_t FTL_gettid(void)
{
#ifdef SYS_gettid
	return (pid_t)syscall(SYS_gettid);
#else
#warning SYS_gettid is not available on this system
	return -1;
#endif // SYS_gettid
}

static void terminate_threads(void)
{
	struct timespec ts;
	// Terminate threads before closing database connections and finishing shared memory
	killed = true;
	// Try to join threads to ensure cancellation has succeeded
	log_info("Waiting for threads to join");
	for(int i = 0; i < THREADS_MAX; i++)
	{
		// Skip threads that have never been started or which are already stopped
		if(!thread_running[i])
			continue;

		// Cancel thread if it is idle
		if(thread_cancellable[i])
		{
			log_info("Thread %s (%d) is idle, terminating it.",
			         thread_names[i], i);
			pthread_cancel(threads[i]);
		}

		// Cancel thread if we cannot set a timeout for joining
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		{
			log_info("Thread %s (%d) is busy, cancelling it (cannot set timeout).",
			         thread_names[i], i);
			pthread_cancel(threads[i]);
			continue;
		}

		// Timeout for joining is 2 seconds for each thread
		ts.tv_sec += 2;

		// Try to join thread and cancel it if it is still busy
		const int s = pthread_timedjoin_np(threads[i], NULL, &ts);
		if(s != 0)
		{
			log_info("Thread %s (%d) is still busy, cancelling it.",
			     thread_names[i], i);
			pthread_cancel(threads[i]);
			continue;
		}
	}
	log_info("All threads joined");
}

void set_nice(void)
{
	const int which = PRIO_PROCESS;
	const id_t pid = getpid();
	const int priority = getpriority(which, pid);

	// config value -999 => do not change niceness
	if(config.misc.nice.v.i == -999)
	{
		// Do not set nice value
		log_debug(DEBUG_CONFIG, "Not changing process priority.");
	}
	else
	{
		// Set nice value
		const int ret = setpriority(which, pid, config.misc.nice.v.i);
		if(ret == -1)
			// ERROR EPERM: The calling process attempted to increase its priority
			// by supplying a negative value but has insufficient privileges.
			// On Linux, the RLIMIT_NICE resource limit can be used to define a limit to
			// which an unprivileged process's nice value can be raised. We are not
			// affected by this limit when pihole-FTL is running with CAP_SYS_NICE
			log_warn("Cannot set process priority to %d: %s. Process priority remains at %d",
			         config.misc.nice.v.i, strerror(errno), priority);
	}
}

// Clean up on exit
void cleanup(const int ret)
{
	// Do proper cleanup only if FTL started successfully
	if(resolver_ready)
	{
		// Terminate threads
		terminate_threads();

		// Close database connection
		lock_shm();
		gravityDB_close();
		unlock_shm();
	}

	// Remove PID file
	removepid();

	// Free regex filter memory
	free_regex();

	// Terminate API
	free_api();

	// Terminate HTTP server (if running)
	http_terminate();

	// Close memory database
	close_memory_database();

	// Remove shared memory objects
	// Important: This invalidated all objects such as
	//            counters-> ... etc.
	// This should be the last action when c
	destroy_shmem();

	// Free environment variables
	freeEnvVars();

	char buffer[42] = { 0 };
	format_time(buffer, 0, timer_elapsed_msec(EXIT_TIMER));
	log_info("########## FTL terminated after%s (code %i)! ##########", buffer, ret);
}

static float last_clock = 0.0f;
static float cpu_usage = 0.0f;
void calc_cpu_usage(const unsigned int interval)
{
	// Get the current resource usage
	// RUSAGE_SELF means here "the calling process" which is the sum of all
	// resources used by all threads in the process
	struct rusage usage = { 0 };
	if(getrusage(RUSAGE_SELF, &usage) != 0)
	{
		log_err("Unable to obtain CPU usage: %s (%i)", strerror(errno), errno);
		return;
	}

	// Calculate the CPU usage: it is the total time spent in user mode and
	// kernel mode by this process since the total time since the last call
	// to this function. 100% means one core is fully used, 200% means two
	// cores are fully used, etc.
	const float this_clock = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec + 1e-6 * (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec);

	// Calculate the CPU usage in this interval
	cpu_usage = 100.0 * (this_clock - last_clock) / interval;

	// Store the current time for the next call to this function
	last_clock = this_clock;
}

float __attribute__((pure)) get_cpu_percentage(void)
{
	return cpu_usage;
}

ssize_t getrandom_fallback(void *buf, size_t buflen, unsigned int flags)
{
	FILE *fp = fopen("/dev/urandom", "r");
	if(fp == NULL)
		return -1;

	if(fread(buf, buflen, 1, fp) != 1)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);

	return buflen;
}

bool ipv6_enabled(void)
{
	// First we check a few virtual system files to see if IPv6 is disabled
	const char *files[] = {
		"/sys/module/ipv6/parameters/disable", // GRUB - ipv6.disable=1
		"/proc/sys/net/ipv6/conf/all/disable_ipv6", // sysctl.conf - net.ipv6.conf.all.disable_ipv6=1
		"/proc/sys/net/ipv6/conf/default/disable_ipv6", // sysctl.conf - net.ipv6.conf.all.disable_ipv6=1
		NULL
	};

	// Loop over the files
	for(int i = 0; files[i] != NULL; i++)
	{
		// Open file for reading
		FILE *f = fopen(files[i], "r");
		if(f == NULL)
			continue;

		// Read first character
		const int c = fgetc(f);
		fclose(f);
		// If the first character is a 1, then IPv6 is disabled
		if(c == '1')
			return false;
	}

	// If the file does not exist or if it does not contain a 1, then we check
	// if /proc/net/if_inet6 has any IPv6-capable interfaces
	// Since Linux 2.6.25 (April 2008), files in /proc/net are a symlink to
	// /proc/self/net and provide information about the network devices and
	// interfaces for the network namespace of which the process is a member
	FILE *f = fopen("/proc/net/if_inet6", "r");

	if(f != NULL)
	{
		// If the file exists, we check if it is empty
		const int c = fgetc(f);
		fclose(f);
		// If the file is empty, then there are no IPv6-capable interfaces
		if(c == EOF)
			return false;
	}

	// else: IPv6 is not obviously disabled and there is at least one
	// IPv6-capable interface
	return true;
}

void init_locale(void)
{
	// Set locale to system default, needed for libidn to work properly
	// Without this, libidn will not be able to convert UTF-8 to ASCII
	// (error message "Character encoding conversion error")
	setlocale(LC_ALL, "");

	// Set locale for numeric values to C to ensure that we always use
	// the dot as decimal separator (even if the system locale uses a
	// comma, e.g., in German)
	setlocale(LC_NUMERIC, "C");
}
