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

pthread_t threads[THREADS_MAX] = { 0 };
bool resolver_ready = false;

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

	//unmask the file mode
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
	const pid_t pid = getpid();
	if((f = fopen(config.files.pid.v.s, "w+")) == NULL)
	{
		log_warn("Unable to write PID to file: %s", strerror(errno));
	}
	else
	{
		fprintf(f, "%i", (int)pid);
		fclose(f);
	}
	log_info("PID of FTL process: %i", (int)pid);
}

static void removepid(void)
{
	FILE *f;
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
	const struct passwd *pw = getpwuid(euid);
	if(pw)
	{
		name = strdup(pw->pw_name);
	}
	else
	{
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
const char *hostname(void)
{
	// Ask kernel for node name if not known
	// This is equivalent to "uname -n"
	if(nodename[0] == '\0')
	{
		struct utsname buf;
		if(uname(&buf) == 0)
			strncpy(nodename, buf.nodename, HOSTNAMESIZE);
		nodename[HOSTNAMESIZE-1] = '\0';
	}
	return nodename;
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
		if(info.uptime > DELAY_UPTIME)
		{
			log_info("Not sleeping as system has finished booting");
			return;
		}
	}
	else
	{
		log_err("Unable to obtain sysinfo: %s (%i)", strerror(errno), errno);
	}

	// Sleep if requested by DELAY_STARTUP
	log_info("Sleeping for %d seconds as requested by configuration ...", config.misc.delay_startup.v.ui);
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
		if(thread_cancellable[i])
		{
			log_info("Thread %s (%d) is idle, terminating it.",
			         thread_names[i], i);
			pthread_cancel(threads[i]);
		}

		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		{
			log_info("Thread %s (%d) is busy, cancelling it (cannot set timeout).",
			         thread_names[i], i);
			pthread_cancel(threads[i]);
			continue;
		}

		// Timeout for joining is 2 seconds for each thread
		ts.tv_sec += 2;

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

	// Remove shared memory objects
	// Important: This invalidated all objects such as
	//            counters-> ... etc.
	// This should be the last action when cleaning up
	destroy_shmem();

	char buffer[42] = { 0 };
	format_time(buffer, 0, timer_elapsed_msec(EXIT_TIMER));
	log_info("########## FTL terminated after%s (code %i)! ##########", buffer, ret);
}

static clock_t last_clock = -1;
static float cpu_usage = 0.0f;
void calc_cpu_usage(void)
{
	// Get the current CPU usage
	const clock_t clk = clock();
	if(clk == (clock_t)-1)
	{
		log_warn("calc_cpu_usage() failed: %s", strerror(errno));
		return;
	}
	if(last_clock == -1)
	{
		// Initialize the value and return
		last_clock = clk;
		return;
	}
	// Percentage of CPU time spent executing instructions
	cpu_usage = 100.0f * (clk - last_clock) / CLOCKS_PER_SEC;
	last_clock = clk;
}

float __attribute__((pure)) get_cpu_percentage(void)
{
	return cpu_usage;
}
