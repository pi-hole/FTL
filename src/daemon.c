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
// parse_proc_stat()
#include "procps.h"
// destroy_entropy()
#include "webserver/x509.h"

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
		// Free config to silence meaningless (but still loud) memcheck
		// warnings about lost memory concerning the parsed config
		free_config(&config, true);
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

	savePID();

	// Closing stdin, stdout and stderr is handled by dnsmasq
}

/**
 * @brief Save the current process ID (PID) to a file.
 *
 * This function retrieves the PID of the current process and writes it to a
 * specified file. If the file cannot be opened for writing, an error is logged.
 * Otherwise, the PID is written to the file and the file is closed. The PID is
 * also logged for informational purposes.
 *
 * @return void
 */
void savePID(void)
{
	// Get PID of the current process
	const pid_t pid = getpid();
	// Open file for writing
	FILE *f = NULL;
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

/**
 * @brief Empties the PID file
 *
 * This function opens the PID file in write mode, which effectively
 * empties its contents. If the file cannot be opened, a warning is logged.
 *
 * @note This function does not remove the PID file, it only empties it.
 */
static void removePID(void)
{
	FILE *f = NULL;
	// Open file for writing to overwrite/empty it
	if((f = fopen(config.files.pid.v.s, "w")) == NULL)
	{
		log_warn("Unable to empty PID file: %s", strerror(errno));
		return;
	}
	fclose(f);

	log_info("PID file emptied");
}

/**
 * @brief Retrieves the username of the effective user ID of the calling process.
 *
 * This function uses the `geteuid()` function to get the effective user ID (EUID) of the calling process
 * and then searches the user database for an entry with a matching UID using the `getpwuid()` function.
 * If a matching entry is found, the username is returned. If no matching entry is found, the UID is
 * returned as a string. If an error occurs during the lookup, a warning is logged.
 *
 * @return A dynamically allocated string containing the username or UID. The caller is responsible for
 * freeing the allocated memory. Returns NULL if memory allocation fails.
 */
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

			// Only set domain name if node name is not empty: the
			// kernel replies with '(none)' in this case.
			if(!(buf.domainname[0] == '(' && strncmp(buf.domainname, "(none)", 6) == 0))
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
	// Terminate threads before closing database connections and finishing shared memory
	killed = true;
	// Try to join threads to ensure cancellation has succeeded
	log_info("Waiting for threads to join");
	for(int i = 0; i < THREADS_MAX; i++)
	{
		log_debug(DEBUG_EXTRA, "Joining %s thread (%d)", thread_names[i], i);
		// Skip threads that have never been started or which are already stopped
		if(threads[i] == 0)
		{
			log_debug(DEBUG_EXTRA, "Skipping thread as it was never started");
			continue;
		}

		// Cancel thread if it is idle
		if(thread_cancellable[i])
		{
			log_info("Thread %s (%d) is idle, terminating it.",
			         thread_names[i], i);
			pthread_cancel(threads[i]);
			continue;
		}

		// Cancel thread if we cannot set a timeout for joining
		struct timespec ts;
		memset(&ts, 0, sizeof(ts));
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
		if(pthread_timedjoin_np(threads[i], NULL, &ts) != 0)
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
		{
			if(errno == EACCES || errno == EPERM)
			{
				// from man 2 setpriority:
				//
				// ERRORS
				// [...]
				// EACCES The caller attempted to set a lower nice value (i.e.,  a  higher
				//        process  priority),  but did not have the required privilege (on
				//        Linux: did not have the CAP_SYS_NICE capability).
				//
				// EPERM  A process was located, but its effective user ID did  not  match
				//        either  the effective or the real user ID of the caller, and was
				//        not privileged (on Linux: did not have the CAP_SYS_NICE capabil‐
				//        ity).
				// [...]
				log_warn("Insufficient permissions to set process priority to %d (CAP_SYS_NICE required), process priority remains at %d",
				         config.misc.nice.v.i, priority);
			}
			else
			{
				// Other error
				log_warn("Cannot set process priority to %d: %s. Process priority remains at %d",
				         config.misc.nice.v.i, strerror(errno), priority);
			}
		}
	}
}

// Clean up on exit
void cleanup(const int ret)
{
	// Do proper cleanup only if FTL started successfully
	if(resolver_ready)
	{
		// Terminate threads
		log_debug(DEBUG_ANY, "Terminating: Stopping threads");
		terminate_threads();

		// Close database connection
		lock_shm();
		log_debug(DEBUG_ANY, "Terminating: Closing gravity database");
		gravityDB_close();
		unlock_shm();
	}

	// Remove PID file
	log_debug(DEBUG_ANY, "Terminating: Removing PID file");
	removePID();

	// Free regex filter memory
	log_debug(DEBUG_ANY, "Terminating: Freeing regex filter memory");
	free_regex();

	// Terminate API
	log_debug(DEBUG_ANY, "Terminating: Stopping API");
	free_api();

	// Terminate HTTP server (if running)
	log_debug(DEBUG_ANY, "Terminating: Stopping HTTP server");
	http_terminate();

	// Close memory database
	log_debug(DEBUG_ANY, "Terminating: Closing memory database");
	close_memory_database();

	// Free environment variables
	log_debug(DEBUG_ANY, "Terminating: Freeing environment variables");
	freeEnvVars();

	// Free config
	log_debug(DEBUG_ANY, "Terminating: Freeing configuration");
	free_config(&config, true);

	// Remove shared memory objects
	// Important: This invalidated all objects such as
	//            counters-> ... etc.
	// This should be the last action when cleaning up
	log_debug(DEBUG_ANY, "Terminating: Removing shared memory");
	destroy_shmem();

	char buffer[42] = { 0 };
	format_time(buffer, 0, timer_elapsed_msec(EXIT_TIMER));
	if(ret == RESTART_FTL_CODE)
		log_info("########## FTL terminated after%s (internal restart)! ##########", buffer);
	else
		log_info("########## FTL terminated after%s (code %i)! ##########", buffer, ret);

	// Finally, free log config memory
	if(config.files.log.ftl.t == CONF_STRING_ALLOCATED)
		free(config.files.log.ftl.v.s);
}

static float ftl_cpu_usage = 0.0f;
static float total_cpu_usage = 0.0f;
void calc_cpu_usage(const unsigned int interval)
{
	// Get number of cores if we are normalizing CPU usage below
	const unsigned int norm_factor = config.misc.normalizeCPU.v.b ? get_nprocs_conf() : 1;

	// Get the current FTL CPU time
	const double ftl_cpu_time = parse_proc_self_stat();

	// Calculate the CPU usage in this interval
	static double last_ftl_cpu_time = 0.0f;
	ftl_cpu_usage = 100.0 * (ftl_cpu_time - last_ftl_cpu_time) / interval / norm_factor;
	last_ftl_cpu_time = ftl_cpu_time;

	// Calculate the total CPU usage
	const double cpu_time = parse_proc_stat();
	
	// Calculate the CPU usage since the last call to this function
	static double last_cpu_time = 0.0f;
	total_cpu_usage = 100.0 * (cpu_time - last_cpu_time) / interval / norm_factor;
	last_cpu_time = cpu_time;

	log_debug(DEBUG_EXTRA, "CPU usage in the last %u seconds: FTL %.4f%%, total %.4f%% (normalized by factor %ux)",
	          interval, ftl_cpu_usage, total_cpu_usage, norm_factor);
}

float __attribute__((pure)) get_ftl_cpu_percentage(void)
{
	// Return the smaller of the two values to avoid showing a CPU usage
	// higher than the total CPU usage. This can happen due to rounding
	// errors and rare interval comparison differences.
	return ftl_cpu_usage < total_cpu_usage ? ftl_cpu_usage : total_cpu_usage;
}

float __attribute__((pure)) get_total_cpu_percentage(void)
{
	return total_cpu_usage;
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
