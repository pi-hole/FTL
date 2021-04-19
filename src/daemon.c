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
#include "config.h"
#include "log.h"
// sleepms()
#include "timers.h"
// close_telnet_socket()
#include "api/socket.h"
// gravityDB_close()
#include "database/gravity-db.h"
// dbclose()
#include "database/common.h"
// destroy_shmem()
#include "shmem.h"
// killed
#include "signals.h"

pthread_t threads[THREADS_MAX] = { 0 };
bool resolver_ready = false;

void go_daemon(void)
{
	// Create child process
	pid_t process_id = fork();

	// Indication of fork() failure
	if (process_id < 0)
	{
		logg("fork failed!\n");
		// Return failure in exit status
		exit(EXIT_FAILURE);
	}

	// PARENT PROCESS. Need to kill it.
	if (process_id > 0)
	{
		printf("FTL started!\n");
		// return success in exit status
		exit(EXIT_SUCCESS);
	}

	//unmask the file mode
	umask(0);

	//set new session
	// creates a session and sets the process group ID
	const pid_t sid = setsid();
	if(sid < 0)
	{
		// Return failure
		logg("setsid failed!\n");
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
		logg("fork failed!\n");
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
	if((f = fopen(FTLfiles.pid, "w+")) == NULL)
	{
		logg("WARNING: Unable to write PID to file.");
		logg("         Continuing anyway...");
	}
	else
	{
		fprintf(f, "%i", (int)pid);
		fclose(f);
	}
	logg("PID of FTL process: %i", (int)pid);
}

static void removepid(void)
{
	FILE *f;
	if((f = fopen(FTLfiles.pid, "w")) == NULL)
	{
		logg("WARNING: Unable to empty PID file");
		return;
	}
	fclose(f);
}

char *getUserName(void)
{
	char * name;
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

void delay_startup(void)
{
	// Exit early if not sleeping
	if(config.delay_startup == 0u)
		return;

	// Sleep if requested by DELAY_STARTUP
	logg("Sleeping for %d seconds as requested by configuration ...",
	     config.delay_startup);
	sleep(config.delay_startup);
	logg("Done sleeping, continuing startup of resolver...\n");
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
	int s;
	struct timespec ts;
	// Terminate threads before closing database connections and finishing shared memory
	killed = true;
	// Try to join threads to ensure cancellation has succeeded
	logg("Waiting for threads to join");
	for(int i = 0; i < THREADS_MAX; i++)
	{
		if(thread_cancellable[i])
		{
			logg("Thread %s (%d) is idle, terminating it.",
			     thread_names[i], i);
			pthread_cancel(threads[i]);
		}

		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		{
			logg("Thread %s (%d) is busy, cancelling it (cannot set timout).",
			     thread_names[i], i);
			pthread_cancel(threads[i]);
			continue;
		}

		// Timeout for joining is 2 seconds for each thread
		ts.tv_sec += 2;

		if((s = pthread_timedjoin_np(threads[i], NULL, &ts)) != 0)
		{
			logg("Thread %s (%d) is still busy, cancelling it.",
			     thread_names[i], i);
			pthread_cancel(threads[i]);
			continue;
		}
	}
	logg("All threads joined");
}

// Clean up on exit
void cleanup(const int ret)
{
	// Do proper cleanup only if FTL started successfully
	if(resolver_ready)
	{
		terminate_threads();

		// Close database connection
		gravityDB_close();

		// Close sockets and delete Unix socket file handle
		close_telnet_socket();
		close_unix_socket(true);
	}

	// Empty API port file, port 0 = truncate file
	saveport(0);

	// Remove PID file
	removepid();

	// Remove shared memory objects
	// Important: This invalidated all objects such as
	//            counters-> ... etc.
	// This should be the last action when cleaning up
	destroy_shmem();

	char buffer[42] = { 0 };
	format_time(buffer, 0, timer_elapsed_msec(EXIT_TIMER));
	logg("########## FTL terminated after%s (code %i)! ##########", buffer, ret);
}
