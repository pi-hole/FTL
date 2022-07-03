
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2022 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Supervisor routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "supervisor.h"
#include "log.h"
#include "daemon.h"
// sleepms()
#include "timers.h"

// PATH_MAX
#include <limits.h>
// waitpid()
#include <sys/wait.h>

static pid_t child_pid;

static void signal_handler(int sig, siginfo_t *si, void *unused)
{
	// Forward signal to child
	logg("### Supervisor received signal \"%s\" (%d), forwarding to %d", strsignal(sig), sig, child_pid);
	kill(child_pid, sig);
}

// Register ordinary signals handler
static void redirect_signals(void)
{
	struct sigaction old_action;

	// Loop over all possible signals, including real-time signals
	for(unsigned int signum = 0; signum < NSIG; signum++)
	{
		// Do not modify SIGCHLD handling
		if(signum == SIGCHLD)
			continue;

		// Catch this signal
		sigaction (signum, NULL, &old_action);
		if(old_action.sa_handler != SIG_IGN)
		{
			struct sigaction SIGaction;
			memset(&SIGaction, 0, sizeof(struct sigaction));
			SIGaction.sa_flags = SA_SIGINFO | SA_RESTART;
			sigemptyset(&SIGaction.sa_mask);
			SIGaction.sa_sigaction = &signal_handler;
			sigaction(signum, &SIGaction, NULL);
		}
	}
}

int supervisor(int argc, char* argv[])
{
	// Replace "--supervised" by "no-deamon"
	argv[1] = (char*)"no-daemon";

	// Fork supervisor into background
	go_daemon();

	char self[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", self, sizeof self) == 0)
		strcpy(self, "/usr/bin/pihole-FTL");

	// Start FTL in non-daemon sub-process
	bool restart = true;
	int rc = EXIT_SUCCESS;
	do
	{
		logg("### Supervisor: Starting %s", self);

		int status;
		if((child_pid = fork()) == 0)
		{
			// Launch child from PATH
			execv(self, argv);
			/* if execl() was successful, this won't be reached */
			exit(127);
		}

		if (child_pid > 0)
		{
			// Redirect signals to the child's PID
			redirect_signals();

			/* the parent process calls waitpid() on the child */
			const pid_t wrc = waitpid(child_pid, &status, 0);
			if (wrc != -1)
			{
				if (WIFEXITED(status))
				{
					rc = WEXITSTATUS(status);
					logg("### Supervisor: Subprocess exited with code %d", rc);
					restart = (rc != 0 && rc != 127);
				}
				else if(WIFSIGNALED(status))
				{
					const int sig = WTERMSIG(status);
					logg("### Supervisor: Subprocess was terminated by external signal %s (%d)", strsignal(sig), sig);
					rc = -1;
					restart = false;
				}
				else if(WIFSTOPPED(status))
				{
					const int sig = WSTOPSIG(status);
					logg("### Supervisor: Subprocess was stopped by external signal %s (%d)", strsignal(sig), sig);
					rc = -1;
					restart = false;
				}
				else
				{
					/* the program didn't terminate normally */
					logg("### Supervisor: Abnormal termination of subprocess");
					rc = -1;
					restart = true;
				}
			}
			else
			{
				logg("### Supervisor: waitpid() failed: %s (%d)", strerror(errno), errno);
			}
		}
		else
		{
			logg("### Supervisor: fork() failed: %s (%d)", strerror(errno), errno);
		}

	// Delay restarting to avoid race-collisions with left-over shared memory files
	if(restart)
		sleepms(1000);
	} while( restart );

	logg("### Supervisor: Terminated (code %d)", rc);
	return rc;
}
