/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Signal processing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#if defined(__GLIBC__)
#include <execinfo.h>
#endif
#include "signals.h"
#include "log.h"
#include "memory.h"
// ls_dir()
#include "files.h"
// FTL_reload_all_domainlists()
#include "datastructure.h"
#include "config.h"

#define BINARY_NAME "pihole-FTL"

volatile sig_atomic_t killed = 0;
static volatile pid_t pid = 0;
static time_t FTLstarttime = 0;
extern volatile int exit_code;

#if defined(__GLIBC__)
static void print_addr2line(const char *symbol, const void *address, const int j, const void *offset)
{
	// Only do this analysis for our own binary (skip trying to analyse libc.so, etc.)
	if(strstr(symbol, BINARY_NAME) == NULL)
		return;

	// Find first occurence of '(' or ' ' in the obtaned symbol string and
	// assume everything before that is the file name. (Don't go beyond the
	// string terminator \0)
	int p = 0;
	while(symbol[p] != '(' && symbol[p] != ' ' && symbol[p] != '\0')
		p++;

	// Compute address cleaned by binary offset
	void *addr = (void*)(address-offset);

	// Invoke addr2line command and get result through pipe
	char addr2line_cmd[256];
	snprintf(addr2line_cmd, sizeof(addr2line_cmd), "addr2line %p -e %.*s", addr, p, symbol);
	FILE *addr2line = NULL;
	char linebuffer[256];
	if((addr2line = popen(addr2line_cmd, "r")) != NULL &&
	   fgets(linebuffer, sizeof(linebuffer), addr2line) != NULL)
	{
		char *pos;
		// Strip possible newline at the end of the addr2line output
		if ((pos=strchr(linebuffer, '\n')) != NULL)
			*pos = '\0';
		logg("L[%04i]: %s", j, linebuffer);
	}
	pclose(addr2line);
}
#endif

static void __attribute__((noreturn)) SIGSEGV_handler(int sig, siginfo_t *si, void *unused)
{
	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("---------------------------->  FTL crashed!  <----------------------------");
	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("Please report a bug at https://github.com/pi-hole/FTL/issues");
	logg("and include in your report already the following details:");

	if(FTLstarttime != 0)
	{
		logg("FTL has been running for %li seconds", time(NULL)-FTLstarttime);
	}
	log_FTL_version(true);

	logg("Received signal: %s", strsignal(sig));
	logg("     at address: %p", si->si_addr);
	switch (si->si_code)
	{
		case SEGV_MAPERR: logg("     with code: SEGV_MAPERR (Address not mapped to object)"); break;
		case SEGV_ACCERR: logg("     with code: SEGV_ACCERR (Invalid permissions for mapped object)"); break;
#if defined(SEGV_BNDERR)
		case SEGV_BNDERR: logg("     with code: SEGV_BNDERR (Failed address bound checks)"); break;
#endif
		default: logg("     with code: Unknown (%i)", si->si_code); break;
	}

// Check GLIBC availability as MUSL does not support live backtrace generation
#if defined(__GLIBC__)
	// Try to obtain backtrace. This may not always be helpful, but it is better than nothing
	void *buffer[255];
	const int calls = backtrace(buffer, sizeof(buffer)/sizeof(void *));
	logg("Backtrace:");

	char ** bcktrace = backtrace_symbols(buffer, calls);
	if(bcktrace == NULL)
		logg("Unable to obtain backtrace symbols!");

	// Try to compute binary offset from backtrace_symbols result
	void *offset = NULL;
	for(int j = 0; j < calls; j++)
	{
		void *p1 = NULL, *p2 = NULL;
		char *pend = NULL;
		if((pend = strrchr(bcktrace[j], '(')) != NULL &&
		   strstr(bcktrace[j], BINARY_NAME) != NULL &&
		   sscanf(pend, "(+%p) [%p]", &p1, &p2) == 2)
		   offset = (void*)(p2-p1);
	}

	for(int j = 0; j < calls; j++)
	{
		logg("B[%04i]: %p, %s", j, buffer[j],
		     bcktrace != NULL ? bcktrace[j] : "---");

		if(bcktrace != NULL)
			print_addr2line(bcktrace[j], buffer[j], j, offset);
	}
	if(bcktrace != NULL)
		free(bcktrace);
#else
	logg("!!! INFO: pihole-FTL has not been compiled with glibc/backtrace support, not generating one !!!");
#endif
	// Print content of /dev/shm
	ls_dir("/dev/shm");


	logg("Thank you for helping us to improve our FTL engine!");

	// Terminate main process if crash happened in a TCP worker
	if(pid != getpid())
	{
		// This is a forked process
		logg("Asking parent pihole-FTL (PID %i) to shut down", (int)pid);
		kill(pid, SIGTERM);
		logg("FTL fork terminated!");
	}
	else
	{
		// This is the main process
		logg("FTL terminated!");
	}

	// Terminate process indicating failure
	exit_code = EXIT_FAILURE;
	exit(exit_code);
}

static void SIGRT_handler(int signum, siginfo_t *si, void *unused)
{ 
	// Ignore real-time signals outside of the main process (TCP forks)
	if(pid != getpid())
		return;

	int rtsig = signum - SIGRTMIN;
	logg("Received: %s (%d -> %d)", strsignal(signum), signum, rtsig);

	if(rtsig == 0)
	{
		// Reload
		// - gravity
		// - exact whitelist
		// - regex whitelist
		// - exact blacklist
		// - exact blacklist
		// WITHOUT wiping the DNS cache itself
		FTL_reload_all_domainlists();

		// Reload the privacy level in case the user changed it
		get_privacy_level(NULL);
	}
}

// Register SIGSEGV handler
void handle_SIGSEGV(void)
{
	struct sigaction old_action;

	// Catch SIGSEGV
	sigaction (SIGSEGV, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN)
	{
		struct sigaction SEGVaction;
		memset(&SEGVaction, 0, sizeof(struct sigaction));
		SEGVaction.sa_flags = SA_SIGINFO;
		sigemptyset(&SEGVaction.sa_mask);
		SEGVaction.sa_sigaction = &SIGSEGV_handler;
		sigaction(SIGSEGV, &SEGVaction, NULL);
	}

	// Log start time of FTL
	FTLstarttime = time(NULL);

}

// Register real-time signal handler
void handle_realtime_signals(void)
{
	// This function is only called once (after forking), store the PID of
	// the main process
	pid = getpid();

	// Catch first five real-time signals
	for(unsigned int i = 0; i < 5; i++)
	{
		struct sigaction SIGACTION;
		memset(&SIGACTION, 0, sizeof(struct sigaction));
		SIGACTION.sa_flags = SA_SIGINFO;
		sigemptyset(&SIGACTION.sa_mask);
		SIGACTION.sa_sigaction = &SIGRT_handler;
		sigaction(SIGRTMIN + i, &SIGACTION, NULL);
	}
}
