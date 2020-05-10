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

volatile sig_atomic_t killed = 0;
static time_t FTLstarttime = 0;

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

	for(int j = 0; j < calls; j++)
	{
		logg("B[%04i]: %p, %s", j, buffer[j],
		     bcktrace != NULL ? bcktrace[j] : "---");
	}
	if(bcktrace != NULL)
		free(bcktrace);
#else
	logg("!!! INFO: pihole-FTL has not been compiled with glibc/backtrace support, not generating one !!!");
#endif
	// Print content of /dev/shm
	ls_dir("/dev/shm");

	logg("Thank you for helping us to improve our FTL engine!");

	// Print message and abort
	logg("FTL terminated!");
	exit(EXIT_FAILURE);
}

static void SIGRT_handler(int signum, siginfo_t *si, void *unused)
{ 
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
	}
} 

void handle_signals(void)
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

	// Log start time of FTL
	FTLstarttime = time(NULL);
}
