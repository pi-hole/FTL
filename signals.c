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
#include <execinfo.h>

volatile sig_atomic_t killed = 0;
time_t FTLstarttime = 0;

static void SIGSEGV_handler(int sig, siginfo_t *si, void *unused)
{
	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("---------------------------->  FTL crashed!  <----------------------------");
	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("Please report a bug at https://github.com/pi-hole/FTL/issues");
	logg("and include in your report already the following details:\n");

	if(FTLstarttime != 0)
	{
		logg("FTL has been running for %i seconds", time(NULL)-FTLstarttime);
	}
	log_FTL_version();

	logg("Received signal: %s", strsignal(sig));
	logg("     at address: %lu", (unsigned long) si->si_addr);
	switch (si->si_code)
	{
		case SEGV_MAPERR: logg("     with code: SEGV_MAPERR (Address not mapped to object)"); break;
		case SEGV_ACCERR: logg("     with code: SEGV_ACCERR (Invalid permissions for mapped object)"); break;
#if defined(SEGV_BNDERR)
		case SEGV_BNDERR: logg("     with code: SEGV_BNDERR (Failed address bound checks)"); break;
#endif
		default: logg("     with code: Unknown (%i), ",si->si_code); break;
	}

	// Try to obtain backtrace. This may not always be helpful, but it is better than nothing
	void *buffer[255];
	const int calls = backtrace(buffer, sizeof(buffer)/sizeof(void *));
	char ** bcktrace = backtrace_symbols(buffer, calls);
	if(bcktrace == NULL)
	{
		logg("Unable to obtain backtrace (%i)!",calls);
	}
	else
	{
		logg("Backtrace:");
		int j;
		for (j = 0; j < calls; j++)
		{
			logg("B[%04i]: %s",j,bcktrace[j]);
		}
	}
	free(bcktrace);

	logg("Thank you for helping us to improve our FTL engine!");

	// Print message and abort
	logg("FTL terminated!");
	abort();
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

	// Log start time of FTL
	FTLstarttime = time(NULL);
}
