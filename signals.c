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

volatile sig_atomic_t killed = 0;
int FTLstarttime = 0;

static void SIGTERM_handler(int sig, siginfo_t *si, void *unused)
{
	logg("FATAL: FTL received SIGTERM from PID/UID %i/%i, scheduled to exit gracefully", (int)si->si_pid, (int)si->si_uid);
	killed = 1;
}

static void SIGINT_handler(int sig, siginfo_t *si, void *unused)
{
	// Should probably not use printf in signal handler, but this will anyhow exit immediately
	logg("FATAL: FTL received SIGINT (Ctrl + C, PID/UID %i/%i), exiting immediately!", (int)si->si_pid, (int)si->si_uid);
	exit(EXIT_FAILURE);
}

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

	logg("\nReceived signal: %s", strsignal(sig));
	logg("     at address: %lu", (unsigned long) si->si_addr);
	switch (si->si_code)
	{
		case SEGV_MAPERR: logg("      with code: SEGV_MAPERR (Address not mapped to object)"); break;
		case SEGV_ACCERR: logg("      with code: SEGV_ACCERR (Invalid permissions for mapped object)"); break;
#if defined(SEGV_BNDERR)
		case SEGV_BNDERR: logg("      with code: SEGV_BNDERR (Failed address bound checks)"); break;
#endif
		default: logg("      with code: Unknown (%i), ",si->si_code); break;
	}

	// Print memory usage
	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata + memory.querytypedata;
	logg("Memory usage (structs): %lu", structbytes);
	logg("Memory usage (dynamic): %lu\n", dynamicbytes);

	// Getting backtrace symbols is meaningless here since if we would now start a backtrace
	// then the addresses would only point to this signal handler
	logg("Thank you for helping us to improve our FTL engine!");

	// Print message and abort
	logg("FTL terminated!");
	abort();
}

static void SIGUSR1_handler(int signum)
{
	logg("NOTICE: Received signal SIGUSR1");
	flush = true;
}

void handle_signals(void)
{
	// Catch SIGTERM
	struct sigaction old_action;
	sigaction (SIGTERM, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN)
	{
		struct sigaction TERMaction;
		memset(&TERMaction, 0, sizeof(struct sigaction));
		TERMaction.sa_flags = SA_SIGINFO;
		sigemptyset(&TERMaction.sa_mask);
		TERMaction.sa_sigaction = &SIGTERM_handler;
		sigaction(SIGTERM, &TERMaction, NULL);
	}

	// Catch SIGINT
	sigaction (SIGTERM, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN)
	{
		struct sigaction INTaction;
		memset(&INTaction, 0, sizeof(struct sigaction));
		INTaction.sa_flags = SA_SIGINFO;
		sigemptyset(&INTaction.sa_mask);
		INTaction.sa_sigaction = &SIGINT_handler;
		sigaction(SIGINT, &INTaction, NULL);
	}

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

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

	// Catch SIGUSR1
	sigaction (SIGUSR1, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN)
	{
		struct sigaction USR1action;
		memset(&USR1action, 0, sizeof(struct sigaction));
		sigemptyset(&USR1action.sa_mask);
		USR1action.sa_handler = &SIGUSR1_handler;
		sigaction(SIGUSR1, &USR1action, NULL);
	}

	// Log start time of FTL
	FTLstarttime = time(NULL);
}
