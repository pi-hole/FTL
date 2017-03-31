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

static void SIGTERM_handler(int signum)
{
	killed = 1;
}

static void SIGSEGV_handler(int sig, siginfo_t *si, void *unused)
{
	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("---------------------------->  FTL crashed!  <----------------------------");
	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("> Please report a bug at https://github.com/pi-hole/FTL/issues");
	logg("> and include in your report already the following details:");
	logg(">");
	logg_str  ("> Received signal: ", strsignal(sig));
	logg_ulong("       at address: ", (unsigned long) si->si_addr);
	switch (si->si_code)
	{
		case SEGV_MAPERR: logg("        with code: SEGV_MAPERR (Address not mapped to object)"); break;
		case SEGV_ACCERR: logg("        with code: SEGV_ACCERR (Invalid permissions for mapped object)"); break;
#if defined(SEGV_BNDERR)
		case SEGV_BNDERR: logg("        with code: SEGV_BNDERR (Failed address bound checks)"); break;
#endif
		default: logg_int("        with code: Unknown, ",si->si_code); break;
	}

	// Print memory usage
	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata + memory.querytypedata;
	logg_ulong("> Memory usage (structs): ", structbytes);
	logg_ulong("> Memory usage (dynamic): ", dynamicbytes);
	logg(">");

	// Getting backtrace symbols is meaningless here since if we would now start a backtrace
	// then the addresses would only point to this signal handler
	logg("> Thank you for helping us to improve our FTL engine!");

	if(debug)
	{
		logg("> Debug mode detected - trying to automatically attach gdb...");
		char cmd[256];
		sprintf(cmd, "gdb \"pihole-FTL\" %d", getpid());
		logg_int("gdb call returned: ",system(cmd));
	}

	// Print message and return
	logg("FTL terminated!");
	exit(EXIT_FAILURE);
}

void handle_signals(void)
{
	// Catch SIGTERM
	struct sigaction TERMaction;
	memset(&TERMaction, 0, sizeof(struct sigaction));
	sigemptyset(&TERMaction.sa_mask);
	TERMaction.sa_handler = &SIGTERM_handler;
	sigaction(SIGTERM, &TERMaction, NULL);

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	// Catch SIGSEGV
	struct sigaction SEGVaction;
	memset(&SEGVaction, 0, sizeof(struct sigaction));
	SEGVaction.sa_flags = SA_SIGINFO;
	sigemptyset(&SEGVaction.sa_mask);
	SEGVaction.sa_sigaction = &SIGSEGV_handler;
	sigaction(SIGSEGV, &SEGVaction, NULL);
}
