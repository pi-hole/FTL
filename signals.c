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

void term(int signum)
{
	killed = 1;
}

void SIGSEGV_handler(int sig) {
	void *buffer[100] = { NULL };
	int nptrs;
	char **strings;

	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("---------------------------->  FTL crashed!  <----------------------------");
	logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logg("> Please report a bug at https://github.com/pi-hole/FTL/issues");
	logg("> Please include in your report the following details:");
	logg(">");
	logg_str("> Error signal: ", strsignal(sig));

	// Print memory usage
	unsigned long int structbytes = sizeof(countersStruct) + sizeof(ConfigStruct) + counters.queries_MAX*sizeof(queriesDataStruct) + counters.forwarded_MAX*sizeof(forwardedDataStruct) + counters.clients_MAX*sizeof(clientsDataStruct) + counters.domains_MAX*sizeof(domainsDataStruct) + counters.overTime_MAX*sizeof(overTimeDataStruct) + (counters.wildcarddomains)*sizeof(*wildcarddomains);
	unsigned long int dynamicbytes = memory.wildcarddomains + memory.domainnames + memory.clientips + memory.clientnames + memory.forwardedips + memory.forwardednames + memory.forwarddata + memory.querytypedata;
	logg_ulong("> Memory usage (structs): ", structbytes);
	logg_ulong("> Memory usage (dynamic): ", dynamicbytes);
	logg(">");

	// get void*'s for all entries on the stack
	nptrs = backtrace(buffer, 100);
	logg_int("> Number of obtained backtrace addresses: ", nptrs);

	// Get backtrace symbols
	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		logg("> Backtrace failed!");
		exit(EXIT_FAILURE);
	}

	int j;
	for (j = 0; j < nptrs; j++)
		logg_str(">   BT ", strings[j]);
	free(strings);

	logg(">");
	logg("> Additionally, in order to make the above backtrace useful,");
	logg("> please also run the following command to generate a disassembly of your binary:");
	logg(">    objdump -d $(which pihole-FTL) > pihole-FTL.objdump");
	logg("> and then attach the file pihole-FTL.objdump to your bug report.");
	logg("> We can provide support for attaching large files through our Tricorder system.");
	logg(">");
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
	struct sigaction TERMaction;
	memset(&TERMaction, 0, sizeof(struct sigaction));
	TERMaction.sa_handler = term;
	sigaction(SIGTERM, &TERMaction, NULL);

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	struct sigaction SEGVaction;
	memset(&SEGVaction, 0, sizeof(struct sigaction));
	SEGVaction.sa_handler = SIGSEGV_handler;
	sigaction(SIGSEGV, &SEGVaction, NULL);
}
