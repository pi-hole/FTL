/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Core routine
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "daemon.h"
#include "log.h"
#include "setupVars.h"
#include "args.h"
#include "config.h"
#include "database/common.h"
#include "database/query-table.h"
#include "main.h"
#include "signals.h"
#include "regex_r.h"
// init_shmem()
#include "shmem.h"
#include "capabilities.h"
#include "timers.h"
#include "procps.h"
// init_overtime()
#include "overTime.h"

char * username;
bool needGC = false;
bool needDBGC = false;
bool startup = true;
volatile int exit_code = EXIT_SUCCESS;

int main (int argc, char* argv[])
{
	// Get user pihole-FTL is running as
	// We store this in a global variable
	// such that the log routine can access
	// it if needed
	username = getUserName();

	// Parse arguments
	// We run this also for no direct arguments
	// to have arg{c,v}_dnsmasq initialized
	parse_args(argc, argv);

	// Try to open FTL log
	init_FTL_log();
	timer_start(EXIT_TIMER);
	logg("########## FTL started on %s! ##########", hostname());
	log_FTL_version(false);

	// Catch signals not handled by dnsmasq
	// We configure real-time signals later (after dnsmasq has forked)
	handle_signals();

	// Initialize shared memory
	if(!init_shmem(true))
	{
		logg("Initialization of shared memory failed.");
		// Check if there is already a running FTL process
		check_running_FTL();
		return EXIT_FAILURE;
	}

	// Process pihole-FTL.conf
	read_FTLconf();

	// pihole-FTL should really be run as user "pihole" to not mess up with file permissions
	// print warning otherwise
	if(strcmp(username, "pihole") != 0)
		logg("WARNING: Starting pihole-FTL as user %s is not recommended", username);

	// Delay startup (if requested)
	// Do this before reading the database to make this option not only
	// useful for interfaces that aren't ready but also for fake-hwclocks
	// which aren't ready at this point
	delay_startup();

	// Initialize overTime datastructure
	initOverTime();

	// Initialize query database (pihole-FTL.db)
	db_init();

	// Try to import queries from long-term database if available
	if(config.DBimport)
		DB_read_queries();

	log_counter_info();
	check_setupVarsconf();

	// Check for availability of advanced capabilities
	// immediately before starting the resolver.
	check_capabilities();

	// Start the resolver
	startup = false;
	if(config.debug != 0)
	{
		for(int i = 0; i < argc_dnsmasq; i++)
			logg("DEBUG: argv[%i] = \"%s\"", i, argv_dnsmasq[i]);
	}
	main_dnsmasq(argc_dnsmasq, argv_dnsmasq);

	logg("Shutting down...");
	// Extra grace time is needed as dnsmasq script-helpers may not be
	// terminating immediately
	sleepms(250);

	// Save new queries to database (if database is used)
	if(config.DBexport)
	{
		lock_shm();
		int saved;
		if((saved = DB_save_queries(NULL)) > -1)
			logg("Finished final database update (stored %d queries)", saved);
		unlock_shm();
	}

	cleanup(exit_code);

	return exit_code;
}
