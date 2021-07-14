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
#include "config/config.h"
#include "database/common.h"
#include "main.h"
#include "signals.h"
#include "regex_r.h"
// init_shmem()
#include "shmem.h"
#include "capabilities.h"
#include "timers.h"
// http_terminate()
#include "webserver/webserver.h"
#include "procps.h"
// init_memory_database(), import_queries_from_disk()
#include "database/query-table.h"
// init_overtime()
#include "overTime.h"

char *username;
bool needGC = false;
bool needDBGC = false;
bool startup = true;
volatile int exit_code = EXIT_SUCCESS;

int main (int argc, char *argv[])
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

	// Initialize FTL log
	init_FTL_log(argc > 0 ? argv[0] : NULL);
	timer_start(EXIT_TIMER);
	log_info("########## FTL started on %s! ##########", hostname());
	log_FTL_version(false);

	// Catch signals not handled by dnsmasq
	// We configure real-time signals later (after dnsmasq has forked)
	handle_signals();

	// Initialize shared memory
	if(!init_shmem(true))
	{
		log_crit("Initialization of shared memory failed.");
		// Check if there is already a running FTL process
		check_running_FTL();
		return EXIT_FAILURE;
	}

	// Process FTL config file
	readFTLconf();

	// pihole-FTL should really be run as user "pihole" to not mess up with file permissions
	// print warning otherwise
	if(strcmp(username, "pihole") != 0)
		log_warn("Starting pihole-FTL as user %s is not recommended", username);

	// Delay startup (if requested)
	// Do this before reading the database to make this option not only
	// useful for interfaces that aren't ready but also for fake-hwclocks
	// which aren't ready at this point
	delay_startup();

	// Initialize overTime datastructure
	initOverTime();

	// Initialize query database (pihole-FTL.db)
	db_init();

	// Initialize in-memory databases
	if(!init_memory_databases())
	{
		log_crit("FATAL: Cannot initialize in-memory database.");
		return EXIT_FAILURE;
	}

	// Try to import queries from long-term database if available
	if(config.DBimport)
	{
		import_queries_from_disk();
		DB_read_queries();
	}

	log_counter_info();
	check_setupVarsconf();

	// Check for availability of advanced capabilities
	// immediately before starting the resolver.
	check_capabilities();

	// Initialize pseudo-random number generator
	srand(time(NULL));

	startup = false;
	if(config.debug != 0)
	{
		for(int i = 0; i < argc_dnsmasq; i++)
			log_debug(DEBUG_ANY, "argv[%i] = \"%s\"", i, argv_dnsmasq[i]);
	}
	// Check initial blocking status
	check_blocking_status();

	// Start the resolver
	main_dnsmasq(argc_dnsmasq, argv_dnsmasq);

	log_info("Shutting down...");
	// Extra grace time is needed as dnsmasq script-helpers may not be
	// terminating immediately
	sleepms(250);

	// Save new queries to database (if database is used)
	if(config.DBexport)
	{
		export_queries_to_disk(true);
		log_info("Finished final database update");
	}

	cleanup(exit_code);

	return exit_code;
}
