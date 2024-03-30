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
#include "config/setupVars.h"
#include "args.h"
#include "config/config.h"
#include "main.h"
// exit_code
#include "signals.h"
#include "regex_r.h"
// init_shmem()
#include "shmem.h"
#include "capabilities.h"
#include "timers.h"
#include "procps.h"
// init_overtime()
#include "overTime.h"
// export_queries_to_disk()
#include "database/query-table.h"

#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
#pragma message "Minimum GLIBC version: " xstr(__GLIBC__) "." xstr(__GLIBC_MINOR__)
#else
#pragma message "Minimum GLIBC version: unknown, assuming this is a MUSL build"
#endif

char *username;
bool needGC = false;
bool needDBGC = false;
bool startup = true;
jmp_buf exit_jmp;

int main (int argc, char *argv[])
{
	// Initialize locale (needed for libidn)
	init_locale();

	// Get user pihole-FTL is running as
	// We store this in a global variable
	// such that the log routine can access
	// it if needed
	username = getUserName();

	// Obtain log file location
	getLogFilePath();

	// Parse arguments
	// We run this also for no direct arguments
	// to have arg{c,v}_dnsmasq initialized
	parse_args(argc, argv);

	// Initialize FTL log
	init_FTL_log(argc > 0 ? argv[0] : NULL);
	// Try to open FTL log
	init_config_mutex();
	timer_start(EXIT_TIMER);
	log_info("########## FTL started on %s! ##########", hostname());
	log_FTL_version(false);

	// Catch signals not handled by dnsmasq
	// We configure real-time signals later (after dnsmasq has forked)
	handle_signals();

	// Process pihole.toml configuration file
	// The file is rewritten after parsing to ensure that all
	// settings are present and have a valid value
	if(readFTLconf(&config, true))
		log_info("Parsed config file "GLOBALTOMLPATH" successfully");

	// Set process priority
	set_nice();

	// Initialize shared memory
	if(!init_shmem())
	{
		log_crit("Initialization of shared memory failed.");
		// Check if there is already a running FTL process
		check_running_FTL();
		return EXIT_FAILURE;
	}

	// pihole-FTL should really be run as user "pihole" to not mess up with file permissions
	// print warning otherwise
	if(strcmp(username, "pihole") != 0)
		log_warn("Starting pihole-FTL as user %s is not recommended", username);

	// Write PID early on so systemd cannot be fooled during DELAY_STARTUP
	// times. The PID in this file will later be overwritten after forking
	savepid();

	// Delay startup (if requested)
	// Do this before reading the database to make this option not only
	// useful for interfaces that aren't ready but also for fake-hwclocks
	// which aren't ready at this point
	delay_startup();

	// Initialize overTime datastructure
	initOverTime();

	// Check for availability of capabilities in debug mode
	if(config.debug.caps.v.b)
		check_capabilities();

	// Initialize pseudo-random number generator
	srand(time(NULL));

	// Start the resolver
	startup = false;
	// Stop writing to STDOUT
	log_ctrl(true, false);

	// Call embedded dnsmasq only on the first run
	// Skip it here if we jump back to this point from die()
	const int jmpret = setjmp(exit_jmp);
	if(jmpret == 0)
		main_dnsmasq(argc_dnsmasq, (char**)argv_dnsmasq);
	else
	{
		// We are jumping back to this point from dnsmasq's die()
		log_debug(DEBUG_ANY, "Jumped back to main() from dnsmasq/die()");
		dnsmasq_failed = true;

		if(!resolver_ready)
		{
			// If dnsmasq never finished initializing, we need to
			// launch the threads
			FTL_fork_and_bind_sockets(NULL, false);
		}

		// Loop here to keep the webserver running unless requested to restart
		while(!FTL_terminate)
			sleepms(100);
	}

	log_info("Shutting down... // exit code %d // jmpret %d", exit_code, jmpret);
	// Extra grace time is needed as dnsmasq script-helpers and the API may not
	// be terminating immediately
	sleepms(250);

	// Save new queries to database (if database is used)
	if(config.database.maxDBdays.v.ui > 0)
	{
		export_queries_to_disk(true);
		log_info("Finished final database update");
	}

	cleanup(exit_code);

	if(exit_code == RESTART_FTL_CODE)
		execvp(argv[0], argv);

	return exit_code;
}
