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
// verify_FTL()
#include "files.h"
// init_entropy()
#include "webserver/x509.h"
// SQLite3LogCallback()
#include "database/common.h"
// pihole_sqlite3_initalize()
#include "database/sqlite3-ext.h"

char *username;
bool startup = true;
bool forked = false;
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
	getLogFilePath(true);

	// Store binary path and PIE load base address for crash-time backtrace.
	// Must be called before handle_signals() so bin_path is populated before
	// the first possible signal.
	init_backtrace(argc > 0 ? argv[0] : NULL);

	// Parse arguments
	// We run this also for no direct arguments
	// to have arg{c,v}_dnsmasq initialized
	parse_args(argc, argv);

	// Initialize FTL log
	init_FTL_log();
	// Try to open FTL log
	init_config_mutex();
	init_config_lock();
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

	// Check if another FTL process is already running
	if(another_FTL())
		return EXIT_FAILURE;

	// Set process priority
	set_nice();

	// Initialize shared memory
	if(!init_shmem())
	{
		log_crit("Initialization of shared memory failed.");
		return EXIT_FAILURE;
	}

	// pihole-FTL should really be run as user "pihole" to not mess up with file permissions
	// print warning otherwise
	if(strcmp(username, "pihole") != 0)
		log_warn("Starting pihole-FTL as user %s is not recommended", username);

	// Write PID early on so systemd cannot be fooled during DELAY_STARTUP
	// times. The PID in this file will later be overwritten after forking
	savePID();

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
	srand(time(NULL) + getpid());

	// Start the resolver
	startup = false;
	// Stop writing to STDOUT
	log_ctrl(true, false);

	// Initialize SQLite3 logging callback
	// This ensures SQLite3 errors and warnings are logged to FTL.log
	// We use this to possibly catch even more errors in places we do not
	// explicitly check for failures to have happened
	sqlite3_config(SQLITE_CONFIG_LOG, SQLite3LogCallback, NULL);

	// Register Pi-hole provided SQLite3 extensions (see sqlite3-ext.c) and
	// initialize SQLite3 engine
	pihole_sqlite3_initalize();

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

		if(!forked)
		{
			// If dnsmasq never finished initializing, we need to
			// launch the threads
			FTL_fork_and_bind_sockets(NULL, false);
		}

		// Loop here to keep the webserver running unless requested to restart
		while(!killed)
			sleepms(100);
	}

	log_info("Shutting down (exit code %d, jmpret %d)", exit_code, jmpret);
	// Extra grace time is needed as dnsmasq script-helpers and the API may not
	// be terminating immediately
	sleepms(250);

	// Save new queries to database
	export_queries_to_disk(true);
	log_info("Finished final database update");

	cleanup(exit_code);

	if(exit_code == RESTART_FTL_CODE)
		execvp(argv[0], argv);

	return exit_code;
}
