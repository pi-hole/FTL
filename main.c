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

char * username;
bool needGC = false;
bool needDBGC = false;

// Prototype
int main_dnsmasq(int argc, char **argv);

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
	open_FTL_log(true);
	logg("########## FTL started! ##########");
	log_FTL_version();
	init_thread_lock();

	// pihole-FTL should really be run as user "pihole" to not mess up with file permissions
	// print warning otherwise
	if(strcmp(username, "pihole") != 0)
		logg("WARNING: Starting pihole-FTL as user %s is not recommended", username);

	// Process pihole-FTL.conf
	read_FTLconf();

	// Read and compile possible regex filters
	read_regex_from_file();

	// Catch signals like SIGTERM and SIGINT
	// Other signals like SIGHUP, SIGUSR1 are handled by the resolver part
	handle_signals();

	// Initialize database
	if(config.maxDBdays != 0)
		db_init();

	// Try to import queries from long-term database if available
	if(database)
		read_data_from_DB();

	log_counter_info();
	check_setupVarsconf();

	// Preparations done - start the resolver
	main_dnsmasq(argc_dnsmasq, argv_dnsmasq);

	logg("Shutting down...");

	// Cancel active threads as we don't need them any more
	if(ipv4telnet) pthread_cancel(telnet_listenthreadv4);
	if(ipv6telnet) pthread_cancel(telnet_listenthreadv6);
	pthread_cancel(socket_listenthread);

	// Save new queries to database
	if(database)
	{
		save_to_DB();
		logg("Finished final database update");
	}

	// Close sockets
	close_telnet_socket();
	close_unix_socket();

	// Invalidate blocking regex if compiled
	free_regex();

	//Remove PID file
	removepid();
	logg("########## FTL terminated after %.1f ms! ##########", timer_elapsed_msec(EXIT_TIMER));
	return 1;
}
