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
	username = getUserName();

	if(argc > 1)
		parse_args(argc, argv);

	// Try to open FTL log
	open_FTL_log(true);
	logg("########## FTL started! ##########");
	log_FTL_version();
	init_thread_lock();

	// pihole-FTL should really be run as user "pihole" to not mess up with the file permissions
	// still allow this if "debug" flag is set
	if(strcmp(username,"pihole") != 0 && !debug)
	{
		logg("Warning: Starting pihole-FTL directly is not recommended.");
		logg("         Instead, use system commands for starting pihole-FTL as service (systemctl / service).");
	}

	read_FTLconf();

	if(!debug && daemonmode)
		go_daemon();
	else
		savepid();

	// Catch signals like SIGHUP, SIGUSR1, etc.
	// TODO: Maybe we should have this handled by the dnsmasq part
	//handle_signals();

	// Initialize database
	if(config.maxDBdays != 0)
		db_init();

	// Try to import queries from long-term database if available
	if(database)
		read_data_from_DB();

	log_counter_info();
	check_setupVarsconf();

	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Bind to sockets
	bind_sockets();

	// Start TELNET IPv4 thread
	pthread_t telnet_listenthreadv4;
	if(ipv4telnet && pthread_create( &telnet_listenthreadv4, &attr, telnet_listening_thread_IPv4, NULL ) != 0)
	{
		logg("Unable to open IPv4 telnet listening thread. Exiting...");
		return EXIT_FAILURE;
	}

	// Start TELNET IPv6 thread
	pthread_t telnet_listenthreadv6;
	if(ipv6telnet &&  pthread_create( &telnet_listenthreadv6, &attr, telnet_listening_thread_IPv6, NULL ) != 0)
	{
		logg("Unable to open IPv6 telnet listening thread. Exiting...");
		return EXIT_FAILURE;
	}

	// Start SOCKET thread
	pthread_t socket_listenthread;
	if(pthread_create( &socket_listenthread, &attr, socket_listening_thread, NULL ) != 0)
	{
		logg("Unable to open Unix socket listening thread. Exiting...");
		return EXIT_FAILURE;
	}

	// Start database thread if database is used
	pthread_t DBthread;
	if(database && pthread_create( &DBthread, &attr, DB_thread, NULL ) != 0)
	{
		logg("Unable to open database thread. Exiting...");
		return EXIT_FAILURE;
	}

	// Start thread that will stay in the background until garbage collection needs to be done
	pthread_t GCthread;
	if(pthread_create( &GCthread, &attr, GC_thread, NULL ) != 0)
	{
		logg("Unable to open GC thread. Exiting...");
		return EXIT_FAILURE;
	}

	// Actually start the resolver in here
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

	//Remove PID file
	removepid();
	logg("########## FTL terminated after %.1f ms! ##########", timer_elapsed_msec(EXIT_TIMER));
	return 1;
}
