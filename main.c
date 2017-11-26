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

int main (int argc, char* argv[]) {
	username = getUserName();

	if(argc > 1)
		parse_args(argc, argv);

	// Try to open FTL log
	open_FTL_log(true);
	open_pihole_log();
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

	handle_signals();

	read_gravity_files();

	if(config.maxDBdays != 0)
		db_init();

	logg("Starting initial log file parsing");
	initial_log_parsing();
	logg("Finished initial log file parsing");
	log_counter_info();
	check_setupVarsconf();

	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_t piholelogthread;
	if(pthread_create( &piholelogthread, &attr, pihole_log_thread, NULL ) != 0)
	{
		logg("Unable to open Pi-hole log processing thread. Exiting...");
		killed = 1;
	}

	pthread_t socket_listenthread;
	if(pthread_create( &socket_listenthread, &attr, socket_listenting_thread, NULL ) != 0)
	{
		logg("Unable to open socket listening thread. Exiting...");
		killed = 1;
	}

	while(!killed)
	{
		sleepms(100);

		bool runGCthread = false, runDBthread = false;

		if(((time(NULL) - GCdelay)%GCinterval) == 0)
			runGCthread = true;

		if(database && ((time(NULL)%DBinterval) == 0))
			runDBthread = true;

		// Garbadge collect in regular interval, but don't do it if the threadlocks is set
		// This will also run reresolveHostnames()
		if(runGCthread || needGC)
		{
			// Wait until we are allowed to work on the data
			while(threadwritelock || threadreadlock)
				sleepms(100);

			needGC = false;
			runGCthread = false;

			if(config.rolling_24h)
			{
				pthread_t GCthread;
				if(pthread_create( &GCthread, &attr, GC_thread, NULL ) != 0)
				{
					logg("Unable to open GC thread. Exiting...");
					killed = 1;
				}
			}

			if(database)
				DBdeleteoldqueries = true;

			// Avoid immediate re-run of GC thread
			while(((time(NULL) - GCdelay)%GCinterval) == 0)
				sleepms(100);
		}

		// Dump to database in regular interval
		if(runDBthread)
		{
			// Wait until we are allowed to work on the data
			while(threadwritelock || threadreadlock)
				sleepms(100);

			runDBthread = false;

			pthread_t DBthread;
			if(pthread_create( &DBthread, &attr, DB_thread, NULL ) != 0)
			{
				logg("WARN: Unable to open DB thread.");
			}

			// Avoid immediate re-run of DB thread
			while(((time(NULL)%DBinterval) == 0))
				sleepms(100);
		}

		// Handle SIGHUP
		if(rereadgravity)
		{
			enable_thread_lock("pihole_main_thread");
			// Have to re-read gravity files
			rereadgravity = false;
			read_gravity_files();
			disable_thread_lock("pihole_main_thread");
		}
	}


	logg("Shutting down...");
	pthread_cancel(piholelogthread);
	pthread_cancel(socket_listenthread);
	close_socket(SOCKET);
	removepid();
	logg("########## FTL terminated! ##########");
	return 1;
}
