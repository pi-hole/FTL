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
#include "version.h"

char * username;
bool needGC = false;

int main (int argc, char* argv[]) {
	username = getUserName();

	if(argc > 1)
		parse_args(argc, argv);

	// pihole-FTL should really be run as user "pihole" to not mess up with the file permissions
	// still allow this if "debug" flag is set
	if(strcmp(username,"pihole") != 0 && !debug)
	{
		printf("\n!!! WARNING !!!\nStaring pihole-FTL directly is not recommended.\nInstead, use\n              sudo service pihole-FTL restart\n\n");
		exit(EXIT_FAILURE);
	}

	open_FTL_log();
	open_pihole_log();
	logg("########## FTL started! ##########");
	logg_const_str("FTL branch: ", GIT_BRANCH);
	logg_const_str("FTL hash: ", GIT_VERSION);
	logg_const_str("FTL date: ", GIT_DATE);
	logg_str("FTL user: ", username);

	read_FTLconf();

	if(!debug)
		go_daemon();
	else
		savepid(getpid());

	handle_signals();

	read_gravity_files();

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

	// Initialize sockets only after initial log parsing
	init_socket();

	pthread_t listenthread;
	if(pthread_create( &listenthread, &attr, listenting_thread, NULL ) != 0)
	{
		logg("Unable to open Socket listening thread. Exiting...");
		killed = 1;
	}

	if(config.rolling_24h)
	{
		pthread_t GCthread;
		if(pthread_create( &GCthread, &attr, GC_thread, NULL ) != 0)
		{
			logg("Unable to start initial GC thread. Exiting...");
			killed = 1;
		}
	}

	while(!killed)
	{
		sleepms(100);

		// Garbadge collect in regular interval, but don't do it if the threadlocks is set
		if(config.rolling_24h && ((((time(NULL) - GCdelay)%GCinterval) == 0 && !(threadwritelock || threadreadlock)) || needGC))
		{
			needGC = false;
			if(debug)
				logg_int("Running GC on data structure due to set interval of [s]: ", GCinterval);

			pthread_t GCthread;
			if(pthread_create( &GCthread, &attr, GC_thread, NULL ) != 0)
			{
				logg("Unable to open GC thread. Exiting...");
				killed = 1;
			}

			while(((time(NULL) - GCdelay)%GCinterval) == 0)
				sleepms(100);
		}
	}


	logg("Shutting down...");
	pthread_cancel(piholelogthread);
	pthread_cancel(listenthread);
//	close_sockets();
	logg("########## FTL terminated! ##########");
	fclose(logfile);
	return 1;
}
