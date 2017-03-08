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

int main (int argc, char* argv[]) {

	if(argc > 1)
		parse_args(argc, argv);

	open_FTL_log();
	open_pihole_log();
	logg("########## FTL started! ##########");
	logg_str("FTL branch: ",GIT_BRANCH);
	logg_str("FTL hash: ",GIT_VERSION);
	logg_str("FTL date: ",GIT_DATE);

	if(!debug)
		go_daemon();
	else
		savepid(getpid());

	handle_signals();

	init_socket();

	read_gravity_files();

	logg("Starting initial log file scan");
	initialscan = true;
	process_pihole_log();
	initialscan = false;
	logg("Finished initial log file scan:");
	log_counter_info();
	check_setupVarsconf();

	pthread_t piholelogthread;
	if(pthread_create( &piholelogthread, NULL, pihole_log_thread, NULL ) != 0)
	{
		logg("Unable to open Pi-hole log processing thread. Exiting...");
		killed = 1;
	}

	pthread_t listenthread;
	if(pthread_create( &listenthread, NULL, listenting_thread, NULL ) != 0)
	{
		logg("Unable to open Socket listening thread. Exiting...");
		killed = 1;
	}

	while(!killed)
	{
		sleepms(100);
	}


	logg("Shutting down...");
	pthread_cancel(piholelogthread);
	pthread_cancel(listenthread);
//	close_sockets();
	logg("########## FTL terminated! ##########");
	fclose(logfile);
	return 1;
}
