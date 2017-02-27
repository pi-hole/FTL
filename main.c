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

	bool clientconnected = false;
	bool waiting = false;

	while(!killed)
	{
		// Daemon loop
		int newdata = checkLogForChanges();
		if(newdata != 0 && !waiting)
		{
			waiting = true;
			timer_start();
		}

		check_socket();

		if (clientsocket > 0)
		{
			clientconnected = true;
			read_socket();
			sleepms(5);
		}
		else if(clientconnected)
		{
			clientconnected = false;
			if(debug)
				logg("Client disconnected");
		}
		else
		{
			listen_socket();
		}

		// Read new data not earlier than 50 msec
		// after they have been discovered
		if(timer_elapsed_msec() > 50)
		{
			waiting = false;
			// Process new data
			if(newdata > 0)
			{
				process_pihole_log();
			}

			// Process flushed log
			if(newdata < 0)
			{
				pihole_log_flushed();
			}
		}
	}

	logg("Shutting down...");
	close_sockets();
	logg("########## FTL terminated! ##########");
	fclose(logfile);
	return 0;
}
