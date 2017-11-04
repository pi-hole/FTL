/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Argument parsing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "version.h"

bool debug = false;
bool daemonmode = true;
bool debugthreads = false;
bool debugclients = false;
bool debugGC = false;
bool runtest = false;
bool debugDB = false;
bool travis = false;
void parse_args(int argc, char* argv[])
{
	int i;
	// start from 1, as argv[0] is the executable name "pihole-FTL"
	for(i=1; i < argc; i++)
	{
		bool ok = false;
		if(strcmp(argv[i], "d") == 0 ||
		   strcmp(argv[i], "debug") == 0)
		{
			debug = true;
			ok = true;
		}

		if(strcmp(argv[i], "debugthreads") == 0)
		{
			debug = true;
			debugthreads = true;
			ok = true;
		}

		if(strcmp(argv[i], "debugclients") == 0)
		{
			debug = true;
			debugclients = true;
			ok = true;
		}

		if(strcmp(argv[i], "debugGC") == 0)
		{
			debug = true;
			debugGC = true;
			ok = true;
		}

		if(strcmp(argv[i], "debugDB") == 0)
		{
			debug = true;
			debugDB = true;
			ok = true;
		}

		if(strcmp(argv[i], "test") == 0)
			killed = 1;

		if(strcmp(argv[i], "-v") == 0 ||
		   strcmp(argv[i], "version") == 0)
		{
			if(strcmp(GIT_BRANCH, "master") == 0)
				printf("%s\n",GIT_VERSION);
			else
				printf("vDev-%s\n",GIT_HASH);
			exit(EXIT_SUCCESS);
		}

		if(strcmp(argv[i], "-t") == 0 ||
		   strcmp(argv[i], "tag") == 0)
		{
			printf("%s\n",GIT_TAG);
			exit(EXIT_SUCCESS);
		}

		if(strcmp(argv[i], "-b") == 0 ||
		   strcmp(argv[i], "branch") == 0)
		{
			printf("%s\n",GIT_BRANCH);
			exit(EXIT_SUCCESS);
		}

		// pihole-FTL running
		// will test if another pihole-FTL process is running
		// and exits even if not (instead of starting a new one)
		if(strcmp(argv[i], "running") == 0)
		{
			runtest = true;
			ok = true;
		}

		// Don't go into background
		if(strcmp(argv[i], "-f") == 0 ||
		   strcmp(argv[i], "no-daemon") == 0)
		{
			daemonmode = false;
			ok = true;
		}

		// Use files in local places for Travis-CI tests
		if(strcmp(argv[i], "travis-ci") == 0)
		{
			travis = true;
			FTLfiles.log = "pihole-FTL.log";
			FTLfiles.db = "pihole-FTL.db";
			files.log = "pihole.log";
			ok = true;
		}

		// List of implemented arguments
		if(strcmp(argv[i], "-h") == 0 ||
		   strcmp(argv[i], "help") == 0)
		{
			printf("pihole-FTL - The Pi-hole FTL engine\n\n");
			printf("Usage:    sudo service pihole-FTL <action>\n");
			printf("where '<action>' is one of start / stop / restart\n\n");
			printf("Available arguments:\n");
			printf("\td,  debug         More verbose logging,\n");
			printf("\t                  don't go into daemon mode\n");
			printf("\t    test          Don't start pihole-FTL but\n");
			printf("\t                  instead quit immediately\n");
			printf("\t-v, version       Return version\n");
			printf("\t-t, tag           Return git tag\n");
			printf("\t-b, branch        Return git branch\n");
			printf("\t    running       Test if another pihole-FTL\n");
			printf("\t                  process is running and exit\n");
			printf("\t                  even if not (instead of\n");
			printf("\t                  starting a new one)\n");
			printf("\t-f, no-daemon     Don't go into daemon mode\n");
			printf("\t-h, help          Display this help and exit\n");
			printf("\n\nOnline help: https://github.com/pi-hole/FTL\n\n");
			exit(EXIT_SUCCESS);
		}

		// Complain if invalid options have been found
		if(!ok)
		{
			printf("pihole-FTL: invalid option -- '%s'\nTry '%s --help' for more information\n\n", argv[i], argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}
