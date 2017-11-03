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
	for(i=0; i < argc; i++) {
		if((strcmp(argv[i], "d") == 0) || (strcmp(argv[i], "debug") == 0))
			debug = true;

		if(strcmp(argv[i], "debugthreads") == 0)
		{
			debug = true;
			debugthreads = true;
		}

		if(strcmp(argv[i], "debugclients") == 0)
		{
			debug = true;
			debugclients = true;
		}

		if(strcmp(argv[i], "debugGC") == 0)
		{
			debug = true;
			debugGC = true;
		}

		if(strcmp(argv[i], "debugDB") == 0)
		{
			debug = true;
			debugDB = true;
		}

		if(strcmp(argv[i], "test") == 0)
			killed = 1;

		if(strcmp(argv[i], "version") == 0)
		{
			if(strcmp("master",GIT_TAG) == 0)
				printf("%s\n",GIT_VERSION);
			else
				printf("vDev-%s\n",GIT_HASH);
			exit(EXIT_SUCCESS);
		}

		if(strcmp(argv[i], "tag") == 0)
		{
			printf("%s\n",GIT_TAG);
			exit(EXIT_SUCCESS);
		}

		if(strcmp(argv[i], "branch") == 0)
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
		}

		if(strcmp(argv[i], "no-daemon") == 0 || strcmp(argv[i], "-f") == 0)
		{
			daemonmode = false;
		}

		// Use files in local places for Travis-CI tests
		if(strcmp(argv[i], "travis-ci") == 0)
		{
			travis = true;
			FTLfiles.log = "pihole-FTL.log";
			FTLfiles.db = "pihole-FTL.db";
			files.log = "pihole.log";
		}

		// Other arguments are ignored
	}
}
