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
bool travis = false;
int argc_dnsmasq = 0;
char **argv_dnsmasq = NULL;

void parse_args(int argc, char* argv[])
{
	int i;

	// Regardless of any arguments, we always pass "-k" (nofork) to dnsmasq
	argc_dnsmasq = 2;
	argv_dnsmasq = calloc(argc_dnsmasq, sizeof(char*));
	argv_dnsmasq[0] = "";
	argv_dnsmasq[1] = "-k";

	// start from 1, as argv[0] is the executable name "pihole-FTL"
	for(i=1; i < argc; i++)
	{
		bool ok = false;
		if(strcmp(argv[i], "d") == 0 ||
		   strcmp(argv[i], "debug") == 0)
		{
			debug = true;
			ok = true;

			// Replace "-k" by "-d" (debug mode implies nofork)
			argv_dnsmasq[1] = "-d";
		}

		if(strcmp(argv[i], "test") == 0)
		{
			killed = 1;
			ok = true;
		}

		if(strcmp(argv[i], "-v") == 0 ||
		   strcmp(argv[i], "version") == 0 ||
		   strcmp(argv[i], "--version") == 0)
		{
			const char * commit = GIT_HASH;
			const char * tag = GIT_TAG;
			if(strlen(tag) > 1)
			{
				printf("%s\n",GIT_VERSION);
			}
			else
			{
				char hash[8];
				// Extract first 7 characters of the hash
				strncpy(hash, commit, 7); hash[7] = 0;
				printf("vDev-%s\n", hash);
			}
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
			// FTLfiles.db will be set to "pihole-FTL.db" via config file on Travis
			FTLfiles.conf = "pihole-FTL.conf";
			FTLfiles.socketfile = "pihole-FTL.sock";
			files.log = "pihole.log";
			ok = true;
		}

		// Implement dnsmasq's test function
		if(strcmp(argv[i], "dnsmasq-test") == 0)
		{
			char *arg[2];
			arg[0] = "";
			arg[1] = "--test";
			main_dnsmasq(2,arg);
			ok = true;
		}

		// If we find "--" we collect everything behind that for dnsmasq
		if(strcmp(argv[i], "--") == 0)
		{
			int j;
			argc_dnsmasq = argc - i + 1;
			if(argv_dnsmasq != NULL) free(argv_dnsmasq);
			argv_dnsmasq = calloc(argc_dnsmasq + 2,sizeof(char*));
			argv_dnsmasq[0] = "";
			if(debug) argv_dnsmasq[1] = "-d";
			else      argv_dnsmasq[1] = "-k";

			for(j=2; j < argc_dnsmasq; j++)
			{
				argv_dnsmasq[j] = strdup(argv[i+j-1]);
				if(debug) logg("dnsmasq options: [%i]: %s",j,argv_dnsmasq[j]);
			}
			return;
		}

		// List of implemented arguments
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "help") == 0 || strcmp(argv[i], "--help") == 0)
		{
			printf("pihole-FTL - The Pi-hole FTL engine\n\n");
			printf("Usage:    sudo service pihole-FTL <action>\n");
			printf("where '<action>' is one of start / stop / restart\n\n");
			printf("Available arguments:\n");
			printf("\t    debug         More verbose logging,\n");
			printf("\t                  don't go into daemon mode\n");
			printf("\t    test          Don't start pihole-FTL but\n");
			printf("\t                  instead quit immediately\n");
			printf("\t-v, version       Return version\n");
			printf("\t-t, tag           Return git tag\n");
			printf("\t-b, branch        Return git branch\n");
			printf("\t-f, no-daemon     Don't go into daemon mode\n");
			printf("\t-h, help          Display this help and exit\n");
			printf("\tdnsmasq-test      Test syntax of dnsmasq's\n");
			printf("\t                  config files and exit\n");
			printf("\n\nOnline help: https://github.com/pi-hole/FTL\n");
			exit(EXIT_SUCCESS);
		}

		// Return success error code on this undocumented flag
		if(strcmp(argv[i], "--resolver") == 0)
		{
			printf("True\n");
			exit(EXIT_SUCCESS);
		}

		// Complain if invalid options have been found
		if(!ok)
		{
			printf("pihole-FTL: invalid option -- '%s'\nTry '%s --help' for more information\n", argv[i], argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}
