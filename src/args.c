/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Argument parsing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// DNSMASQ COPYRIGHT
#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN

#include "FTL.h"
#include "args.h"
#include "version.h"
#include "memory.h"
#include "main.h"
#include "log.h"
// global variable killed
#include "signals.h"
#include "lua/ftl_lua.h"
#include <readline/history.h>
#include <wordexp.h>

static bool debug = false;
bool daemonmode = true;
int argc_dnsmasq = 0;
const char** argv_dnsmasq = NULL;

static inline bool strEndsWith(const char *input, const char *end){
	return strcmp(input + strlen(input) - strlen(end), end) == 0;
}

void parse_args(int argc, char* argv[])
{
	// Regardless of any arguments, we always pass "-k" (nofork) to dnsmasq
	argc_dnsmasq = 2;
	argv_dnsmasq = calloc(argc_dnsmasq, sizeof(char*));
	argv_dnsmasq[0] = "";
	argv_dnsmasq[1] = "-k";

	bool consume_for_dnsmasq = false;
	// If the binary name is "dnsmasq" (e.g., symlink /usr/bin/dnsmasq -> /usr/bin/pihole-FTL),
	// we operate in drop-in mode and consume all arguments for the embedded dnsmasq core
	if(strEndsWith(argv[0], "dnsmasq"))
		consume_for_dnsmasq = true;

	// start from 1, as argv[0] is the executable name
	for(int i = 1; i < argc; i++)
	{
		bool ok = false;

		// Implement dnsmasq's test function, no need to prepare the entire FTL
		// environment (initialize shared memory, lead queries from long-term
		// database, ...) when the task is a simple (dnsmasq) syntax check
		if(strcmp(argv[i], "dnsmasq-test") == 0 ||
		   strcmp(argv[i], "--test") == 0)
		{
			const char *arg[2];
			arg[0] = "";
			arg[1] = "--test";
			main_dnsmasq(2, arg);
			ok = true;
		}

		// If we find "--" we collect everything behind that for dnsmasq
		if(strcmp(argv[i], "--") == 0)
		{
			// Remember that the rest is for dnsmasq ...
			consume_for_dnsmasq = true;

			// ... and skip the current argument ("--")
			continue;
		}

		// If consume_for_dnsmasq is true, we collect all remaining options for
		// dnsmasq
		if(consume_for_dnsmasq)
		{
			argc_dnsmasq = argc - i + 2;
			if(argv_dnsmasq != NULL)
				free(argv_dnsmasq);

			argv_dnsmasq = calloc(argc_dnsmasq, sizeof(const char*));
			argv_dnsmasq[0] = "";

			if(debug)
				argv_dnsmasq[1] = "-d";
			else
				argv_dnsmasq[1] = "-k";

			if(debug)
			{
				printf("dnsmasq options: [0]: %s\n", argv_dnsmasq[0]);
				printf("dnsmasq options: [1]: %s\n", argv_dnsmasq[1]);
			}

			int j = 2;
			while(i < argc)
			{
				argv_dnsmasq[j++] = strdup(argv[i++]);
				if(debug)
					printf("dnsmasq options: [%i]: %s\n", j-1, argv_dnsmasq[j-1]);
			}

			// Return early: We have consumes all available command line arguments
			return;
		}

		// What follows beyond this point are FTL internal command line arguments

		if(strcmp(argv[i], "d") == 0 ||
		   strcmp(argv[i], "debug") == 0)
		{
			debug = true;
			daemonmode = false;
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
			printf("%s\n", get_FTL_version());
			exit(EXIT_SUCCESS);
		}

		if(strcmp(argv[i], "-vv") == 0) // Extended version
		{
			printf("Pi-hole FTL: %s\n", get_FTL_version());
			printf("dnsmasq: "DNSMASQ_VERSION"  "COPYRIGHT"\n");
			printf("LUA: "LUA_COPYRIGHT"\n");
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
			printf("\t-vv               Return extended version\n");
			printf("\t-t, tag           Return git tag\n");
			printf("\t-b, branch        Return git branch\n");
			printf("\t-f, no-daemon     Don't go into daemon mode\n");
			printf("\t-h, help          Display this help and exit\n");
			printf("\tdnsmasq-test      Test syntax of dnsmasq's\n");
			printf("\t                  config files and exit\n");
			printf("\t--lua, lua        FTL's lua interpreter\n");
			printf("\t--luac, luac      FTL's lua compiler\n");
			printf("\n\nOnline help: https://github.com/pi-hole/FTL\n");
			exit(EXIT_SUCCESS);
		}

		// Return success error code on this undocumented flag
		if(strcmp(argv[i], "--resolver") == 0)
		{
			printf("True\n");
			exit(EXIT_SUCCESS);
		}

		// Expose internal lua interpreter
		if(strcmp(argv[i], "lua") == 0 ||
		   strcmp(argv[i], "--lua") == 0)
		{
			if(argc == i + 1) // No arguments after this one
				printf("Pi-hole FTL %s\n", get_FTL_version());
#if defined(LUA_USE_READLINE)
			wordexp_t word;
			wordexp(LUA_HISTORY_FILE, &word, WRDE_NOCMD);
			const char *history_file = NULL;
			if(word.we_wordc == 1)
			{
				history_file = word.we_wordv[0];
				const int ret_r = read_history(history_file);
				if(debug)
					printf("FTL hint: Reading history: %s = %i (%s)\n", history_file, ret_r, ret_r == 0 ? "success" : strerror(ret_r));

				// The history file may not exist, try to create an empty one in this case
				if(ret_r == ENOENT)
				{
					printf("FTL hint: Creating new history: %s\n", history_file);
					FILE *history = fopen(history_file, "w");
					if(history != NULL)
						fclose(history);
				}
			}
#endif
			const int ret = lua_main(argc - i, &argv[i]);
#if defined(LUA_USE_READLINE)
			if(history_file != NULL)
			{
				const int ret_w = write_history(history_file);
				if(debug)
					printf("FTL hint: Writing history: %s = %i (%s)\n", history_file, ret_w, ret_w == 0 ? "success" : strerror(ret_w));
				wordfree(&word);
			}
#endif
			exit(ret);
		}

		// Expose internal lua compiler
		if(strcmp(argv[i], "luac") == 0 ||
		   strcmp(argv[i], "--luac") == 0)
		{
			if(argc == i + 1) // No arguments after this one
				printf("Pi-hole FTL %s\n", get_FTL_version());
			exit(luac_main(argc - i, &argv[i]));
		}

		// Complain if invalid options have been found
		if(!ok)
		{
			printf("pihole-FTL: invalid option -- '%s'\nTry '%s --help' for more information\n", argv[i], argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}
