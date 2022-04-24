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
#include "main.h"
#include "log.h"
// global variable killed
#include "signals.h"
// regex_speedtest()
#include "regex_r.h"
// init_shmem()
#include "shmem.h"
// LUA dependencies
#include "lua/ftl_lua.h"
// run_dhcp_discover()
#include "dhcp-discover.h"
// defined in dnsmasq.c
extern void print_dnsmasq_version(void);

// defined in database/shell.c
extern int sqlite3_shell_main(int argc, char **argv);

bool dnsmasq_debug = false;
bool daemonmode = true, cli_mode = false;
int argc_dnsmasq = 0;
const char** argv_dnsmasq = NULL;

static inline bool strEndsWith(const char *input, const char *end){
	return strcmp(input + strlen(input) - strlen(end), end) == 0;
}

void parse_args(int argc, char* argv[])
{
	bool quiet = false;
	// Regardless of any arguments, we always pass "-k" (nofork) to dnsmasq
	argc_dnsmasq = 3;
	argv_dnsmasq = calloc(argc_dnsmasq, sizeof(char*));
	argv_dnsmasq[0] = "";
	argv_dnsmasq[1] = "-k";
	argv_dnsmasq[2] = "";

	bool consume_for_dnsmasq = false;
	// If the binary name is "dnsmasq" (e.g., symlink /usr/bin/dnsmasq -> /usr/bin/pihole-FTL),
	// we operate in drop-in mode and consume all arguments for the embedded dnsmasq core
	if(strEndsWith(argv[0], "dnsmasq"))
		consume_for_dnsmasq = true;

	// If the binary name is "lua"  (e.g., symlink /usr/bin/lua -> /usr/bin/pihole-FTL),
	// we operate in drop-in mode and consume all arguments for the embedded lua engine
	// Also, we do this if the first argument is a file with ".lua" ending
	if(strEndsWith(argv[0], "lua") ||
	   (argc > 1 && strEndsWith(argv[1], ".lua")))
		exit(run_lua_interpreter(argc, argv, false));

	// If the binary name is "luac"  (e.g., symlink /usr/bin/luac -> /usr/bin/pihole-FTL),
	// we operate in drop-in mode and consume all arguments for the embedded luac engine
	if(strEndsWith(argv[0], "luac"))
		exit(run_luac(argc, argv));

	// If the binary name is "sqlite3"  (e.g., symlink /usr/bin/sqlite3 -> /usr/bin/pihole-FTL),
	// we operate in drop-in mode and consume all arguments for the embedded SQLite3 engine
	// Also, we do this if the first argument is a file with ".db" ending
	if(strEndsWith(argv[0], "sqlite3") ||
	   (argc > 1 && strEndsWith(argv[1], ".db")))
			exit(sqlite3_shell_main(argc, argv));

	// start from 1, as argv[0] is the executable name
	for(int i = 1; i < argc; i++)
	{
		bool ok = false;

		// Expose internal lua interpreter
		if(strcmp(argv[i], "lua") == 0 ||
		   strcmp(argv[i], "--lua") == 0)
		{
			exit(run_lua_interpreter(argc - i, &argv[i], dnsmasq_debug));
		}

		// Expose internal lua compiler
		if(strcmp(argv[i], "luac") == 0 ||
		   strcmp(argv[i], "--luac") == 0)
		{
			exit(luac_main(argc - i, &argv[i]));
		}

		// Expose embedded SQLite3 engine
		if(strcmp(argv[i], "sql") == 0 ||
		   strcmp(argv[i], "sqlite3") == 0 ||
		   strcmp(argv[i], "--sqlite3") == 0)
		{
			// Human-readable table output mode
			if(i+1 < argc && strcmp(argv[i+1], "-h") == 0)
			{
				int argc2 = argc - i + 5 - 2;
				char **argv2 = calloc(argc2, sizeof(char*));
				argv2[0] = argv[0]; // Application name
				argv2[1] = (char*)"-column";
				argv2[2] = (char*)"-header";
				argv2[3] = (char*)"-nullvalue";
				argv2[4] = (char*)"(null)";
				// i = "sqlite3"
				// i+1 = "-h"
				for(int j = 0; j < argc - i - 2; j++)
					argv2[5 + j] = argv[i + 2 + j];
				exit(sqlite3_shell_main(argc2, argv2));
			}
			else
				exit(sqlite3_shell_main(argc - i, &argv[i]));
		}

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

			// Special command interpretation for "pihole-FTL -- --help dhcp"
			if(argc > 1 && strcmp(argv[argc-2], "--help") == 0 && strcmp(argv[argc-1], "dhcp") == 0)
			{
				display_opts();
				exit(EXIT_SUCCESS);
			}
			// and "pihole-FTL -- --help dhcp6"
			if(argc > 1 && strcmp(argv[argc-2], "--help") == 0 && strcmp(argv[argc-1], "dhcp6") == 0)
			{
				display_opts6();
				exit(EXIT_SUCCESS);
			}

			// ... and skip the current argument ("--")
			continue;
		}

		// If consume_for_dnsmasq is true, we collect all remaining options for
		// dnsmasq
		if(consume_for_dnsmasq)
		{
			if(argv_dnsmasq != NULL)
				free(argv_dnsmasq);

			argc_dnsmasq = argc - i + 3;
			argv_dnsmasq = calloc(argc_dnsmasq, sizeof(const char*));
			argv_dnsmasq[0] = "";

			if(dnsmasq_debug)
			{
				argv_dnsmasq[1] = "-d";
				argv_dnsmasq[2] = "--log-debug";
			}
			else
			{
				argv_dnsmasq[1] = "-k";
				argv_dnsmasq[2] = "";
			}

			if(dnsmasq_debug)
			{
				printf("dnsmasq options: [0]: %s\n", argv_dnsmasq[0]);
				printf("dnsmasq options: [1]: %s\n", argv_dnsmasq[1]);
				printf("dnsmasq options: [2]: %s\n", argv_dnsmasq[2]);
			}

			int j = 3;
			while(i < argc)
			{
				argv_dnsmasq[j++] = strdup(argv[i++]);
				if(dnsmasq_debug)
					printf("dnsmasq options: [%i]: %s\n", j-1, argv_dnsmasq[j-1]);
			}

			// Return early: We have consumes all available command line arguments
			return;
		}

		// What follows beyond this point are FTL internal command line arguments

		if(strcmp(argv[i], "d") == 0 ||
		   strcmp(argv[i], "debug") == 0)
		{
			dnsmasq_debug = true;
			daemonmode = false;
			ok = true;

			// Replace "-k" by "-d" (dnsmasq_debug mode implies nofork)
			argv_dnsmasq[1] = "-d";
		}

		// Full start FTL but shut down immediately once everything is up
		// This ensures we'd catch any dnsmasq config errors,
		// incorrect file permissions, etc.
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

		// Extended version output
		if(strcmp(argv[i], "-vv") == 0)
		{
			// Print FTL version
			printf("****************************** FTL **********************************\n");
			printf("Version:         %s\n", get_FTL_version());
			printf("Branch:          %s\n", GIT_BRANCH);
			printf("Commit:          %s (%s)\n", GIT_HASH, GIT_DATE);
			printf("Architecture:    %s\n", FTL_ARCH);
			printf("Compiler:        %s\n\n", FTL_CC);

			// Print dnsmasq version and compile time options
			print_dnsmasq_version();

			// Print SQLite3 version and compile time options
			printf("****************************** SQLite3 ******************************\n");
			printf("Version:         %s\n", sqlite3_libversion());
			printf("Compile options: ");
			unsigned int o = 0;
			const char *opt = NULL;
			while((opt = sqlite3_compileoption_get(o++)) != NULL)
			{
				if(o != 1)
					printf(" ");
				printf("%s", opt);
			}
			printf("\n");
			printf("******************************** LUA ********************************\n");
			printf(LUA_COPYRIGHT"\n");
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

		// Quiet mode
		if(strcmp(argv[i], "-q") == 0)
		{
			quiet = true;
			ok = true;
		}

		// Regex test mode
		if(strcmp(argv[i], "regex-test") == 0)
		{
			// Enable stdout printing
			cli_mode = true;
			if(argc == i + 2)
				exit(regex_test(dnsmasq_debug, quiet, argv[i + 1], NULL));
			else if(argc == i + 3)
				exit(regex_test(dnsmasq_debug, quiet, argv[i + 1], argv[i + 2]));
			else
			{
				printf("pihole-FTL: invalid option -- '%s' need either one or two parameters\nTry '%s --help' for more information\n", argv[i], argv[0]);
				exit(EXIT_FAILURE);
			}
		}

		// Regex test mode
		if(strcmp(argv[i], "dhcp-discover") == 0)
		{
			// Enable stdout printing
			cli_mode = true;
			exit(run_dhcp_discover());
		}

		// List of implemented arguments
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "help") == 0 || strcmp(argv[i], "--help") == 0)
		{
			printf("pihole-FTL - The Pi-hole FTL engine\n\n");
			printf("Usage:    sudo service pihole-FTL <action>\n");
			printf("where '<action>' is one of start / stop / restart\n\n");
			printf("Available arguments:\n");
			printf("\t    debug           More verbose logging,\n");
			printf("\t                    don't go into daemon mode\n");
			printf("\t    test            Don't start pihole-FTL but\n");
			printf("\t                    instead quit immediately\n");
			printf("\t-v, version         Return FTL version\n");
			printf("\t-vv                 Return more version information\n");
			printf("\t-t, tag             Return git tag\n");
			printf("\t-b, branch          Return git branch\n");
			printf("\t-f, no-daemon       Don't go into daemon mode\n");
			printf("\t-h, help            Display this help and exit\n");
			printf("\tdnsmasq-test        Test syntax of dnsmasq's\n");
			printf("\t                    config files and exit\n");
			printf("\tregex-test str      Test str against all regular\n");
			printf("\t                    expressions in the database\n");
			printf("\tregex-test str rgx  Test str against regular expression\n");
			printf("\t                    given by rgx\n");
			printf("\t--lua, lua          FTL's lua interpreter\n");
			printf("\t--luac, luac        FTL's lua compiler\n");
			printf("\tdhcp-discover       Discover DHCP servers in the local\n");
			printf("\t                    network\n");
			printf("\tsql, sqlite3        FTL's SQLite3 shell\n");
			printf("\tsql -h, sqlite3 -h  FTL's SQLite3 shell (human-readable mode)\n");
			printf("\n\nOnline help: https://github.com/pi-hole/FTL\n");
			exit(EXIT_SUCCESS);
		}

		// Return success error code on this undocumented flag
		if(strcmp(argv[i], "--resolver") == 0)
		{
			printf("True\n");
			exit(EXIT_SUCCESS);
		}

		// Return number of errors on this undocumented flag
		if(strcmp(argv[i], "--check-structs") == 0)
		{
			exit(check_struct_sizes());
		}

		// Complain if invalid options have been found
		if(!ok)
		{
			printf("pihole-FTL: invalid option -- '%s'\n", argv[i]);
			printf("Command: '");
			for(int j = 0; j < argc; j++)
			{
				printf("%s", argv[j]);
				if(j < argc - 1)
					printf(" ");
			}
			printf("'\nTry '%s --help' for more information\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}

// Extended SGR sequence:
//
// "\x1b[%dm"
//
// where %d is one of the following values for commonly supported colors:
//
// 0: reset colors/style
// 1: bold
// 4: underline
// 30 - 37: black, red, green, yellow, blue, magenta, cyan, and white text
// 40 - 47: black, red, green, yellow, blue, magenta, cyan, and white background
//
// https://en.wikipedia.org/wiki/ANSI_escape_code#SGR
//
#define COL_NC		"\x1b[0m"  // normal font
#define COL_BOLD	"\x1b[1m"  // bold font
#define COL_ITALIC	"\x1b[3m"  // italic font
#define COL_ULINE	"\x1b[4m"  // underline font
#define COL_GREEN	"\x1b[32m" // normal foreground color
#define COL_YELLOW	"\x1b[33m" // normal foreground color
#define COL_GRAY	"\x1b[90m" // bright foreground color
#define COL_RED		"\x1b[91m" // bright foreground color
#define COL_BLUE	"\x1b[94m" // bright foreground color
#define COL_PURPLE	"\x1b[95m" // bright foreground color
#define COL_CYAN	"\x1b[96m" // bright foreground color

static inline bool __attribute__ ((const)) is_term(void)
{
	// test whether STDOUT refers to a terminal
	return isatty(fileno(stdout)) == 1;
}

// Returns green [✓]
const char __attribute__ ((const)) *cli_tick(void)
{
	return is_term() ? "["COL_GREEN"✓"COL_NC"]" : "[✓]";
}

// Returns red [✗]
const char __attribute__ ((const)) *cli_cross(void)
{
	return is_term() ? "["COL_RED"✗"COL_NC"]" : "[✗]";
}

// Returns [i]
const char __attribute__ ((const)) *cli_info(void)
{
	return is_term() ? COL_BOLD"[i]"COL_NC : "[i]";
}

// Returns [?]
const char __attribute__ ((const)) *cli_qst(void)
{
	return "[?]";
}

// Returns green "done!""
const char __attribute__ ((const)) *cli_done(void)
{
	return is_term() ? COL_GREEN"done!"COL_NC : "done!";
}

// Sets font to bold
const char __attribute__ ((const)) *cli_bold(void)
{
	return is_term() ? COL_BOLD : "";
}

// Resets font to normal
const char __attribute__ ((const)) *cli_normal(void)
{
	return is_term() ? COL_NC : "";
}
