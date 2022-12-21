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

#include <nettle/bignum.h>
#if !defined(NETTLE_VERSION_MAJOR)
#  define NETTLE_VERSION_MAJOR 2
#  define NETTLE_VERSION_MINOR 0
#endif

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
extern void print_dnsmasq_version(const char *yellow, const char *green, const char *bold, const char *normal);

// defined in database/shell.c
extern int sqlite3_shell_main(int argc, char **argv);

bool dnsmasq_debug = false;
bool daemonmode = true, cli_mode = false;
int argc_dnsmasq = 0;
const char** argv_dnsmasq = NULL;

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

static inline bool __attribute__ ((pure)) is_term(void)
{
	// test whether STDOUT refers to a terminal
	return isatty(fileno(stdout)) == 1;
}

// Returns green [✓]
const char __attribute__ ((pure)) *cli_tick(void)
{
	return is_term() ? "["COL_GREEN"✓"COL_NC"]" : "[✓]";
}

// Returns red [✗]
const char __attribute__ ((pure)) *cli_cross(void)
{
	return is_term() ? "["COL_RED"✗"COL_NC"]" : "[✗]";
}

// Returns [i]
const char __attribute__ ((pure)) *cli_info(void)
{
	return is_term() ? COL_BOLD"[i]"COL_NC : "[i]";
}

// Returns [?]
const char __attribute__ ((const)) *cli_qst(void)
{
	return "[?]";
}

// Returns green "done!""
const char __attribute__ ((pure)) *cli_done(void)
{
	return is_term() ? COL_GREEN"done!"COL_NC : "done!";
}

// Sets font to bold
const char __attribute__ ((pure)) *cli_bold(void)
{
	return is_term() ? COL_BOLD : "";
}

// Resets font to normal
const char __attribute__ ((pure)) *cli_normal(void)
{
	return is_term() ? COL_NC : "";
}

// Set color if STDOUT is a terminal
static const char __attribute__ ((pure)) *cli_color(const char *color)
{
	return is_term() ? color : "";
}

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
			exit(main_dnsmasq(2, arg));
		}

		// If we find "--" we collect everything behind that for dnsmasq
		if(strcmp(argv[i], "--") == 0)
		{
			// Remember that the rest is for dnsmasq ...
			consume_for_dnsmasq = true;

			// ... and skip the current argument ("--")
			continue;
		}

		// List available DHCPv4 config options
		if(strcmp(argv[i], "--list-dhcp") == 0 || strcmp(argv[i], "--list-dhcp4") == 0)
		{
			display_opts();
			exit(EXIT_SUCCESS);
		}
		// List available DHCPv6 config options
		if(strcmp(argv[i], "--list-dhcp6") == 0)
		{
			display_opts6();
			exit(EXIT_SUCCESS);
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
			const char *bold = cli_bold();
			const char *normal = cli_normal();
			const char *green = cli_color(COL_GREEN);
			const char *yellow = cli_color(COL_YELLOW);

			// Print FTL version
			printf("****************************** %s%sFTL%s **********************************\n",
			       yellow, bold, normal);
			printf("Version:         %s%s%s%s\n",
			       green, bold, get_FTL_version(), normal);
			printf("Branch:          " GIT_BRANCH "\n");
			printf("Commit:          " GIT_HASH " (" GIT_DATE ")\n");
			printf("Architecture:    " FTL_ARCH "\n");
			printf("Compiler:        " FTL_CC "\n\n");

			// Print dnsmasq version and compile time options
			print_dnsmasq_version(yellow, green, bold, normal);

			// Print SQLite3 version and compile time options
			printf("****************************** %s%sSQLite3%s ******************************\n",
			       yellow, bold, normal);
			printf("Version:         %s%s%s%s\n",
			       green, bold, sqlite3_libversion(), normal);
			printf("Features:        ");
			unsigned int o = 0;
			const char *opt = NULL;
			while((opt = sqlite3_compileoption_get(o++)) != NULL)
			{
				if(o != 1)
					printf(" ");
				printf("%s", opt);
			}
			printf("\n\n");
			printf("******************************** %s%sLUA%s ********************************\n",
			       yellow, bold, normal);
			printf("Version:         %s%s" LUA_VERSION_MAJOR "." LUA_VERSION_MINOR"%s\n",
			       green, bold, normal);
			printf("Libraries:       ");
			print_embedded_scripts();
			printf("\n\n");
			printf("***************************** %s%sLIBNETTLE%s *****************************\n",
			       yellow, bold, normal);
			printf("Version:         %s%s" xstr(NETTLE_VERSION_MAJOR) "." xstr(NETTLE_VERSION_MINOR) "%s\n",
			       green, bold, normal);
			printf("GMP:             %s\n", NETTLE_USE_MINI_GMP ? "Mini" : "Full");
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

		if(strcmp(argv[i], "--hash") == 0)
		{
			printf("%s\n",GIT_HASH);
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
			const char *bold = cli_bold();
			const char *normal = cli_normal();
			const char *blue = cli_color(COL_BLUE);
			const char *cyan = cli_color(COL_CYAN);
			const char *gray = cli_color(COL_GRAY);
			const char *green = cli_color(COL_GREEN);
			const char *yellow = cli_color(COL_YELLOW);
			const char *purple = cli_color(COL_PURPLE);

			printf("%sThe Pi-hole FTL engine - %s%s\n\n", bold, get_FTL_version(), normal);
			printf("Typically, pihole-FTL runs as a system service and is controlled\n");
			printf("by %ssudo service pihole-FTL %s<action>%s where %s<action>%s is one out\n", green, purple, normal, purple, normal);
			printf("of %sstart%s, %sstop%s, or %srestart%s.\n\n", green, normal, green, normal, green, normal);
			printf("pihole-FTL exposes some features going beyond the standard\n");
			printf("%sservice pihole-FTL%s command. These are:\n\n", green, normal);

			printf("%sVersion information:%s\n", yellow, normal);
			printf("\t%s-v%s, %sversion%s         Return FTL version\n", green, normal, green, normal);
			printf("\t%s-vv%s                 Return verbose version information\n", green, normal);
			printf("\t%s-t%s, %stag%s             Return git tag\n", green, normal, green, normal);
			printf("\t%s-b%s, %sbranch%s          Return git branch\n", green, normal, green, normal);
			printf("\t%s--hash%s              Return git commit hash\n\n", green, normal);

			printf("%sRegular expression testing:%s\n", yellow, normal);
			printf("\t%sregex-test %sstr%s      Test %sstr%s against all regular\n", green, blue, normal, blue, normal);
			printf("\t                    expressions in the database\n");
			printf("\t%sregex-test %sstr %srgx%s  Test %sstr%s against regular expression\n", green, blue, cyan, normal, blue, normal);
			printf("\t                    given by regular expression %srgx%s\n\n", cyan, normal);

			printf("    Example: %spihole-FTL regex-test %ssomebad.domain %sbad%s\n", green, blue, cyan, normal);
			printf("    to test %ssomebad.domain%s against %sbad%s\n\n", blue, normal, cyan, normal);
			printf("    An optional %s-q%s prevents any output (exit code testing):\n", gray, normal);
			printf("    %spihole-FTL %s-q%s regex-test %ssomebad.domain %sbad%s\n\n", green, gray, green, blue, cyan, normal);

			printf("%sEmbedded Lua engine:%s\n", yellow, normal);
			printf("\t%s--lua%s, %slua%s          FTL's lua interpreter\n", green, normal, green, normal);
			printf("\t%s--luac%s, %sluac%s        FTL's lua compiler\n\n", green, normal, green, normal);

			printf("    Usage: %spihole-FTL lua %s[OPTIONS] [SCRIPT [ARGS]]%s\n\n", green, cyan, normal);
			printf("    Options:\n\n");
			printf("    - %s[OPTIONS]%s is an optional set of options. All available\n", cyan, normal);
			printf("      options can be seen by running %spihole-FTL lua --help%s\n", green, normal);
			printf("    - %s[SCRIPT]%s is the optional name of a Lua script.\n", cyan, normal);
			printf("      If this script does not exist, an interactive shell is\n");
			printf("      started instead.\n");
			printf("    - %s[SCRIPT [ARGS]]%s can be used to pass optional args to\n", cyan, normal);
			printf("      the script.\n\n");

			printf("%sEmbedded SQLite3 shell:%s\n", yellow, normal);
			printf("\t%ssql %s[-h]%s, %ssqlite3 %s[-h]%s        FTL's SQLite3 shell\n", green, gray, normal, green, gray, normal);
			printf("\t%s-h%s starts a special %shuman-readable mode%s\n\n", gray, normal, bold, normal);

			printf("    Usage: %spihole-FTL sqlite3 %s[-h] %s[OPTIONS] [FILENAME] [SQL]%s\n\n", green, gray, cyan, normal);
			printf("    Options:\n\n");
			printf("    - %s[OPTIONS]%s is an optional set of options. All available\n", cyan, normal);
			printf("      options can be found in %spihole-FTL sqlite3 --help%s\n", green, normal);
			printf("    - %s[FILENAME]%s is the optional name of an SQLite database.\n", cyan, normal);
			printf("      A new database is created if the file does not previously\n");
			printf("      exist. If this argument is omitted, SQLite3 will use a\n");
			printf("      transient in-memory database instead.\n");
			printf("    - %s[SQL]%s is an optional SQL statement to be executed. If\n", cyan, normal);
			printf("      omitted, an interactive shell is started instead.\n\n");

			printf("%sEmbedded dnsmasq options:%s\n", yellow, normal);
			printf("\t%sdnsmasq-test%s        Test syntax of dnsmasq's config\n", green, normal);
			printf("\t%s--list-dhcp4%s        List known DHCPv4 config options\n", green, normal);
			printf("\t%s--list-dhcp6%s        List known DHCPv6 config options\n\n", green, normal);

			printf("%sDebugging and special use:%s\n", yellow, normal);
			printf("\t%sd%s, %sdebug%s            Enter debugging mode\n", green, normal, green, normal);
			printf("\t%stest%s                Don't start pihole-FTL but\n", green, normal);
			printf("\t                    instead quit immediately\n");
			printf("\t%s-f%s, %sno-daemon%s       Don't go into daemon mode\n\n", green, normal, green, normal);

			printf("%sOther:%s\n", yellow, normal);
			printf("\t%sdhcp-discover%s       Discover DHCP servers in the local\n", green, normal);
			printf("\t                    network\n");
			printf("\t%s-h%s, %shelp%s            Display this help and exit\n\n", green, normal, green, normal);
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
