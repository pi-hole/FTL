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

#ifdef HAVE_MBEDTLS
#include <mbedtls/version.h>
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
// gravity_parseList()
#include "tools/gravity-parseList.h"
// run_dhcp_discover()
#include "tools/dhcp-discover.h"
// mg_version()
#include "webserver/civetweb/civetweb.h"
// cJSON_Version()
#include "webserver/cJSON/cJSON.h"
#include "config/cli.h"
#include "config/config.h"
// compression functions
#include "zip/gzip.h"
// teleporter functions
#include "zip/teleporter.h"
// printTOTP()
#include "api/api.h"
// generate_certificate()
#include "webserver/x509.h"
// run_dhcp_discover()
#include "tools/dhcp-discover.h"
// run_arp_scan()
#include "tools/arp-scan.h"
// run_performance_test()
#include "config/password.h"
// idn2_to_ascii_lz()
#include <idn2.h>
// sha256sum()
#include "files.h"
// resolveHostname()
#include "resolve.h"

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
#define COL_RED		"\x1b[91m" // bright foreground color
#define COL_BLUE	"\x1b[94m" // bright foreground color
#define COL_PURPLE	"\x1b[95m" // bright foreground color
#define COL_CYAN	"\x1b[96m" // bright foreground color

static bool __attribute__ ((pure)) is_term(void)
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

// Go back to beginning of line and erase to end of line if STDOUT is a terminal
const char __attribute__ ((pure)) *cli_over(void)
{
	// \x1b[K is the ANSI escape sequence for "erase to end of line"
	return is_term() ? "\r\x1b[K" : "\r";
}

static inline bool strEndsWith(const char *input, const char *end)
{
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

	// Compression feature
	if((argc == 3 || argc == 4) &&
	   (strcmp(argv[1], "gzip") == 0 || strcmp(argv[1], "--gzip") == 0))
	{
		// Enable stdout printing
		cli_mode = true;
		log_ctrl(false, true);

		// Get input and output file names
		const char *infile = argv[2];
		bool is_gz = strEndsWith(infile, ".gz");
		char *outfile = NULL;
		if(argc == 4)
		{
			// If an output file is given, we use it
			outfile = strdup(argv[3]);
		}
		else if(is_gz)
		{
			// If no output file is given, and this is a gzipped
			// file, we use the input file name without ".gz"
			// appended
			outfile = calloc(strlen(infile)-2, sizeof(char));
			memcpy(outfile, infile, strlen(infile)-3);
		}
		else
		{
			// If no output file is given, and this is not a gzipped
			// file, we use the input file name with ".gz" appended
			outfile = calloc(strlen(infile)+4, sizeof(char));
			strcpy(outfile, infile);
			strcat(outfile, ".gz");
		}

		bool success = false;
		if(is_gz)
		{
			// If the input file is already gzipped, we decompress it
			success = inflate_file(infile, outfile, true);
		}
		else
		{
			// If the input file is not gzipped, we compress it
			success = deflate_file(infile, outfile, true);
		}

		// Free allocated memory
		free(outfile);

		// Return exit code
		exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	// Set config option through CLI
	if(argc > 1 && strcmp(argv[1], "--config") == 0)
	{
		// Enable stdout printing
		cli_mode = true;
		log_ctrl(false, false);
		readFTLconf(&config, false);
		log_ctrl(false, true);
		clear_debug_flags(); // No debug printing wanted
		if(argc == 2)
			exit(get_config_from_CLI(NULL, false));
		else if(argc == 3)
			exit(get_config_from_CLI(argv[2], false));
		else if(argc == 4 && strcmp(argv[2], "-q") == 0)
			exit(get_config_from_CLI(argv[3], true));
		else if(argc == 4)
			exit(set_config_from_CLI(argv[2], argv[3]));
		else
		{
			printf("Usage: %s --config [<config item key>] [<value>]\n", argv[0]);
			printf("Example: %s --config dns.blockESNI true\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}


	// Set config option through CLI
	if(argc == 2 && strcmp(argv[1], "--totp") == 0)
	{
		cli_mode = true;
		log_ctrl(false, false);
		readFTLconf(&config, false);
		log_ctrl(false, true);
		clear_debug_flags(); // No debug printing wanted
		exit(printTOTP());
	}


	// Create teleporter archive through CLI
	if(argc == 2 && strcmp(argv[1], "--teleporter") == 0)
	{
		// Enable stdout printing
		cli_mode = true;
		log_ctrl(false, true);
		readFTLconf(&config, false);
		exit(write_teleporter_zip_to_disk() ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	// Import teleporter archive through CLI
	if(argc == 3 && strcmp(argv[1], "--teleporter") == 0)
	{
		// Enable stdout printing
		cli_mode = true;
		log_ctrl(false, true);
		readFTLconf(&config, false);
		exit(read_teleporter_zip_from_disk(argv[2]) ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	// Generate X.509 certificate
	if(argc > 1 && strcmp(argv[1], "--gen-x509") == 0)
	{
		if(argc < 3 || argc > 5)
		{
			printf("Usage: %s --gen-x509 <output file> [<domain>] [rsa]\n", argv[0]);
			printf("Example:          %s --gen-x509 /etc/pihole/tls.pem\n", argv[0]);
			printf(" with domain:     %s --gen-x509 /etc/pihole/tls.pem pi.hole\n", argv[0]);
			printf(" RSA with domain: %s --gen-x509 /etc/pihole/tls.pem nanopi.lan rsa\n", argv[0]);
			exit(EXIT_FAILURE);
		}
		// Enable stdout printing
		cli_mode = true;
		log_ctrl(false, true);
		const char *domain = argc > 3 ? argv[3] : "pi.hole";
		const bool rsa = argc > 4 && strcasecmp(argv[4], "rsa") == 0;
		exit(generate_certificate(argv[2], rsa, domain) ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	// Parse X.509 certificate
	if(argc > 1 &&
	  (strcmp(argv[1], "--read-x509") == 0 ||
	   strcmp(argv[1], "--read-x509-key") == 0))
	{
		if(argc > 4)
		{
			printf("Usage: %s %s [<input file>] [<domain>]\n", argv[0], argv[1]);
			printf("Example: %s %s /etc/pihole/tls.pem\n", argv[0], argv[1]);
			printf(" with domain: %s %s /etc/pihole/tls.pem pi.hole\n", argv[0], argv[1]);
			exit(EXIT_FAILURE);
		}

		// Option parsing
		// Should we report on the private key?
		const bool private_key = strcmp(argv[1], "--read-x509-key") == 0;
		// If no certificate file is given, we use the one from the config
		const char *certfile = NULL;
		if(argc == 2)
		{
			readFTLconf(&config, false);
			certfile = config.webserver.tls.cert.v.s;
		}
		else
			certfile = argv[2];

		// If no domain is given, we only check the certificate
		const char *domain = argc > 3 ? argv[3] : NULL;

		// Enable stdout printing
		cli_mode = true;
		log_ctrl(false, true);

		enum cert_check result = read_certificate(certfile, domain, private_key);

		if(argc < 4)
			exit(result == CERT_OKAY ? EXIT_SUCCESS : EXIT_FAILURE);
		else if(result == CERT_DOMAIN_MATCH)
		{
			printf("Certificate matches domain %s\n", argv[3]);
			exit(EXIT_SUCCESS);
		}
		else
		{
			printf("Certificate does not match domain %s\n", argv[3]);
			exit(EXIT_FAILURE);
		}
	}

	// If the first argument is "gravity" (e.g., /usr/bin/pihole-FTL gravity),
	// we offer some specialized gravity tools
	if(argc > 1 && (strcmp(argv[1], "gravity") == 0 || strcmp(argv[1], "antigravity") == 0))
	{
		const bool antigravity = strcmp(argv[1], "antigravity") == 0;

		// pihole-FTL gravity parseList <infile> <outfile> <adlistID>
		if(argc == 6 && strcasecmp(argv[2], "parseList") == 0)
		{
			// Parse the given list and write the result to the given file
			exit(gravity_parseList(argv[3], argv[4], argv[5], false, antigravity));
		}

		// pihole-FTL gravity checkList <infile>
		if(argc == 4 && strcasecmp(argv[2], "checkList") == 0)
		{
			// Parse the given list and write the result to the given file
			exit(gravity_parseList(argv[3], "", "-1", true, antigravity));
		}

		printf("Incorrect usage of pihole-FTL gravity subcommand\n");
		exit(EXIT_FAILURE);
	}

	// DHCP discovery mode
	if(argc > 1 && strcmp(argv[1], "dhcp-discover") == 0)
	{
		// Enable stdout printing
		cli_mode = true;
		exit(run_dhcp_discover());
	}

	// Password hashing performance test
	if(argc > 1 && (strcmp(argv[1], "--perf") == 0 || strcmp(argv[1], "performance") == 0))
	{
		// Enable stdout printing
		cli_mode = true;
		exit(run_performance_test());
	}

	// ARP scanning mode
	if(argc > 1 && strcmp(argv[1], "arp-scan") == 0)
	{
		// Enable stdout printing
		cli_mode = true;
		const bool scan_all = argc > 2 && strcmp(argv[2], "-a") == 0;
		const bool extreme_mode = argc > 2 && strcmp(argv[2], "-x") == 0;
		exit(run_arp_scan(scan_all, extreme_mode));
	}

	// IDN2 conversion mode
	if(argc > 1 && strcmp(argv[1], "idn2") == 0)
	{
		// Enable stdout printing
		cli_mode = true;
		if(argc == 3)
		{
			// Convert unicode domain to punycode
			char *punycode = NULL;
			const int rc = idn2_to_ascii_lz(argv[2], &punycode, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
			if (rc != IDN2_OK)
			{
				// Invalid domain name
				printf("Invalid domain name: %s\n", argv[2]);
				exit(EXIT_FAILURE);
			}

			// Convert punycode domain to lowercase
			for(unsigned int i = 0u; i < strlen(punycode); i++)
				punycode[i] = tolower(punycode[i]);

			printf("%s\n", punycode);
			exit(EXIT_SUCCESS);

		}
		else if(argc == 4 && (strcmp(argv[2], "-d") == 0 || strcmp(argv[2], "--decode") == 0))
		{
			// Convert punycode domain to unicode
			char *unicode = NULL;
			const int rc = idn2_to_unicode_lzlz(argv[3], &unicode, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
			if (rc != IDN2_OK)
			{
				// Invalid domain name
				printf("Invalid domain name: %s\n", argv[3]);
				exit(EXIT_FAILURE);
			}

			printf("%s\n", unicode);
			exit(EXIT_SUCCESS);
		}
		else
		{
			printf("Usage: %s idn2 [--decode] <domain>\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	// sha256sum mode
	if(argc == 3 && strcmp(argv[1], "sha256sum") == 0)
	{
		// Enable stdout printing
		cli_mode = true;
		uint8_t checksum[SHA256_DIGEST_SIZE];
		if(!sha256sum(argv[2], checksum))
			exit(EXIT_FAILURE);

		// Convert checksum to hex string
		char hex[SHA256_DIGEST_SIZE*2+1];
		sha256_raw_to_hex(checksum, hex);

		// Print result
		printf("%s  %s\n", hex, argv[2]);
		exit(EXIT_SUCCESS);
	}

	// Local reverse name resolver
	if(argc == 3 && strcasecmp(argv[1], "ptr") == 0)
	{
		// Enable stdout printing
		cli_mode = true;

		// Need to get dns.port and the resolver settings
		readFTLconf(&config, false);

		char *name = resolveHostname(argv[2], true);
		if(name == NULL)
			exit(EXIT_FAILURE);

		// Print result
		printf("%s\n", name);
		free(name);
		exit(EXIT_SUCCESS);
	}

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
			// Special non-interative mode
			else if(i+1 < argc && strcmp(argv[i+1], "-ni") == 0)
			{
				int argc2 = argc - i + 4 - 2;
				char **argv2 = calloc(argc2, sizeof(char*));
				argv2[0] = argv[0]; // Application name
				argv2[1] = (char*)"-batch";
				argv2[2] = (char*)"-init";
				argv2[3] = (char*)"/dev/null";
				// i = "sqlite3"
				// i+1 = "-ni"
				for(int j = 0; j < argc - i - 2; j++)
					argv2[4 + j] = argv[i + 2 + j];
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
			log_ctrl(false, true);
			exit(main_dnsmasq(2, (char**)arg));
		}

		// Implement dnsmasq's test function, no need to prepare the entire FTL
		// environment (initialize shared memory, lead queries from long-term
		// database, ...) when the task is a simple (dnsmasq) syntax check
		if(argc == 3 && strcmp(argv[1], "dnsmasq-test-file") == 0)
		{
			const char *arg[3];
			char *filename = calloc(strlen(argv[2])+strlen("--conf-file=")+1, sizeof(char));
			arg[0] = "";
			sprintf(filename, "--conf-file=%s", argv[2]);
			arg[1] = filename;
			arg[2] = "--test";
			log_ctrl(false, true);
			exit(main_dnsmasq(3, (char**)arg));
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
			const char *red = cli_color(COL_RED);
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
			printf("\n");
			printf("****************************** %s%sCivetWeb%s *****************************\n",
			       yellow, bold, normal);
#ifdef MBEDTLS_VERSION_STRING_FULL
			printf("Version:         %s%s%s%s with %smbed TLS %s%s"MBEDTLS_VERSION_STRING"%s\n",
			       green, bold, mg_version(), normal, yellow, green, bold, normal);
#else
			printf("Version:         %s%s%s%s\n", green, bold, mg_version(), normal);
#endif
			printf("Features:        ");
			if(mg_check_feature(MG_FEATURES_FILES))
				printf("Files: %sYes%s, ", green, normal);
			else
				printf("Files: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_TLS))
				printf("TLS: %sYes%s, ", green, normal);
			else
				printf("TLS: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_CGI))
				printf("CGI: %sYes%s, ", green, normal);
			else
				printf("CGI: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_IPV6))
				printf("IPv6: %sYes%s, \n", green, normal);
			else
				printf("IPv6: %sNo%s, \n", red, normal);
			if(mg_check_feature(MG_FEATURES_WEBSOCKET))
				printf("                 WebSockets: %sYes%s, ", green, normal);
			else
				printf("                 WebSockets: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_SSJS))
				printf("Server-side JavaScript: %sYes%s\n", green, normal);
			else
				printf("Server-side JavaScript: %sNo%s\n", red, normal);
			if(mg_check_feature(MG_FEATURES_LUA))
				printf("                 Lua: %sYes%s, ", green, normal);
			else
				printf("                 Lua: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_CACHE))
				printf("Cache: %sYes%s, ", green, normal);
			else
				printf("Cache: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_STATS))
				printf("Stats: %sYes%s, ", green, normal);
			else
				printf("Stats: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_COMPRESSION))
				printf("Compression: %sYes%s\n", green, normal);
			else
				printf("Compression: %sNo%s\n", red, normal);
			if(mg_check_feature(MG_FEATURES_HTTP2))
				printf("                 HTTP2: %sYes%s, ", green, normal);
			else
				printf("                 HTTP2: %sNo%s, ", red, normal);
			if(mg_check_feature(MG_FEATURES_X_DOMAIN_SOCKET))
				printf("Unix domain sockets: %sYes%s\n", green, normal);
			else
				printf("Unix domain sockets: %sNo%s\n", red, normal);
			printf("\n");
			printf("****************************** %s%scJSON%s ********************************\n",
			       yellow, bold, normal);
			printf("Version:         %s%s%s%s\n", green, bold, cJSON_Version(), normal);
			printf("\n");
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

		// List of implemented arguments
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "help") == 0 || strcmp(argv[i], "--help") == 0)
		{
			const char *bold = cli_bold();
			const char *normal = cli_normal();
			const char *blue = cli_color(COL_BLUE);
			const char *cyan = cli_color(COL_CYAN);
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
			printf("    An optional %s-q%s prevents any output (exit code testing):\n", purple, normal);
			printf("    %spihole-FTL %s-q%s regex-test %ssomebad.domain %sbad%s\n\n", green, purple, green, blue, cyan, normal);

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
			printf("\t%ssql%s, %ssqlite3%s                      FTL's SQLite3 shell\n", green, normal, green, normal);

			printf("    Usage: %spihole-FTL sqlite3 %s[OPTIONS] [FILENAME] [SQL]%s\n\n", green, cyan, normal);
			printf("    Options:\n\n");
			printf("    - %s[OPTIONS]%s is an optional set of options. All available\n", cyan, normal);
			printf("      options can be found in %spihole-FTL sqlite3 --help%s.\n", green, normal);
			printf("      The first option can be either %s-h%s or %s-ni%s, see below.\n", purple, normal, purple, normal);
			printf("    - %s[FILENAME]%s is the optional name of an SQLite database.\n", cyan, normal);
			printf("      A new database is created if the file does not previously\n");
			printf("      exist. If this argument is omitted, SQLite3 will use a\n");
			printf("      transient in-memory database instead.\n");
			printf("    - %s[SQL]%s is an optional SQL statement to be executed. If\n", cyan, normal);
			printf("      omitted, an interactive shell is started instead.\n\n");
			printf("    There are two special %spihole-FTL sqlite3%s mode switches:\n", green, normal);
			printf("    %s-h%s  %shuman-readable%s mode:\n", purple, normal, bold, normal);
			printf("        In this mode, the output of the shell is formatted in\n");
			printf("        a human-readable way. This is especially useful for\n");
			printf("        debugging purposes. %s-h%s is a shortcut for\n", purple, normal);
			printf("        %spihole-FTL sqlite3 %s-column -header -nullvalue '(null)'%s\n\n", green, purple, normal);
			printf("    %s-ni%s %snon-interative%s mode\n", purple, normal, bold, normal);
			printf("        In this mode, batch mode is enforced and any possibly\n");
			printf("        existing .sqliterc file is ignored. %s-ni%s is a shortcut\n", purple, normal);
			printf("        for %spihole-FTL sqlite3 %s-batch -init /dev/null%s\n\n", green, purple, normal);
			printf("    Usage: %spihole-FTL sqlite3 %s-ni %s[OPTIONS] [FILENAME] [SQL]%s\n\n", green, purple, cyan, normal);

			printf("%sEmbedded dnsmasq options:%s\n", yellow, normal);
			printf("\t%sdnsmasq-test%s        Test syntax of dnsmasq's config\n", green, normal);
			printf("\t%s--list-dhcp4%s        List known DHCPv4 config options\n", green, normal);
			printf("\t%s--list-dhcp6%s        List known DHCPv6 config options\n\n", green, normal);

			printf("%sDebugging and special use:%s\n", yellow, normal);
			printf("\t%sd%s, %sdebug%s            Enter debugging mode: Don't go into \n", green, normal, green, normal);
			printf("\t                    daemon mode and verbose logging\n");
			printf("\t%stest%s                Don't start pihole-FTL but instead\n", green, normal);
			printf("\t                    process everything and quit immediately\n");
			printf("\t%s-f%s, %sno-daemon%s       Don't go into daemon mode\n\n", green, normal, green, normal);

			printf("%sConfig options:%s\n", yellow, normal);
			printf("\t%s--config %skey%s        Get current value of config item %skey%s\n", green, blue, normal, blue, normal);
			printf("\t%s--config %skey %svalue%s  Set new %svalue%s of config item %skey%s\n\n", green, blue, cyan, normal, cyan, normal, blue, normal);

			printf("%sEmbedded GZIP un-/compressor:%s\n", yellow, normal);
			printf("    A simple but fast in-memory gzip compressor\n\n");
			printf("    Usage: %spihole-FTL --compress %sinfile %s[outfile]%s\n", green, cyan, purple, normal);
			printf("    Usage: %spihole-FTL --uncompress %sinfile %s[outfile]%s\n\n", green, cyan, purple, normal);
			printf("    - %sinfile%s is the file to be compressed.\n", cyan, normal);
			printf("    - %s[outfile]%s is the optional target. If omitted, FTL will\n", purple, normal);
			printf("      %s--compress%s:   use the %sinfile%s and append %s.gz%s at the end\n", green, normal, cyan, normal, cyan, normal);
			printf("      %s--uncompress%s: use the %sinfile%s and remove %s.gz%s at the end\n\n", green, normal, cyan, normal, cyan, normal);

			printf("%sTeleporter:%s\n", yellow, normal);
			printf("\t%s--teleporter%s        Create a Teleporter archive in the\n", green, normal);
			printf("\t                    current directory and print its name\n");
			printf("\t%s--teleporter%s file%s   Import the Teleporter archive %sfile%s\n\n", green, cyan, normal, cyan, normal);

			printf("%sTLS X.509 certificate generator:%s\n", yellow, normal);
			printf("    Generate a self-signed certificate suitable for SSL/TLS\n");
			printf("    and store it in %soutfile%s.\n\n", cyan, normal);
			printf("    By default, this new certificate is based on the elliptic\n");
			printf("    curve secp521r1. If the optional flag %s[rsa]%s is specified,\n", purple, normal);
			printf("    an RSA (4096 bit) key will be generated instead.\n\n");
			printf("    Usage: %spihole-FTL --gen-x509 %soutfile %s[rsa]%s\n\n", green, cyan, purple, normal);

			printf("%sTLS X.509 certificate parser:%s\n", yellow, normal);
			printf("    Parse the given X.509 certificate and optionally check if\n");
			printf("    it matches a given domain. If no domain is given, only a\n");
			printf("    human-readable output string is printed.\n\n");
			printf("    If no certificate file is given, the one from the config\n");
			printf("    is used (if applicable). If --read-x509-key is used, details\n");
			printf("    about the private key are printed as well.\n\n");
			printf("    Usage: %spihole-FTL --read-x509 %s[certfile] %s[domain]%s\n", green, cyan, purple, normal);
			printf("    Usage: %spihole-FTL --read-x509-key %s[certfile] %s[domain]%s\n\n", green, cyan, purple, normal);

			printf("%sGravity tools:%s\n", yellow, normal);
			printf("    Check domains in a given file for validity using Pi-hole's\n");
			printf("    gravity filters. The expected input format is one domain\n");
			printf("    per line (no HOSTS lists, etc.)\n\n");
			printf("    Usage: %spihole-FTL gravity checkList %sinfile%s\n\n", green, cyan, normal);

			printf("%sIDN2 conversion:%s\n", yellow, normal);
			printf("    Convert a given internationalized domain name (IDN) to\n");
			printf("    punycode or vice versa.\n\n");
			printf("    Encoding: %spihole-FTL idn2 %sdomain%s\n", green, cyan, normal);
			printf("    Decoding: %spihole-FTL idn2 -d %spunycode%s\n\n", green, cyan, normal);

			printf("%sOther:%s\n", yellow, normal);
			printf("\t%sptr %sIP%s              Resolve IP address to hostname\n", green, cyan, normal);
			printf("\t%ssha256sum %sfile%s      Calculate SHA256 checksum of a file\n", green, cyan, normal);
			printf("\t%sdhcp-discover%s       Discover DHCP servers in the local\n", green, normal);
			printf("\t                    network\n");
			printf("\t%sarp-scan %s[-a/-x]%s    Use ARP to scan local network for\n", green, cyan, normal);
			printf("\t                    possible IP conflicts\n");
			printf("\t                    Append %s-a%s to force scan on all\n", cyan, normal);
			printf("\t                    interfaces\n");
			printf("\t                    Append %s-x%s to force scan on all\n", cyan, normal);
			printf("\t                    interfaces and scan 10x more often\n");
			printf("\t%s--totp%s              Generate valid TOTP token for 2FA\n", green, normal);
			printf("\t                    authentication (if enabled)\n");
			printf("\t%s--perf%s              Run performance-tests based on the\n", green, normal);
			printf("\t                    BALLOON password-hashing algorithm\n");
			printf("\t%s--%s [OPTIONS]%s        Pass OPTIONS to internal dnsmasq resolver\n", green, cyan, normal);
			printf("\t%s-h%s, %shelp%s            Display this help and exit\n\n", green, normal, green, normal);
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

// defined in src/dnsmasq/option.c
extern void reset_usage_indicator(void);
// defined in src/log.h
bool only_testing = false;
void test_dnsmasq_options(int argc, const char *argv[])
{
	// Reset getopt before calling read_opts
	optind = 0;

	// Signal we don't want to jump back to FTL's main()
	// but die after configuration parsing
	only_testing = true;

	// Call dnsmasq's option parser
	reset_usage_indicator();
	read_opts(argc, (char**)argv, NULL);
}
