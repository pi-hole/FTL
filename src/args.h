/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Argument parsing prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef ARGS_H
#define ARGS_H

void parse_args(int argc, char *argv[]);

extern bool daemonmode, cli_mode;
extern int argc_dnsmasq;
extern const char ** argv_dnsmasq;

const char *cli_tick(void) __attribute__ ((pure));
const char *cli_cross(void) __attribute__ ((pure));
const char *cli_info(void) __attribute__ ((pure));
const char *cli_qst(void) __attribute__ ((const));
const char *cli_done(void) __attribute__ ((pure));
const char *cli_bold(void) __attribute__ ((pure));
const char *cli_normal(void) __attribute__ ((pure));
const char *cli_color(const char *color) __attribute__ ((pure));
const char *cli_over(void) __attribute__ ((pure));
const char *cli_underline(void) __attribute__ ((pure));
const char *cli_italics(void) __attribute__ ((pure));

void test_dnsmasq_options(int argc, const char *argv[]);

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
#define CLI_OVER	"\r\x1b[K" // go back to beginning of line and erase to end of line

#endif //ARGS_H
