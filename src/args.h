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
extern bool fail_on_error;

const char *cli_tick(void) __attribute__ ((pure));
const char *cli_cross(void) __attribute__ ((pure));
const char *cli_info(void) __attribute__ ((pure));
const char *cli_qst(void) __attribute__ ((const));
const char *cli_done(void) __attribute__ ((pure));
const char *cli_bold(void) __attribute__ ((pure));
const char *cli_normal(void) __attribute__ ((pure));
const char *cli_over(void) __attribute__ ((pure));
const char *cli_underline(void) __attribute__ ((pure));
const char *cli_italics(void) __attribute__ ((pure));

void test_dnsmasq_options(int argc, const char *argv[]);

#endif //ARGS_H
