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

void parse_args(int argc, char* argv[]);

extern bool daemonmode, cli_mode;
extern int argc_dnsmasq;
extern const char ** argv_dnsmasq;

#endif //ARGS_H
