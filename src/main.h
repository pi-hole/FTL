/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Main prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef MAIN_H
#define MAIN_H

int main_dnsmasq(int argc, const char ** argv);

extern char * username;
extern bool startup;

#endif //MAIN_H
