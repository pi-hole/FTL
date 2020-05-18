/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Daemon prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DAEMON_H
#define DAEMON_H

void go_daemon(void);
void savepid(void);
char * getUserName(void);
void removepid(void);
void delay_startup(void);

extern bool resolver_ready;

#endif //DAEMON_H
