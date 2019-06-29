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
void timer_start(const int i);
double timer_elapsed_msec(const int i);
void sleepms(const int milliseconds);
void savepid(void);
char * getUserName(void);
void removepid(void);

#endif //DAEMON_H
