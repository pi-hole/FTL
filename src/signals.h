/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Signal handling prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SIGNALS_H
#define SIGNALS_H

void handle_SIGSEGV(void);
void handle_realtime_signals(void);

extern volatile sig_atomic_t killed;

#endif //SIGNALS_H
