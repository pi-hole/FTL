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

#include "enums.h"

#define SIGUSR6 (SIGRTMIN + 6)

// defined in dnsmasq/dnsmasq.h
extern volatile char FTL_terminate;

void handle_signals(void);
void handle_realtime_signals(void);
pid_t main_pid(void);
void thread_sleepms(const enum thread_types thread, const int milliseconds);
void generate_backtrace(void);

extern volatile int exit_code;
extern volatile sig_atomic_t killed;
extern volatile sig_atomic_t want_to_reimport_aliasclients;
extern volatile sig_atomic_t want_to_reload_lists;

extern volatile sig_atomic_t thread_cancellable[THREADS_MAX];
extern volatile sig_atomic_t thread_running[THREADS_MAX];
extern const char *thread_names[THREADS_MAX];

#endif //SIGNALS_H
