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

// pid_t
#include <sys/types.h>

#include "enums.h"

#define SIGUSR6 (SIGRTMIN + 6)
#define SIGUSR32 (SIGRTMIN + 32)

void handle_signals(void);
void handle_realtime_signals(void);
pid_t main_pid(void);
void check_if_want_terminate(void);
void thread_sleepms(const enum thread_types thread, const int milliseconds);
void generate_backtrace(void);
int sigtest(void);
void restart_ftl(const char *reason);
pid_t debugger(void);

extern volatile int exit_code;
extern volatile sig_atomic_t killed;
extern volatile sig_atomic_t want_to_reimport_aliasclients;
extern volatile sig_atomic_t want_to_reload_lists;

extern volatile sig_atomic_t thread_cancellable[THREADS_MAX];
extern const char * const thread_names[THREADS_MAX];

#define BREAK_IF_KILLED() { if(killed) break; }

#endif //SIGNALS_H
