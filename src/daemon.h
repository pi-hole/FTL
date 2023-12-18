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

#include "enums.h"
extern pthread_t threads[THREADS_MAX];

void go_daemon(void);
void savepid(void);
char *getUserName(void);
const char *hostname(void);
const char *domainname(void);
void delay_startup(void);
bool is_fork(const pid_t mpid, const pid_t pid) __attribute__ ((const));
void cleanup(const int ret);
void set_nice(void);
void calc_cpu_usage(const unsigned int interval);
float get_cpu_percentage(void) __attribute__((pure));
bool ipv6_enabled(void);
void init_locale(void);

#include <sys/syscall.h>
#include <unistd.h>
// Get ID of current thread (incorrectly shown as "PID" in, e.g., htop)
// We define this wrapper ourselves as the GNU C Library only added it
// in 2019 meaning that, while we're writing this, it will not be widely
// available. It was only added even later (end of 2019) to musl libc.
// https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=1d0fc213824eaa2a8f8c4385daaa698ee8fb7c92
// https://www.openwall.com/lists/musl/2019/08/01/11
// To avoid any conflicts, also in the future, we use our own macro for this
#if !defined(SYS_gettid) && defined(__NR_gettid)
#define SYS_gettid __NR_gettid
#endif // !SYS_gettid && __NR_gettid
pid_t FTL_gettid(void);
#define gettid FTL_gettid

// getrandom() is only available since glibc 2.25
// https://www.gnu.org/software/gnulib/manual/html_node/sys_002frandom_002eh.html
#if !defined(__GLIBC__) || __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)
#include <sys/random.h>
#else
#define getrandom getrandom_fallback
#endif

ssize_t getrandom_fallback(void *buf, size_t buflen, unsigned int flags);

extern bool resolver_ready;
extern bool dnsmasq_failed;

#endif //DAEMON_H
