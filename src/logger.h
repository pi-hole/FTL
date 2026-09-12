/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Asynchronous logging subsystem
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

// enum debug_flag
#include "enums.h"

// Maximum message size in bytes (including the NUL terminator).  This is the
// single truncation point for the whole logging subsystem: messages are
// formatted once on the producer side and every sink (FTL.log, pihole.log,
// webserver.log and the FIFO) renders the canonical record below.  Previously
// the log-file sinks truncated long lines at their own 2048-byte buffers,
// which could lead to different truncation depending on the destination.
#define LOGGER_MAX_MESSAGE 2048u

// Number of slots in the lock-free log queue.  Each slot holds one record
// (LOGGER_MAX_MESSAGE bytes plus ~40 bytes of metadata), totalling roughly
// 8.2 MiB of shared memory.  The size must be a compile time constant so the
// queue can live in shared memory (shared with dnsmasq TCP-query forks).
// 256 slots were enough for steady-state logging but overflowed during
// short, intense bursts (e.g. hundreds of concurrent DNS queries, each
// producing a burst of DEBUG records); records dropped there surfaced as
// "log records were dropped" warnings in the test suite.
#define LOGGER_RING_SLOTS 4096u

// Eventfd poll timeout for the logger thread.  Records are normally signaled
// via the eventfd; the timeout catches the remaining races (an out-of-order
// producer still copying its head-of-line record, a wake that was satisfied
// while the consumer was already draining).
#define LOGGER_POLL_TIMEOUT_MS 20

// Who produced a log record.  Decides which file sink (FTL.log vs.
// webserver.log vs. pihole.log) a record is written to and which FIFO buffer
// it is relayed to.
enum log_source {
	LOG_SOURCE_FTL,       // _FTL_log()
	LOG_SOURCE_DNSMASQ,   // FTL_dnsmasq_log() (my_syslog())
	LOG_SOURCE_WEBSERVER, // _log_web()
};

// One canonical log record.  Records live in the shared-memory ring, so they
// must never contain pointers or heap-allocated payloads: records produced by
// dnsmasq TCP-query forks are consumed by the main process' logger thread.
struct log_record {
	double ts;               // production time (epoch seconds, double_time())
	int priority;            // syslog priority (see sys/syslog.h)
	enum debug_flag flag;    // FTL debug flag (used by priostr/debugstr)
	enum log_source source;  // who produced the record
	pid_t pid;               // producing process
	pid_t tid;               // producing thread
	bool is_fork;            // pid != main_pid() at production time
	size_t len;              // byte length of message (excluding NUL)
	char func[16];           // dnsmasq component suffix ("-dhcp", "-tftp", ...)
	char message[LOGGER_MAX_MESSAGE];
};

// Fill the process/thread/time fields of a record.  The caller then formats
// the actual message into rec->message, sets rec->len and calls log_ring_push().
void log_record_init(struct log_record *rec, const enum log_source source,
                     const int priority, const enum debug_flag flag);

// Enqueue a record.  Lock-free; never blocks.  When the ring is full the
// record is dropped - low priorities immediately, high priorities (WARNING
// and above) after a bounded retry so the logger thread can catch up.  Returns
// false when the record was dropped.  Safe to call from a crash handler and
// from dnsmasq TCP-query fork children.
bool log_ring_push(struct log_record *rec);

// Total count of log records dropped because the log queue was full.  Includes
// drops by dnsmasq TCP-query fork children.  Zero when the queue has not been
// created yet.
uint32_t logger_dropped_count(void);

// Initialize the logging subsystem: create the queue in shared memory and the
// eventfd, spawn the logger thread and wait until the configured sinks are
// open.  Called once at startup and again after the daemonize double-fork
// (post-daemonize restart, see FTL_fork_and_bind_sockets()).
bool logger_start(void);

// Stop the logger thread, waiting for it to drain the queue.  Pre-fork only.
void logger_stop(void);

// Final shutdown: stop the logger thread, drain whatever is left and unmap the
// shared-memory queue.  Called at the very end of cleanup().
void logger_shutdown(void);

// Re-read the config-derived sink paths and reopen the sinks.
// Main thread only.
void logger_reconfigure(void);

// Block until the log queue is drained, the in-memory FIFO dnsmasq buffer is
// cleared and pihole.log is truncated.  Returns 0 on success, -1 when no
// pihole.log is open, or a positive errno when the truncation failed.  Used by
// the API flush action.
int logger_flush(void);

// Request a sink reopen from a signal handler (SIGUSR2).  Async-signal-safe:
// only touches atomics and the eventfd.
void logger_sig_reopen(void);

#endif // LOGGER_H
