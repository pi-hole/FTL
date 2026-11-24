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

// Single truncation point for all sinks (including NUL terminator).
#define LOGGER_MAX_MESSAGE 2048u

// Lock-free ring size; compile-time constant for shared-memory fork compatibility.
#define LOGGER_RING_SLOTS 2048u

// Poll timeout to catch wake-up races.
#define LOGGER_POLL_TIMEOUT_MS 20

// Per-sink userspace write-batch buffer; set to 0 to disable batching.
#ifndef LOGGER_SINK_BUFFER_SIZE
#define LOGGER_SINK_BUFFER_SIZE 65536u
#endif

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
	double ts;                  // production time (epoch seconds, double_time())
	int priority;               // syslog priority (see sys/syslog.h)
	enum log_source source;     // who produced the record
	union {                     // union: mutually exclusive on source
		enum debug_flag flag;   // FTL debug flag (used by priostr/debugstr)
		enum dnsmasq_func func; // dnsmasq component suffix ("-dhcp", "-tftp", ...)
	} u;
	pid_t pid;                  // producing process
	pid_t tid;                  // producing thread
	bool is_fork;               // pid != main_pid() at production time
	size_t len;                 // byte length of message (excluding NUL)
	char message[LOGGER_MAX_MESSAGE];
};

// Fill the process/thread/time fields of a record.  The caller then formats
// the actual message into rec->message, sets rec->len and calls log_ring_push().
void log_record_init(struct log_record *rec, const enum log_source source,
                     const int priority, const enum debug_flag flag);

// Lock-free enqueue; drops on full ring (high priorities retry briefly).
// Safe from crash handlers and dnsmasq TCP fork children.
bool log_ring_push(struct log_record *rec);

// Total count of log records dropped because the log queue was full.  Includes
// drops by dnsmasq TCP-query fork children.  Zero when the queue has not been
// created yet.
uint32_t logger_dropped_count(void);

// Initialize ring/eventfd, start logger thread, wait for sinks to open.
// Also used after daemonize double-fork.
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
