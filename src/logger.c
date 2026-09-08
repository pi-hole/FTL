/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Asynchronous logging subsystem
*
 *  All producers (FTL threads, the web server, dnsmasq and the dnsmasq
 *  TCP-query fork children) enqueue canonical log records into a lock-free
 *  bounded ring in shared memory.  A single logger thread drains the ring and
 *  performs every sink I/O: FTL.log, webserver.log, pihole.log and the
 *  in-memory FIFO (API /logs).  This removes the per-file mutexes that were
 *  needed when every producer wrote directly.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#include "FTL.h"
#include "version.h"
#include "daemon.h"
#include "args.h"
#include "logger.h"
#include "log.h"
#include "config/config.h"
#include "shmem.h"
#include "signals.h"

#include <stdatomic.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

// The FTL.h error-instrumented wrappers log on failure (log_warn -> enqueue),
// which recurses when the logger thread itself hits an error.  logger.c uses
// the raw libc calls instead; every sink write already carries its own
// fallback logic (syslog relay, dropping) below.
#undef free
#undef strdup
#undef calloc
#undef realloc
#undef printf
#undef fprintf
#undef vprintf
#undef vfprintf
#undef sprintf
#undef snprintf
#undef vsnprintf
#undef write
#undef strlen
#undef strnlen
#undef strncpy
#undef memset
#undef memcpy
#undef memmove
#undef strstr
#undef strcmp
#undef strncmp
#undef strcasecmp
#undef strncasecmp
#undef strcat
#undef strncat
#undef memcmp
#undef memmem

// The queue must work across a plain fork() (dnsmasq TCP children relay log
// records to the main process).  That requires the _Atomic operations on the
// counter/seq fields to be real instructions, not libc-internal locks.
//
// 64-bit counters cover i586+ (cmpxchg8b) and ARMv6K+ (ldrexd/strexd).  The
// original Raspberry Pi 1 is ARMv6 non-K (ARM1176JZF-S): no ldrexd/strexd, so
// ATOMIC_LLONG_LOCK_FREE is not 2 and 64-bit counters would fall back to
// libc/libatomic locks.  For that target use 32-bit counters instead: they
// ARE native LDREX/STREX instructions there, and the ring arithmetic is
// correct modulo 2^32 because the producer-consumer distance never exceeds
// LOGGER_RING_SLOTS, which is far below 2^32:
//   - "tail - head" computed in 32 bits equals the true distance whenever that
//     distance fits in 32 bits (it always does: the queue is bounded by
//     LOGGER_RING_SLOTS), and
//   - the per-slot seq markers only ever need to differ from the "consumed"
//     and "published" values of the same slot, which are separated by a power
//     of two (LOGGER_RING_SLOTS) and hence never collide modulo 2^32 - the
//     same invariant the 64-bit counters rely on, just without the safety
//     margin of an astronomically larger counter space.
#if ATOMIC_LLONG_LOCK_FREE == 2
typedef uint64_t log_ring_counter_t;
#else
typedef uint32_t log_ring_counter_t;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "the log ring fallback needs lock-free 32-bit atomics");
#endif

// ---- Shared-memory ring ---------------------------------------------------
// Layout shared verbatim with dnsmasq TCP-query forks, which produce records
// here (relayed to the main process).  Only the logger thread in the main
// process ever consumes.  The structure is deliberately POD: no pointers, no
// padding surprises beyond normal alignment.

typedef struct {
	_Atomic log_ring_counter_t head;                // next counter value to consume
	_Atomic log_ring_counter_t tail;                // next counter value to claim
	_Atomic log_ring_counter_t seq[LOGGER_RING_SLOTS]; // per-slot generation markers
	struct log_record slot[LOGGER_RING_SLOTS];      // the records themselves
	_Atomic uint32_t dropped;             // records dropped due to a full queue
} logRing;

static logRing *ring = NULL;
static size_t ring_size = 0;
static char ring_name[64] = { 0 };                  // for shm_unlink()

// eventfd used to wake the logger thread
static int wake_fd = -1;

// ---- Thread state ----------------------------------------------------------
static pthread_t logger_thread;
static _Atomic bool thread_running = false;
static _Atomic bool stop_requested = false;

// Control requests posted by the control API (logger_reconfigure,
// logger_flush) and the SIGUSR2 handler, consumed by the logger thread.
// Posting is lock-free (plain atomics + eventfd write).
enum {
	CTRL_PATHS = 1u << 0,   // (re)target webserver/dnsmasq sinks (logger_reconfigure)
	CTRL_REOPEN = 1u << 1,  // reopen all sinks (SIGUSR2)
	CTRL_FLUSH = 1u << 2,   // drain, clear FIFO_DNSMASQ, truncate pihole.log
};
static _Atomic uint32_t logger_ctrl = 0;

// Flush completion handshake (logger_flush() -> logger thread -> reply)
static pthread_mutex_t flush_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t flush_cond = PTHREAD_COND_INITIALIZER;
static uint64_t flush_request_id = 0;
static uint64_t flush_done_id = 0;
static int flush_trunc_err = 0;

// ---- Sinks ------------------------------------------------------------------
#define LOGGER_MAX_PATH 4096

typedef struct {
	char path[LOGGER_MAX_PATH];  // owned by the logger thread
	int fd;                      // -1 when closed/unavailable
	dev_t dev;                   // identity of the file fd was opened on,
	ino_t ino;                   // for the stale-descriptor guard in sink_close()
} loggerSink;

static loggerSink sink_ftl = { .path = { 0 }, .fd = -1 };
static loggerSink sink_webserver = { .path = { 0 }, .fd = -1 };
static loggerSink sink_dnsmasq = { .path = { 0 }, .fd = -1 };

// Snapshot of the config-derived logging settings.  The logger thread never
// touches the live config (which the main thread may be parsing); it only
// reads this immutable-ish copy, guarded by snapshot_mutex.
typedef struct {
	char path_webserver[LOGGER_MAX_PATH];
	char path_dnsmasq[LOGGER_MAX_PATH];
	bool hide_dnsmasq_warn;  // copied from config.misc.hide_dnsmasq_warn
} loggerSnapshot;

static loggerSnapshot snapshot;
static pthread_mutex_t snapshot_mutex = PTHREAD_MUTEX_INITIALIZER;

// ---- Forward declarations ---------------------------------------------------
static void *logger_thread_main(void *arg);
static void logger_wake(void);
static void publish_sink_fds(void);

// ---- Ring queue (Vyukov bounded MPSC with per-slot seq markers) -------------
static bool log_ring_enqueue(struct log_record *rec, log_ring_counter_t *claimed)
{
	logRing *r = ring;
	if (r == NULL)
		return false;

	log_ring_counter_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
	for (;;)
	{
		// The queue is full once the distance tail-head reaches the capacity.
		// head only ever increases, so a tail validated here can never be
		// written over a slot the consumer has not yet consumed.
		const log_ring_counter_t head = atomic_load_explicit(&r->head, memory_order_acquire);
		if (tail - head >= LOGGER_RING_SLOTS)
			return false;

		if (atomic_compare_exchange_weak_explicit(&r->tail, &tail, tail + 1,
		                                          memory_order_relaxed,
		                                          memory_order_relaxed))
			break;
		// tail was updated by the failed CAS; re-check capacity and retry
	}

	const log_ring_counter_t slot = tail % LOGGER_RING_SLOTS;
	r->slot[slot] = *rec;  // contains no pointers; plain POD copy
	// Publish with a release store: the consumer observes the record's data
	// (via the copying read) only after seeing this marker.
	atomic_store_explicit(&r->seq[slot], tail + 1, memory_order_release);
	*claimed = tail;
	return true;
}

static bool log_ring_pop(struct log_record *rec)
{
	logRing *r = ring;
	if (r == NULL)
		return false;

	// Single consumer: no CAS needed on head.
	const log_ring_counter_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
	const log_ring_counter_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
	if (head == tail)
		return false;  // empty

	const log_ring_counter_t slot = head % LOGGER_RING_SLOTS;
	// Head-of-line slot not yet published: its producer is still copying
	// the record.  Report empty; the caller will retry shortly.  This lets
	// the consumer safely wait out out-of-order producers.
	if (atomic_load_explicit(&r->seq[slot], memory_order_acquire) != head + 1)
		return false;

	*rec = r->slot[slot];
	// Mark the slot consumed: the marker value now equals the counter a future
	// producer will claim for this slot, which the head-of-line check above
	// keeps distinct from the published (head+1) value.
	atomic_store_explicit(&r->seq[slot],
	                      head + LOGGER_RING_SLOTS, memory_order_release);
	// Advance head after publishing seq so producers observe the correct slot
	// availability on their next tail CAS.
	atomic_store_explicit(&r->head, head + 1, memory_order_release);
	return true;
}

static void logger_drain_eventfd(void)
{
	// Drain the eventfd counter so an already-satisfied wake-up does not make
	// the consumer spin through empty drains.
	uint64_t v;
	while (read(wake_fd, &v, sizeof(v)) > 0) { /* keep draining */ }
}

static void logger_wake(void)
{
	if (wake_fd < 0)
		return;
	const uint64_t one = 1;
	(void)!write(wake_fd, &one, sizeof(one));
}

static bool logger_ring_prepare(void)
{
	// The queue must survive the daemonize double-fork (the consumer thread
	// is respawned in the grandchild via logger_start()), so it is backed by
	// a POSIX shared-memory object.  The PID in the name isolates instances
	// (and matches the /dev/shm/FTL-* cleanup pattern used by the test suite).
	snprintf(ring_name, sizeof(ring_name), "/FTL-%d-logging", (int)getpid());

	int fd = shm_open(ring_name, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0 && errno == EEXIST)
	{
		// Stale object from a crashed incarnation holding the same PID
		shm_unlink(ring_name);
		fd = shm_open(ring_name, O_RDWR | O_CREAT | O_EXCL, 0600);
	}
	if (fd < 0)
		return false;

	ring_size = sizeof(logRing);
	if (ftruncate(fd, (off_t)ring_size) != 0)
	{
		close(fd);
		shm_unlink(ring_name);
		return false;
	}

	ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (ring == MAP_FAILED)
	{
		ring = NULL;
		shm_unlink(ring_name);
		return false;
	}

	return true;
}

static void logger_ring_teardown(void)
{
	if (ring != NULL)
	{
		munmap(ring, ring_size);
		ring = NULL;
	}
	if (ring_name[0] != '\0')
	{
		shm_unlink(ring_name);
		ring_name[0] = '\0';
	}
	if (wake_fd >= 0)
	{
		close(wake_fd);
		wake_fd = -1;
	}
}

// ---- Producer side ------------------------------------------------------------
void log_record_init(struct log_record *rec, const enum log_source source,
                     const int priority, const enum debug_flag flag)
{
	// Capture the production time with sub-second precision up front.  Every
	// sink renders this value, so the timestamps in the log files are the
	// exact production timestamps with millisecond precision - they are never
	// re-sampled when the logger thread drains the record.
	rec->ts = double_time();
	rec->priority = priority;
	rec->flag = flag;
	rec->source = source;
	rec->pid = getpid();
	rec->tid = gettid();
	// Classify the producing process NOW: main_pid() changes once the daemon
	// double-fork completes, and records produced before that (FTL startup
	// lines) must still be rendered as the main process, not as a fork.
	rec->is_fork = is_fork(main_pid(), rec->pid);
	rec->len = 0;
	rec->func[0] = '\0';
	rec->message[0] = '\0';
}

static bool try_enqueue(struct log_record *rec)
{
	// Backpressure policy: low-severity records are dropped immediately when
	// the queue is full, WARNING/ERROR after a bounded retry and CRIT/beyond
	// after a longer retry, so the daemon threads never block on logging.
	const unsigned int max_retries = rec->priority <= LOG_CRIT     ? 1000u :
	                                 rec->priority <= LOG_WARNING  ? 100u  : 0u;

	unsigned int retries = 0;
	log_ring_counter_t claimed;
	for (;;)
	{
		if (log_ring_enqueue(rec, &claimed))
		{
			// Wake the consumer only when OUR record made the previously
			// empty queue non-empty (head == claimed still holds).  If the
			// consumer is already draining past our slot it needs no wake;
			// records are drained in order and the poll timeout covers the
			// remaining boundary races.
			if (atomic_load_explicit(&ring->head, memory_order_acquire) == claimed)
				logger_wake();
			return true;
		}

		if (retries++ >= max_retries)
		{
			atomic_fetch_add_explicit(&ring->dropped, 1, memory_order_relaxed);
			return false;
		}
		// Bounded spin instead of usleep: this may run inside a crash handler.
		sched_yield();
	}
}

bool log_ring_push(struct log_record *rec)
{
	// Queue not yet created (logger not started) or already torn down
	// (shutdown): fall back to syslog so the message is not lost entirely.
	// This mirrors the old behavior when no FTL.log was open.
	if (ring == NULL)
	{
		syslog(rec->priority, "%s", rec->message);
		return false;
	}

	return try_enqueue(rec);
}

// Total count of log records dropped because the log queue was full.  Includes
// drops by dnsmasq TCP-query fork children.  Zero when the queue has not been
// created yet.
uint32_t logger_dropped_count(void)
{
	if (ring == NULL)
		return 0;
	return atomic_load_explicit(&ring->dropped, memory_order_relaxed);
}

// ---- Formatting helpers -------------------------------------------------------
// Replicate get_idstr()'s output from a record (the producer-side process/thread
// classification is preserved in rec->is_fork).
static void logger_get_idstr(char *idstr, const size_t size,
                             const struct log_record *rec)
{
	if(rec->pid == rec->tid)
	{
		if(rec->is_fork)
			snprintf(idstr, size, "%i/F%i", (int)rec->pid, (int)main_pid());
		else
			snprintf(idstr, size, "%iM", (int)rec->pid);
	}
	else
	{
		if(rec->is_fork)
			snprintf(idstr, size, "%i/F%i/T%i",
			         (int)rec->pid, (int)main_pid(), (int)rec->tid);
		else
			snprintf(idstr, size, "%i/T%i", (int)rec->pid, (int)rec->tid);
	}
}

// Priority string for the file/FIFO sinks.  dnsmasq has no FTL debug
// flags, so its LOG_DEBUG is a plain "DEBUG" rather than the DEBUG_ANY
// catch-all priostr() maps to.  (Same as the previous FTL_dnsmasq_log().)
static const char *logger_prio(const struct log_record *rec)
{
	if(rec->source == LOG_SOURCE_DNSMASQ && rec->priority == LOG_DEBUG)
		return "DEBUG";
	return priostr(rec->priority, rec->flag);
}

// ---- Sink primitives ------------------------------------------------------------
static bool sink_write(loggerSink *sink, const char *buf, const size_t len)
{
	if(sink->fd < 0)
		return false;

	ssize_t written = 0;
	while(written < (ssize_t)len)
	{
		ssize_t rc = write(sink->fd, buf + written, len - (size_t)written);
		if(rc < 0)
		{
			if(errno == EINTR)
				continue;
			return false;
		}
		if(rc == 0)
			return false;
		written += rc;
	}
	return true;
}

static void sink_close(loggerSink *sink)
{
	if(sink->fd < 0)
		return;

	// Stale-descriptor guard: across fork() (daemon mode) the pre-fork logger
	// thread may have been frozen between its sink_close() and the matching
	// reopen, leaving this process with a sink fd number that is no longer
	// occupied by the sink file.  Closing such a recycled descriptor here
	// would destroy whatever the number was reused for (e.g. a freshly bound
	// dnsmasq DNS listener socket) and silently kill that listener.  Only
	// close the descriptor when it still refers to the file opened for the
	// sink; otherwise just drop the stale number.
	struct stat st;
	if(fstat(sink->fd, &st) != 0 || st.st_dev != sink->dev || st.st_ino != sink->ino)
	{
		sink->fd = -1;
		return;
	}
	close(sink->fd);
	sink->fd = -1;
}

static void sink_store_path(loggerSink *sink, const char *path)
{
	if(path != NULL && path[0] != '\0')
	{
		snprintf(sink->path, sizeof(sink->path), "%s", path);
		// Strip any trailing newline that a malicious/corrupt path value
		// could smuggle in.
		for(size_t i = 0; sink->path[i] != '\0'; i++)
			if(sink->path[i] == '\n')
				sink->path[i] = '\0';
	}
	else
	{
		sink->path[0] = '\0';
	}
}

// Reopen one sink, warning appropriately on failure.  A failed open is left
// closable later, so a later reopen (e.g. the SIGUSR2 one) can revive a sink
// that failed initially (missing directory, EACCES).
static void sink_open(loggerSink *sink, const bool is_ftl)
{
	struct stat st;
	sink_close(sink);
	if(sink->path[0] == '\0')
		return;
	sink->fd = open(sink->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
	                S_IRUSR | S_IWUSR | S_IRGRP);
	if(sink->fd < 0 && is_ftl)
	{
		// Report the failure on stderr and via syslog:
		fprintf(stderr,
		        "ERROR: Opening of FTL log (%s) failed: %s\nUsing syslog instead!\n",
		        sink->path, strerror(errno));
		syslog(LOG_ERR, "Opening of FTL's log file failed, using syslog instead!");
		return;
	}

	if(sink->fd < 0)
		return;

	// Remember the identity of the file we opened so sink_close() can detect
	// a descriptor that was recycled (see the guard there).
	if(fstat(sink->fd, &st) != 0)
	{
		const int error = errno;
		close(sink->fd);
		sink->fd = -1;
		errno = error;
		return;
	}
	sink->dev = st.st_dev;
	sink->ino = st.st_ino;
}

// Write a bare FTL.log warning from the logger thread itself (bypassing the
// queue - we ARE the logger).  Failure to open web/pihole logs uses this so
// the "still relayed to the FTL log" guarantee holds even though the warning
// cannot be enqueued.
static void __attribute__ ((format(printf, 2, 3))) logger_write_direct_warning(loggerSink *sink, const char *fmt, ...)
{
	char msg[LOGGER_MAX_MESSAGE];
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	// Build the idstr of the logger thread itself
	struct log_record me = { 0 };
	me.pid = getpid();
	me.tid = gettid();
	me.is_fork = is_fork(main_pid(), me.pid);
	char idstr[42];
	logger_get_idstr(idstr, sizeof(idstr), &me);

	char timestring[TIMESTR_SIZE];
	get_timestr(timestring, double_time(), true, false);

	// Sized so the longest message (LOGGER_MAX_MESSAGE bytes) plus the
	// timestamp, idstr and fixed prefix can never be truncated
	char line[LOGGER_MAX_MESSAGE + 512];
	int off = snprintf(line, sizeof(line), "%s [%s] WARNING: %s",
	                   timestring, idstr, msg);
	if(off < 0 || off >= (int)sizeof(line))
		off = (int)sizeof(line) - 1;
	line[off++] = '\n';

	if(!sink_write(sink, line, (size_t)off))
		syslog(LOG_WARNING, "%s", msg);
}

// ---- Record rendering -----------------------------------------------------------
// Render one "TIMESTRING [idstr] PRIO: <message>\n" line (the FTL.log and
// webserver.log format) into the given sink.  Returns false when no write
// happened (fd missing or write error) so the caller can apply its fallback.
static bool logger_file_line(loggerSink *sink, const struct log_record *rec,
                             const char *prio)
{
	char timestring[TIMESTR_SIZE];
	get_timestr(timestring, rec->ts, true, false);

	char idstr[42];
	logger_get_idstr(idstr, sizeof(idstr), rec);

	// Same 2048-byte line cap as the previous per-file writers
	char line[2048];
	int off = snprintf(line, sizeof(line), "%s [%s] %s: ",
	                   timestring, idstr, prio);
	if(off < 0 || off >= (int)sizeof(line))
		off = (int)sizeof(line) - 1;

	if(rec->len > 0)
	{
		const size_t space = sizeof(line) - (size_t)off - 1u;  // room for '\n'
		const size_t copy = rec->len < space ? rec->len : space;
		memcpy(line + off, rec->message, copy);
		off += (int)copy;
	}
	line[off++] = '\n';

	return sink_write(sink, line, (size_t)off);
}

// pihole.log, byte-identical to the previous FTL_write_dnsmasq_log()
static void logger_dnsmasq_line(struct log_record *rec)
{
	time_t now = (time_t)rec->ts;
	char ctime_buf[26];
	const char *ctime_str = ctime_r(&now, ctime_buf);
	if(ctime_str == NULL)
		ctime_str = "Thu Jan  1 00:00:00 1970\n";
	char ts_buf[16];
	snprintf(ts_buf, sizeof(ts_buf), "%.15s", ctime_str + 4);

	char line[2048];
	int off = snprintf(line, sizeof(line), "%s dnsmasq%s[%d]: ",
	                   ts_buf, rec->func, (int)rec->pid);
	if(off < 0 || off >= (int)sizeof(line))
		off = (int)sizeof(line) - 1;

	if(rec->len > 0)
	{
		const size_t space = sizeof(line) - (size_t)off - 1u;
		const size_t copy = rec->len < space ? rec->len : space;
		memcpy(line + off, rec->message, copy);
		off += (int)copy;
	}
	line[off++] = '\n';

	if(!sink_write(&sink_dnsmasq, line, (size_t)off) && rec->priority <= LOG_WARNING)
		// pihole.log unavailable - keep warnings/errors durable via syslog
		syslog(rec->priority, "%s", rec->message);
}

// ---- Dispatch -----------------------------------------------------------------
// Relay a record into the SHM FIFO.  This thread is the sole FIFO writer
// (every producer goes through the ring), so no lock is taken here: locking
// would let the thread re-enter a mutex it already holds whenever a lock- or
// timing-debug line produced below loops back through the queue.
static void logger_fifo(struct log_record *rec, const char *prio)
{
	size_t flen = rec->len + 1u;  // include zero-terminator
	if(flen > MAX_MSG_FIFO)
		flen = MAX_MSG_FIFO;

	enum fifo_logs which = FIFO_FTL;
	switch(rec->source)
	{
		case LOG_SOURCE_FTL:       which = FIFO_FTL;       break;
		case LOG_SOURCE_DNSMASQ:   which = FIFO_DNSMASQ;   break;
		case LOG_SOURCE_WEBSERVER: which = FIFO_WEBSERVER; break;
	}

	// Store the record's production timestamp (same double epoch-seconds
	// representation that double_time() yields for the synchronous path)
	add_to_fifo_buffer(which, rec->message, prio, flen, rec->ts);
}

static void logger_dispatch(struct log_record *rec)
{
	const char *prio = logger_prio(rec);

	// The FIFO relay happens for every record, matching the previous behavior.
	logger_fifo(rec, prio);

	switch(rec->source)
	{
		case LOG_SOURCE_FTL:
			if(!logger_file_line(&sink_ftl, rec, prio))
				// No FTL.log available - fall back to syslog
				syslog(rec->priority, "%s", rec->message);
			break;
		case LOG_SOURCE_WEBSERVER:
			// webserver.log unavailable: keep severe messages durable in
			// FTL.log (previous behavior, minus the duplicate FIFO entry)
			if(!logger_file_line(&sink_webserver, rec, prio) &&
			   rec->priority <= LOG_WARNING)
			{
				if(!logger_file_line(&sink_ftl, rec, prio))
					syslog(rec->priority, "%s", rec->message);
			}
			break;
		case LOG_SOURCE_DNSMASQ:
			logger_dnsmasq_line(rec);
			break;
	}
}

static void logger_drain(void)
{
	struct log_record rec;
	while(log_ring_pop(&rec))
		logger_dispatch(&rec);
}

// ---- Flush ------------------------------------------------------------------
static void logger_do_flush(void)
{
	// Drain everything enqueued so far, then clear the in-memory dnsmasq FIFO
	// and truncate pihole.log so an API flush empties exactly the records
	// produced before the request was posted.
	logger_drain();

	int trunc_err = 0;
	// Clear the dnsmasq FIFO.  Same single-writer argument as logger_fifo():
	// no other thread appends to the FIFO, so no lock is required.
	if(fifo_log)
		memset(&fifo_log->logs[FIFO_DNSMASQ], 0,
		       sizeof(fifo_log->logs[FIFO_DNSMASQ]));

	if(sink_dnsmasq.fd < 0)
		trunc_err = -1;                              // no log file open
	else if(ftruncate(sink_dnsmasq.fd, 0) != 0)
		trunc_err = errno;                           // fd stays usable for appending

	// Signal completion to the waiting API thread
	pthread_mutex_lock(&flush_mutex);
	flush_done_id = flush_request_id;
	flush_trunc_err = trunc_err;
	pthread_cond_broadcast(&flush_cond);
	pthread_mutex_unlock(&flush_mutex);
}

// ---- Sink (re)configuration -----------------------------------------------------
static void logger_reopen_all(void)
{
	sink_open(&sink_ftl, true);
	sink_open(&sink_webserver, false);
	sink_open(&sink_dnsmasq, false);
	publish_sink_fds();
}

// (Re)target webserver.log and pihole.log from the
// config snapshot.  The FTL sink keeps whatever fd it had - exactly what the
// previous code did (FTL.log was only ever opened during init).
static void logger_update_paths(void)
{
	pthread_mutex_lock(&snapshot_mutex);
	char webserver_path[LOGGER_MAX_PATH];
	char dnsmasq_path[LOGGER_MAX_PATH];
	const bool hide_dnsmasq_warn = snapshot.hide_dnsmasq_warn;
	snprintf(webserver_path, sizeof(webserver_path), "%s", snapshot.path_webserver);
	snprintf(dnsmasq_path, sizeof(dnsmasq_path), "%s", snapshot.path_dnsmasq);
	pthread_mutex_unlock(&snapshot_mutex);

	sink_store_path(&sink_webserver, webserver_path);
	sink_store_path(&sink_dnsmasq, dnsmasq_path);
	sink_open(&sink_webserver, false);
	const int webserver_error = errno;
	sink_open(&sink_dnsmasq, false);
	const int dnsmasq_error = errno;
	publish_sink_fds();

	// Emit the "unavailable" warnings via the normal path (mirroring the old
	// log_warn()) now that the sinks are (re)opened
	if(sink_webserver.fd < 0 && webserver_path[0] != '\0')
		logger_write_direct_warning(&sink_ftl,
			"webserver.log is unavailable (%s); warnings are still relayed to the FTL log",
			strerror(webserver_error));
	if(sink_dnsmasq.fd < 0 && dnsmasq_path[0] != '\0')
	{
		if(hide_dnsmasq_warn)
			logger_write_direct_warning(&sink_ftl,
				"pihole.log is unavailable (%s); dnsmasq warnings are hidden (misc.hide_dnsmasq_warn)",
				strerror(dnsmasq_error));
		else
			logger_write_direct_warning(&sink_ftl,
				"pihole.log is unavailable (%s); dnsmasq warnings are still relayed to the FTL log",
				strerror(dnsmasq_error));
	}
}

static void logger_process_controls(void)
{
	const uint32_t ctrl = atomic_exchange_explicit(&logger_ctrl, 0,
	                                                memory_order_acq_rel);
	if(ctrl == 0)
		return;

	// A pending flush must always be answered - an API thread may be blocked
	// in logger_flush() waiting for the completion handshake, even while the
	// logger is shutting down.
	if(ctrl & CTRL_FLUSH)
		logger_do_flush();

	// Path changes and sink reopens are pointless once the thread is stopping
	if(stop_requested)
		return;

	if(ctrl & CTRL_PATHS)
		logger_update_paths();
	if(ctrl & CTRL_REOPEN)
		logger_reopen_all();
}

// ---- The logger thread ------------------------------------------------------------
static void *logger_thread_main(void *arg)
{
	(void)arg;

	prctl(PR_SET_NAME, "logger", 0, 0, 0);

	logger_reopen_all();

	atomic_store_explicit(&thread_running, true, memory_order_release);

	for(;;)
	{
		// Drain the whole batch that made the queue non-empty
		logger_drain();

		// Apply control requests after the drain: a flush must see the queue
		// empty, a reopen must not race a write.
		logger_process_controls();

		if(atomic_load_explicit(&stop_requested, memory_order_acquire))
			break;

		// Nothing drained and no control pending: wait for a producer.  The
		// poll timeout covers the remaining wake-up races (an out-of-order
		// producer still copying its head-of-line record, a wake that was
		// satisfied while the consumer was already draining).
		const uint32_t ctrl = atomic_load_explicit(&logger_ctrl, memory_order_relaxed);
		if(ctrl == 0)
		{
			struct pollfd pfd = { .fd = wake_fd, .events = POLLIN };
			const int pollrc = poll(&pfd, 1, LOGGER_POLL_TIMEOUT_MS);
			if(pollrc > 0)
				logger_drain_eventfd();
		}
	}

	// Final drain so shutdown never loses the records that raced the stop
	// request, then process any final controls (e.g. a pending flush).
	logger_drain();
	logger_process_controls();

	return NULL;
}

// ---- Public control API -----------------------------------------------------------
static void logger_take_snapshot(void)
{
	// Main thread only - the logger thread must never read the live config.
	// This runs before any dnsmasq fork and while the logger thread either
	// does not exist yet or is only reading the previous snapshot copy.
	pthread_mutex_lock(&snapshot_mutex);
	snapshot.hide_dnsmasq_warn = config.misc.hide_dnsmasq_warn.v.b;
	if(config.files.log.webserver.v.s != NULL)
		snprintf(snapshot.path_webserver, sizeof(snapshot.path_webserver), "%s",
		         config.files.log.webserver.v.s);
	else
		snapshot.path_webserver[0] = '\0';
	if(config.files.log.dnsmasq.v.s != NULL)
	{
		// "-" used to select stderr via dnsmasq's log-facility; since FTL
		// writes pihole.log itself it is no longer supported. Fall back to
		// the default path so no file named "-" is created.
		if(strcmp(config.files.log.dnsmasq.v.s, "-") == 0)
		{
			log_warn("files.log.dnsmasq = \"-\" (log to stderr) is no longer supported, using %s instead (see https://github.com/pi-hole/FTL/pull/2960)",
			         config.files.log.dnsmasq.d.s);
			if(config.files.log.dnsmasq.t == CONF_STRING_ALLOCATED)
				free(config.files.log.dnsmasq.v.s);
			config.files.log.dnsmasq.v.s = strdup(config.files.log.dnsmasq.d.s);
			config.files.log.dnsmasq.t = CONF_STRING_ALLOCATED;
		}
		snprintf(snapshot.path_dnsmasq, sizeof(snapshot.path_dnsmasq), "%s",
		         config.files.log.dnsmasq.v.s);
	}
	else
		snapshot.path_dnsmasq[0] = '\0';
	pthread_mutex_unlock(&snapshot_mutex);
}

bool logger_start(void)
{
	// The ring + eventfd are never torn down by logger_stop(), so starting
	// again after a stop only needs a fresh thread.
	if(atomic_load_explicit(&thread_running, memory_order_acquire))
		return true;

	if(ring == NULL && !logger_ring_prepare())
	{
		syslog(LOG_ERR, "Cannot create log queue in shared memory: %s",
		       strerror(errno));
		return false;
	}

	if(wake_fd < 0)
		wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if(wake_fd < 0)
	{
		syslog(LOG_ERR, "Cannot create log wakeup eventfd: %s", strerror(errno));
		return false;
	}

	logger_take_snapshot();

	// Seed the FTL sink path.  On the first start only FTL.log is active
	// (configured via getLogFilePath()); webserver.log/pihole.log paths
	// arrive later through logger_reconfigure().
	if(config.files.log.ftl.v.s != NULL)
		sink_store_path(&sink_ftl, config.files.log.ftl.v.s);

	if(pthread_create(&logger_thread, NULL, logger_thread_main, NULL) != 0)
	{
		syslog(LOG_ERR, "Cannot create logger thread: %s", strerror(errno));
		return false;
	}

	// Wait (bounded) for the logger thread to open its sinks so that
	// subsequent code (dnsmasq close_fds) sees the published fds.
	for(unsigned int i = 0; i < 10000u &&
	    !atomic_load_explicit(&thread_running, memory_order_acquire); i++)
		sched_yield();

	return true;
}

void logger_stop(void)
{
	if(!atomic_load_explicit(&thread_running, memory_order_acquire))
		return;

	atomic_store_explicit(&stop_requested, true, memory_order_release);
	logger_wake();
	pthread_join(logger_thread, NULL);
	atomic_store_explicit(&thread_running, false, memory_order_relaxed);
	atomic_store_explicit(&stop_requested, false, memory_order_relaxed);

	// The sinks, ring and eventfd stay alive across a stop/start cycle. This
	// lets daemonization join the logger before fork(), then restart it in the
	// child without losing the inherited sink state.
	// (logger_stop() does NOT close sinks or tear down the ring; that only
	// happens in logger_shutdown().)
}

void logger_shutdown(void)
{
	// Drain the queue even if the thread is gone (logger_start() failed and
	// nothing was ever consumed).  Normally: post stop, drain whatever the
	// thread left.
	if(atomic_load_explicit(&thread_running, memory_order_acquire))
		logger_stop();

	// Belt-and-suspenders: after the thread has joined, retry the remaining
	// records from this (the only) remaining thread before destroying the
	// queue.  Records the main thread produced while shutting down after the
	// logger was stopped (banner, destroy_shmem() debug output, ...) are
	// drained here.  The FIFO relay inside logger_dispatch() is a no-op in
	// this window because destroy_shmem() already cleared fifo_log.
	struct log_record leftover;
	while(log_ring_pop(&leftover))
		logger_dispatch(&leftover);

	sink_close(&sink_ftl);
	sink_close(&sink_webserver);
	sink_close(&sink_dnsmasq);
	logger_ring_teardown();
}

void logger_reconfigure(void)
{
	logger_take_snapshot();
	atomic_fetch_or_explicit(&logger_ctrl, CTRL_PATHS, memory_order_release);
	logger_wake();
}

int logger_flush(void)
{
	pthread_mutex_lock(&flush_mutex);

	// Request + wait, generating a new request id so concurrent calls each
	// wait for their own completion.
	flush_request_id++;
	const uint64_t my_request = flush_request_id;
	atomic_fetch_or_explicit(&logger_ctrl, CTRL_FLUSH, memory_order_release);
	logger_wake();

	while(flush_done_id < my_request)
		pthread_cond_wait(&flush_cond, &flush_mutex);

	const int trunc_err = flush_trunc_err;
	pthread_mutex_unlock(&flush_mutex);
	return trunc_err;
}

void logger_sig_reopen(void)
{
	// Async-signal-safe: only touches an atomic and writes the eventfd
	atomic_fetch_or_explicit(&logger_ctrl, CTRL_REOPEN, memory_order_release);
	if(wake_fd >= 0)
	{
		const uint64_t one = 1;
		(void)!write(wake_fd, &one, sizeof(one));
	}
}

// ---- fd publication (dnsmasq close_fds()) --------------------------------------
// Published as a fixed-size atomic array of LOGGER_MAX_SINK_FDS entries: the
// three log files and the eventfd.
#define LOGGER_MAX_SINK_FDS 4
static _Atomic int logger_fds[LOGGER_MAX_SINK_FDS];

static void publish_sink_fds(void)
{
	const int fds[LOGGER_MAX_SINK_FDS] = {
		sink_ftl.fd,
		sink_webserver.fd,
		sink_dnsmasq.fd,
		wake_fd,
	};
	for(int i = 0; i < LOGGER_MAX_SINK_FDS; i++)
		atomic_store_explicit(&logger_fds[i], fds[i], memory_order_release);
}

int __attribute__((pure)) is_log_fd(const int fd)
{
	if(fd < 0)
		return false;

	// The array starts out full of 0, but dnsmasq close_fds() only runs after
	// the logger thread has published (logger_reopen_all() -> publish).
	for(int i = 0; i < LOGGER_MAX_SINK_FDS; i++)
		if(atomic_load_explicit(&logger_fds[i], memory_order_acquire) == fd)
			return true;
	return false;
}
