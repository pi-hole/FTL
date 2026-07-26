/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Signal processing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
// Universal unwind backtrace via GCC's libgcc - works on glibc AND musl, static AND dynamic
#if defined(USE_UNWIND)
#  include <unwind.h>
#  include <limits.h>    // PATH_MAX
#  include <sys/mman.h>  // mmap() - used for the intentional crash test subcommand
#  include <dlfcn.h>     // dladdr() - dynamic symbol lookup from .dynsym
#  include <ucontext.h>  // ucontext_t - register snapshot from SA_SIGINFO handlers
#  include <fcntl.h>     // open() - raw, signal-safe /proc/self/maps reading
#  include <poll.h>      // poll() - bound the addr2line subprocess wall-clock
#  include <sys/wait.h>  // waitpid()/WIFEXITED() - reap the addr2line child
#endif
#include "signals.h"
// logging routines
#include "log.h"
// cli_color() - ANSI colors only when stdout is an interactive terminal
#include "args.h"
// ls_dir()
#include "files.h"
// gettid()
#include "daemon.h"
// Eventqueue routines
#include "events.h"
// sleepms()
#include "timers.h"
// struct config
#include "config/config.h"

#define BINARY_NAME "pihole-FTL"

volatile sig_atomic_t killed = 0;
static volatile pid_t mpid = 0;
static time_t FTLstarttime = 0;
volatile int exit_code = EXIT_SUCCESS;

// Saved by the SIGTERM handler for deferred logging in the main loop.
// Only pid_t and uid_t (both integer types) are safe to write from a
// signal handler via volatile.
static volatile pid_t term_sender_pid = 0;
static volatile uid_t term_sender_uid = 0;

// Store the SIGTERM source for re-logging during cleanup so the termination
// reason is always visible near the final "FTL terminated" message, even if
// earlier log lines have been lost (see #2818)
static char term_source[256] = { 0 };

// Binary path stored by init_backtrace() - signal-handler-safe static buffer,
// never reallocated, safe to read from any context including signal handlers
#if defined(USE_UNWIND)
static char bin_path[PATH_MAX] = { 0 };
#endif

#if defined(USE_UNWIND)
// PIE load base address - set once at startup by init_backtrace() using the
// __ehdr_start linker symbol (GNU ld / lld / mold). __ehdr_start points to the
// ELF header in memory, which equals the ASLR slide for PIE binaries and the
// static load address for non-PIE. Either way: file_vaddr = runtime_addr -
// exe_load_addr is exactly what addr2line expects. This is a linker symbol, not
// a libc function, so it is reliable on glibc AND musl, static AND dynamic -
// unlike dl_iterate_phdr, whose behaviour for static executables varies across
// musl versions and may leave exe_load_addr == 0.
static uintptr_t exe_load_addr = 0;
// Provided by the linker for every ELF executable (GNU ld, lld, mold, gold).
extern const char __ehdr_start;
#endif // USE_UNWIND

// Initialize the backtrace subsystem.
// Must be called early in main() (before handle_signals()) so that bin_path
// and exe_load_addr are ready when the first crash handler fires.
void init_backtrace(const char *argv0)
{
#if defined(USE_UNWIND)
	// /proc/self/exe gives the canonical absolute path even when argv[0] is
	// a relative path, a bare binary name, or a symlink.
	ssize_t len = readlink("/proc/self/exe", bin_path, sizeof(bin_path) - 1u);
	if(len > 0)
		bin_path[len] = '\0';
	else if(argv0 != NULL)
	{
		strncpy(bin_path, argv0, sizeof(bin_path) - 1u);
		bin_path[sizeof(bin_path) - 1u] = '\0';
	}

	// Cache the PIE load base address for addr2line offset adjustment.
	// __ehdr_start is a linker symbol pointing at the ELF header in memory,
	// which equals the ASLR load base for PIE binaries.
	exe_load_addr = (uintptr_t)&__ehdr_start;
#else
	// Unused, cannot generate backtraces right now on non-gcc targets -
	// this silences a warning about unused parameters in this case
	(void)argv0;
#endif // USE_UNWIND
}

#if defined(USE_UNWIND)
// State carried through each _Unwind_Backtrace callback invocation
struct unwind_state {
	void **frames;
	int    count;
	int    max;
};

enum backtrace_source {
	BT_SOURCE_NONE,
	BT_SOURCE_SIGNAL_CONTEXT,
	BT_SOURCE_UNWIND_FALLBACK,
};

// Callback invoked by _Unwind_Backtrace for each frame on the call stack.
// Signal-handler-safe: no heap allocation, no stdio, no locks.
static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context *ctx, void *arg)
{
	struct unwind_state *state = (struct unwind_state *)arg;
	if(state->count >= state->max)
		return _URC_END_OF_STACK;
	// _Unwind_GetIPInfo() reports whether the IP already points *at* the
	// instruction (ip_before_insn != 0, as for signal frames) or is a return
	// address pointing *past* the call (ip_before_insn == 0, the common case).
	int ip_before_insn = 0;
	uintptr_t ip = _Unwind_GetIPInfo(ctx, &ip_before_insn);
	if(ip == 0)
		return _URC_END_OF_STACK;
	// For a return address, step back by one so the address falls inside the
	// call instruction and addr2line resolves the correct source line.  An
	// IP that is already "before insn" (e.g. a signal frame) must be kept
	// as-is, otherwise it would shift to the previous instruction.
	if(!ip_before_insn)
		ip -= 1u;
	state->frames[state->count++] = (void *)ip;
	return _URC_NO_REASON;
}
#endif // USE_UNWIND (unwind_callback)

#if defined(USE_UNWIND)
// A single snapshot of all process memory mappings, taken once per unwind
// attempt.  FTL's /proc/self/maps has well under 100 entries; 512 is a
// generous ceiling that keeps the snapshot a fixed, allocation-free size.
#define MAPS_MAX_ENTRIES 512
struct map_entry {
	uintptr_t start;
	uintptr_t end;
	bool readable;
	bool executable;
};
struct maps_snapshot {
	struct map_entry entries[MAPS_MAX_ENTRIES];
	int count;
};

// Parse a run of hexadecimal digits, advancing *pp past them.
// Returns false (without advancing) when no digit is present.
static bool parse_hex(const char **pp, uintptr_t *out)
{
	const char *p = *pp;
	uintptr_t val = 0;
	int digits = 0;
	for(;; p++)
	{
		const char c = *p;
		uintptr_t d;
		if(c >= '0' && c <= '9')      d = (uintptr_t)(c - '0');
		else if(c >= 'a' && c <= 'f') d = (uintptr_t)(c - 'a' + 10);
		else if(c >= 'A' && c <= 'F') d = (uintptr_t)(c - 'A' + 10);
		else break;
		val = (val << 4) | d;
		digits++;
	}
	if(digits == 0)
		return false;
	*pp = p;
	*out = val;
	return true;
}

// Parse one "/proc/self/maps" line ("start-end perms ...") into snap.
// Manual hex/character parsing keeps this free of stdio and sscanf, neither
// of which is async-signal-safe.
static void parse_maps_line(const char *line, struct maps_snapshot *snap)
{
	if(snap->count >= MAPS_MAX_ENTRIES)
		return;

	const char *p = line;
	uintptr_t start = 0, end = 0;
	if(!parse_hex(&p, &start) || *p++ != '-')
		return;
	if(!parse_hex(&p, &end) || *p++ != ' ')
		return;

	// Permission field, e.g. "r-xp"; need at least the r/w/x columns.
	if(p[0] == '\0' || p[1] == '\0' || p[2] == '\0')
		return;

	struct map_entry *e = &snap->entries[snap->count++];
	e->start = start;
	e->end = end;
	e->readable = (p[0] == 'r');
	e->executable = (p[2] == 'x');
}

// Capture all process memory mappings into snap using raw open()/read()/close()
// so this snapshot path avoids non-async-signal-safe stdio (fopen/fgets) - that
// would risk a deadlock or secondary crash if the fault happened while libc held
// an internal lock.  Taken once per unwind instead of per frame.
static void capture_maps_snapshot(struct maps_snapshot *snap)
{
	snap->count = 0;

	const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if(fd < 0)
		return;

	char buf[4096];
	char line[512];
	size_t line_len = 0;
	for(;;)
	{
		const ssize_t got = read(fd, buf, sizeof(buf));
		if(got < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		if(got == 0)
			break;

		for(ssize_t i = 0; i < got; i++)
		{
			const char c = buf[i];
			if(c == '\n')
			{
				line[line_len] = '\0';
				parse_maps_line(line, snap);
				line_len = 0;
			}
			// Drop the overflow of an over-long line but keep scanning for
			// the newline so the next line stays aligned.
			else if(line_len < sizeof(line) - 1u)
				line[line_len++] = c;
		}

		if(snap->count >= MAPS_MAX_ENTRIES)
			break;
	}

	close(fd);
}

// True when [addr, addr+bytes) is inside a readable mapping of the snapshot.
static bool is_readable_range(const struct maps_snapshot *snap, const uintptr_t addr, const size_t bytes)
{
	if(bytes == 0u)
		return false;

	for(int i = 0; i < snap->count; i++)
	{
		const struct map_entry *e = &snap->entries[i];
		if(e->readable && addr >= e->start && addr < e->end &&
		   (size_t)(e->end - addr) >= bytes)
			return true;
	}
	return false;
}

// True when addr points into an executable mapping of the snapshot.
static bool is_executable_address(const struct maps_snapshot *snap, const uintptr_t addr)
{
	for(int i = 0; i < snap->count; i++)
	{
		const struct map_entry *e = &snap->entries[i];
		if(e->executable && addr >= e->start && addr < e->end)
			return true;
	}
	return false;
}

// Try to unwind from signal context using frame pointers.
// This captures caller frames before the signal trampoline on targets where
// the frame pointer chain is available.
// *complete is set true when the walk reached the outermost frame on its own
// (the chain ended in a NULL frame pointer / return address) and false when it
// had to stop early on a corrupt or not-yet-set-up frame pointer - the latter
// is the cue for the caller to cross-check against the libgcc unwinder.
static int collect_from_signal_context(void **frames, const int max_frames, void *context,
                                       bool *complete)
{
	if(complete != NULL)
		*complete = false;
	if(context == NULL || max_frames <= 0)
		return 0;

	ucontext_t *uc = (ucontext_t *)context;
	uintptr_t ip = 0;
	uintptr_t fp = 0;

#if defined(__x86_64__)
	ip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
	fp = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
#elif defined(__aarch64__)
	ip = (uintptr_t)uc->uc_mcontext.pc;
	fp = (uintptr_t)uc->uc_mcontext.regs[29];
#else
	(void)uc;
	return 0;
#endif

	// Snapshot the mappings once up front.  The frame-pointer walk validates
	// every candidate address against this snapshot instead of re-parsing
	// /proc/self/maps per frame (previously O(frames) file opens).  Thread-local
	// static storage keeps it off the 16 KiB alternate signal stack while giving
	// each thread its own copy, so two threads taking a fatal signal at once do
	// not corrupt each other's snapshot.  TLS in the executable uses the
	// local-exec model, so it stays usable from the crash handler.
	static _Thread_local struct maps_snapshot snap;
	capture_maps_snapshot(&snap);

	int count = 0;
	// Frame 0 is the faulting instruction pointer straight from the signal
	// context, not a return address, so record it as-is.  The caller frames
	// below are return addresses and get the usual -1 adjustment to point
	// back inside the call instruction for accurate addr2line/dladdr lookup.
	if(ip != 0)
		frames[count++] = (void *)ip;

	bool walk_complete = false;
	while(count < max_frames && fp != 0)
	{
		if((fp & (sizeof(uintptr_t) - 1u)) != 0)
			break;

		if(!is_readable_range(&snap, fp, 2u*sizeof(uintptr_t)))
			break;

		const uintptr_t *frame = (const uintptr_t *)fp;
		const uintptr_t next_fp = frame[0];
		const uintptr_t ret = frame[1];

		if(ret == 0)
		{
			// Outermost frame: its saved return address is NULL, so the
			// chain ended naturally rather than being cut short.
			walk_complete = true;
			break;
		}
		if(!is_executable_address(&snap, ret - 1u))
			break;

		frames[count++] = (void *)(ret - 1u);

		if(next_fp == 0)
		{
			// Outermost frame reached: the ABI requires the topmost saved
			// frame pointer to be NULL (e.g. _start zeroes it).
			walk_complete = true;
			break;
		}
		if(next_fp <= fp || next_fp - fp > 1u*1024u*1024u)
			break;

		fp = next_fp;
	}

	if(complete != NULL)
		*complete = walk_complete;
	return count;
}

// Collect a backtrace either from an interrupted signal context (preferred)
// or from the current stack as fallback.
static int collect_backtrace_frames(void **frames, const int max_frames, void *context,
                                    enum backtrace_source *source, bool *complete)
{
	if(complete != NULL)
		*complete = false;
	if(max_frames <= 0)
		return 0;

	const int from_signal_context = collect_from_signal_context(frames, max_frames, context, complete);
	if(from_signal_context > 0)
	{
		if(source != NULL)
			*source = BT_SOURCE_SIGNAL_CONTEXT;
		return from_signal_context;
	}

	struct unwind_state state = { frames, 0, max_frames };
	_Unwind_Backtrace(unwind_callback, &state);
	if(source != NULL)
		*source = BT_SOURCE_UNWIND_FALLBACK;
	// The libgcc unwinder walks the whole stack itself, so there is nothing to
	// cross-check against - treat its result as complete.
	if(complete != NULL)
		*complete = true;
	return state.count;
}
#endif // USE_UNWIND (collect_backtrace_frames)

#if defined(USE_UNWIND)
// Extract the mapped-file basename for a single "/proc/self/maps" line if it
// contains addr.  Returns true (and fills buf) on a match with a path, false
// otherwise.  Manual parsing keeps this free of sscanf (not async-signal-safe).
static bool maps_line_name_for_addr(const char *line, const uintptr_t a,
                                    char *buf, const size_t buflen)
{
	const char *p = line;
	uintptr_t start = 0, end = 0;
	if(!parse_hex(&p, &start) || *p++ != '-')
		return false;
	if(!parse_hex(&p, &end) || *p++ != ' ')
		return false;
	if(!(a >= start && a < end))
		return false;

	// Skip the perms, offset, dev and inode columns to reach the path:
	// "perms offset dev inode <spaces> path".
	for(int field = 0; field < 4 && *p != '\0'; field++)
	{
		while(*p != '\0' && *p != ' ') p++;
		while(*p == ' ') p++;
	}
	if(*p == '\0')
		return false; // anonymous mapping, no path

	const char *base = strrchr(p, '/');
	const char *name = base ? base + 1 : p;
	strncpy(buf, name, buflen - 1u);
	buf[buflen - 1u] = '\0';
	return true;
}

// Look up which /proc/self/maps entry contains addr and copy the basename
// of the mapped file (e.g. "libc.so.6", "[vdso]") into buf.  buf is left empty
// when the address is not found or has no path.  Uses raw open()/read() and
// manual parsing to avoid the stdio (fopen/fgets/sscanf) that the rest of this
// last-resort fallback would otherwise pull into the crash handler.  It still
// calls a few plain string helpers (strrchr/strncpy/strcmp), so it is not
// fully async-signal-safe.
static void find_mapping_name(const void *addr, char *buf, const size_t buflen)
{
	if(buflen == 0u)
		return;
	// Honor the "left empty" contract for every early-return path below so
	// callers never observe stale buffer contents.
	buf[0] = '\0';

	const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if(fd < 0)
		return;

	const uintptr_t a = (uintptr_t)addr;
	char rbuf[4096];
	char line[512];
	size_t line_len = 0;
	bool done = false;
	while(!done)
	{
		const ssize_t got = read(fd, rbuf, sizeof(rbuf));
		if(got < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		if(got == 0)
			break;

		for(ssize_t i = 0; i < got; i++)
		{
			const char c = rbuf[i];
			if(c == '\n')
			{
				line[line_len] = '\0';
				if(maps_line_name_for_addr(line, a, buf, buflen))
				{
					done = true;
					break;
				}
				line_len = 0;
			}
			else if(line_len < sizeof(line) - 1u)
				line[line_len++] = c;
		}
	}

	close(fd);
}

// Per-frame resolution state.  Stored in a fixed static array (not on the
// 16 KiB alternate signal stack) so the symbolization pass cannot overflow it.
struct frame_info {
	void *addr;        // absolute return/instruction address
	const char *obj;   // object file path for "addr2line -e" ("" if unknown)
	uintptr_t rel;     // address relative to that object's load base
	Dl_info dl;        // dladdr() result (valid only when have_dl)
	bool have_dl;      // dladdr() succeeded for this frame
	bool resolved;     // addr2line produced a function name + source location
	char func[256];    // addr2line function name (when resolved)
	char loc[256];     // addr2line "file:line" (when resolved)
};

// Resolve a frame's object file and relative address with a single dladdr()
// call, reused for the reproducer command, addr2line, and the symbol fallback.
// Frames in the main executable prefer the canonical bin_path over dladdr's
// reported name.
static void resolve_frame_object(void *addr, struct frame_info *fi)
{
	fi->addr = addr;
	fi->resolved = false;
	fi->func[0] = '\0';
	fi->loc[0] = '\0';

	Dl_info dl = { 0 };
	if(dladdr(addr, &dl) != 0 && dl.dli_fname != NULL && dl.dli_fbase != NULL)
	{
		fi->dl = dl;
		fi->have_dl = true;
		if((uintptr_t)dl.dli_fbase == exe_load_addr && bin_path[0] != '\0')
		{
			fi->obj = bin_path;
			fi->rel = (uintptr_t)addr - exe_load_addr;
		}
		else
		{
			fi->obj = dl.dli_fname;
			fi->rel = (uintptr_t)addr - (uintptr_t)dl.dli_fbase;
		}
	}
	else
	{
		fi->have_dl = false;
		fi->obj = bin_path; // may be "" when the binary path is unknown
		fi->rel = (uintptr_t)addr - exe_load_addr;
	}
}

// Outcome of the batched addr2line pass, used to print a single closing hint.
enum a2l_status {
	A2L_OK,          // addr2line ran (some frames may still lack debug info)
	A2L_DISABLED,    // addr2line resolution disabled via config
	A2L_UNAVAILABLE, // addr2line could not be executed (not installed)
	A2L_TIMED_OUT,   // addr2line exceeded the watchdog deadline
};

#define ADDR2LINE_TIMEOUT_SECONDS 5
#define ADDR2LINE_MAX_BATCH 128

// Parse a chunk of addr2line's "func\nloc\n" output (one pair per requested
// address, in order) into the frames listed in `order`.  Splitting the byte
// stream into lines here keeps the reader free of stdio buffering.  Carries
// line state across chunks via *line_len/*lineno and sets *done once every
// frame in the batch has a result.
static void parse_addr2line_output(const char *chunk, const ssize_t chunklen,
                                   struct frame_info *fi, const int *order, const int ng,
                                   char *line, size_t *line_len, int *lineno, bool *done)
{
	for(ssize_t b = 0; b < chunklen && !*done; b++)
	{
		const char c = chunk[b];
		if(c != '\n')
		{
			if(*line_len < 511u)
				line[(*line_len)++] = c;
			continue;
		}
		line[*line_len] = '\0';
		*line_len = 0;

		const int frame = *lineno / 2;
		if(frame < ng)
		{
			struct frame_info *f = &fi[order[frame]];
			if(*lineno % 2 == 0)
			{
				// Function-name line; ignore addr2line's "??" placeholder.
				if(line[0] != '\0' && strcmp(line, "??") != 0)
				{
					strncpy(f->func, line, sizeof(f->func) - 1u);
					f->func[sizeof(f->func) - 1u] = '\0';
				}
			}
			else if(f->func[0] != '\0')
			{
				// "file:line" line; only a frame with a function name counts
				// as resolved.
				strncpy(f->loc, line, sizeof(f->loc) - 1u);
				f->loc[sizeof(f->loc) - 1u] = '\0';
				f->resolved = true;
			}
		}
		(*lineno)++;
		if(*lineno >= 2 * ng)
			*done = true;
	}
}

// Outcome of a single addr2line invocation.  A2L_RUN_MISSING (addr2line not
// installed) is reported to the user; A2L_RUN_SPAWN_FAIL (a transient pipe/fork
// failure) is not — it just means this batch could not be symbolized.
enum a2l_run {
	A2L_RUN_OK = 0,          // addr2line ran (frames may still lack debug info)
	A2L_RUN_TIMED_OUT = 1,   // exceeded the wall-clock deadline
	A2L_RUN_MISSING = -1,    // addr2line could not be executed (exit 127)
	A2L_RUN_SPAWN_FAIL = -2, // pipe2()/fork() failed (resource exhaustion)
};

// Spawn "addr2line -f -e <obj> <rel...>" for one object and read its output,
// bounded by a wall-clock deadline enforced with poll() + kill().  Unlike a
// SIGALRM/itimer watchdog this keeps no process-wide signal or timer state and
// performs no cross-thread siglongjmp(), so it is safe in the multi-threaded
// daemon.  Spawning directly avoids popen()'s /bin/sh and stdio buffering.
// This is not async-signal-safe (it uses snprintf(), poll() and execvp());
// symbolization is a best-effort step that runs only after the raw frame
// addresses have already been collected and can be logged.
static enum a2l_run run_addr2line_object(const char *obj, struct frame_info *fi,
                                         const int *order, const int ng)
{
	// argv and the per-address strings.  Thread-local static storage keeps the
	// 16 KiB alternate signal stack free while giving concurrent callers
	// (e.g. the lock-debug paths) independent, race-free workspaces.  TLS in
	// the executable uses the local-exec model: a direct thread-pointer offset,
	// no lazy allocation, so it stays usable from the crash handler.
	static _Thread_local char addrbuf[ADDR2LINE_MAX_BATCH][2 + 2 * sizeof(uintptr_t) + 1];
	static _Thread_local char *argv[4 + ADDR2LINE_MAX_BATCH + 1];
	int argc = 0;
	argv[argc++] = (char *)"addr2line";
	argv[argc++] = (char *)"-f";
	argv[argc++] = (char *)"-e";
	argv[argc++] = (char *)obj;
	for(int k = 0; k < ng && k < ADDR2LINE_MAX_BATCH; k++)
	{
		snprintf(addrbuf[k], sizeof(addrbuf[k]), "0x%zx", (size_t)fi[order[k]].rel);
		argv[argc++] = addrbuf[k];
	}
	argv[argc] = NULL;

	int pipefd[2];
	if(pipe2(pipefd, O_CLOEXEC) != 0)
		return A2L_RUN_SPAWN_FAIL;

	const pid_t pid = fork();
	if(pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		return A2L_RUN_SPAWN_FAIL;
	}
	if(pid == 0)
	{
		// Child: stdout -> pipe, stderr -> /dev/null, then exec.  dup2() clears
		// O_CLOEXEC on the duplicate so fds 1/2 survive exec; the originals are
		// closed here so the exec'd addr2line inherits no extra descriptors.
		dup2(pipefd[1], STDOUT_FILENO);
		const int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
		if(devnull >= 0)
		{
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		close(pipefd[0]);
		close(pipefd[1]);
		execvp("addr2line", argv);
		_exit(127); // addr2line not found / not executable
	}

	// Parent: read the response until EOF or the monotonic deadline.
	close(pipefd[1]);

	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += ADDR2LINE_TIMEOUT_SECONDS;

	char buf[4096];
	char line[512];
	size_t line_len = 0;
	int lineno = 0;
	bool done = false;
	bool timed_out = false;
	while(!done)
	{
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		const long remaining_ms = (deadline.tv_sec - now.tv_sec) * 1000L +
		                          (deadline.tv_nsec - now.tv_nsec) / 1000000L;
		if(remaining_ms <= 0)
		{
			timed_out = true;
			break;
		}

		struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
		const int pr = poll(&pfd, 1, (int)remaining_ms);
		if(pr < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		if(pr == 0)
		{
			timed_out = true;
			break;
		}

		const ssize_t got = read(pipefd[0], buf, sizeof(buf));
		if(got < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		if(got == 0)
			break; // EOF: addr2line finished

		parse_addr2line_output(buf, got, fi, order, ng, line, &line_len, &lineno, &done);
	}

	close(pipefd[0]);
	if(timed_out)
		kill(pid, SIGKILL);

	int status = 0;
	// Loop on EINTR so the child is always reaped (no zombie) and status is
	// populated before we classify the run below.
	while(waitpid(pid, &status, 0) < 0 && errno == EINTR)
		; // retry

	if(timed_out)
		return A2L_RUN_TIMED_OUT;
	if(WIFEXITED(status) && WEXITSTATUS(status) == 127)
		return A2L_RUN_MISSING;
	return A2L_RUN_OK;
}

// Resolve as many frames as possible by running addr2line once per distinct
// object (so a static-pie build resolves the whole stack in a single
// subprocess).  Returns whether addr2line ran, was disabled, missing, or
// timed out.
static enum a2l_status resolve_frames_addr2line(struct frame_info *fi, const int n)
{
	if(!config.misc.addr2line.v.b)
		return A2L_DISABLED;

	bool processed[ADDR2LINE_MAX_BATCH] = { false };
	bool any_unavailable = false;
	for(int i = 0; i < n && i < ADDR2LINE_MAX_BATCH; i++)
	{
		if(processed[i])
			continue;
		processed[i] = true;
		if(fi[i].obj == NULL || fi[i].obj[0] == '\0')
			continue;

		// Gather every remaining frame that shares this object, in order.
		int order[ADDR2LINE_MAX_BATCH];
		int ng = 0;
		order[ng++] = i;
		for(int j = i + 1; j < n && ng < ADDR2LINE_MAX_BATCH; j++)
		{
			if(processed[j] || fi[j].obj == NULL || strcmp(fi[j].obj, fi[i].obj) != 0)
				continue;
			processed[j] = true;
			order[ng++] = j;
		}

		switch(run_addr2line_object(fi[i].obj, fi, order, ng))
		{
			case A2L_RUN_TIMED_OUT:
				// Hung addr2line: stop and fall back to dladdr symbols.
				return A2L_TIMED_OUT;
			case A2L_RUN_MISSING:
				// addr2line is genuinely not installed; advise the user.
				any_unavailable = true;
				break;
			case A2L_RUN_SPAWN_FAIL:
			case A2L_RUN_OK:
				// A transient pipe/fork failure just leaves this batch
				// unresolved; do not claim addr2line is missing.
				break;
		}
	}

	return any_unavailable ? A2L_UNAVAILABLE : A2L_OK;
}

// Log one resolved/unresolved backtrace frame as a single line.  Mirrors gdb's
// coloring: function names in yellow, source locations / object names in green.
// cli_color() yields the codes only on an interactive terminal, so the daemon's
// crash log in FTL.log stays plain text.
// Resolved:   "  #N  func_name                    src/file.c:line"
// Symbol:     "  #N  0xADDR in func (+0xoff) from libc.so.6"
// Raw:        "  #N  0xADDR in ?? () from <mapping>"
static void log_frame(const int idx, const struct frame_info *fi)
{
	const char *col_func = cli_color(COL_YELLOW); // function names
	const char *col_loc = cli_color(COL_GREEN);   // source paths / objects
	const char *col_off = cli_color(COL_NC);       // reset

	if(fi->resolved)
	{
		// Strip the compile-time source root to show project-relative paths
		// (e.g. "src/signals.c:42" not "/home/user/FTL/src/signals.c:42").
		const char *display_loc = fi->loc;
#if defined(SOURCE_ROOT)
		if(strncmp(fi->loc, SOURCE_ROOT, sizeof(SOURCE_ROOT) - 1u) == 0)
			display_loc = fi->loc + sizeof(SOURCE_ROOT) - 1u;
#endif
		// %-30s pads the (uncolored) function name argument, so column
		// alignment is unaffected by the surrounding escape codes.
		log_info("  #%-2i  %s%-30s%s  %s%s%s", idx,
		         col_func, fi->func, col_off, col_loc, display_loc, col_off);
		return;
	}

	// addr2line produced nothing (disabled, missing, timed out, or no debug
	// info).  Fall back to the dladdr() symbol from .dynsym, present even in
	// stripped shared libraries.
	if(fi->have_dl && fi->dl.dli_sname != NULL)
	{
		const char *lib = fi->dl.dli_fname ? strrchr(fi->dl.dli_fname, '/') : NULL;
		const char *libname = lib ? lib + 1 : (fi->dl.dli_fname ? fi->dl.dli_fname : "?");
		const uintptr_t offset = (uintptr_t)fi->addr - (uintptr_t)fi->dl.dli_saddr;
		log_info("  #%-2d  %p in %s%s%s (+0x%zx) from %s%s%s",
		         idx, fi->addr, col_func, fi->dl.dli_sname, col_off,
		         (size_t)offset, col_loc, libname, col_off);
		return;
	}

	// No symbol at all - fall back to the mapping name ([vdso], [stack], ...).
	char mapping[128] = { 0 };
	find_mapping_name(fi->addr, mapping, sizeof(mapping));
	if(mapping[0] != '\0')
		log_info("  #%-2d  %p in ?? () from %s%s%s",
		         idx, fi->addr, col_loc, mapping, col_off);
	else
		log_info("  #%-2d  %p in ?? ()", idx, fi->addr);
}
#endif // USE_UNWIND

volatile sig_atomic_t thread_cancellable[THREADS_MAX] = { false };
const char * const thread_names[THREADS_MAX] = {
	"database",
	"housekeeper",
	"dns-client",
	"timer",
	"ntp-client",
	"ntp-server4",
	"ntp-server6",
	"webserver",
	"dotdoh",
};

// Private prototypes
static void terminate(void);

// Return the (null-terminated) name of the calling thread
// The name is stored in the buffer as well as returned for convenience
static char * __attribute__ ((nonnull (1))) getthread_name(char buffer[16])
{
	prctl(PR_GET_NAME, buffer, 0, 0, 0);
	return buffer;
}


#if defined(USE_UNWIND)
// Resolve and log one set of collected frames: one dladdr() per frame, a
// batched addr2line pass, the per-frame lines, then - only when needed - a note
// about why symbolization was incomplete plus copy-pasteable offline addr2line
// commands for any frame that stayed unresolved.
static void symbolize_and_render_frames(void **frames, const int frame_count)
{
	// Thread-local static storage keeps this off the 16 KiB alternate signal
	// stack while giving concurrent callers (e.g. the lock-debug paths)
	// independent, race-free workspaces.  TLS in the executable uses the
	// local-exec model, so it stays usable from the crash handler.
	static _Thread_local struct frame_info fi[128];
	const int n = frame_count > 128 ? 128 : frame_count;

	// Resolve each frame's object + relative address once (one dladdr() per
	// frame, reused below for addr2line, the symbol fallback, and the
	// reproducer command).
	for(int i = 0; i < n; i++)
		resolve_frame_object(frames[i], &fi[i]);

	// Symbolize via batched addr2line (one invocation per object, bounded by a
	// watchdog timer), then render every frame in order.
	const enum a2l_status st = resolve_frames_addr2line(fi, n);
	for(int i = 0; i < n; i++)
		log_frame(i, &fi[i]);

	// Explain why symbolization was incomplete, if it was.
	if(st == A2L_DISABLED)
		log_info("  (addr2line resolution disabled via config; frames shown via dladdr only)");
	else if(st == A2L_UNAVAILABLE)
		log_info("  addr2line is not installed (e.g. \"apt install binutils\" or \"apk add binutils\").");
	else if(st == A2L_TIMED_OUT)
		log_info("  addr2line exceeded its %d s watchdog.", ADDR2LINE_TIMEOUT_SECONDS);

	// For any frame addr2line could not pin to a source location, print a
	// copy-pasteable command to resolve it offline (after installing binutils,
	// or on a build that still has matching debug info).  When every frame
	// resolved, this stays silent.
	int unresolved = 0;
	for(int i = 0; i < n; i++)
		if(!fi[i].resolved)
			unresolved++;

	if(unresolved > 0)
	{
		log_info("  Resolve the %d unresolved frame%s offline by running:",
		         unresolved, unresolved == 1 ? "" : "s");
		for(int i = 0; i < n; i++)
		{
			if(fi[i].resolved)
				continue;
			if(fi[i].obj != NULL && fi[i].obj[0] != '\0')
				log_info("    addr2line -f -e \"%s\" %p", fi[i].obj, (void *)fi[i].rel);
			else
				log_info("    #%-2i  %p  (object unknown)", i, fi[i].addr);
		}
	}
}
#endif // USE_UNWIND

// Log backtrace to the FTL log.
// Prefers walking the interrupted signal context (frame pointers) and falls
// back to _Unwind_Backtrace (GCC libgcc) when no context is available or the
// walk yields nothing.  Both paths work on all targets - glibc AND musl,
// static-pie AND dynamic, all architectures.
static void generate_backtrace_internal(void *context)
{
#if defined(USE_UNWIND)
	void *frames[128];
	enum backtrace_source source = BT_SOURCE_NONE;
	bool complete = false;
	const int frame_count = collect_backtrace_frames(frames, 128, context, &source, &complete);
	const char *source_str = source == BT_SOURCE_SIGNAL_CONTEXT ?
	                         " from signal context" : "";

	log_info("Backtrace (%d frames%s):", frame_count, source_str);
	symbolize_and_render_frames(frames, frame_count);

	// When the signal-context frame-pointer walk stopped early (a corrupt or
	// not-yet-set-up frame pointer - exactly the kind of damaged stack that
	// tends to cause the crash), cross-check it against libgcc's DWARF-CFI
	// unwinder, which can cross frame-pointer-less boundaries the walk cannot.
	// Only shown when it actually recovers more frames than the truncated walk.
	if(source == BT_SOURCE_SIGNAL_CONTEXT && !complete && frame_count > 0)
	{
		void *cross[128];
		struct unwind_state state = { cross, 0, 128 };
		_Unwind_Backtrace(unwind_callback, &state);

		// frames[0] is the exact faulting PC; the libgcc unwinder records the
		// same value for the interrupted frame (kept as-is by _Unwind_GetIPInfo
		// because it is a signal frame), so it marks where the real stack
		// begins - everything above it is our own handler + the signal
		// trampoline and is skipped.  If the value is not found, libgcc could
		// not unwind past the signal frame, so there is nothing trustworthy to
		// add and the cross-check is omitted.
		int start = -1;
		for(int i = 0; i < state.count; i++)
			if(cross[i] == frames[0])
			{
				start = i;
				break;
			}

		const int cross_count = (start >= 0) ? state.count - start : 0;
		if(cross_count > frame_count)
		{
			log_info("Cross-check backtrace (libgcc/_Unwind, %d frames):", cross_count);
			symbolize_and_render_frames(cross + start, cross_count);
		}
	}

	log_info("  --- end of backtrace ---");
#else
	log_info("!!! INFO: pihole-FTL has not been compiled with unwinding support, cannot generate backtrace !!!");
#endif
}

void generate_backtrace(void)
{
	generate_backtrace_internal(NULL);
}

/**
 * @brief Terminates the program due to an error.
 *
 * This function sets the exit code to indicate failure and raises a SIGTERM
 * signal to terminate the main process. It is intended to be called when a
 * critical error occurs that requires the program to exit.
 */
static void terminate_error(void)
{
	exit_code = EXIT_FAILURE;
	raise(SIGTERM);
}

static void __attribute__((noreturn)) signal_handler(int sig, siginfo_t *si, void *context)
{
	log_info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	log_info("---------------------------->  FTL crashed!  <----------------------------");
	log_info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	log_info("Please report a bug at https://github.com/pi-hole/FTL/issues");
	log_info("and include in your report already the following details:");

	if(FTLstarttime != 0)
	{
		log_info("FTL has been running for %lli seconds", (long long)time(NULL) - FTLstarttime);
	}
	log_FTL_version(true);
	char namebuf[16];
	log_info("Process details: MID: %i", mpid);
	log_info("                 PID: %i", getpid());
	log_info("                 TID: %i", gettid());
	log_info("                 Name: %s", getthread_name(namebuf));

	log_info("Received signal: %s", strsignal(sig));
	log_info("     at address: %p", si->si_addr);

	// Segmentation fault - program crashed
	if(sig == SIGSEGV)
	{
		switch (si->si_code)
		{
			case SEGV_MAPERR:  log_info("     with code:  SEGV_MAPERR (Address not mapped to object)"); break;
			case SEGV_ACCERR:  log_info("     with code:  SEGV_ACCERR (Invalid permissions for mapped object)"); break;
#ifdef SEGV_BNDERR
			case SEGV_BNDERR:  log_info("     with code:  SEGV_BNDERR (Failed address bound checks)"); break;
#endif
#ifdef SEGV_PKUERR
			case SEGV_PKUERR:  log_info("     with code:  SEGV_PKUERR (Protection key checking failure)"); break;
#endif
#ifdef SEGV_ACCADI
			case SEGV_ACCADI:  log_info("     with code:  SEGV_ACCADI (ADI not enabled for mapped object)"); break;
#endif
#ifdef SEGV_ADIDERR
			case SEGV_ADIDERR: log_info("     with code:  SEGV_ADIDERR (Disrupting MCD error)"); break;
#endif
#ifdef SEGV_ADIPERR
			case SEGV_ADIPERR: log_info("     with code:  SEGV_ADIPERR (Precise MCD exception)"); break;
#endif
			default:           log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	// Bus error - memory manager problem
	else if(sig == SIGBUS)
	{
		switch (si->si_code)
		{
			case BUS_ADRALN:    log_info("     with code:  BUS_ADRALN (Invalid address alignment)"); break;
			case BUS_ADRERR:    log_info("     with code:  BUS_ADRERR (Non-existent physical address)"); break;
			case BUS_OBJERR:    log_info("     with code:  BUS_OBJERR (Object specific hardware error)"); break;
#if defined (BUS_MCEERR_AR)
			// 2025-May: not defined by uClibc
			case BUS_MCEERR_AR: log_info("     with code:  BUS_MCEERR_AR (Hardware memory error: action required)"); break;
#endif
#if defined (BUS_MCEERR_AO)
			// 2025-May: not defined by uClibc
			case BUS_MCEERR_AO: log_info("     with code:  BUS_MCEERR_AO (Hardware memory error: action optional)"); break;
#endif
			default:            log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	// Illegal error - Illegal instruction detected
	else if(sig == SIGILL)
	{
		switch (si->si_code)
		{
			case ILL_ILLOPC:   log_info("     with code:  ILL_ILLOPC (Illegal opcode)"); break;
			case ILL_ILLOPN:   log_info("     with code:  ILL_ILLOPN (Illegal operand)"); break;
			case ILL_ILLADR:   log_info("     with code:  ILL_ILLADR (Illegal addressing mode)"); break;
			case ILL_ILLTRP:   log_info("     with code:  ILL_ILLTRP (Illegal trap)"); break;
			case ILL_PRVOPC:   log_info("     with code:  ILL_PRVOPC (Privileged opcode)"); break;
			case ILL_PRVREG:   log_info("     with code:  ILL_PRVREG (Privileged register)"); break;
			case ILL_COPROC:   log_info("     with code:  ILL_COPROC (Coprocessor error)"); break;
			case ILL_BADSTK:   log_info("     with code:  ILL_BADSTK (Internal stack error)"); break;
#ifdef ILL_BADIADDR
			case ILL_BADIADDR: log_info("     with code:  ILL_BADIADDR (Unimplemented instruction address)"); break;
#endif
			default:           log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	// Floating point exception error
	else if(sig == SIGFPE)
	{
		switch (si->si_code)
		{
			case FPE_INTDIV:   log_info("     with code:  FPE_INTDIV (Integer divide by zero)"); break;
			case FPE_INTOVF:   log_info("     with code:  FPE_INTOVF (Integer overflow)"); break;
			case FPE_FLTDIV:   log_info("     with code:  FPE_FLTDIV (Floating point divide by zero)"); break;
			case FPE_FLTOVF:   log_info("     with code:  FPE_FLTOVF (Floating point overflow)"); break;
			case FPE_FLTUND:   log_info("     with code:  FPE_FLTUND (Floating point underflow)"); break;
			case FPE_FLTRES:   log_info("     with code:  FPE_FLTRES (Floating point inexact result)"); break;
			case FPE_FLTINV:   log_info("     with code:  FPE_FLTINV (Floating point invalid operation)"); break;
			case FPE_FLTSUB:   log_info("     with code:  FPE_FLTSUB (Subscript out of range)"); break;
#ifdef FPE_FLTUNK
			case FPE_FLTUNK:   log_info("     with code:  FPE_FLTUNK (Undiagnosed floating-point exception)"); break;
#endif
#ifdef FPE_CONDTRAP
			case FPE_CONDTRAP: log_info("     with code:  FPE_CONDTRAP (Trap on condition)"); break;
#endif
			default:           log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	generate_backtrace_internal(context);

	// Flush stdout immediately so the backtrace is visible even if a
	// subsequent fault in cleanup() kills the process before exit() runs.
	fflush(stdout);

	// Print content of /dev/shm
	ls_dir("/dev/shm");

	log_info("Please also include some lines from above the !!!!!!!!! header.");
	log_info("Thank you for helping us to improve our FTL engine!");

	// Terminate main process if crash happened in a TCP worker
	if(main_pid() != getpid())
	{
		// This is a forked process
		log_info("Asking parent pihole-FTL (PID %i) to shut down", (int)mpid);
		kill(mpid, SIGRTMIN+2);
		log_info("FTL fork terminated!");

		// Terminate fork indicating failure
		exit(EXIT_FAILURE);
	}
	else if(gettid() != getpid())
	{
		// This is a thread, signal to the main process to shut down
		log_info("Shutting down thread...");
		terminate_error();

		// Exit the thread here, it failed anyway
		pthread_exit(NULL);
	}
	else
	{
		// This is the main process
		cleanup(EXIT_FAILURE);

		// Terminate process indicating failure
		exit(EXIT_FAILURE);
	}
}

static void SIGRT_handler(int signum, siginfo_t *si, void *context)
{
	(void)context;
	(void)si;
	// Backup errno
	const int _errno = errno;

	// Ignore real-time signals outside of the main process (TCP forks)
	if(mpid != getpid())
	{
		// Restore errno before returning
		errno = _errno;
		return;
	}

	// Do NOT call log_info() or strsignal() here - they are not
	// async-signal-safe and can deadlock if the signal arrives while
	// malloc's internal lock is held. The events set below are logged
	// when processed in the main loop / database thread.
	const int rtsig = signum - SIGRTMIN;

	if(rtsig == 0)
	{
		// Reload
		// - gravity
		// - allowed domains and regex
		// - denied domains and regex
		// WITHOUT wiping the DNS cache itself
		set_event(RELOAD_GRAVITY);
	}
	else if(rtsig == 2)
	{
		// Terminate FTL indicating failure
		terminate_error();
	}
	else if(rtsig == 3)
	{
		// Reimport alias-clients from database
		set_event(REIMPORT_ALIASCLIENTS);
	}
	else if(rtsig == 4)
	{
		// Re-resolve all clients and forward destinations
		// Force refreshing hostnames according to
		// REFRESH_HOSTNAMES config option
		set_event(RERESOLVE_HOSTNAMES_FORCE);
	}
	else if(rtsig == 5)
	{
		// Parse neighbor cache
		set_event(PARSE_NEIGHBOR_CACHE);
	}
	// else if(rtsig == 6)
	// {
	// 	// Signal internally used to signal dnsmasq it has to stop
	// }
	else if(rtsig == 7)
	{
		// Search for hash collisions in the lookup tables
		set_event(SEARCH_LOOKUP_HASH_COLLISIONS);
	}

	// SIGRT32: Used internally by valgrind, do not use

	// Restore errno before returning back to previous context
	errno = _errno;
}

static void SIGTERM_handler(int signum, siginfo_t *si, void *context)
{
	(void)context;
	(void)signum;
	// Ignore SIGTERM outside of the main process (TCP forks)
	if(mpid != getpid())
		return;

	// Save sender info for deferred logging (async-signal-safe: just
	// writing volatile integer types). The expensive lookup of the
	// sender's process name and username is done in log_sigterm_info()
	// called from the main loop after the signal handler returns.
	term_sender_pid = si->si_pid;
	term_sender_uid = si->si_uid;

	// Request deferred termination. The actual raise(SIGUSR6)/killed
	// assignment happens in terminate(), called from check_if_want_terminate()
	// which is invoked periodically from the main loop (gc.c) - keeping
	// the signal handler free of non-async-signal-safe calls like
	// log_info(), time(), and gravity_running checks.
	want_terminate = true;
}

// Log details about who sent the SIGTERM. Called from the main shutdown
// path (outside signal context) so it is safe to use stdio, getpwuid,
// and logging functions.
void log_sigterm_info(void)
{
	const pid_t kill_pid = term_sender_pid;
	const uid_t kill_uid = term_sender_uid;

	if(kill_pid == 0)
		return; // SIGTERM handler never ran

	// Get name of the process that sent the terminating signal
	char kill_name[256] = { 0 };
	char kill_exe [256] = { 0 };
	snprintf(kill_exe, sizeof(kill_exe), "/proc/%ld/cmdline", (long int)kill_pid);
	FILE *fp = fopen(kill_exe, "r");
	if(fp != NULL)
	{
		size_t read = 0;
		if((read = fread(kill_name, sizeof(char), sizeof(kill_name), fp)) > 0)
		{
			// cmdline contains null-separated arguments - replace
			// null bytes with spaces for display
			for(unsigned int i = 0; i < min((size_t)read, sizeof(kill_name)); i++)
			{
				if(kill_name[i] == '\0')
					kill_name[i] = ' ';
			}

			// Remove any trailing spaces
			for(unsigned int i = read - 1; i > 0; i--)
			{
				if(kill_name[i] == ' ')
					kill_name[i] = '\0';
				else
					break;
			}
		}
		else
			strcpy(kill_name, "N/A");
		fclose(fp);
	}
	else
		strcpy(kill_name, "N/A");

	// Get username of the process that sent the terminating signal
	char kill_user[256] = { 0 };
	struct passwd *pwd = getpwuid(kill_uid);
	if(pwd != NULL)
		strncpy(kill_user, pwd->pw_name, sizeof(kill_user));
	else
		strcpy(kill_user, "N/A");

	// Log who sent the signal and store for re-logging during cleanup (#2818)
	log_info("Asked to terminate by \"%s\" (PID %ld, user %s UID %ld)",
	         kill_name, (long int)kill_pid, kill_user, (long int)kill_uid);
	snprintf(term_source, sizeof(term_source),
	         "\"%s\" (PID %ld, user %s UID %ld)",
	         kill_name, (long int)kill_pid, kill_user, (long int)kill_uid);
}

// Checks if the program should terminate or not. Called periodically from
// the main loop (gc.c) and API action handlers - never from signal context.
static time_t last_term_warning = 0;
void check_if_want_terminate(void)
{
	if(!want_terminate)
		// We are not asked to terminate
		return;

	// Return early if we are not allowed to terminate
	if(gravity_running)
	{
		// Only log once every 30 seconds or if any debugging is enabled
		if(time(NULL) - last_term_warning > 30 || debug_flags[DEBUG_ANY])
		{
			log_info("Not terminating as gravity is still running...");
			last_term_warning = time(NULL);
		}
		return;
	}

	// Terminate if gravity is not running
	terminate();
}

// Terminates the DNS service by signaling or marking it as failed
static void terminate(void)
{
	// Terminate dnsmasq to stop DNS service
	if(!dnsmasq_failed)
	{
		log_debug(DEBUG_ANY, "Sending SIGUSR6 to dnsmasq to stop DNS service");
		raise(SIGUSR6);
	}
	else
	{
		log_debug(DEBUG_ANY, "Embedded dnsmasq failed, exiting on request");
		killed = true;
	}
}

// Register ordinary signals handler
// Alternate signal stack so the crash handler can run even when the
// regular stack has overflowed. SIGSTKSZ is not a compile-time constant
// on glibc >= 2.34, so use a fixed 16 KiB buffer (the minimum required
// by POSIX is MINSIGSTKSZ which is typically 2-8 KiB; 16 KiB gives
// ample room for the backtrace/logging calls in our crash handler).
#define FTL_ALT_STACK_SIZE 16384
static uint8_t alt_stack_mem[FTL_ALT_STACK_SIZE];

void handle_signals(void)
{
	// Install an alternate signal stack for crash handlers. Without
	// this, a stack overflow fault cannot be diagnosed because the
	// handler itself would overflow the same stack.
	stack_t ss = {
		.ss_sp = alt_stack_mem,
		.ss_size = FTL_ALT_STACK_SIZE,
		.ss_flags = 0
	};
	sigaltstack(&ss, NULL);

	struct sigaction old_action;

	const int crash_signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE };
	for(unsigned int i = 0; i < ArraySize(crash_signals); i++)
	{
		sigaction(crash_signals[i], NULL, &old_action);
		if(old_action.sa_handler != SIG_IGN)
		{
			struct sigaction SIGaction = { 0 };
			// SA_SIGINFO:   deliver siginfo_t with fault details
			// SA_ONSTACK:   run on the alternate signal stack
			// SA_RESETHAND: reset to SIG_DFL after first invocation,
			//               preventing infinite re-entry if the
			//               handler itself faults (e.g. heap corruption
			//               causes log_info to SIGSEGV again)
			SIGaction.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
			sigemptyset(&SIGaction.sa_mask);
			SIGaction.sa_sigaction = &signal_handler;
			sigaction(crash_signals[i], &SIGaction, NULL);
		}
	}

	// SIGTERM: graceful shutdown - no SA_ONSTACK or SA_RESETHAND needed
	sigaction(SIGTERM, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN)
	{
		struct sigaction SIGaction = { 0 };
		SIGaction.sa_flags = SA_SIGINFO;
		sigemptyset(&SIGaction.sa_mask);
		SIGaction.sa_sigaction = &SIGTERM_handler;
		sigaction(SIGTERM, &SIGaction, NULL);
	}

	// Log start time of FTL
	FTLstarttime = time(NULL);
}

// Register real-time signal handler
void handle_realtime_signals(void)
{
	// This function is only called once (after forking), store the PID of
	// the main process
	mpid = getpid();

	// Catch all real-time signals
	for(int signum = SIGRTMIN; signum <= SIGRTMAX; signum++)
	{
		if(signum == SIGUSR6)
			// Skip SIGUSR6 as it is used internally to signify
			// dnsmasq to stop
			continue;
		if(signum == SIGUSR32)
			// Skip SIGUSR32 as it is used internally by valgrind
			// and should not be used
			continue;

		struct sigaction SIGACTION = { 0 };
		SIGACTION.sa_flags = SA_SIGINFO;
		sigemptyset(&SIGACTION.sa_mask);
		SIGACTION.sa_sigaction = &SIGRT_handler;
		sigaction(signum, &SIGACTION, NULL);
	}
}

// Return PID of the main FTL process
pid_t main_pid(void)
{
	if(mpid > 0)
		// Has already been set
		return mpid;
	else
		// Has not been set so far
		return getpid();
}

// Deliberately NOT marked __attribute__((pure)): the buffer this reads is
// written from SIGTERM_handler, which GCC's pure analysis cannot see, so a
// pure annotation would let the compiler cache/hoist the result across an
// asynchronous signal-handler update. Suppress the corresponding warning
// for just this function (see #2839).
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
#endif
const char *get_term_source(void)
{
	return term_source[0] != '\0' ? term_source : NULL;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

void thread_sleepms(const enum thread_types thread, const int milliseconds)
{
	if(killed)
		return;

	thread_cancellable[thread] = true;
	sleepms(milliseconds);
	thread_cancellable[thread] = false;
}

static void print_signal(int signum, siginfo_t *si, void *context)
{
	printf("Received signal %d: \"%s\"\n", signum, strsignal(signum));
	fflush(stdin);
	if(signum == SIGTERM)
		exit(EXIT_SUCCESS);
}

// Register handler that catches *all* signals and displays them
int sigtest(void)
{
	printf("PID: %d\n", getpid());
	// Catch all real-time signals
	for(int signum = 0; signum <= SIGRTMAX; signum++)
	{
		struct sigaction SIGACTION = { 0 };
		SIGACTION.sa_flags = SA_SIGINFO;
		sigemptyset(&SIGACTION.sa_mask);
		SIGACTION.sa_sigaction = &print_signal;
		sigaction(signum, &SIGACTION, NULL);
	}

	printf("Waiting (30sec)...\n");
	fflush(stdin);

	// Sleep here for 30 seconds
	sleepms(30000);

	// Exit successfully
	return EXIT_SUCCESS;
}

int sigrtmin(void)
{
	printf("%d\n", SIGRTMIN);
	return EXIT_SUCCESS;
}

void restart_ftl(const char *reason)
{
	log_info("Restarting FTL: %s", reason);
	exit_code = RESTART_FTL_CODE;
	// Send SIGTERM to FTL
	kill(main_pid(), SIGTERM);
}

/**
 * @brief Checks if the current process is being debugged.
 *
 * This function reads the /proc/self/status file to determine if the current
 * process is being debugged by looking for the TracerPid field. If the field
 * is found and has a non-zero value, it indicates that the process is being
 * debugged.
 *
 * @return The PID of the debugger if the process is being debugged, otherwise 0.
 */
pid_t debugger(void)
{
	FILE *status = fopen("/proc/self/status", "r");
	if(status == NULL)
	{
		// Failed to open status file, assume not being debugged
		log_debug(DEBUG_ANY, "Failed to open /proc/self/status: %s", strerror(errno));
		return 0;
	}

	char line[256] = { 0 };
	while(fgets(line, sizeof(line), status) != NULL)
	{
		if(strncmp(line, "TracerPid:", 10) == 0)
		{
			// TracerPid field found
			fclose(status);
			return atoi(line + 10);
		}
	}
	fclose(status);
	return 0;
}
