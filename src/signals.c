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
#include "signals.h"
// logging routines
#include "log.h"
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

// For backtrace
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <dlfcn.h>
#include <link.h>

#define BINARY_NAME "pihole-FTL"

volatile sig_atomic_t killed = 0;
static volatile pid_t mpid = -1;
static time_t FTLstarttime = 0;
static char bin_name[256] = { 0 };
volatile int exit_code = EXIT_SUCCESS;

volatile sig_atomic_t thread_cancellable[THREADS_MAX] = { false };
volatile sig_atomic_t thread_running[THREADS_MAX] = { false };
const char *thread_names[THREADS_MAX] = { "" };

void set_bin_name(const char *name)
{
	strncpy(bin_name, name, sizeof(bin_name)-1);
	bin_name[sizeof(bin_name)-1] = '\0';
}

// Return the (null-terminated) name of the calling thread
// The name is stored in the buffer as well as returned for convenience
static char * __attribute__ ((nonnull (1))) getthread_name(char buffer[16])
{
	prctl(PR_GET_NAME, buffer, 0, 0, 0);
	return buffer;
}

static void print_addr2line(const char *symbol, const void *addr)
{
	// Only do this analysis for our own binary (skip trying to analyse libc.so, etc.)
	if(strstr(symbol, BINARY_NAME) == NULL)
		return;

	// Find first occurrence of '(' or ' ' in the obtaned symbol string and
	// assume everything before that is the file name. (Don't go beyond the
	// string terminator \0)
	int p = 0;
	while(symbol[p] != '(' && symbol[p] != ' ' && symbol[p] != '\0')
		p++;

	// Invoke addr2line command and get result through pipe
	char addr2line_cmd[256];
	snprintf(addr2line_cmd, sizeof(addr2line_cmd), "addr2line %p -e %.*s", addr, p, symbol);
	FILE *addr2line = NULL;
	char linebuffer[512];
	if((addr2line = popen(addr2line_cmd, "r")) != NULL &&
	   fgets(linebuffer, sizeof(linebuffer), addr2line) != NULL)
	{
		char *pos;
		// Strip possible newline at the end of the addr2line output
		if ((pos=strchr(linebuffer, '\n')) != NULL)
			*pos = '\0';
	}
	else
	{
		snprintf(linebuffer, sizeof(linebuffer), "N/A (%p -> %s)", addr, addr2line_cmd);
	}
	// Log result
	log_info("      %s", linebuffer);

	// Close pipe
	if(addr2line != NULL)
		pclose(addr2line);
}

// Inspired by https://stackoverflow.com/a/8876887
void *base_addr = NULL;
static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	static int once = 0;

	if (once) return 0;
	once = 1;

	for (int j = 0; j < info->dlpi_phnum; j++)
	{
		if (info->dlpi_phdr[j].p_type == PT_LOAD)
		{
			base_addr = (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
			break;
		}
	}
	return 0;
}

void generate_backtrace(void) {
	unw_cursor_t cursor; unw_context_t uc;
	unw_word_t ip, sp;

	log_info(" ");

	// Get the base address of the main executable
	dl_iterate_phdr(phdr_callback, NULL);
	log_info("Generating backtrace (base address: %p)...", base_addr);

	// Get unwind context
	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);

	// Skip the first frame (this function)
	unw_step(&cursor);

	// Iterate over the stack frames
	unsigned int i = 1;
	do
	{
		// Get the program counter
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		// Get the stack pointer
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		// Get the name of the shared object
		char sname[256];
		unw_word_t offset;
		int ret = unw_get_proc_name(&cursor, sname, sizeof(sname), &offset);
		if (ret && ret != -UNW_ENOMEM)
		{
			if (ret != -UNW_EUNSPEC)
				log_err("unw_get_proc_name: %s [%d]", unw_strerror(ret), ret);
			strcpy(sname, "?");
		}

		// Get the procedure information
		unw_proc_info_t pip;
		ret = unw_get_proc_info(&cursor, &pip);
		if (ret)
		{
			log_err("unw_get_proc_info: %s [%d]", unw_strerror(ret), ret);
			continue;
		}

		// Get the file name of defining object (binary/library name,
		// fname_dl) and the name of the nearest symbol (sname_dl)
		void *ptr = (void *)(pip.start_ip + offset);
		Dl_info dlinfo;
		const char *fname_dl = bin_name, *sname_dl = sname;
		if (dladdr(ptr, &dlinfo))
		{
			if(dlinfo.dli_fname && *dlinfo.dli_fname)
				fname_dl = dlinfo.dli_fname;
			if(dlinfo.dli_sname && *dlinfo.dli_sname)
				sname_dl = dlinfo.dli_sname;
		}

		// Compute the offset of the address from the base address to get
		// the offset within the PIE binary/library (needed for addr2line)
		// Note: We only do this for the main binary, not for libraries
		void *ptr_off = strstr(fname_dl, BINARY_NAME) != NULL ? (void*)(ptr-base_addr) : ptr;

		// Print this stack frame's details
		log_info("  %02u: %s(%s+0x%p) [%p -> %p]", i++, fname_dl, sname_dl, (void*)offset, ptr, ptr_off);
		print_addr2line(fname_dl, ptr_off);
		print_addr2line(fname_dl, (void*)ip);
		log_info(" ");
	} while(unw_step(&cursor) > 0);
}

static void __attribute__((noreturn)) signal_handler(int sig, siginfo_t *si, void *unused)
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
			case BUS_MCEERR_AR: log_info("     with code:  BUS_MCEERR_AR (Hardware memory error: action required)"); break;
			case BUS_MCEERR_AO: log_info("     with code:  BUS_MCEERR_AO (Hardware memory error: action optional)"); break;
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

	generate_backtrace();

	// Print content of /dev/shm
	ls_dir("/dev/shm");

	log_info("Please also include some lines from above the !!!!!!!!! header.");
	log_info("Thank you for helping us to improve our FTL engine!");

	// Terminate main process if crash happened in a TCP worker
	if(mpid != getpid() && mpid != -1)
	{
		// This is a forked process
		log_info("Asking parent pihole-FTL (PID %i) to shut down", (int)mpid);
		kill(mpid, SIGRTMIN+2);
		log_info("FTL fork terminated!");
	}
	else
	{
		// This is the main process
		cleanup(EXIT_FAILURE);
	}

	// Terminate process indicating failure
	exit(EXIT_FAILURE);
}

static void SIGRT_handler(int signum, siginfo_t *si, void *unused)
{
	// Backup errno
	const int _errno = errno;

	// Ignore real-time signals outside of the main process (TCP forks)
	if(mpid != getpid())
	{
		// Restore errno before returning
		errno = _errno;
		return;
	}

	int rtsig = signum - SIGRTMIN;
	log_info("Received: %s (%d -> %d)", strsignal(signum), signum, rtsig);

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
		exit_code = EXIT_FAILURE;
		kill(0, SIGTERM);
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

	// Restore errno before returning back to previous context
	errno = _errno;
}

// Register ordinary signals handler
void handle_signals(void)
{
	struct sigaction old_action;

	const int signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE };
	for(unsigned int i = 0; i < ArraySize(signals); i++)
	{
		// Catch this signal
		sigaction (signals[i], NULL, &old_action);
		if(old_action.sa_handler != SIG_IGN)
		{
			struct sigaction SIGaction;
			memset(&SIGaction, 0, sizeof(struct sigaction));
			SIGaction.sa_flags = SA_SIGINFO;
			sigemptyset(&SIGaction.sa_mask);
			SIGaction.sa_sigaction = &signal_handler;
			sigaction(signals[i], &SIGaction, NULL);
		}
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
		struct sigaction SIGACTION;
		memset(&SIGACTION, 0, sizeof(struct sigaction));
		SIGACTION.sa_flags = SA_SIGINFO;
		sigemptyset(&SIGACTION.sa_mask);
		SIGACTION.sa_sigaction = &SIGRT_handler;
		sigaction(signum, &SIGACTION, NULL);
	}
}

// Return PID of the main FTL process
pid_t main_pid(void)
{
	if(mpid > -1)
		// Has already been set
		return mpid;
	else
		// Has not been set so far
		return getpid();
}

void thread_sleepms(const enum thread_types thread, const int milliseconds)
{
	if(killed)
		return;

	thread_cancellable[thread] = true;
	sleepms(milliseconds);
	thread_cancellable[thread] = false;
}
