# Pi-hole: A black hole for Internet advertisements
# (c) 2018 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL-Engine
# Makefile
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

DNSMASQVERSION = "pi-hole-2.80"
DNSMASQOPTS = -DHAVE_DNSSEC -DHAVE_DNSSEC_STATIC
# Flags for compiling with libidn : -DHAVE_IDN
# Flags for compiling with libidn2: -DHAVE_LIBIDN2 -DIDN2_VERSION_NUMBER=0x02000003

FTLDEPS = FTL.h routines.h version.h api.h dnsmasq_interface.h shmem.h
FTLOBJ = main.o memory.o log.o daemon.o datastructure.o signals.o socket.o request.o grep.o setupVars.o args.o gc.o config.o database.o msgpack.o api.o dnsmasq_interface.o resolve.o regex.o shmem.o capabilities.o networktable.o overTime.o

DNSMASQDEPS = config.h dhcp-protocol.h dns-protocol.h radv-protocol.h dhcp6-protocol.h dnsmasq.h ip6addr.h metrics.h ../dnsmasq_interface.h
DNSMASQOBJ = arp.o dbus.o domain.o lease.o outpacket.o rrfilter.o auth.o dhcp6.o edns0.o log.o poll.o slaac.o blockdata.o dhcp.o forward.o loop.o radv.o tables.o bpf.o dhcp-common.o helper.o netlink.o rfc1035.o tftp.o cache.o dnsmasq.o inotify.o network.o rfc2131.o util.o conntrack.o dnssec.o ipset.o option.o rfc3315.o crypto.o dump.o ubus.o metrics.o

# Get git commit version and date
GIT_BRANCH := $(shell git branch | sed -n 's/^\* //p')
GIT_HASH := $(shell git --no-pager describe --always --dirty)
GIT_VERSION := $(shell git --no-pager describe --tags --always --dirty)
GIT_DATE := $(shell git --no-pager show --date=short --format="%ai" --name-only | head -n 1)
GIT_TAG := $(shell git describe --tags --abbrev=0)

# Is compiler at least gcc version 8? We cannot do ifgt in Makefile, so we use the shell expr command
GCCVERSION8 := $(shell expr `$(CC) -dumpversion | cut -f1 -d.` \>= 8)

# Code hardening and debugging improvements
# -fstack-protector-strong: The program will be resistant to having its stack overflowed
# -Wp,-D_FORTIFY_SOURCE=2 and -O1 or higher: This causes certain unsafe glibc functions to be replaced with their safer counterparts
# -Wl,-z,relro: reduces the possible areas of memory in a program that can be used by an attacker that performs a successful memory corruption exploit
# -Wl,-z,now: When combined with RELRO above, this further reduces the regions of memory available to memory corruption attacks
# -pie -fPIE: For ASLR (address space layout randomization)
# -g3: More debugging information
# -fno-omit-frame-pointer: get nicer stacktraces
# -fasynchronous-unwind-tables: Increased reliability of backtraces
# -fexceptions: Enable table-based thread cancellation
# -Wl,-z,defs: Detect and reject underlinking (phenomenon caused by missing shared library arguments when invoking the linked editor to produce another shared library)
# -Wl,-z,now: Disable lazy binding
# -Wl,-z,relro: Read-only segments after relocation
HARDENING_FLAGS=-fstack-protector-strong -Wp,-D_FORTIFY_SOURCE=2 -O3 -Wl,-z,relro,-z,now -pie -fPIE -fexceptions -fasynchronous-unwind-tables -Wl,-z,defs -Wl,-z,now -Wl,-z,relro
DEBUG_FLAGS=-rdynamic -fno-omit-frame-pointer

# -DSQLITE_OMIT_LOAD_EXTENSION: This option omits the entire extension loading mechanism from SQLite, including sqlite3_enable_load_extension() and sqlite3_load_extension() interfaces. (needs -ldl linking option, otherwise)
# -DSQLITE_DEFAULT_MEMSTATUS=0: This setting causes the sqlite3_status() interfaces that track memory usage to be disabled. This helps the sqlite3_malloc() routines run much faster, and since SQLite uses sqlite3_malloc() internally, this helps to make the entire library faster.
# -DSQLITE_OMIT_DEPRECATED: Omitting deprecated interfaces and features will not help SQLite to run any faster. It will reduce the library footprint, however. And it is the right thing to do.
# -DSQLITE_OMIT_PROGRESS_CALLBACK: The progress handler callback counter must be checked in the inner loop of the bytecode engine. By omitting this interface, a single conditional is removed from the inner loop of the bytecode engine, helping SQL statements to run slightly faster.
SQLITEFLAGS=-DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_MEMORYDB

# -Wall: This enables all the warnings about constructions that some users consider questionable, and that are easy to avoid (or modify to prevent the warning), even in conjunction with macros. This also enables some language-specific warnings described in C++ Dialect Options and Objective-C and Objective-C++ Dialect Options.
# -Wextra: This enables some extra warning flags that are not enabled by -Wall.
# -Wno-unused-parameter: Disable warning for unused parameters. For threads that don't need arguments, we still have to provide a void* args which is then unused.
WARNFLAGS=-Wall -Wextra -Wno-unused-parameter

# Extra warning flags we apply only to the FTL part of the code (used not for foreign code such as dnsmasq and SQLite3)
# -Werror: Halt on any warnings, useful for enforcing clean code without any warnings (we use it only for our code part)
# -Waddress: Warn about suspicious uses of memory addresses
# -Wlogical-op: Warn about suspicious uses of logical operators in expressions
# -Wmissing-field-initializers: Warn if a structure's initializer has some fields missing
# -Woverlength-strings: Warn about string constants that are longer than the "minimum maximum length specified in the C standard
# -Wformat: Check calls to printf and scanf, etc., to make sure that the arguments supplied have types appropriate to the format string specified, and that the conversions specified in the format string make sense.
# -Wformat-nonliteral: If -Wformat is specified, also warn if the format string is not a string literal and so cannot be checked, unless the format function takes its format arguments as a va_list.
# -Wuninitialized: Warn if an automatic variable is used without first being initialized
# -Wswitch-enum: Warn whenever a switch statement has an index of enumerated type and lacks a case for one or more of the named codes of that enumeration.
# -Wshadow: Warn whenever a local variable or type declaration shadows another variable, parameter, type, class member, or whenever a built-in function is shadowed.
# -Wfloat-equal: Warn if floating-point values are used in equality comparisons
# -Wunsafe-loop-optimizations -funsafe-loop-optimizations: Warn if the loop cannot be optimized because the compiler cannot assume anything on the bounds of the loop indices
# -Wpointer-arith: Warn about anything that depends on the "size of" a function type or of "void".  GNU C assigns these types a size of 1
# -Wundef: Warn if an undefined identifier is evaluated in an "#if" directive
# -Wbad-function-cast: Warn when a function call is cast to a non-matching type
# -Wwrite-strings: When compiling C, give string constants the type "const char[length]" so that copying the address of one into a non-"const" "char *" pointer produces a warning
# -Wparentheses: Warn if parentheses are omitted in certain contexts, such as when there is an assignment in a context where a truth value is expected, or when operators are nested whose precedence people often get confused about
# -Wlogical-op: Warn about suspicious uses of logical operators in expressions
# -Wstrict-prototypes: Warn if a function is declared or defined without specifying the argument types
# -Wmissing-prototypes: Warn if a global function is defined without a previous prototype declaration
# -Wredundant-decls: Warn if anything is declared more than once in the same scope
# -Winline: Warn if a function that is declared as inline cannot be inlined
ifeq "$(GCCVERSION8)" "1"
  # -Wduplicated-cond: Warn about duplicated conditions in an if-else-if chain
  # -Wduplicated-branches: Warn when an if-else has identical branches
  # -Wcast-align=strict: Warn whenever a pointer is cast such that the required alignment of the target is increased. For example, warn if a "char *" is cast to an "int *" regardless of the target machine.
  # -Wlogical-not-parentheses: Warn about logical not used on the left hand side operand of a comparison
  EXTRAWARNGCC8=-Wduplicated-cond -Wduplicated-branches -Wcast-align=strict -Wlogical-not-parentheses -Wsuggest-attribute=pure -Wsuggest-attribute=const -Wsuggest-attribute=noreturn -Wsuggest-attribute=malloc -Wsuggest-attribute=format -Wsuggest-attribute=cold
else
  EXTRAWARNGCC8=
endif
EXTRAWARN=-Werror -Waddress -Wlogical-op -Wmissing-field-initializers -Woverlength-strings -Wformat -Wformat-nonliteral -Wuninitialized -Wswitch-enum -Wshadow \
-Wfloat-equal -Wunsafe-loop-optimizations -funsafe-loop-optimizations -Wbad-function-cast -Wwrite-strings -Wparentheses -Wlogical-op -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Winline $(EXTRAWARNGCC8)

# -FILE_OFFSET_BITS=64: used by stat(). Avoids problems with files > 2 GB on 32bit machines
CCFLAGS=-std=gnu11 -I$(IDIR) $(WARNFLAGS) -D_FILE_OFFSET_BITS=64 $(HARDENING_FLAGS) $(DEBUG_FLAGS) $(CFLAGS) $(SQLITEFLAGS)

# for FTL we need the pthread library
# for dnsmasq we need the nettle crypto library and the gmp maths library
# We link the two libraries statically. Although this increases the binary file size by about 1 MB, it saves about 5 MB of shared libraries and makes deployment easier
#LIBS=-pthread -lnettle -lgmp -lhogweed
LIBS=-pthread -lrt -Wl,-Bstatic -L/usr/local/lib -lhogweed -lgmp -lnettle -Wl,-Bdynamic
# Flags for compiling with libidn : -lidn
# Flags for compiling with libidn2: -lidn2

IDIR = .
ODIR = obj
DNSMASQDIR = dnsmasq
DNSMASQODIR = $(DNSMASQDIR)/obj

_FTLDEPS = $(patsubst %,$(IDIR)/%,$(FTLDEPS))
_FTLOBJ = $(patsubst %,$(ODIR)/%,$(FTLOBJ))

_DNSMASQDEPS = $(patsubst %,$(DNSMASQDIR)/%,$(DNSMASQDEPS))
_DNSMASQOBJ = $(patsubst %,$(DNSMASQODIR)/%,$(DNSMASQOBJ))

all: pihole-FTL
$(ODIR)/%.o: %.c $(_FTLDEPS) | $(ODIR)
	$(CC) -c -o $@ $< -g3 $(CCFLAGS) $(EXTRAWARN)

$(DNSMASQODIR)/%.o: $(DNSMASQDIR)/%.c $(_DNSMASQDEPS) | $(DNSMASQODIR)
	$(CC) -c -o $@ $< -g3 $(CCFLAGS) -DVERSION=\"$(DNSMASQVERSION)\" $(DNSMASQOPTS)

$(ODIR):
	mkdir -p $(ODIR)

$(DNSMASQODIR):
	mkdir -p $(DNSMASQODIR)

$(ODIR)/sqlite3.o: $(IDIR)/sqlite3.c | $(ODIR)
	$(CC) -c -o $@ $< $(CCFLAGS)

pihole-FTL: $(_FTLOBJ) $(_DNSMASQOBJ) $(ODIR)/sqlite3.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS)

.PHONY: clean force install

clean:
	rm -f $(ODIR)/*.o $(DNSMASQODIR)/*.o pihole-FTL

# # recreate version.h when GIT_VERSION changes, uses temporary file version~
version~: force
	@echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE) $(GIT_TAG)' | cmp -s - $@ || echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE) $(GIT_TAG)' > $@
version.h: version~
	@echo '#define GIT_VERSION "$(GIT_VERSION)"' > "$@"
	@echo '#define GIT_DATE "$(GIT_DATE)"' >> "$@"
	@echo '#define GIT_BRANCH "$(GIT_BRANCH)"' >> "$@"
	@echo '#define GIT_TAG "$(GIT_TAG)"' >> "$@"
	@echo '#define GIT_HASH "$(GIT_HASH)"' >> "$@"
	@echo "Making FTL version on branch $(GIT_BRANCH) - $(GIT_VERSION) ($(GIT_DATE))"

prefix=/usr

# install target just installs the executable
# other requirements (correct ownership of files, etc.) is managed by
# the service script on sudo service pihole-FTL (re)start
install: pihole-FTL
	install -m 0755 pihole-FTL $(prefix)/bin
	/sbin/setcap CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_ADMIN+eip $(prefix)/bin/pihole-FTL
