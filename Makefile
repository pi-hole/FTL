# Pi-hole: A black hole for Internet advertisements
# (c) 2018 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL-Engine
# Makefile
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

IDIR = src
ODIR = build

DNSMASQ_VERSION = "pi-hole-2.81"
DNSMASQ_OPTS = -DHAVE_DNSSEC -DHAVE_DNSSEC_STATIC -DHAVE_IDN

FTL_DEPS = *.h database/*.h api/*.h version.h
FTL_DB_OBJ = database/common.o database/query-table.o database/network-table.o database/gravity-db.o database/database-thread.o \
             database/sqlite3-ext.o database/message-table.o
FTL_API_OBJ = api/http-common.o api/routes.o api/ftl.o api/stats.o api/dns.o api/version.o api/auth.o api/settings.o
FTL_OBJ = $(FTL_DB_OBJ) $(FTL_API_OBJ) main.o memory.o log.o daemon.o datastructure.o signals.o files.o setupVars.o args.o gc.o config.o dnsmasq_interface.o resolve.o regex.o shmem.o capabilities.o overTime.o timers.o vector.o

DNSMASQ_DEPS = config.h dhcp-protocol.h dns-protocol.h radv-protocol.h dhcp6-protocol.h dnsmasq.h ip6addr.h metrics.h ../dnsmasq_interface.h
DNSMASQ_OBJ = arp.o dbus.o domain.o lease.o outpacket.o rrfilter.o auth.o dhcp6.o edns0.o log.o poll.o slaac.o blockdata.o dhcp.o forward.o \
              loop.o radv.o tables.o bpf.o dhcp-common.o helper.o netlink.o rfc1035.o tftp.o cache.o dnsmasq.o inotify.o network.o rfc2131.o \
              util.o conntrack.o dnssec.o ipset.o option.o rfc3315.o crypto.o dump.o ubus.o metrics.o

# We can remove the NO_SSL later on. It adds additional constraints to the build system (availablity of libSSL-dev)
# -DNO_CGI = no CGI support (we don't need it)
# -DNO_SSL_DL -DNO_SSL = no SSL support (for now)
# -DUSE_SERVER_STATS = makes a few anonymous statistics available, such as
#   - Number of connections (currently and total)
#   - Amount of data read and written
# -DUSE_IPV6: add IPv6 support
CIVETWEB_OPTS = -DNO_CGI -DNO_SSL_DL -DNO_SSL -DUSE_SERVER_STATS -DUSE_IPV6
CIVETWEB_DEPS = civetweb.h
CIVETWEB_OBJ = civetweb.o

# cJSON does not need/has compile-time options
CJSON_DEPS = cJSON.h
CJSON_OBJ = cJSON.o

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
# -g3: More debugging information
# -fno-omit-frame-pointer: get nicer stacktraces
# -funwind-tables: Generate static data for unwinding
# -fasynchronous-unwind-tables: Increased reliability of backtraces
# -fexceptions: Enable table-based thread cancellation
# -Wl,-z,defs: Detect and reject underlinking (phenomenon caused by missing shared library arguments when invoking the linked editor to produce another shared library)
# -Wl,-z,now: Disable lazy binding
# -Wl,-z,relro: Read-only segments after relocation
HARDENING_FLAGS=-fstack-protector-strong -Wp,-D_FORTIFY_SOURCE=2 -O3 -Wl,-z,relro,-z,now -fexceptions -funwind-tables -fasynchronous-unwind-tables -Wl,-z,defs -Wl,-z,now -Wl,-z,relro
DEBUG_FLAGS=-rdynamic -fno-omit-frame-pointer

# -DSQLITE_OMIT_LOAD_EXTENSION: This option omits the entire extension loading mechanism from SQLite, including sqlite3_enable_load_extension() and sqlite3_load_extension() interfaces. (needs -ldl linking option, otherwise)
# -DSQLITE_DEFAULT_MEMSTATUS=0: This setting causes the sqlite3_status() interfaces that track memory usage to be disabled. This helps the sqlite3_malloc() routines run much faster, and since SQLite uses sqlite3_malloc() internally, this helps to make the entire library faster.
# -DSQLITE_OMIT_DEPRECATED: Omitting deprecated interfaces and features will not help SQLite to run any faster. It will reduce the library footprint, however. And it is the right thing to do.
# -DSQLITE_OMIT_PROGRESS_CALLBACK: The progress handler callback counter must be checked in the inner loop of the bytecode engine. By omitting this interface, a single conditional is removed from the inner loop of the bytecode engine, helping SQL statements to run slightly faster.
# -DSQLITE_DEFAULT_FOREIGN_KEYS=1: This macro determines whether enforcement of foreign key constraints is enabled or disabled by default for new database connections.
# -DSQLITE_DQS=0: This setting disables the double-quoted string literal misfeature.
SQLITE_FLAGS=-DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_MEMORYDB -DSQLITE_DEFAULT_FOREIGN_KEYS=1 -DSQLITE_DQS=0

# -Wall: This enables all the warnings about constructions that some users consider questionable, and that are easy to avoid (or modify to prevent the warning), even in conjunction with macros. This also enables some language-specific warnings described in C++ Dialect Options and Objective-C and Objective-C++ Dialect Options.
# -Wextra: This enables some extra warning flags that are not enabled by -Wall.
# -Wno-unused-parameter: Disable warning for unused parameters. For threads that don't need arguments, we still have to provide a void* args which is then unused.
WARN_FLAGS=-Wall -Wextra -Wno-unused-parameter

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
  EXTRAWARN_GCC8=-Wduplicated-cond -Wduplicated-branches -Wcast-align=strict -Wlogical-not-parentheses -Wsuggest-attribute=pure -Wsuggest-attribute=const -Wsuggest-attribute=noreturn -Wsuggest-attribute=malloc -Wsuggest-attribute=format -Wsuggest-attribute=cold
else
  EXTRAWARN_GCC8=
endif
EXTRAWARN=-Werror -Waddress -Wlogical-op -Wmissing-field-initializers -Woverlength-strings -Wformat -Wformat-nonliteral -Wuninitialized -Wswitch-enum -Wshadow \
-Wfloat-equal -Wbad-function-cast -Wwrite-strings -Wparentheses -Wlogical-op -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Winline $(EXTRAWARN_GCC8)

# -FILE_OFFSET_BITS=64: used by stat(). Avoids problems with files > 2 GB on 32bit machines
CCFLAGS=-std=gnu11 -pipe -I$(IDIR) $(WARN_FLAGS) -D_FILE_OFFSET_BITS=64 $(HARDENING_FLAGS) $(DEBUG_FLAGS) $(CFLAGS) $(SQLITE_FLAGS) -DHAVE_POLL_H
# We define HAVE_POLL_H as this is needed for the musl builds to succeed

# for FTL we need the pthread library
# for dnsmasq we need the nettle crypto library and the gmp maths library
# We link the two libraries statically. Although this increases the binary file size by about 1 MB, it saves about 5 MB of shared libraries and makes deployment easier
LIBS=-pthread -lrt -Wl,-Bstatic -L/usr/local/lib -lhogweed -lgmp -lnettle -lidn

# Do we want to compile a statically linked musl executable?
ifeq "$(STATIC)" "true"
  CC := $(CC) -Wl,-Bstatic -static-libgcc -static-pie
else
  LIBS := $(LIBS) -Wl,-Bdynamic
  # -pie -fPIE: (Dynamic) position independent executable
  HARDENING_FLAGS := $(HARDENING_FLAGS) -pie -fPIE
endif

DB_OBJ_DIR = $(ODIR)/database
API_OBJ_DIR = $(ODIR)/api
DNSMASQ_OBJ_DIR = $(ODIR)/dnsmasq
CIVETWEB_OBJ_DIR = $(ODIR)/civetweb
CJSON_OBJ_DIR = $(ODIR)/cJSON

_FTL_DEPS = $(patsubst %,$(IDIR)/%,$(FTL_DEPS))
_FTL_OBJ = $(patsubst %,$(ODIR)/%,$(FTL_OBJ))

_DNSMASQ_DEPS = $(patsubst %,$(IDIR)/dnsmasq/%,$(DNSMASQ_DEPS))
_DNSMASQ_OBJ = $(patsubst %,$(DNSMASQ_OBJ_DIR)/%,$(DNSMASQ_OBJ))

_CIVETWEB_DEPS = $(patsubst %,$(IDIR)/civetweb/%,$(CIVETWEB_DEPS))
_CIVETWEB_OBJ = $(patsubst %,$(CIVETWEB_OBJ_DIR)/%,$(CIVETWEB_OBJ))

_CJSON_DEPS = $(patsubst %,$(IDIR)/cJSON/%,$(CJSON_DEPS))
_CJSON_OBJ = $(patsubst %,$(CJSON_OBJ_DIR)/%,$(CJSON_OBJ))

all: pihole-FTL

# Compile FTL source code files with virtually all possible warnings a modern gcc can generate
$(_FTL_OBJ): $(ODIR)/%.o: $(IDIR)/%.c $(_FTL_DEPS) | $(ODIR) $(DB_OBJ_DIR) $(API_OBJ_DIR)
	$(CC) -c -o $@ $< -g3 $(CCFLAGS) $(EXTRAWARN)

# Compile the contained external codes with much less strict requirements as they fail to compile
# when enforcing the standards we enforce for the rest of our FTL code base
$(_DNSMASQ_OBJ): $(DNSMASQ_OBJ_DIR)/%.o: $(IDIR)/dnsmasq/%.c $(_DNSMASQ_DEPS) | $(DNSMASQ_OBJ_DIR)
	$(CC) -c -o $@ $< -g3 $(CCFLAGS) -DVERSION=\"$(DNSMASQ_VERSION)\" $(DNSMASQ_OPTS)
$(_CIVETWEB_OBJ): $(CIVETWEB_OBJ_DIR)/%.o: $(IDIR)/civetweb/%.c $(_CIVETWEB_DEPS) | $(CIVETWEB_OBJ_DIR)
	$(CC) -c -o $@ $< -g3 $(CCFLAGS) $(CIVETWEB_OPTS)
$(_CJSON_OBJ): $(CJSON_OBJ_DIR)/%.o: $(IDIR)/cJSON/%.c $(_CJSON_DEPS) | $(CJSON_OBJ_DIR)
	$(CC) -c -o $@ $< -g3 $(CCFLAGS)

$(DB_OBJ_DIR)/sqlite3.o: $(IDIR)/database/sqlite3.c | $(DB_OBJ_DIR)
	$(CC) -c -o $@ $< -g3 $(CCFLAGS)

$(ODIR):
	mkdir -p $(ODIR)

$(DB_OBJ_DIR):
	mkdir -p $(DB_OBJ_DIR)

$(API_OBJ_DIR):
	mkdir -p $(API_OBJ_DIR)

$(DNSMASQ_OBJ_DIR):
	mkdir -p $(DNSMASQ_OBJ_DIR)

$(CIVETWEB_OBJ_DIR):
	mkdir -p $(CIVETWEB_OBJ_DIR)

$(CJSON_OBJ_DIR):
	mkdir -p $(CJSON_OBJ_DIR)

pihole-FTL: $(_FTL_OBJ) $(_DNSMASQ_OBJ) $(_CIVETWEB_OBJ) $(_CJSON_OBJ) $(DB_OBJ_DIR)/sqlite3.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS)

.PHONY: clean force install

clean:
	rm -rf $(ODIR) pihole-FTL

# If CIRCLE_JOB is unset (local compilation), ask uname -m and add locally compiled comment
ifeq ($(strip $(CIRCLE_JOB)),)
FTL_ARCH := $(shell uname -m) (compiled locally)
else
FTL_ARCH := $(CIRCLE_JOB) (compiled on CI)
endif
# Get compiler version
FTL_CC := $(shell $(CC) --version | head -n 1)

# # recreate version.h when GIT_VERSION changes, uses temporary file version~
$(IDIR)/version~: force
	@echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE) $(GIT_TAG)' | cmp -s - $@ || echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE) $(GIT_TAG)' > $@
$(IDIR)/version.h: $(IDIR)/version~
	@echo '#ifndef VERSION_H' > "$@"
	@echo '#define VERSION_H' >> "$@"
	@echo '#define GIT_VERSION "$(GIT_VERSION)"' >> "$@"
	@echo '#define GIT_DATE "$(GIT_DATE)"' >> "$@"
	@echo '#define GIT_BRANCH "$(GIT_BRANCH)"' >> "$@"
	@echo '#define GIT_TAG "$(GIT_TAG)"' >> "$@"
	@echo '#define GIT_HASH "$(GIT_HASH)"' >> "$@"
	@echo '#define FTL_ARCH "$(FTL_ARCH)"' >> "$@"
	@echo '#define FTL_CC "$(FTL_CC)"' >> "$@"
	@echo '#endif // VERSION_H' >> "$@"
	@echo "Making FTL version on branch $(GIT_BRANCH) - $(GIT_VERSION) / $(GIT_TAG) / $(GIT_HASH) ($(GIT_DATE))"

PREFIX=/usr
SETCAP = $(shell which setcap)

# install target just installs the executable
# other requirements (correct ownership of files, etc.) is managed by
# the service script on sudo service pihole-FTL (re)start
install: pihole-FTL
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 0755 pihole-FTL $(DESTDIR)$(PREFIX)/bin
	$(SETCAP) CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_ADMIN+eip $(DESTDIR)$(PREFIX)/bin/pihole-FTL
