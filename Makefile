# Pi-hole: A black hole for Internet advertisements
# (c) 2017 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Makefile
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

DEPS = FTL.h routines.h version.h
OBJ = main.o structs.o log.o daemon.o parser.o signals.o socket.o request.o grep.o setupVars.o args.o flush.o threads.o gc.o config.o

# Get git commit version and date
GIT_BRANCH := $(shell git branch | sed -n 's/^\* //p')
GIT_VERSION := $(shell git --no-pager describe --tags --always --dirty)
GIT_DATE := $(shell git --no-pager show --date=short --format="%ai" --name-only | head -n 1)
GIT_TAG := $(shell git describe --tags --abbrev=0)

# -fstack-protector: The program will be resistant to having its stack overflowed
# -D_FORTIFY_SOURCE=2 and -O1 or higher: This causes certain unsafe glibc functions to be replaced with their safer counterparts
# -Wl,-z,relro: reduces the possible areas of memory in a program that can be used by an attacker that performs a successful memory corruption exploit
# -Wl,-z,now: When combined with RELRO above, this further reduces the regions of memory available to memory corruption attacks
# -pie -fPIE: For ASLR
# -g3: More debugging information
# _FILE_OFFSET_BITS=64: used by stat(). Avoids problems with files > 2 GB on 32bit machines
# -fsanitize=address: AddressSanitizer
# -fno-omit-frame-pointer: get nicer stacktraces
CC=gcc
HARDENING_FLAGS=-fstack-protector -D_FORTIFY_SOURCE=2 -O3 -Wl,-z,relro,-z,now -pie -fPIE
DEBUG_FLAGS=-g3 -rdynamic -fno-omit-frame-pointer #-fsanitize=address
CCFLAGS=-I$(IDIR) -Wall -Wextra -Wno-unused-parameter -D_FILE_OFFSET_BITS=64 $(HARDENING_FLAGS) $(DEBUG_FLAGS) $(CFLAGS)
LIBS=-pthread

ODIR =obj
IDIR =.
LDIR =lib

_DEPS = $(patsubst %,$(IDIR)/%,$(DEPS))

_OBJ = $(patsubst %,$(ODIR)/%,$(OBJ))

all: pihole-FTL

$(ODIR)/%.o: %.c $(_DEPS) | $(ODIR)
	$(CC) -c -o $@ $< $(CCFLAGS)

$(ODIR):
	mkdir -p $(ODIR)

pihole-FTL: $(_OBJ)
	$(CC) -v $(CCFLAGS) -o $@ $^ $(LIBS)

.PHONY: clean force install

clean:
	rm -f $(ODIR)/*.o pihole-FTL

# recreate version.h when GIT_VERSION changes, uses temporary file version~
version~: force
	@echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE) $(GIT_TAG)' | cmp -s - $@ || echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE) $(GIT_TAG)' > $@
version.h: version~
	@echo '#define GIT_VERSION "$(GIT_VERSION)"' > "$@"
	@echo '#define GIT_DATE "$(GIT_DATE)"' >> "$@"
	@echo '#define GIT_BRANCH "$(GIT_BRANCH)"' >> "$@"
	@echo '#define GIT_TAG "$(GIT_TAG)"' >> "$@"
	@echo "Making FTL version on branch $(GIT_BRANCH) - $(GIT_VERSION) ($(GIT_DATE))"

prefix=/usr

install: pihole-FTL
	install -m 0755 pihole-FTL $(prefix)/bin
	touch /var/log/pihole-FTL.log /var/run/pihole-FTL.pid /var/run/pihole-FTL.port
	chown pihole:pihole /var/log/pihole-FTL.log /run/pihole-FTL.pid /run/pihole-FTL.port
	chmod 0644 /var/log/pihole-FTL.log /var/run/pihole-FTL.pid /var/run/pihole-FTL.port
