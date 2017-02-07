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
OBJ = main.o structs.o log.o daemon.o parser.o signals.o socket.o request.o grep.o setupVars.o args.o

# Get git commit version and date
GIT_BRANCH := $(shell git branch | sed -n 's/^\* //p')
GIT_VERSION := $(shell git --no-pager describe --tags --always --dirty)
GIT_DATE := $(shell git --no-pager show --date=short --format="%ai" --name-only | head -n 1)

CC=gcc
CFLAGS=-I$(IDIR) -Wall -g -fstack-protector -static
LIBS=-rdynamic

ODIR =obj
IDIR =.
LDIR =lib

_DEPS = $(patsubst %,$(IDIR)/%,$(DEPS))

_OBJ = $(patsubst %,$(ODIR)/%,$(OBJ))

$(ODIR)/%.o: %.c $(_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pihole-FTL: $(_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

.PHONY: clean force install

clean:
	rm -f $(ODIR)/*.o pihole-FTL

# recreate version.h when GIT_VERSION changes, uses temporary file version~
version~: force
	@echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE)' | cmp -s - $@ || echo '$(GIT_BRANCH) $(GIT_VERSION) $(GIT_DATE)' > $@
version.h: version~
	@echo '#define GIT_VERSION "$(GIT_VERSION)"' > "$@"
	@echo '#define GIT_DATE "$(GIT_DATE)"' >> "$@"
	@echo '#define GIT_BRANCH "$(GIT_BRANCH)"' >> "$@"
	@echo "Making FTL version on branch $(GIT_BRANCH) - $(GIT_VERSION) ($(GIT_DATE))"

prefix=/usr/local

install: pihole-FTL
	install -m 0755 pihole-FTL $(prefix)/bin
	touch /var/log/pihole-FTL.log /var/run/pihole-FTL.pid /var/run/pihole-FTL.port
	chmod 0666 /var/log/pihole-FTL.log /var/run/pihole-FTL.pid /var/run/pihole-FTL.port
