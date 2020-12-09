# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/syscalls/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        calloc.c
        free.c
        realloc.c
        strdup.c
        syscalls.h
        )

add_library(syscalls OBJECT ${sources})
target_compile_options(syscalls PRIVATE ${EXTRAWARN})
