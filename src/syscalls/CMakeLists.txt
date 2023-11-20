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
        accept.c
        asprintf.c
        calloc.c
        ftlallocate.c
        fopen.c
        fprintf.c
        free.c
        pthread_mutex_lock.c
        realloc.c
        recv.c
        recvfrom.c
        select.c
        sendto.c
        snprintf.c
        sprintf.c
        strdup.c
        string.c
        syscalls.h
        vasprintf.c
        vfprintf.c
        vsnprintf.c
        vsprintf.c
        write.c
        )

add_library(syscalls OBJECT ${sources})
target_compile_options(syscalls PRIVATE ${EXTRAWARN})
