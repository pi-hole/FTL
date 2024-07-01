# Pi-hole: A black hole for Internet advertisements
# (c) 2024 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/ntp/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(ntp_sources
        server.c
        client.c
        rtc.c
        ntp.h
        )

add_library(ntp OBJECT ${ntp_sources})
target_compile_options(ntp PRIVATE "${EXTRAWARN}")
target_include_directories(ntp PRIVATE ${PROJECT_SOURCE_DIR}/src)
