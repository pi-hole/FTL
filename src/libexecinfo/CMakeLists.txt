# Pi-hole: A black hole for Internet advertisements
# (c) 2023 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/libexecinfo/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(libexecinfo_sources
        execinfo.c
        execinfo.h
        stacktraverse.c
        stacktraverse.h
        )

add_library(libexecinfo OBJECT ${libexecinfo_sources})
target_compile_options(libexecinfo PRIVATE "-Wno-frame-address")
target_include_directories(libexecinfo PRIVATE ${PROJECT_SOURCE_DIR}/src)
