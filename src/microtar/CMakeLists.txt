# Pi-hole: A black hole for Internet advertisements
# (c) 2023 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/microtar/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        microtar-mmap.c
        microtar-mmap.h
        microtar.c
        microtar.h
        )

add_library(microtar OBJECT ${sources})
target_compile_options(microtar PRIVATE)
target_include_directories(microtar PRIVATE ${PROJECT_SOURCE_DIR}/src)
