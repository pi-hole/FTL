# Pi-hole: A black hole for Internet advertisements
# (c) 2023 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/compression/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        gzip.c
        gzip.h
        teleporter.c
        teleporter.h
        )

add_library(compression OBJECT ${sources})
target_compile_options(compression PRIVATE)
target_compile_options(compression PRIVATE ${EXTRAWARN})
target_include_directories(compression PRIVATE ${PROJECT_SOURCE_DIR}/src)

add_subdirectory(miniz)