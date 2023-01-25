# Pi-hole: A black hole for Internet advertisements
# (c) 2023 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/miniz/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        miniz.c
        miniz.h
)

add_library(miniz OBJECT ${sources})
target_compile_options(miniz PRIVATE)
target_include_directories(miniz PRIVATE ${PROJECT_SOURCE_DIR}/src)
