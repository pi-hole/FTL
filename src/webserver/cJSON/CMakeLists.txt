# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/cJSON/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        cJSON.c
        cJSON.h
        )

add_library(cJSON OBJECT ${sources})
target_compile_options(cJSON PRIVATE)
target_include_directories(cJSON PRIVATE ${PROJECT_SOURCE_DIR}/src)
