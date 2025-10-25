# Pi-hole: A black hole for Internet advertisements
# (c) 2025 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/config/tomlc17/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        tomlc17.c
        tomlc17.h
        )

add_library(tomlc17 OBJECT ${sources})

target_include_directories(tomlc17 PRIVATE ${PROJECT_SOURCE_DIR}/src)
