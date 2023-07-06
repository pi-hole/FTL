# Pi-hole: A black hole for Internet advertisements
# (c) 2021 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/config/tomlc99/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        toml.c
        toml.h
        )

add_library(tomlc99 OBJECT ${sources})

target_include_directories(tomlc99 PRIVATE ${PROJECT_SOURCE_DIR}/src)
