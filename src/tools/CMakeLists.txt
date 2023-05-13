# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/tools/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(tools_sources
        dhcp-discover.c
        dhcp-discover.h
        )

add_library(tools OBJECT ${tools_sources})
target_compile_options(tools PRIVATE "${EXTRAWARN}")
target_include_directories(tools PRIVATE ${PROJECT_SOURCE_DIR}/src)
