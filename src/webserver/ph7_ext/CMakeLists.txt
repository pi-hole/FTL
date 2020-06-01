# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/webserver/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        extensions.h
        gethostname.c
        )

add_library(ph7_ext OBJECT ${sources})
add_dependencies(ph7_ext gen_version)
target_compile_options(ph7_ext PRIVATE ${EXTRAWARN})
target_include_directories(ph7_ext PRIVATE ${PROJECT_SOURCE_DIR}/src)
