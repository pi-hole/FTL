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
        http-common.c
        http-common.h
        webserver.c
        webserver.h
        ph7.c
        ph7.h
        json_macros.h
        )

add_library(webserver OBJECT ${sources})
add_dependencies(webserver gen_version)
target_compile_options(webserver PRIVATE ${EXTRAWARN})
target_include_directories(webserver PRIVATE ${PROJECT_SOURCE_DIR}/src)

add_subdirectory(ph7_ext)