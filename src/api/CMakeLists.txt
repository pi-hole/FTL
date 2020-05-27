# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/api/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        api.c
        api.h
        msgpack.c
        request.c
        request.h
        socket.c
        socket.h
        )

add_library(api OBJECT ${sources})
add_dependencies(api gen_version)
target_compile_options(api PRIVATE ${EXTRAWARN})
target_include_directories(api PRIVATE ${PROJECT_SOURCE_DIR}/src)
