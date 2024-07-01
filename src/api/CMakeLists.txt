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
        2fa.c
        action.c
        api_helper.h
        api.h
        api.c
        auth.c
        auth.h
        config.c
        dhcp.c
        dns.c
        network.c
        history.c
        info.c
        list.c
        logs.c
        queries.c
        search.c
        stats_database.c
        stats.c
        teleporter.c
        theme.c
        theme.h
        )

add_library(api OBJECT ${sources})
add_dependencies(api gen_version)
target_compile_options(api PRIVATE ${EXTRAWARN})
target_include_directories(api PRIVATE ${PROJECT_SOURCE_DIR}/src)
add_subdirectory(docs)
