# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/cluster/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(cluster_sources
        auth.c
        auth.h
        cluster.c
        cluster.h
        discover.c
        discover.h
        http.c
        http.h
        sync.c
        sync.h
        dhcp.c
        dhcp.h
        vip.c
        vip.h
        )

add_library(cluster OBJECT ${cluster_sources})
target_compile_options(cluster PRIVATE "${EXTRAWARN}")
target_include_directories(cluster PRIVATE ${PROJECT_SOURCE_DIR}/src)
