# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/dotdoh/CMakeLists.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(dotdoh_sources
        upstream_uri.c
        upstream_uri.h
        framing.c
        framing.h
        edns_pad.c
        edns_pad.h
        registry.c
        registry.h
        tls_client.c
        tls_client.h
        quic_client.c
        quic_client.h
        proxy.c
        proxy.h
        )

add_library(dotdoh OBJECT ${dotdoh_sources})
target_compile_options(dotdoh PRIVATE "${EXTRAWARN}")
target_include_directories(dotdoh PRIVATE ${PROJECT_SOURCE_DIR}/src)
