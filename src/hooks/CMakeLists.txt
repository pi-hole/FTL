# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/hooks/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(hooks_sources
        blocking_metadata.c
        blocking_metadata.h
        cache.c
        cache.h
        cache_info.c
        cache_info.h
        check_blocking.c
        check_blocking.h
        CNAME.c
        CNAME.h
        detect_blocked_IP.c
        detect_blocked_IP.h
        dhcp.c
        dhcp.h
        dnsmasq_reload.c
        dnsmasq_reload.h
        dnssec.c
        dnssec.h
        extract_question_flags.c
        extract_question_flags.h
        fork_and_bind.c
        fork_and_bind.h
        forwarded.c
        forwarded.h
        forwarding_failed.c
        forwarding_failed.h
        header_analysis.c
        header_analysis.h
        iface.c
        iface.h
        log.c
        log.h
        multiple_replies.c
        multiple_replies.h
        new_query.c
        new_query.h
        print_flags.c
        print_flags.h
        query_blocked.c
        query_blocked.h
        query_in_progress.c
        query_in_progress.h
        received_reply.c
        received_reply.h
        set_reply.c
        set_reply.h
        tcp_workers.c
        tcp_workers.h
        upstream_error.c
        upstream_error.h
        )

add_library(hooks OBJECT ${hooks_sources})
target_compile_options(hooks PRIVATE "${EXTRAWARN}")
target_include_directories(hooks PRIVATE ${PROJECT_SOURCE_DIR}/src)
