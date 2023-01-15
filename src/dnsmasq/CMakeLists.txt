# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/dnsmasq/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        arp.c
        auth.c
        blockdata.c
        bpf.c
        cache.c
        config.h
        conntrack.c
        crypto.c
        dbus.c
        dhcp-common.c
        dhcp-protocol.h
        dhcp.c
        dhcp6-protocol.h
        dhcp6.c
        dns-protocol.h
        dnsmasq.c
        dnsmasq.h
        dnssec.c
        domain.c
        domain-match.c
        dump.c
        edns0.c
        forward.c
        hash-questions.c
        helper.c
        inotify.c
        ip6addr.h
        ipset.c
        lease.c
        log.c
        loop.c
        metrics.c
        metrics.h
        netlink.c
        network.c
        nftset.c
        option.c
        outpacket.c
        pattern.c
        poll.c
        radv-protocol.h
        radv.c
        rfc1035.c
        rfc2131.c
        rfc3315.c
        rrfilter.c
        slaac.c
        tables.c
        tftp.c
        ubus.c
        util.c
        )

add_library(dnsmasq OBJECT ${sources})
target_compile_definitions(dnsmasq PRIVATE VERSION=\"${DNSMASQ_VERSION}\")
target_compile_definitions(dnsmasq PRIVATE CONFFILE=\"/etc/pihole/dnsmasq.conf\")
target_compile_options(dnsmasq PRIVATE -Wno-maybe-uninitialized)
target_include_directories(dnsmasq PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/src/lua)
