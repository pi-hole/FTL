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
target_compile_definitions(dnsmasq PRIVATE VERSION=\"${DNSMASQ_VERSION}\" HAVE_DNSSEC HAVE_DNSSEC_STATIC HAVE_IDN HAVE_LUASCRIPT)
target_compile_options(dnsmasq PRIVATE -Wno-maybe-uninitialized)
target_include_directories(dnsmasq PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/src/lua)
