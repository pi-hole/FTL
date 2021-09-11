#!/bin/bash
# Test script to quickly test for arbitrary resource records
# Originally written by Daxtorim, see
# https://discourse.pi-hole.net/t/pi-hole-wont-cache-results-if-answer-doesnt-fit-known-reply-types-and-will-always-display-n-a-0-0ms-as-reply-in-query-log/49171/3

pihole="127.0.0.1"
for i in a aaaa any cname srv soa ptr txt naptr mx ds rrsig dnskey ns svcb https
do
    if [ "$i" = "ptr" ]; then
        # Also test reverse address lookups in addition to PTR
        # ptr.dns.netmeister.org below
        ip4="$(dig +short a netmeister.org)"
        ip6="$(dig +short aaaa netmeister.org)"
        dig +noall +answer +retry=0 +timeout=30 "@${pihole}" -x "${ip4}"
        dig +noall +answer +retry=0 +timeout=30 "@${pihole}" -x "${ip6}"
    fi
    if [ "$i" = "svcb" ]; then
        j="TYPE64"
    elif [ "$i" = "https" ]; then
        j="TYPE65"
    else
        j="$i"
    fi
    echo "dig ${j} ${i}.dns.netmeister.org"
    dig +noall +answer +retry=0 +timeout=30 "@${pihole}" ${j} "${i}.dns.netmeister.org"
    echo ""
done
echo ""
