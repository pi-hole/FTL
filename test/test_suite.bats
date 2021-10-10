#!./test/libs/bats/bin/bats

@test "Version, Tag, Branch, Hash, Date is reported" {
  run bash -c 'echo ">version >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "version "* ]]
  [[ ${lines[2]} == "tag "* ]]
  [[ ${lines[3]} == "branch "* ]]
  [[ ${lines[4]} == "hash "* ]]
  [[ ${lines[5]} == "date "* ]]
  [[ ${lines[6]} == "" ]]
}

@test "Running a second instance is detected and prevented" {
  run bash -c 'su pihole -s /bin/sh -c "/home/pihole/pihole-FTL -f"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[9]} == *"Initialization of shared memory failed." ]]
  [[ ${lines[10]} == *"HINT: pihole-FTL is already running!"* ]]
}

@test "Starting tests without prior history" {
  run bash -c 'grep -c "Total DNS queries: 0" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Initial blocking status is enabled" {
  run bash -c 'grep -c "Blocking status is enabled" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Number of compiled regex filters as expected" {
  run bash -c 'grep "Compiled [0-9]* whitelist" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == *"Compiled 2 whitelist and 9 blacklist regex filters"* ]]
}

@test "Blacklisted domain is blocked" {
  run bash -c "dig blacklisted.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Gravity domain is blocked" {
  run bash -c "dig gravity.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Gravity domain is blocked (TCP)" {
  run bash -c "dig gravity.ftl @127.0.0.1 +tcp +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Gravity domain + whitelist exact match is not blocked" {
  run bash -c "dig whitelisted.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.4" ]]
}

@test "Gravity domain + whitelist regex match is not blocked" {
  run bash -c "dig gravity-whitelisted.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.5" ]]
}

@test "Regex blacklist match is blocked" {
  run bash -c "dig regex5.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Regex blacklist mismatch is not blocked" {
  run bash -c "dig regexA.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.4" ]]
}

@test "Regex blacklist match + whitelist exact match is not blocked" {
  run bash -c "dig regex1.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.1" ]]
}

@test "Regex blacklist match + whitelist regex match is not blocked" {
  run bash -c "dig regex2.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.2" ]]
}

@test "Client 2: Gravity match matching unassociated whitelist is blocked" {
  run bash -c "dig whitelisted.ftl -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
}

@test "Client 2: Regex blacklist match matching unassociated whitelist is blocked" {
  run bash -c "dig regex1.ftl -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
}

@test "Same domain is not blocked for client 1 ..." {
  run bash -c "dig regex1.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.1" ]]
}

@test "... or client 3" {
  run bash -c "dig regex1.ftl -b 127.0.0.3  @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.1" ]]
}

@test "Client 2: Unassociated blacklist match is not blocked" {
  run bash -c "dig blacklisted.ftl -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.3" ]]
}

@test "Client 3: Exact blacklist domain is not blocked" {
  run bash -c "dig blacklisted.ftl -b 127.0.0.3 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.3" ]]
}

@test "Client 3: Regex blacklist domain is not blocked" {
  run bash -c "dig regex1.ftl -b 127.0.0.3 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.1" ]]
}

@test "Client 3: Gravity domain is not blocked" {
  run bash -c "dig a.ftl -b 127.0.0.3 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.1" ]]
}

@test "Client 4: Client is recognized by MAC address" {
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.4 @127.0.0.1 +short"
  run sleep 0.1
  run bash -c "grep -c \"Found database hardware address 127.0.0.4 -> aa:bb:cc:dd:ee:ff\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Gravity database: Client aa:bb:cc:dd:ee:ff found. Using groups (4)\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex blacklist: Querying groups for client 127.0.0.4: \"SELECT id from vw_regex_blacklist WHERE group_id IN (4);\"' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex whitelist: Querying groups for client 127.0.0.4: \"SELECT id from vw_regex_whitelist WHERE group_id IN (4);\"' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_whitelist WHERE domain = ? AND group_id IN (4));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_blacklist WHERE domain = ? AND group_id IN (4));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_gravity WHERE domain = ? AND group_id IN (4));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex whitelist ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.4' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
  run bash -c "grep -c 'Regex blacklist ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.4' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "9" ]]
}

@test "Client 5: Client is recognized by MAC address" {
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.5 @127.0.0.1 +short"
  run sleep 0.1
  run bash -c "grep -c \"Found database hardware address 127.0.0.5 -> aa:bb:cc:dd:ee:ff\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Gravity database: Client aa:bb:cc:dd:ee:ff found. Using groups (4)\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex blacklist: Querying groups for client 127.0.0.5: \"SELECT id from vw_regex_blacklist WHERE group_id IN (4);\"' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex whitelist: Querying groups for client 127.0.0.5: \"SELECT id from vw_regex_whitelist WHERE group_id IN (4);\"' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_whitelist WHERE domain = ? AND group_id IN (4));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_blacklist WHERE domain = ? AND group_id IN (4));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_gravity WHERE domain = ? AND group_id IN (4));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex whitelist ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.5' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
  run bash -c "grep -c 'Regex blacklist ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.5' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "9" ]]
}

@test "Client 6: Client is recognized by interface name" {
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.6 @127.0.0.1 +short"
  run sleep 0.1
  run bash -c "grep -c \"Found database hardware address 127.0.0.6 -> 00:11:22:33:44:55\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"There is no record for 00:11:22:33:44:55 in the client table\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Found database interface 127.0.0.6 -> enp0s123\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Gravity database: Client 00:11:22:33:44:55 found (identified by interface enp0s123). Using groups (5)\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex blacklist: Querying groups for client 127.0.0.6: \"SELECT id from vw_regex_blacklist WHERE group_id IN (5);\"' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex whitelist: Querying groups for client 127.0.0.6: \"SELECT id from vw_regex_whitelist WHERE group_id IN (5);\"' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_whitelist WHERE domain = ? AND group_id IN (5));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_blacklist WHERE domain = ? AND group_id IN (5));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT EXISTS(SELECT domain from vw_gravity WHERE domain = ? AND group_id IN (5));' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex whitelist ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.6' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
  run bash -c "grep -c 'Regex blacklist ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.6' /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "9" ]]
}

@test "Normal query (A) is not blocked" {
  run bash -c "dig A a.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.1" ]]
}

@test "Normal query (AAAA) is not blocked (TCP query)" {
  run bash -c "dig AAAA aaaa.ftl @127.0.0.1 +short +tcp"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "fe80::1c01" ]]
}

@test "Mozilla canary domain is blocked with NXDOMAIN" {
  run bash -c "dig A use-application-dns.net @127.0.0.1"
  printf "dig: %s\n" "${lines[@]}"
  [[ ${lines[3]} == *"status: NXDOMAIN"* ]]
  run bash -c 'grep -c "Mozilla canary domain use-application-dns.net is NXDOMAIN" /var/log/pihole.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Local DNS reply test" {
  run bash -c "bash test/dig.sh | tee dig.log"
  printf "%s\n" "${lines[@]}"
}

@test "CNAME inspection: Shallow CNAME is blocked" {
  run bash -c "dig A cname-1.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "CNAME inspection: Deep CNAME is blocked" {
  run bash -c "dig A cname-4.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "DNSSEC: SECURE domain is resolved" {
  run bash -c "dig A sigok.verteiltesysteme.net @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *"status: NOERROR"* ]]
}

@test "DNSSEC: BOGUS domain is rejected" {
  run bash -c "dig A sigfail.verteiltesysteme.net @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *"status: SERVFAIL"* ]]
}

@test "Statistics as expected" {
  run bash -c 'echo ">stats >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "domains_being_blocked 3" ]]
  [[ ${lines[2]} == "dns_queries_today 47" ]]
  [[ ${lines[3]} == "ads_blocked_today 8" ]]
  #[[ ${lines[4]} == "ads_percentage_today 7.792208" ]]
  [[ ${lines[5]} == "unique_domains 34" ]]
  [[ ${lines[6]} == "queries_forwarded 26" ]]
  [[ ${lines[7]} == "queries_cached 13" ]]
  # Clients ever seen is commented out as CircleCI may have
  # more devices in its ARP cache so testing against a fixed
  # number of clients may not work in all cases
  #[[ ${lines[8]} == "clients_ever_seen 8" ]]
  #[[ ${lines[9]} == "unique_clients 8" ]]
  [[ ${lines[10]} == "dns_queries_all_types 47" ]]
  [[ ${lines[11]} == "reply_NODATA 0" ]]
  [[ ${lines[12]} == "reply_NXDOMAIN 4" ]]
  [[ ${lines[13]} == "reply_CNAME 5" ]]
  [[ ${lines[14]} == "reply_IP 23" ]]
  [[ ${lines[15]} == "privacy_level 0" ]]
  [[ ${lines[16]} == "status enabled" ]]
  [[ ${lines[17]} == "" ]]
}

# Here and below: It is not meaningful to assume a particular order
# here as the values are sorted before output. It is unpredictable in
# which order they may come out. While this has always been the same
# when compiling for glibc, the new musl build reveals that another
# library may have a different interpretation here.

@test "Top Clients" {
  run bash -c 'echo ">top-clients >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 32 127.0.0.1 "* ]]
  [[ ${lines[2]} == "1 5 :: "* ]]
  [[ ${lines[3]} == "2 4 127.0.0.3 "* ]]
  [[ ${lines[4]} == "3 3 127.0.0.2 "* ]]
  [[ "${lines[@]}" == *"1 aliasclient-0 some-aliasclient"* ]]
  [[ "${lines[@]}" == *"1 127.0.0.4 "* ]]
  [[ "${lines[@]}" == *"1 127.0.0.5 "* ]]
}

@test "Top Domains" {
  run bash -c 'echo ">top-domains (60) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *" 4 version.bind"* ]]
  [[ "${lines[@]}" == *" 4 regex1.ftl"* ]]
  [[ "${lines[@]}" == *" 3 a.ftl"* ]]
  [[ "${lines[@]}" == *" 2 blacklisted.ftl"* ]]
  [[ "${lines[@]}" == *" 2 aaaa.ftl"* ]]
  [[ "${lines[@]}" == *" 2 net"* ]]
  [[ "${lines[@]}" == *" 2 verteiltesysteme.net"* ]]
  [[ "${lines[@]}" == *" 1 version.ftl"* ]]
  [[ "${lines[@]}" == *" 1 whitelisted.ftl"* ]]
  [[ "${lines[@]}" == *" 1 gravity-whitelisted.ftl"* ]]
  [[ "${lines[@]}" == *" 1 regexa.ftl"* ]]
  [[ "${lines[@]}" == *" 1 regex2.ftl"* ]]
  [[ "${lines[@]}" == *" 1 use-application-dns.net"* ]]
  [[ "${lines[@]}" == *" 1 any.ftl"* ]]
  [[ "${lines[@]}" == *" 1 cname.ftl"* ]]
  [[ "${lines[@]}" == *" 1 srv.ftl"* ]]
  [[ "${lines[@]}" == *" 1 soa.ftl"* ]]
  [[ "${lines[@]}" == *" 1 ptr.ftl"* ]]
  [[ "${lines[@]}" == *" 1 txt.ftl"* ]]
  [[ "${lines[@]}" == *" 1 naptr.ftl"* ]]
  [[ "${lines[@]}" == *" 1 mx.ftl"* ]]
  [[ "${lines[@]}" == *" 1 ns.ftl"* ]]
  [[ "${lines[@]}" == *" 1 svcb.ftl"* ]]
  [[ "${lines[@]}" == *" 1 https.ftl"* ]]
  [[ "${lines[@]}" == *" 1 sigok.verteiltesysteme.net"* ]]
  [[ "${lines[@]}" == *" 1 ."* ]]
  [[ "${lines[@]}" == *" 1 sigfail.verteiltesysteme.net"* ]]
}

@test "Top Ads" {
  run bash -c 'echo ">top-ads (20) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *" 4 gravity.ftl"* ]]
  [[ "${lines[@]}" == *" 1 blacklisted.ftl"* ]]
  [[ "${lines[@]}" == *" 1 whitelisted.ftl"* ]]
  [[ "${lines[@]}" == *" 1 regex5.ftl"* ]]
  [[ "${lines[@]}" == *" 1 regex1.ftl"* ]]
  [[ "${lines[@]}" == *" 1 cname-1.ftl"* ]]
  [[ "${lines[@]}" == *" 1 cname-4.ftl"* ]]
  [[ ${lines[8]} == "" ]]
}

@test "Domain auditing, approved domains are not shown" {
  run bash -c 'echo ">top-domains for audit >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} != *"google.com"* ]]
}

@test "Upstream Destinations reported correctly" {
  run bash -c 'echo ">forward-dest >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "-2 17.02 blocklist blocklist" ]]
  [[ ${lines[2]} == "-1 27.66 cache cache" ]]
  [[ ${lines[3]} == "0 51.06 127.0.0.1#5555 127.0.0.1#5555" ]]
  [[ ${lines[4]} == "1 4.26 127.0.0.1#5554 127.0.0.1#5554" ]]
  [[ ${lines[5]} == "" ]]
}

@test "Query Types reported correctly" {
  run bash -c 'echo ">querytypes >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]}  == "A (IPv4): 51.06" ]]
  [[ ${lines[2]}  == "AAAA (IPv6): 4.26" ]]
  [[ ${lines[3]}  == "ANY: 2.13" ]]
  [[ ${lines[4]}  == "SRV: 2.13" ]]
  [[ ${lines[5]}  == "SOA: 2.13" ]]
  [[ ${lines[6]}  == "PTR: 2.13" ]]
  [[ ${lines[7]}  == "TXT: 12.77" ]]
  [[ ${lines[8]}  == "NAPTR: 2.13" ]]
  [[ ${lines[9]}  == "MX: 2.13" ]]
  [[ ${lines[10]} == "DS: 4.26" ]]
  [[ ${lines[11]} == "RRSIG: 0.00" ]]
  [[ ${lines[12]} == "DNSKEY: 6.38" ]]
  [[ ${lines[13]} == "NS: 2.13" ]]
  [[ ${lines[14]} == "OTHER: 2.13" ]]
  [[ ${lines[15]} == "SVCB: 2.13" ]]
  [[ ${lines[16]} == "HTTPS: 2.13" ]]
  [[ ${lines[17]} == "" ]]
}

# Here and below: Reply time is varying. don't test for a particular value (..."*"...)

@test "Get all queries shows expected content" {
  run bash -c 'echo ">getallqueries >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]}  == *" TXT version.ftl 127.0.0.1 3 2 6 "*" N/A -1 N/A#0 \"\" \"0\""* ]]
  [[ ${lines[2]}  == *" TXT version.bind 127.0.0.1 3 2 6 "*" N/A -1 N/A#0 \"\" \"1\""* ]]
  [[ ${lines[3]}  == *" A blacklisted.ftl 127.0.0.1 5 2 4 "*" N/A -1 N/A#0 \"\" \"2\""* ]]
  [[ ${lines[4]}  == *" A gravity.ftl 127.0.0.1 1 2 4 "*" N/A -1 N/A#0 \"\" \"3\""* ]]
  [[ ${lines[5]}  == *" A gravity.ftl 127.0.0.1 1 2 4 "*" N/A -1 N/A#0 \"\" \"4\""* ]]
  [[ ${lines[6]}  == *" A whitelisted.ftl 127.0.0.1 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"5\""* ]]
  [[ ${lines[7]}  == *" A gravity-whitelisted.ftl 127.0.0.1 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"6\""* ]]
  [[ ${lines[8]}  == *" A regex5.ftl 127.0.0.1 4 2 4 "*" N/A 6 N/A#0 \"\" \"7\""* ]]
  [[ ${lines[9]}  == *" A regexa.ftl 127.0.0.1 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"8\""* ]]
  [[ ${lines[10]} == *" A regex1.ftl 127.0.0.1 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"9\""* ]]
  [[ ${lines[11]} == *" A regex2.ftl 127.0.0.1 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"10\""* ]]
  [[ ${lines[12]} == *" A whitelisted.ftl 127.0.0.2 1 2 4 "*" N/A -1 N/A#0 \"\" \"11\""* ]]
  [[ ${lines[13]} == *" A regex1.ftl 127.0.0.2 4 2 4 "*" N/A 6 N/A#0 \"\" \"12\""* ]]
  [[ ${lines[14]} == *" A regex1.ftl 127.0.0.1 3 2 4 "*" N/A -1 N/A#0 \"\" \"13\""* ]]
  [[ ${lines[15]} == *" A regex1.ftl 127.0.0.3 3 2 4 "*" N/A -1 N/A#0 \"\" \"14\""* ]]
  [[ ${lines[16]} == *" A blacklisted.ftl 127.0.0.2 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"15\""* ]]
  [[ ${lines[17]} == *" A blacklisted.ftl 127.0.0.3 3 2 4 "*" N/A -1 N/A#0 \"\" \"16\""* ]]
  [[ ${lines[18]} == *" A regex1.ftl 127.0.0.3 3 2 4 "*" N/A -1 N/A#0 \"\" \"17\""* ]]
  [[ ${lines[19]} == *" A a.ftl 127.0.0.3 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"18\""* ]]
  [[ ${lines[20]} == *" TXT version.bind 127.0.0.4 3 2 6 "*" N/A -1 N/A#0 \"\" \"19\""* ]]
  [[ ${lines[21]} == *" TXT version.bind 127.0.0.5 3 2 6 "*" N/A -1 N/A#0 \"\" \"20\""* ]]
  [[ ${lines[22]} == *" TXT version.bind 127.0.0.6 3 2 6 "*" N/A -1 N/A#0 \"\" \"21\""* ]]
  [[ ${lines[23]} == *" A a.ftl 127.0.0.1 3 2 4 "*" N/A -1 N/A#0 \"\" \"22\""* ]]
  [[ ${lines[24]} == *" AAAA aaaa.ftl 127.0.0.1 2 2 4 "*" N/A -1 127.0.0.1#5555 \"\" \"23\""* ]]
  [[ ${lines[25]} == *" A use-application-dns.net 127.0.0.1 3 2 2 "*" N/A -1 N/A#0 \"\" \"24\""* ]]
  [[ ${lines[26]} == *" A a.ftl 127.0.0.1 3 2 4 "*" N/A -1 N/A#0 \"\" \"25\""* ]]
  [[ ${lines[27]} == *" AAAA aaaa.ftl 127.0.0.1 3 2 4 "*" N/A -1 N/A#0 \"\" \"26\""* ]]
  [[ ${lines[28]} == *" ANY any.ftl 127.0.0.1 2 2 2 "*" N/A -1 127.0.0.1#5555 \"\" \"27\""* ]]
  [[ ${lines[29]} == *" [CNAME] cname.ftl 127.0.0.1 2 2 2 "*" N/A -1 127.0.0.1#5555 \"\" \"28\""* ]]
  [[ ${lines[30]} == *" SRV srv.ftl 127.0.0.1 2 2 13 "*" N/A -1 127.0.0.1#5555 \"\" \"29\""* ]]
  [[ ${lines[31]} == *" SOA soa.ftl 127.0.0.1 2 2 3 "*" N/A -1 127.0.0.1#5555 \"\" \"30\""* ]]
  [[ ${lines[32]} == *" PTR ptr.ftl 127.0.0.1 2 2 13 "*" N/A -1 127.0.0.1#5555 \"\" \"31\""* ]]
  [[ ${lines[33]} == *" TXT txt.ftl 127.0.0.1 2 2 13 "*" N/A -1 127.0.0.1#5555 \"\" \"32\""* ]]
  [[ ${lines[34]} == *" NAPTR naptr.ftl 127.0.0.1 2 2 13 "*" N/A -1 127.0.0.1#5555 \"\" \"33\""* ]]
  [[ ${lines[35]} == *" MX mx.ftl 127.0.0.1 2 2 13 "*" N/A -1 127.0.0.1#5555 \"\" \"34\""* ]]
  [[ ${lines[36]} == *" NS ns.ftl 127.0.0.1 2 2 2 "*" N/A -1 127.0.0.1#5555 \"\" \"35\""* ]]
  [[ ${lines[37]} == *" SVCB svcb.ftl 127.0.0.1 2 2 13 "*" N/A -1 127.0.0.1#5554 \"\" \"36\""* ]]
  [[ ${lines[38]} == *" HTTPS https.ftl 127.0.0.1 2 2 13 "*" N/A -1 127.0.0.1#5554 \"\" \"37\""* ]]
  [[ ${lines[39]} == *" A cname-1.ftl 127.0.0.1 9 2 3 "*" gravity.ftl -1 127.0.0.1#5555 \"\" \"38\""* ]]
  [[ ${lines[40]} == *" A cname-4.ftl 127.0.0.1 9 2 3 "*" gravity.ftl -1 127.0.0.1#5555 \"\" \"39\""* ]]
  [[ ${lines[41]} == *" A sigok.verteiltesysteme.net 127.0.0.1 2 1 4 "*" N/A -1 127.0.0.1#5555 \"\" \"40\""* ]]
  [[ ${lines[42]} == *" DS net :: 2 1 11 "*" N/A -1 127.0.0.1#5555 \"\" \"41\""* ]]
  [[ ${lines[43]} == *" DNSKEY . :: 2 1 11 "*" N/A -1 127.0.0.1#5555 \"\" \"42\""* ]]
  [[ ${lines[44]} == *" DS verteiltesysteme.net :: 2 1 11 "*" N/A -1 127.0.0.1#5555 \"\" \"43\""* ]]
  [[ ${lines[45]} == *" DNSKEY net :: 2 1 11 "*" N/A -1 127.0.0.1#5555 \"\" \"44\""* ]]
  [[ ${lines[46]} == *" DNSKEY verteiltesysteme.net :: 2 1 11 "*" N/A -1 127.0.0.1#5555 \"\" \"45\""* ]]
  [[ ${lines[47]} == *" A sigfail.verteiltesysteme.net 127.0.0.1 2 3 4 "*" N/A -1 127.0.0.1#5555 \"DNSKEY missing\" \"46\""* ]]
  [[ ${lines[48]} == "" ]]
}

@test "Get all queries (domain filtered) shows expected content" {
  run bash -c 'echo ">getallqueries-domain regexa.ftl >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regexa.ftl 127.0.0.1 2 2 4"* ]]
  [[ ${lines[2]} == "" ]]
}

@test "Recent blocked shows expected content" {
  run bash -c 'echo ">recentBlocked >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "cname-4.ftl" ]]
  [[ ${lines[2]} == "" ]]
}

@test "pihole-FTL.db schema is as expected" {
  run bash -c 'sqlite3 /etc/pihole/pihole-FTL.db .dump'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"CREATE TABLE queries (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT, additional_info TEXT);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE ftl (id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE counters (id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE IF NOT EXISTS \"network\" (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL, interface TEXT NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL, macVendor TEXT, aliasclient_id INTEGER);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE IF NOT EXISTS \"network_addresses\" (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL, lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)), name TEXT, nameUpdated INTEGER, FOREIGN KEY(network_id) REFERENCES network(id));"* ]]
  [[ "${lines[@]}" == *"CREATE INDEX idx_queries_timestamps ON queries (timestamp);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE aliasclient (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, comment TEXT);"* ]]
  # Depending on the version of sqlite3, ftl can be enquoted or not...
  [[ "${lines[@]}" == *"INSERT INTO"?*"ftl"?*"VALUES(0,9);"* ]]
}

@test "Ownership, permissions and type of pihole-FTL.db correct" {
  run bash -c 'ls -l /etc/pihole/pihole-FTL.db'
  printf "%s\n" "${lines[@]}"
  # Depending on the shell (x86_64-musl is built on busybox) there can be one or multiple spaces between user and group
  [[ ${lines[0]} == *"pihole"?*"pihole"* ]]
  [[ ${lines[0]} == "-rw-rw-r--"* ]]
  run bash -c 'file /etc/pihole/pihole-FTL.db'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "/etc/pihole/pihole-FTL.db: SQLite 3.x database"* ]]
}

@test "Test fail on invalid CLI argument" {
  run bash -c '/home/pihole/pihole-FTL abc'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL: invalid option -- 'abc'" ]]
  [[ ${lines[1]} == "Command: '/home/pihole/pihole-FTL abc'" ]]
  [[ ${lines[2]} == "Try '/home/pihole/pihole-FTL --help' for more information" ]]
}

@test "Help CLI argument return help text" {
  run bash -c '/home/pihole/pihole-FTL help'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL - The Pi-hole FTL engine" ]]
  [[ ${lines[3]} == "Available arguments:" ]]
}

@test "No WARNING messages in pihole-FTL.log (besides known capability issues)" {
  run bash -c 'grep "WARNING" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  run bash -c 'grep "WARNING" /var/log/pihole-FTL.log | grep -c -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "No \"database not available\" messages in pihole-FTL.log" {
  run bash -c 'grep -c "database not available" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "No ERROR messages in pihole-FTL.log" {
  run bash -c 'grep "ERROR" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  run bash -c 'grep -c "ERROR" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "No FATAL messages in pihole-FTL.log (besides error due to starting FTL more than once)" {
  run bash -c 'grep "FATAL" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  run bash -c 'grep "FATAL:" /var/log/pihole-FTL.log | grep -c -v "FATAL: create_shm(): Failed to create shared memory object \"FTL-lock\": File exists"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

# Regex tests
@test "Compiled blacklist regex as expected" {
  run bash -c 'grep -c "Compiling blacklist regex 0 (DB ID 6): regex\[0-9\].ftl" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Compiled whitelist regex as expected" {
  run bash -c 'grep -c "Compiling whitelist regex 0 (DB ID 3): regex2" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "Compiling whitelist regex 1 (DB ID 4): ^gravity-whitelisted" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Regex Test 1: \"regex7.ftl\" vs. [database regex]: MATCH" {
  run bash -c './pihole-FTL regex-test "regex7.ftl"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 2: \"a\" vs. \"a\": MATCH" {
  run bash -c './pihole-FTL regex-test "a" "a"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 3: \"aa\" vs. \"^[a-z]{1,3}$\": MATCH" {
  run bash -c './pihole-FTL regex-test "aa" "^[a-z]{1,3}$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 4: \"aaaa\" vs. \"^[a-z]{1,3}$\": NO MATCH" {
  run bash -c './pihole-FTL regex-test "aaaa" "^[a-z]{1,3}$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 5: \"aa\" vs. \"^a(?#some comment)a$\": MATCH (comments)" {
  run bash -c './pihole-FTL regex-test "aa" "^a(?#some comment)a$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 6: \"abc.abc\" vs. \"([a-z]*)\.\1\": MATCH" {
  run bash -c './pihole-FTL regex-test "abc.abc" "([a-z]*)\.\1"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 7: Complex character set: MATCH" {
  run bash -c './pihole-FTL regex-test "__abc#LMN012$x%yz789*" "[[:digit:]a-z#$%]+"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 8: Range expression: MATCH" {
  run bash -c './pihole-FTL regex-test "!ABC-./XYZ~" "[--Z]+"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 9: Back reference: \"aabc\" vs. \"(a)\1{1,2}\": MATCH" {
  run bash -c './pihole-FTL regex-test "aabc" "(a)\1{1,2}"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 10: Back reference: \"foo\" vs. \"(.)\1$\": MATCH" {
  run bash -c './pihole-FTL regex-test "foo" "(.)\1$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 11: Back reference: \"foox\" vs. \"(.)\1$\": NO MATCH" {
  run bash -c './pihole-FTL regex-test "foox" "(.)\1$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 12: Back reference: \"1234512345\" vs. \"([0-9]{5})\1\": MATCH" {
  run bash -c './pihole-FTL regex-test "1234512345" "([0-9]{5})\1"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 13: Back reference: \"12345\" vs. \"([0-9]{5})\1\": NO MATCH" {
  run bash -c './pihole-FTL regex-test "12345" "([0-9]{5})\1"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 14: Complex back reference: MATCH" {
  run bash -c './pihole-FTL regex-test "cat.foo.dog---cat%dog!foo" "(cat)\.(foo)\.(dog)---\1%\3!\2"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 15: Approximate matching, 0 errors: MATCH" {
  run bash -c './pihole-FTL regex-test "foobarzap" "foo(bar){~1}zap"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 16: Approximate matching, 1 error (inside fault-tolerant area): MATCH" {
  run bash -c './pihole-FTL regex-test "foobrzap" "foo(bar){~1}zap"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 17: Approximate matching, 1 error (outside fault-tolert area): NO MATCH" {
  run bash -c './pihole-FTL regex-test "foxbrazap" "foo(bar){~1}zap"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 18: Approximate matching, 0 global errors: MATCH" {
  run bash -c './pihole-FTL regex-test "foobar" "^(foobar){~1}$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 19: Approximate matching, 1 global error: MATCH" {
  run bash -c './pihole-FTL regex-test "cfoobar" "^(foobar){~1}$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 20: Approximate matching, 2 global errors: NO MATCH" {
  run bash -c './pihole-FTL regex-test "ccfoobar" "^(foobar){~1}$"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 21: Approximate matching, insert + substitute: MATCH" {
  run bash -c './pihole-FTL regex-test "oobargoobaploowap" "(foobar){+2#2~2}"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 22: Approximate matching, insert + delete: MATCH" {
  run bash -c './pihole-FTL regex-test "3oifaowefbaoraofuiebofasebfaobfaorfeoaro" "(foobar){+1 -2}"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 23: Approximate matching, insert + delete (insufficient): NO MATCH" {
  run bash -c './pihole-FTL regex-test "3oifaowefbaoraofuiebofasebfaobfaorfeoaro" "(foobar){+1 -1}"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 24: Useful hint for invalid regular expression \"f{x}\": Invalid contents of {}" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "f{x}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"f{x}\": Invalid contents of {}" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 25: Useful hint for invalid regular expression \"a**\": Invalid use of repetition operators" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "a**"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"a**\": Invalid use of repetition operators" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 26: Useful hint for invalid regular expression \"x\\\": Trailing backslash" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "x\\"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"x\\\": Trailing backslash" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 27: Useful hint for invalid regular expression \"[\": Missing ']'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "["'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"[\": Missing ']'" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 28: Useful hint for invalid regular expression \"(\": Missing ')'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "("'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"(\": Missing ')'" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 29: Useful hint for invalid regular expression \"{1\": Missing '}'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "{1"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"{1\": Missing '}'" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 30: Useful hint for invalid regular expression \"[[.foo.]]\": Unknown collating element" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[[.foo.]]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"[[.foo.]]\": Unknown collating element" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 31: Useful hint for invalid regular expression \"[[:foobar:]]\": Unknown character class name" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[[:foobar:]]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"[[:foobar:]]\": Unknown character class name" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 32: Useful hint for invalid regular expression \"(a)\\2\": Invalid back reference" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "(a)\\2"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"(a)\\2\": Invalid back reference" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 33: Useful hint for invalid regular expression \"[g-1]\": Invalid character range" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[g-1]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "REGEX WARNING: Invalid regex CLI filter \"[g-1]\": Invalid character range" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 34: Quiet mode: Match = Return code 0, nothing else" {
  run bash -c './pihole-FTL -q regex-test "fbcdn.net" "f"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Regex Test 35: Quiet mode: Invalid regex = Return code 1, with error message" {
  run bash -c './pihole-FTL -q regex-test "fbcdn.net" "g{x}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "REGEX WARNING: Invalid regex CLI filter \"g{x}\": Invalid contents of {}" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 36: Quiet mode: No Match = Return code 2, nothing else" {
  run bash -c './pihole-FTL -q regex-test "fbcdn.net" "g"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 37: Option \";querytype=A\" working as expected (ONLY matching A queries)" {
  run bash -c 'dig A regex-A @127.0.0.1 +short'
  printf "dig A: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  run bash -c 'dig AAAA regex-A @127.0.0.1 +short'
  printf "dig AAAA: %s\n" "${lines[@]}"
  [[ ${lines[0]} != "::" ]]
}

@test "Regex Test 38: Option \";querytype=!A\" working as expected (NOT matching A queries)" {
  run bash -c 'dig A regex-notA @127.0.0.1 +short'
  printf "dig A: %s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
  run bash -c 'dig AAAA regex-notA @127.0.0.1 +short'
  printf "dig AAAA: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "::" ]]
}

@test "Regex Test 39: Option \";invert\" working as expected (match is inverted)" {
  run bash -c './pihole-FTL -q regex-test "f" "g;invert"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  run bash -c './pihole-FTL -q regex-test "g" "g;invert"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 40: Option \";querytype\" sanity checks" {
  run bash -c './pihole-FTL regex-test "f" g\;querytype=!A\;querytype=A'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
  [[ ${lines[1]} == *"Overwriting previous querytype setting" ]]
}

@test "Regex Test 41: Option \"^;reply=NXDOMAIN\" working as expected" {
  run bash -c 'dig A regex-NXDOMAIN @127.0.0.1'
  printf "dig: %s\n" "${lines[@]}"
  [[ ${lines[3]} == *"status: NXDOMAIN"* ]]
}

@test "Regex Test 42: Option \"^;reply=NODATA\" working as expected" {
  run bash -c 'dig A regex-NODATA @127.0.0.1'
  printf "dig (full): %s\n" "${lines[@]}"
  [[ ${lines[3]} == *"status: NOERROR"* ]]
}

@test "Regex Test 43: Option \";reply=REFUSED\" working as expected" {
  run bash -c 'dig A regex-REFUSED @127.0.0.1'
  printf "dig (full): %s\n" "${lines[@]}"
  [[ ${lines[3]} == *"status: REFUSED"* ]]
}

@test "Regex Test 44: Option \";reply=1.2.3.4\" working as expected" {
  run bash -c 'dig A regex-REPLYv4 @127.0.0.1 +short'
  printf "dig A: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1.2.3.4" ]]
  run bash -c 'dig AAAA regex-REPLYv4 @127.0.0.1 +short'
  printf "dig AAAA: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "::" ]]
}

@test "Regex Test 45: Option \";reply=fe80::1234\" working as expected" {
  run bash -c 'dig A regex-REPLYv6 @127.0.0.1 +short'
  printf "dig A: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  run bash -c 'dig AAAA regex-REPLYv6 @127.0.0.1 +short'
  printf "dig AAAA: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "fe80::1234" ]]
}

@test "Regex Test 46: Option \";reply=1.2.3.4;reply=fe80::1234\" working as expected" {
  run bash -c 'dig A regex-REPLYv46 @127.0.0.1 +short'
  printf "dig A: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1.2.3.4" ]]
  run bash -c 'dig AAAA regex-REPLYv46 @127.0.0.1 +short'
  printf "dig AAAA: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "fe80::1234" ]]
}

# x86_64-musl is built on busybox which has a slightly different
# variant of ls displaying three, instead of one, spaces between the
# user and group names.

@test "Ownership and permissions of pihole-FTL.db correct" {
  run bash -c 'ls -l /etc/pihole/pihole-FTL.db'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == *"pihole pihole"* || ${lines[0]} == *"pihole   pihole"* ]]
  [[ ${lines[0]} == "-rw-rw-r--"* ]]
}

# "ldd" prints library dependencies and the used interpreter for a given program
#
# Dependencies on shared libraries are displayed like
#    libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fa7d28be000)
#
# In this test, we use ldd and check for the dependency arrow "=>" to check if
# our generated binary depends on shared libraries in the way we expect it to

@test "Dependence on shared libraries" {
  run bash -c 'ldd ./pihole-FTL'
  printf "%s\n" "${lines[@]}"
  [[ "${STATIC}" != "true" && "${lines[@]}" == *"=>"* ]] || \
  [[ "${STATIC}" == "true" && "${lines[@]}" != *"=>"* ]]
}

# "file" determines the file type of our generated binary
#
# We use its ability to test whether a specific interpreter is
# required by the given executable. What the interpreter is, is not
# really well documented in "man elf(5)", however, one can say that
# the interpreter is a program that finds and loads the shared
# libraries needed by a program, prepares the program to run, and then
# runs it.
#
# In this test, we use "file" to confirm the absence of the dependence
# on an interpreter for the static binary.

@test "Dependence on specific interpreter" {
  run bash -c 'file ./pihole-FTL'
  printf "%s\n" "${lines[@]}"
  [[ "${STATIC}" != "true" && "${lines[@]}" == *"interpreter"* ]] || \
  [[ "${STATIC}" == "true" && "${lines[@]}" != *"interpreter"* ]]
}

@test "Architecture is correctly reported on startup" {
  run bash -c 'grep "Compiled for" /var/log/pihole-FTL.log'
  printf "Output: %s\n\$CIRCLE_JOB: %s\nuname -m: %s\n" "${lines[@]:-not set}" "${CIRCLE_JOB:-not set}" "$(uname -m)"
  [[ ${lines[0]} == *"Compiled for ${CIRCLE_JOB:-$(uname -m)}"* ]]
}

@test "Building machine (CI) is reported on startup" {
  [[ ${CIRCLE_JOB} != "" ]] && compiled_str="on CI" || compiled_str="locally" && export compiled_str
  run bash -c 'grep "Compiled for" /var/log/pihole-FTL.log'
  printf "Output: %s\n\$CIRCLE_JOB: %s\n" "${lines[@]:-not set}" "${CIRCLE_JOB:-not set}"
  [[ ${lines[0]} == *"(compiled ${compiled_str})"* ]]
}

@test "Compiler version is correctly reported on startup" {
  compiler_version="$(${CC} --version | head -n1)" && export compiler_version
  run bash -c 'grep "Compiled for" /var/log/pihole-FTL.log'
  printf "Output: %s\n\$CC: %s\nVersion: %s\n" "${lines[@]:-not set}" "${CC:-not set}" "${compiler_version:-not set}"
  [[ ${lines[0]} == *"using ${compiler_version}"* ]]
}

@test "No errors on setting busy handlers for the databases" {
  run bash -c 'grep -c "Cannot set busy handler" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "Blocking status is correctly logged in pihole.log" {
  run bash -c 'grep -c "gravity blocked gravity.ftl is 0.0.0.0" /var/log/pihole.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
}

@test "Port file exists and contains expected API port" {
  run bash -c 'cat /run/pihole-FTL.port'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "4711" ]]
}

@test "LUA: Interpreter returns FTL version" {
  run bash -c './pihole-FTL lua -e "print(pihole.ftl_version())"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "v"* ]]
}

@test "LUA: Interpreter loads and enabled bundled library \"inspect\"" {
  run bash -c './pihole-FTL lua -e "print(inspect(inspect))"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *'_DESCRIPTION = "human-readable representations of tables"'* ]]
  [[ ${lines[@]} == *'_VERSION = "inspect.lua 3.1.0"'* ]]
}

@test "EDNS(0) analysis working as expected" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Run test command
  #                                  CLIENT SUBNET          COOKIE                       MAC HEX                     MAC TEXT                                          CPE-ID
  run bash -c 'dig localhost +short +subnet=192.168.1.1/32 +ednsopt=10:1122334455667788 +ednsopt=65001:000102030405 +ednsopt=65073:41413A42423A43433A44443A45453A4646 +ednsopt=65074:414243444546 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole-FTL.log)"
  printf "%s\n" "${log}"

  # Start actual test
  run bash -c "grep -c \"EDNS(0) CLIENT SUBNET: 192.168.1.1/32\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS(0) COOKIE (client-only): 1122334455667788\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS(0) MAC address (BYTE format): 00:01:02:03:04:05\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS(0) MAC address (TEXT format): AA:BB:CC:DD:EE:FF\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS(0) CPE-ID (payload size 6): \\\"ABCDEF\\\" (0x41 0x42 0x43 0x44 0x45 0x46)\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "EDNS(0) ECS can overwrite client address (IPv4)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=192.168.47.97/32 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"**** new UDP IPv4 query[A] query \"localhost\" from lo:192.168.47.97#53 "* ]]
}

@test "EDNS(0) ECS can overwrite client address (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=fe80::b167:af1e:968b:dead/128 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"**** new UDP IPv4 query[A] query \"localhost\" from lo:fe80::b167:af1e:968b:dead#53 "* ]]
}

@test "alias-client is imported and used for configured client" {
  run bash -c 'grep -c "Added alias-client \"some-aliasclient\" (aliasclient-0) with FTL ID 0" /var/log/pihole-FTL.log'
  printf "Added: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "Aliasclient ID 127.0.0.6 -> 0" /var/log/pihole-FTL.log'
  printf "Found ID: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "Client .* (127.0.0.6) IS  managed by this alias-client, adding counts" /var/log/pihole-FTL.log'
  printf "Adding counts: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "EDNS(0) ECS skipped for loopback address (IPv4)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=127.0.0.1/32 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"EDNS(0) CLIENT SUBNET: Skipped 127.0.0.1/32 (IPv4 loopback address)"* ]]
}

@test "EDNS(0) ECS skipped for loopback address (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=::1/128 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole-FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole-FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"EDNS(0) CLIENT SUBNET: Skipped ::1/128 (IPv6 loopback address)"* ]]
}

@test "Embedded SQLite3 shell available and functional" {
  run bash -c './pihole-FTL sqlite3 -help'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Usage: sqlite3 [OPTIONS] FILENAME [SQL]" ]]
}

@test "Embedded SQLite3 shell is called for .db file" {
  run bash -c './pihole-FTL abc.db ".version"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "SQLite 3."* ]]
}

@test "Embedded LUA engine is called for .lua file" {
  echo 'print("Hello from LUA")' > abc.lua
  run bash -c './pihole-FTL abc.lua'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Hello from LUA" ]]
  rm abc.lua
}

@test "Pi-hole PTR generation check" {
  run bash -c "bash test/hostnames.sh | tee ptr.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" != *"ERROR"* ]]
}
