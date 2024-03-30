#!./test/libs/bats/bin/bats

#@test "Version, Tag, Branch, Hash, Date is reported" {
#  run bash -c 'echo ">version >quit" | nc -v 127.0.0.1 4711'
#  printf "%s\n" "${lines[@]}"
#  [[ ${lines[1]} == "version "* ]]
#  [[ ${lines[2]} == "tag "* ]]
#  [[ ${lines[3]} == "branch "* ]]
#  [[ ${lines[4]} == "hash "* ]]
#  [[ ${lines[5]} == "date "* ]]
#  [[ ${lines[6]} == "" ]]
#}
#
#@test "DNS server port is reported over Telnet API" {
#  run bash -c 'echo ">dns-port >quit" | nc -v 127.0.0.1 4711'
#  printf "%s\n" "${lines[@]}"
#  [[ ${lines[1]} == "53" ]]
#  [[ ${lines[2]} == "" ]]
#}
#
#@test "Maxlogage value is reported over Telnet API" {
#  run bash -c 'echo ">maxlogage >quit" | nc -v 127.0.0.1 4711'
#  printf "%s\n" "${lines[@]}"
#  [[ ${lines[1]} == "86400" ]]
#  [[ ${lines[2]} == "" ]]
#}
#
@test "Running a second instance is detected and prevented" {
  run bash -c 'su pihole -s /bin/sh -c "/home/pihole/pihole-FTL -f"'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"CRIT: Initialization of shared memory failed."* ]]
  [[ "${lines[@]}" == *"INFO: pihole-FTL is already running"* ]]
}

@test "dnsmasq options as expected" {
  run bash -c './pihole-FTL -vv | grep "cryptohash"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Features:        IPv6 GNU-getopt no-DBus no-UBus no-i18n IDN2 DHCP DHCPv6 Lua TFTP no-conntrack ipset no-nftset auth cryptohash DNSSEC loop-detect inotify dumpfile" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Starting tests without prior history" {
  run bash -c 'grep -c "Total DNS queries: 0" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Initial blocking status is enabled" {
  run bash -c 'grep -c "Blocking status is enabled" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
}

@test "Number of compiled regex filters as expected" {
  run bash -c 'grep "Compiled [0-9]* allow" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == *"Compiled 2 allow and 11 deny regex for 1 client in "* ]]
}

@test "denied domain is blocked" {
  run bash -c "dig denied.ftl @127.0.0.1 +short"
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

@test "Gravity domain + allowed exact match is not blocked" {
  run bash -c "dig allowed.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.4" ]]
}

@test "Gravity domain + allowed regex match is not blocked" {
  run bash -c "dig gravity-allowed.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.5" ]]
}

@test "Gravity + antigravity exact matches are not blocked" {
  run bash -c "dig antigravity.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.6" ]]
}

@test "Regex denied match is blocked" {
  run bash -c "dig regex5.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Regex denylist mismatch is not blocked" {
  run bash -c "dig regexA.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.4" ]]
}

@test "Regex denylist match + allowlist exact match is not blocked" {
  run bash -c "dig regex1.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.1" ]]
}

@test "Regex denylist match + allowlist regex match is not blocked" {
  run bash -c "dig regex2.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.2.2" ]]
}

@test "Client 2: Gravity match matching unassociated allowlist is blocked" {
  run bash -c "dig allowed.ftl -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
}

@test "Client 2: Regex denylist match matching unassociated whitelist is blocked" {
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

@test "Client 2: Unassociated denylist match is not blocked" {
  run bash -c "dig denied.ftl -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.3" ]]
}

@test "Client 3: Exact denylist domain is not blocked" {
  run bash -c "dig denied.ftl -b 127.0.0.3 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.3" ]]
}

@test "Client 3: Regex denylist domain is not blocked" {
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
  run bash -c "grep -c \"Found database hardware address 127.0.0.4 -> aa:bb:cc:dd:ee:ff\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Gravity database: Client aa:bb:cc:dd:ee:ff found. Using groups (4)\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex deny: Querying groups for client 127.0.0.4: \"SELECT id from vw_regex_blacklist WHERE group_id IN (4);\"' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex allow: Querying groups for client 127.0.0.4: \"SELECT id from vw_regex_whitelist WHERE group_id IN (4);\"' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT id from vw_whitelist WHERE domain = ? AND group_id IN (4);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT id from vw_blacklist WHERE domain = ? AND group_id IN (4);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT adlist_id from vw_gravity WHERE domain = ? AND group_id IN (4);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex allow ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.4' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
  run bash -c "grep -c 'Regex deny ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.4' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "11" ]]
}

@test "Client 5: Client is recognized by MAC address" {
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.5 @127.0.0.1 +short"
  run sleep 0.1
  run bash -c "grep -c \"Found database hardware address 127.0.0.5 -> aa:bb:cc:dd:ee:ff\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Gravity database: Client aa:bb:cc:dd:ee:ff found. Using groups (4)\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex deny: Querying groups for client 127.0.0.5: \"SELECT id from vw_regex_blacklist WHERE group_id IN (4);\"' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex allow: Querying groups for client 127.0.0.5: \"SELECT id from vw_regex_whitelist WHERE group_id IN (4);\"' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT id from vw_whitelist WHERE domain = ? AND group_id IN (4);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT id from vw_blacklist WHERE domain = ? AND group_id IN (4);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT adlist_id from vw_gravity WHERE domain = ? AND group_id IN (4);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0" ]]
  run bash -c "grep -c 'Regex allow ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.5' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
  run bash -c "grep -c 'Regex deny ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.5' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "11" ]]
}

@test "Client 6: Client is recognized by interface name" {
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.6 @127.0.0.1 +short"
  run sleep 0.1
  run bash -c "grep -c \"Found database hardware address 127.0.0.6 -> 00:11:22:33:44:55\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"There is no record for 00:11:22:33:44:55 in the client table\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Found database interface 127.0.0.6 -> enp0s123\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"Gravity database: Client 00:11:22:33:44:55 found (identified by interface enp0s123). Using groups (5)\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex deny: Querying groups for client 127.0.0.6: \"SELECT id from vw_regex_blacklist WHERE group_id IN (5);\"' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex allow: Querying groups for client 127.0.0.6: \"SELECT id from vw_regex_whitelist WHERE group_id IN (5);\"' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT id from vw_whitelist WHERE domain = ? AND group_id IN (5);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT id from vw_blacklist WHERE domain = ? AND group_id IN (5);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'get_client_querystr: SELECT adlist_id from vw_gravity WHERE domain = ? AND group_id IN (5);' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c 'Regex allow ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.6' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
  run bash -c "grep -c 'Regex deny ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.6' /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "11" ]]
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
  run bash -c 'grep -c "Mozilla canary domain use-application-dns.net is NXDOMAIN" /var/log/pihole/pihole.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Local DNS test: A a.ftl" {
  run bash -c "dig A a.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "192.168.1.1" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: AAAA aaaa.ftl" {
  run bash -c "dig AAAA aaaa.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "fe80::1c01" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: ANY any.ftl" {
  run bash -c "dig ANY any.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *"192.168.3.1"* ]]
  [[ ${lines[@]} == *"fe80::3c01"* ]]
  # TXT records should not be returned due to filter-rr=ANY
  [[ ${lines[@]} != *"Some example text"* ]]
}

@test "Local DNS test: CNAME cname-ok.ftl" {
  run bash -c "dig CNAME cname-ok.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "a.ftl." ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: SRV srv.ftl" {
  run bash -c "dig SRV srv.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0 1 80 a.ftl." ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: SOA ftl" {
  run bash -c "dig SOA ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "ns1.ftl. hostmaster.ftl. 0 10800 3600 604800 3600" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: PTR ptr.ftl" {
  run bash -c "dig PTR ptr.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "ptr.ftl." ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: TXT txt.ftl" {
  run bash -c "dig TXT txt.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "\"Some example text\"" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: NAPTR naptr.ftl" {
  run bash -c "dig NAPTR naptr.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *'10 10 "u" "smtp+E2U" "!.*([^.]+[^.]+)$!mailto:postmaster@$1!i" .'* ]]
  [[ ${lines[@]} == *'20 10 "s" "http+N2L+N2C+N2R" "" ftl.'* ]]
}

@test "Local DNS test: MX mx.ftl" {
  run bash -c "dig MX mx.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "50 ns1.ftl." ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: NS ftl" {
  run bash -c "dig NS ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "ns1.ftl." ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: SVCB svcb.ftl" {
  run bash -c "dig SVCB svcb.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '1 port=\"80\".' ]]
  [[ ${lines[1]} == "" ]]
}

@test "Local DNS test: HTTPS https.ftl" {
  run bash -c "dig HTTPS https.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '1 . alpn="h3,h2"' ]]
  [[ ${lines[1]} == "" ]]
}

@test "CNAME inspection: Shallow CNAME is blocked" {
  run bash -c "dig A cname-1.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "CNAME inspection: Deep CNAME is blocked" {
  run bash -c "dig A cname-7.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "CNAME inspection: NODATA CNAME targets are blocked" {
  run bash -c "dig A a-cname.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
  run bash -c "dig AAAA a-cname.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "::" ]]
  [[ ${lines[1]} == "" ]]
  run bash -c "dig A aaaa-cname.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
  run bash -c "dig AAAA aaaa-cname.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "::" ]]
  [[ ${lines[1]} == "" ]]
}

@test "DNSSEC: SECURE domain is resolved" {
  run bash -c "dig A dnssec.works @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *"status: NOERROR"* ]]
}

@test "DNSSEC: BOGUS domain is rejected" {
  run bash -c "dig A fail01.dnssec.works @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *"status: SERVFAIL"* ]]
}

@test "Special domain: NXDOMAIN is returned" {
  run bash -c "dig A mask.icloud.com @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *"status: NXDOMAIN"* ]]
}

@test "Special domain: Record is returned when explicitly allowed" {
  run bash -c "dig A mask.icloud.com -b 127.0.0.2 @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} == *"status: NOERROR"* ]]
}

@test "ABP-style matching working as expected" {
  run bash -c "dig A special.gravity.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
  run bash -c "dig A a.b.c.d.special.gravity.ftl @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "pihole-FTL.db schema is as expected" {
  run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db .dump'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"CREATE TABLE IF NOT EXISTS \"query_storage\" (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL, forward INTEGER, additional_info INTEGER, reply_type INTEGER, reply_time REAL, dnssec INTEGER, list_id INTEGER);"* ]]
  [[ "${lines[@]}" == *"CREATE INDEX idx_queries_timestamps ON \"query_storage\" (timestamp);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE ftl (id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL, description TEXT);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE counters (id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE IF NOT EXISTS \"network\" (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL, interface TEXT NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL, macVendor TEXT, aliasclient_id INTEGER);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE IF NOT EXISTS \"network_addresses\" (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL, lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)), name TEXT, nameUpdated INTEGER, FOREIGN KEY(network_id) REFERENCES network(id));"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE aliasclient (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, comment TEXT);"* ]]
  [[ "${lines[@]}" == *"INSERT INTO ftl VALUES(0,17,'Database version');"* ]]
  # vvv This has been added in version 10 vvv
  [[ "${lines[@]}" == *"CREATE VIEW queries AS SELECT id, timestamp, type, status, CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id = q.domain) ELSE domain END domain,CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id = q.client) ELSE client END client,CASE typeof(forward) WHEN 'integer' THEN (SELECT forward FROM forward_by_id f WHERE f.id = q.forward) ELSE forward END forward,CASE typeof(additional_info) WHEN 'integer' THEN (SELECT content FROM addinfo_by_id a WHERE a.id = q.additional_info) ELSE additional_info END additional_info, reply_type, reply_time, dnssec, list_id FROM query_storage q;"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT NOT NULL);"* ]]
  [[ "${lines[@]}" == *"CREATE UNIQUE INDEX domain_by_id_domain_idx ON domain_by_id(domain);"* ]]
  [[ "${lines[@]}" == *"CREATE UNIQUE INDEX client_by_id_client_idx ON client_by_id(ip,name);"* ]]
  # vvv This has been added in version 11 vvv
  [[ "${lines[@]}" == *"CREATE TABLE addinfo_by_id (id INTEGER PRIMARY KEY, type INTEGER NOT NULL, content NOT NULL);"* ]]
  [[ "${lines[@]}" == *"CREATE UNIQUE INDEX addinfo_by_id_idx ON addinfo_by_id(type,content);"* ]]
  # vvv This has been added in version 15 vvv
  [[ "${lines[@]}" == *"CREATE TABLE session (id INTEGER PRIMARY KEY, login_at TIMESTAMP NOT NULL, valid_until TIMESTAMP NOT NULL, remote_addr TEXT NOT NULL, user_agent TEXT, sid TEXT NOT NULL, csrf TEXT NOT NULL, tls_login BOOL, tls_mixed BOOL, app BOOL);"* ]]
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
  [[ ${lines[0]} == "The Pi-hole FTL engine - "* ]]
}

@test "No WARNING messages in FTL.log (besides known warnings)" {
  run bash -c 'grep "WARNING:" /var/log/pihole/FTL.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|(Cannot set process priority)|FTLCONF_"'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == "" ]]
}

@test "No CRIT messages in FTL.log (besides error due to starting FTL more than once)" {
  run bash -c 'grep "CRIT:" /var/log/pihole/FTL.log | grep -v "CRIT: Initialization of shared memory failed"'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == "" ]]
}

@test "No \"database not available\" messages in FTL.log" {
  run bash -c 'grep -c "database not available" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

# Regex tests
@test "Compiled deny regex as expected" {
  run bash -c 'grep -c "Compiling deny regex 0 (DB ID 6): regex\[0-9\].ftl" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Compiled allow regex as expected" {
  run bash -c 'grep -c "Compiling allow regex 0 (DB ID 3): regex2" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "Compiling allow regex 1 (DB ID 4): ^gravity-allowed" /var/log/pihole/FTL.log'
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
  [[ ${lines[1]} == "Invalid regex CLI filter \"f{x}\": Invalid contents of {}" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 25: Useful hint for invalid regular expression \"a**\": Invalid use of repetition operators" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "a**"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"a**\": Invalid use of repetition operators" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 26: Useful hint for invalid regular expression \"x\\\": Trailing backslash" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "x\\"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"x\\\": Trailing backslash" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 27: Useful hint for invalid regular expression \"[\": Missing ']'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "["'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"[\": Missing ']'" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 28: Useful hint for invalid regular expression \"(\": Missing ')'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "("'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"(\": Missing ')'" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 29: Useful hint for invalid regular expression \"{1\": Missing '}'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "{1"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"{1\": Missing '}'" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 30: Useful hint for invalid regular expression \"[[.foo.]]\": Unknown collating element" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[[.foo.]]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"[[.foo.]]\": Unknown collating element" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 31: Useful hint for invalid regular expression \"[[:foobar:]]\": Unknown character class name" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[[:foobar:]]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"[[:foobar:]]\": Unknown character class name" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 32: Useful hint for invalid regular expression \"(a)\\2\": Invalid back reference" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "(a)\\2"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"(a)\\2\": Invalid back reference" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 33: Useful hint for invalid regular expression \"[g-1]\": Invalid character range" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[g-1]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "Invalid regex CLI filter \"[g-1]\": Invalid character range" ]]
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
  [[ ${lines[0]} == "Invalid regex CLI filter \"g{x}\": Invalid contents of {}" ]]
  [[ $status == 1 ]]
}

@test "Regex Test 36: Quiet mode: No Match = Return code 2, nothing else" {
  run bash -c './pihole-FTL -q regex-test "fbcdn.net" "g"'
  printf "%s\n" "${lines[@]}"
  [[ $status == 2 ]]
}

@test "Regex Test 37: Option \";querytype=A\" working as expected (ONLY matching A queries)" {
  run bash -c 'dig A regex-A @127.0.0.1'
  printf "dig A: %s\n" "${lines[@]}"
  run bash -c 'dig A regex-A @127.0.0.1 +short'
  [[ ${lines[0]} == "0.0.0.0" ]]
  run bash -c 'dig AAAA regex-A @127.0.0.1'
  printf "dig AAAA: %s\n" "${lines[@]}"
  run bash -c 'dig AAAA regex-A @127.0.0.1 +short'
  [[ ${lines[0]} != "::" ]]
}

@test "Regex Test 38: Option \";querytype=!A\" working as expected (NOT matching A queries)" {
  run bash -c 'dig A regex-notA @127.0.0.1'
  printf "dig A: %s\n" "${lines[@]}"
  run bash -c 'dig A regex-notA @127.0.0.1 +short'
  [[ ${lines[0]} != "0.0.0.0" ]]
  run bash -c 'dig AAAA regex-notA @127.0.0.1'
  printf "dig AAAA: %s\n" "${lines[@]}"
  run bash -c 'dig AAAA regex-notA @127.0.0.1 +short'
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
  [[ "${lines[@]}" == *"Overwriting previous querytype setting (multiple \"querytype=...\" found)"* ]]
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

@test "Regex Test 47: Option \";querytype=A\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;querytype=A'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  [[ ${lines[5]} == *"- A"* ]]
}

@test "Regex Test 48: Option \";querytype=!TXT\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;querytype=!TXT'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  [[ "${lines[@]}" != *"- TXT"* ]]
}

@test "Regex Test 49: Option \";reply=NXDOMAIN\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;reply=NXDOMAIN'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  [[ ${lines[4]} == "    Hint: This regex forces reply type NXDOMAIN" ]]
}

@test "Regex Test 50: Option \";invert\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" g\;invert'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  [[ ${lines[4]} == "    Hint: This regex is inverted" ]]
}

@test "Regex Test 51: Option \";querytype=A,HTTPS\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;querytype=A,HTTPS'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  [[ ${lines[5]} == *"- A"* ]]
  [[ ${lines[6]} == *"- HTTPS"* ]]
}

@test "Regex Test 52: Option \";querytype=ANY,HTTPS,SVCB;reply=refused\" working as expected (ONLY matching ANY, HTTPS or SVCB queries)" {
  run bash -c 'dig A regex-multiple.ftl @127.0.0.1'
  printf "dig A: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: NOERROR"* ]]
  run bash -c 'dig AAAA regex-multiple.ftl @127.0.0.1'
  printf "dig AAAA: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: NOERROR"* ]]
  run bash -c 'dig SVCB regex-multiple.ftl @127.0.0.1'
  printf "dig SVCB: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: REFUSED"* ]]
  run bash -c 'dig HTTPS regex-multiple.ftl @127.0.0.1'
  printf "dig HTTPS: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: REFUSED"* ]]
  run bash -c 'dig ANY regex-multiple.ftl @127.0.0.1'
  printf "dig ANY: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: REFUSED"* ]]
}

@test "Regex Test 53: Option \";querytype=!ANY,HTTPS,SVCB;reply=refused\" working as expected (NOT matching ANY, HTTPS or SVCB queries)" {
  run bash -c 'dig A regex-notMultiple.ftl @127.0.0.1'
  printf "dig A: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: REFUSED"* ]]
  run bash -c 'dig AAAA regex-notMultiple.ftl @127.0.0.1'
  printf "dig AAAA: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: REFUSED"* ]]
  run bash -c 'dig SVCB regex-notMultiple.ftl @127.0.0.1'
  printf "dig SVCB: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: NOERROR"* ]]
  run bash -c 'dig HTTPS regex-notMultiple.ftl @127.0.0.1'
  printf "dig HTTPS: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: NOERROR"* ]]
  run bash -c 'dig ANY regex-notMultiple.ftl @127.0.0.1'
  printf "dig ANY: %s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"status: NOERROR"* ]]
}

@test "API addresses reported correctly by CHAOS TXT domain.api.ftl" {
  run bash -c 'dig CHAOS TXT domain.api.ftl +short @127.0.0.1'
  printf "dig (full): %s\n" "${lines[@]}"
  [[ ${lines[0]} == '"http://pi.hole:80/api/" "https://pi.hole:443/api/"' ]]
}

@test "API addresses reported correctly by CHAOS TXT local.api.ftl" {
  run bash -c 'dig CHAOS TXT local.api.ftl +short @127.0.0.1'
  printf "dig (full): %s\n" "${lines[@]}"
  [[ ${lines[0]} == '"http://localhost:80/api/" "https://localhost:443/api/"' ]]
}

@test "API addresses reported by CHAOS TXT api.ftl identical to domain.api.ftl" {
  run bash -c 'dig CHAOS TXT api.ftl +short @127.0.0.1'
  api="${lines[0]}"
  run bash -c 'dig CHAOS TXT domain.api.ftl +short @127.0.0.1'
  domain_api="${lines[0]}"
  [[ "${api}" == "${domain_api}" ]]
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
  run bash -c 'grep "Compiled for" /var/log/pihole/FTL.log'
  printf "Output: %s\n\$CI_ARCH: %s\nuname -m: %s\n" "${lines[@]:-not set}" "${CI_ARCH:-not set}" "$(uname -m)"
  [[ ${lines[0]} == *"Compiled for ${CI_ARCH:-$(uname -m)}"* ]]
}

@test "Building machine (CI) is reported on startup" {
  [[ ${CI_ARCH} != "" ]] && compiled_str="on CI" || compiled_str="locally" && export compiled_str
  run bash -c 'grep "Compiled for" /var/log/pihole/FTL.log'
  printf "Output: %s\n\$CI_ARCH: %s\n" "${lines[@]:-not set}" "${CI_ARCH:-not set}"
  [[ ${lines[0]} == *"(compiled ${compiled_str})"* ]]
}

@test "Compiler version is correctly reported on startup" {
  compiler_version="$(${CC} --version | head -n1)" && export compiler_version
  run bash -c 'grep "Compiled for" /var/log/pihole/FTL.log'
  printf "Output: %s\n\$CC: %s\nVersion: %s\n" "${lines[@]:-not set}" "${CC:-not set}" "${compiler_version:-not set}"
  [[ ${lines[0]} == *"using ${compiler_version}"* ]]
}

@test "No errors on setting busy handlers for the databases" {
  run bash -c 'grep -c "Cannot set busy handler" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "Blocking status is correctly logged in pihole.log" {
  run bash -c 'grep -c "gravity blocked gravity.ftl is 0.0.0.0" /var/log/pihole/pihole.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
}

@test "HTTP server responds with JSON error 404 to unknown API path" {
  run bash -c 'curl -s 127.0.0.1/api/undefined'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '{"error":{"key":"not_found","message":"Not found","hint":"/api/undefined"},"took":'*'}' ]]
}

@test "HTTP server responds with normal error 404 to path outside /admin" {
  run bash -c 'curl -s 127.0.0.1/undefined'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Error 404: Not Found" ]]
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
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  #                                  CLIENT SUBNET          COOKIE                       MAC HEX                     MAC TEXT                                          CPE-ID
  run bash -c 'dig localhost +short +subnet=192.168.1.1/32 +ednsopt=10:1122334455667788 +ednsopt=65001:000102030405 +ednsopt=65073:41413A42423A43433A44443A45453A4646 +ednsopt=65074:414243444546 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  printf "%s\n" "${log}"

  # Start actual test
  run bash -c "grep -c \"EDNS0: CLIENT SUBNET: 192.168.1.1/32\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS0: COOKIE (client-only): 1122334455667788\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS0: MAC address (BYTE format): 00:01:02:03:04:05\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS0: MAC address (TEXT format): AA:BB:CC:DD:EE:FF\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c "grep -c \"EDNS0: CPE-ID (payload size 6): \\\"ABCDEF\\\" (0x41 0x42 0x43 0x44 0x45 0x46)\"" <<< "${log}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "EDNS(0) ECS can overwrite client address (IPv4)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=192.168.47.97/32 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"**** new UDP IPv4 query[A] query \"localhost\" from lo/192.168.47.97#53 "* ]]
}

@test "EDNS(0) ECS can overwrite client address (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=fe80::b167:af1e:968b:dead/128 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"**** new UDP IPv4 query[A] query \"localhost\" from lo/fe80::b167:af1e:968b:dead#53 "* ]]
}

@test "alias-client is imported and used for configured client" {
  run bash -c 'grep -c "Added alias-client \"some-aliasclient\" (aliasclient-0) with FTL ID 0" /var/log/pihole/FTL.log'
  printf "Added: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "Aliasclient ID 127.0.0.6 -> 0" /var/log/pihole/FTL.log'
  printf "Found ID: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "Client .* (127.0.0.6) IS  managed by this alias-client, adding counts" /var/log/pihole/FTL.log'
  printf "Adding counts: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "EDNS(0) ECS skipped for loopback address (IPv4)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=127.0.0.1/32 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"EDNS0: CLIENT SUBNET: Skipped 127.0.0.1/32 (IPv4 loopback address)"* ]]
}

@test "EDNS(0) ECS skipped for loopback address (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=::1/128 @127.0.0.1'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "127.0.0.1" ]]
  [[ $status == 0 ]]

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"EDNS0: CLIENT SUBNET: Skipped ::1/128 (IPv6 loopback address)"* ]]
}

@test "Embedded SQLite3 shell available and functional" {
  run bash -c './pihole-FTL sqlite3 -help'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Usage: sqlite3 [OPTIONS] [FILENAME [SQL]]" ]]
}

@test "Embedded SQLite3 shell is called for .db file" {
  run bash -c './pihole-FTL abc.db ".version"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "SQLite 3."* ]]
}

@test "Embedded SQLite3 shell prints FTL version in interactive mode" {
  # shell.c contains a call to print_FTL_version
  run bash -c "echo -e '.quit\n' | ./pihole-FTL sqlite3 -interactive"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Pi-hole FTL"* ]]
}

@test "Embedded SQLite3 shell ignores .sqliterc \"-ni\"" {
  # Install .sqliterc file at current home directory
  cp test/sqliterc ~/.sqliterc
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/gravity.db \"SELECT value FROM info WHERE property = 'abp_domains';\""
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "1" ]]
  run bash -c "./pihole-FTL sqlite3 -ni /etc/pihole/gravity.db \"SELECT value FROM info WHERE property = 'abp_domains';\""
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  rm ~/.sqliterc
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

@test "No ERROR messages in FTL.log (besides known/intended error)" {
  run bash -c 'grep "ERROR: " /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  run bash -c 'grep "ERROR: " /var/log/pihole/FTL.log | grep -c -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is invalid)"'
  printf "count: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "No CRIT messages in FTL.log (besides error due to testing to start FTL more than once)" {
  run bash -c 'grep "CRIT: " /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  run bash -c 'grep "CRIT: " /var/log/pihole/FTL.log | grep -c -v "Initialization of shared memory failed."'
  printf "count: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "No missing config items in pihole.toml" {
  run bash -c 'grep "DEBUG_CONFIG: " /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  run bash -c 'grep "DEBUG_CONFIG: " /var/log/pihole/FTL.log | grep -c "DOES NOT EXIST"'
  printf "DOES NOT EXIST count: %s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "Check dnsmasq warnings in source code" {
  run bash -c "bash test/dnsmasq_warnings.sh"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "" ]]
}

@test "Pi-hole uses dns.reply.host.IPv4/6 for pi.hole" {
  run bash -c "dig A pi.hole +short @127.0.0.1"
  printf "A: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "10.100.0.10" ]]
  run bash -c "dig AAAA pi.hole +short @127.0.0.1"
  printf "AAAA: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "fe80::10" ]]
}

@test "Pi-hole uses dns.reply.host.IPv4/6 for hostname" {
  run bash -c "dig A $(hostname) +short @127.0.0.1"
  printf "A: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "10.100.0.10" ]]
  run bash -c "dig AAAA $(hostname) +short @127.0.0.1"
  printf "AAAA: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "fe80::10" ]]
}

@test "Pi-hole uses dns.reply.blocking.IPv4/6 for blocked domain" {
  run bash -c 'grep "mode = \"NULL\"" /etc/pihole/pihole.toml'
  printf "grep output: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == '    mode = "NULL"' ]]
  run bash -c './pihole-FTL --config dns.blocking.mode IP'
  printf "setting config: %s\n" "${lines[@]}"
  run bash -c 'grep "mode = \"IP" /etc/pihole/pihole.toml'
  printf "grep output (before reload): %s\n" "${lines[@]}"
  [[ "${lines[0]}" == *'mode = "IP" ### CHANGED, default = "NULL"' ]]
  run bash -c "kill -HUP $(cat /run/pihole-FTL.pid)"
  sleep 1
  run bash -c 'grep "mode = \"IP" /etc/pihole/pihole.toml'
  printf "grep output (after reload): %s\n" "${lines[@]}"
  [[ "${lines[0]}" == *'mode = "IP" ### CHANGED, default = "NULL"' ]]
  run bash -c "dig A denied.ftl +short @127.0.0.1"
  printf "A: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "10.100.0.11" ]]
  run bash -c "dig AAAA denied.ftl +short @127.0.0.1"
  printf "AAAA: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "fe80::11" ]]
}

@test "Antigravity domain is not blocked" {
  run bash -c "dig A antigravity.ftl +short @127.0.0.1"
  printf "A: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "192.168.1.6" ]]
}

@test "Antigravity ABP-domain is not blocked" {
  run bash -c "dig A x.y.z.abp.antigravity.ftl +short @127.0.0.1"
  printf "A: %s\n" "${lines[@]}"
  [[ "${lines[0]}" == "192.168.1.7" ]]
}

@test "Custom DNS records: Multiple domains per line are accepted" {
  run bash -c "dig A abc-custom.com +short @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "1.1.1.1" ]]
  run bash -c "dig A def-custom.de +short @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "1.1.1.1" ]]
}

@test "Custom DNS records: International domains are converted to IDN form" {
  # äste.com ---> xn--ste-pla.com
  run bash -c "dig A xn--ste-pla.com +short @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "2.2.2.2" ]]
  # steä.com -> xn--ste-sla.com
  run bash -c "dig A xn--ste-sla.com +short @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "2.2.2.2" ]]
}

@test "Local CNAME records: International domains are converted to IDN form" {
  # brücke.com ---> xn--brcke-lva.com
  run bash -c "dig A xn--brcke-lva.com +short @127.0.0.1"
  printf "%s\n" "${lines[@]}"
  # xn--ste-pla.com ---> äste.com
  [[ "${lines[0]}" == "xn--ste-pla.com." ]]
  [[ "${lines[1]}" == "2.2.2.2" ]]
}

@test "IDN2 CLI interface correctly encodes/decodes domain according to IDNA2008 + TR46" {
  run bash -c './pihole-FTL idn2 äste.com'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "xn--ste-pla.com" ]]
  run bash -c './pihole-FTL idn2 -d xn--ste-pla.com'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "äste.com" ]]
  run bash -c './pihole-FTL idn2 ß.de'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "xn--zca.de" ]]
  run bash -c './pihole-FTL idn2 -d xn--zca.de'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "ß.de" ]]
}

@test "Environmental variable is favored over config file" {
  # The config file has -10 but we set FTLCONF_misc_nice="-11"
  run bash -c 'grep -B1 "nice = -11" /etc/pihole/pihole.toml'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "  # >>> This config is overwritten by an environmental variable <<<" ]]
  [[ ${lines[1]} == "  nice = -11 ### CHANGED, default = -10" ]]
}

@test "Correct number of environmental variables is logged" {
  run bash -c 'grep -q "3 FTLCONF environment variables found (1 used, 1 invalid, 1 ignored)" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Correct environmental variable is logged" {
  run bash -c 'grep -q "FTLCONF_misc_nice is used" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Invalid environmental variable is logged" {
  run bash -c 'grep -q "FTLCONF_debug_api is invalid" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "Unknown environmental variable is logged, a useful alternative is suggested" {
  run bash -c 'grep -A1 "FTLCONF_dns_upstrrr is unknown" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == *"WARNING: [?] FTLCONF_dns_upstrrr is unknown, did you mean any of these?" ]]
  [[ ${lines[1]} == *"WARNING:     - FTLCONF_dns_upstreams" ]]
}

@test "cJSON_GetErrorPtr and cJSON_InitHooks are never used (for thread-safety reasons)" {
  # cJSON_GetErrorPtr() is not thread-safe but can be replaces by cJSON_ParseWithOpts()
  # cJSON_InitHooks() is only thread-safe if used before any other cJSON function in a thread
  # We grep for the two functions recursively and exclude cJSON.{c,h} where they are defined
  run bash -c 'grep -rE "(cJSON_GetErrorPtr)|(cJSON_InitHooks)" src/ | grep -vE "^src/webserver/cJSON/cJSON."'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "" ]]
}

@test "CLI complains about unknown config key and offers a suggestion" {
  run bash -c './pihole-FTL --config dbg.all'
  [[ ${lines[0]} == "Unknown config option dbg.all, did you mean:" ]]
  [[ ${lines[1]} == " - debug.all" ]]
  [[ $status == 4 ]]
  run bash -c './pihole-FTL --config misc.privacyLLL'
  [[ ${lines[0]} == "Unknown config option misc.privacyLLL, did you mean:" ]]
  [[ ${lines[1]} == " - misc.privacylevel" ]]
  [[ $status == 4 ]]
}

@test "Changing a config option set forced by ENVVAR is not possible via the CLI" {
  run bash -c './pihole-FTL --config misc.nice -12'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Config option misc.nice is read-only (set via environmental variable)" ]]
  [[ $status == 5 ]]
}

@test "Changing a config option set forced by ENVVAR is not possible via the API" {
  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config/misc/nice -d "{\"config\":{\"misc\":{\"nice\":-12}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '{"error":{"key":"bad_request","message":"Config items set via environment variables cannot be changed via the API","hint":"misc.nice"},"took":'*'}' ]]
}

@test "API domain search: Non-existing domain returns expected JSON" {
  run bash -c 'curl -s 127.0.0.1/api/search/non.existent'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '{"search":{"domains":[],"gravity":[],"results":{"domains":{"exact":0,"regex":0},"gravity":{"allow":0,"block":0},"total":0},"parameters":{"N":20,"partial":false,"domain":"non.existent","debug":false}},"took":'*'}' ]]
}

@test "API domain search: antigravity.ftl returns expected JSON" {
  run bash -c 'curl -s 127.0.0.1/api/search/antigravity.ftl'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '{"search":{"domains":[],"gravity":[{"domain":"antigravity.ftl","type":"block","address":"https://pi-hole.net/block.txt","comment":"Fake block-list","enabled":true,"id":1,"date_added":1559928803,"date_modified":1559928803,"type":"block","date_updated":1559928803,"number":2000,"invalid_domains":2,"abp_entries":0,"status":1,"groups":[0,2]},{"domain":"antigravity.ftl","type":"allow","address":"https://pi-hole.net/allow.txt","comment":"Fake allow-list","enabled":true,"id":2,"date_added":1559928803,"date_modified":1559928803,"type":"allow","date_updated":1559928803,"number":2000,"invalid_domains":2,"abp_entries":0,"status":1,"groups":[0]},{"domain":"@@||antigravity.ftl^","type":"allow","address":"https://pi-hole.net/allow.txt","comment":"Fake allow-list","enabled":true,"id":2,"date_added":1559928803,"date_modified":1559928803,"type":"allow","date_updated":1559928803,"number":2000,"invalid_domains":2,"abp_entries":0,"status":1,"groups":[0]}],"results":{"domains":{"exact":0,"regex":0},"gravity":{"allow":2,"block":1},"total":3},"parameters":{"N":20,"partial":false,"domain":"antigravity.ftl","debug":false}},"took":'*'}' ]]
}

@test "API domain search: Internationalized/partially capital domain returns expected lowercase punycode domain" {
  run bash -c 'curl -s 127.0.0.1/api/search/äBC.com?debug=true | jq .search.debug.punycode'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '"xn--bc-uia.com"' ]]
}

@test "API history: Returns full 24 hours even if only a few queries are made" {
  run bash -c 'curl -s 127.0.0.1/api/history | jq ".history | length"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "145" ]]
}

@test "API history/clients: Returns full 24 hours even if only a few queries are made" {
  run bash -c 'curl -s 127.0.0.1/api/history/clients | jq ".history | length"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "145" ]]
}

@test "Check /api/lists?type=block returning only blocking lists" {
  run bash -c 'curl -s 127.0.0.1/api/lists?type=block | jq ".lists[].type"'
  printf "%s\n" "${lines[@]}"
  # Check no allow entries are present
  [[ ${lines[@]} != *"allow"* ]]
}

@test "Check /api/lists?type=allow returning only allowing lists" {
  run bash -c 'curl -s 127.0.0.1/api/lists?type=allow | jq ".lists[].type"'
  printf "%s\n" "${lines[@]}"
  # Check no block entries are present
  [[ ${lines[@]} != *"block"* ]]
}

@test "Check /api/lists without type parameter returning all lists" {
  run bash -c 'curl -s 127.0.0.1/api/lists | jq ".lists[].type"'
  printf "%s\n" "${lines[@]}"
  # Check both block and allow entries are present
  [[ ${lines[@]} == *"allow"* ]]
  [[ ${lines[@]} == *"block"* ]]
}

@test "API: No UNKNOWN reply in API" {
  run bash -c 'curl -s 127.0.0.1/api/queries?reply=UNKNOWN | jq .queries'
  printf "%s\n" "${lines[@]}"
  run bash -c 'curl -s 127.0.0.1/api/queries?reply=UNKNOWN | jq ".queries | length"'
  [[ ${lines[0]} == "0" ]]
}

@test "API: No UNKNOWN status in API" {
  run bash -c 'curl -s 127.0.0.1/api/queries?status=UNKNOWN | jq .queries'
  printf "%s\n" "${lines[@]}"
  run bash -c 'curl -s 127.0.0.1/api/queries?status=UNKNOWN | jq ".queries | length"'
  [[ ${lines[0]} == "0" ]]
}

@test "API authorization (without password): No login required" {
  run bash -c 'curl -s 127.0.0.1/api/auth'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '{"session":{"valid":true,"totp":false,"sid":null,"validity":-1},"took":'*'}' ]]
}

@test "Config validation working on the CLI (type-based checking)" {
  run bash -c './pihole-FTL --config dns.port true'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Config setting dns.port is invalid, allowed options are: unsigned integer (16 bit)' ]]
  [[ $status == 2 ]]

  run bash -c './pihole-FTL --config dns.revServers "abc"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Config setting dns.revServers is invalid: not valid JSON, error at: abc' ]]
  [[ $status == 2 ]]
}

@test "Config validation working on the API (type-based checking)" {
  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config -d "{\"config\":{\"dns\":{\"blockESNI\":15.5}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"error\":{\"key\":\"bad_request\",\"message\":\"Config item is invalid\",\"hint\":\"dns.blockESNI: not of type bool\"},\"took\":"*"}" ]]

  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config -d "{\"config\":{\"dns\":{\"piholePTR\":\"something_else\"}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"error\":{\"key\":\"bad_request\",\"message\":\"Config item is invalid\",\"hint\":\"dns.piholePTR: invalid option\"},\"took\":"*"}" ]]
}

@test "Config validation working on the CLI (validator-based checking)" {
  run bash -c './pihole-FTL --config dns.hosts "[\"111.222.333.444 abc\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: dns.hosts[0]: neither a valid IPv4 nor IPv6 address ("111.222.333.444")' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config dns.hosts "[\"1.1.1.1 cf\",\"8.8.8.8 google\",\"1.2.3.4\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: dns.hosts[2]: entry does not have at least one hostname ("1.2.3.4")' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config dns.revServers "[\"abc,def,ghi\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: dns.revServers[0]: <enabled> not a boolean ("abc")' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config dns.revServers "[\"true,abc,def,ghi\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: dns.revServers[0]: <ip-address> neither a valid IPv4 nor IPv6 address ("abc")' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config dns.revServers "[\"true,1.2.3.4/55,def,ghi\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: dns.revServers[0]: <prefix-len> not a valid IPv4 prefix length ("55")' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config dns.revServers "[\"true,::1/255,def,ghi\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: dns.revServers[0]: <prefix-len> not a valid IPv6 prefix length ("255")' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config dns.revServers "[\"true,1.1.1.1,def\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: dns.revServers[0]: entry does not have all required elements (<enabled>,<ip-address>[/<prefix-len>],<server>[#<port>],<domain>)' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config dns.revServers "[\"true,1.1.1.1,def,ghi\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'New dnsmasq configuration is not valid ('*'resolve at line '*' of /etc/pihole/dnsmasq.conf.temp: "rev-server=1.1.1.1,def"), config remains unchanged' ]]
  [[ $status == 3 ]]

  run bash -c './pihole-FTL --config webserver.api.excludeClients "[\".*\",\"$$$\",\"[[[\"]"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == 'Invalid value: webserver.api.excludeClients[2]: not a valid regex ("[[["): Missing '\'']'\' ]]
  [[ $status == 3 ]]
}

@test "Config validation working on the API (validator-based checking)" {
  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config -d "{\"config\":{\"files\":{\"pcap\":\"%gh4b\"}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"error\":{\"key\":\"bad_request\",\"message\":\"Config item validation failed\",\"hint\":\"files.pcap: not a valid file path (\\\"%gh4b\\\")\"},\"took\":"*"}" ]]

  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config -d "{\"config\":{\"dns\":{\"cnameRecords\":[\"a\"]}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"error\":{\"key\":\"bad_request\",\"message\":\"Config item validation failed\",\"hint\":\"dns.cnameRecords[0]: not a valid CNAME definition (too few elements)\"},\"took\":"*"}" ]]

  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config -d "{\"config\":{\"dns\":{\"cnameRecords\":[\"a,b,c\",\"a,b,c,,c\"]}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"error\":{\"key\":\"bad_request\",\"message\":\"Config item validation failed\",\"hint\":\"dns.cnameRecords[1]: contains an empty string at position 3\"},\"took\":"*"}" ]]

  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config -d "{\"config\":{\"dns\":{\"cnameRecords\":[\"a,b,c\",\"a,b,c\",5]}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"error\":{\"key\":\"bad_request\",\"message\":\"Config item is invalid\",\"hint\":\"dns.cnameRecords: array has invalid elements\"},\"took\":"*"}" ]]
}

@test "Create, set, and use application password" {
  run bash -c 'curl -s 127.0.0.1/api/auth/app'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == '{"app":{"password":"'*'","hash":"'*'"},"took":'*'}' ]]

  # Extract password and hash from response
  password="$(echo ${lines[0]} | jq .app.password)"
  pwhash="$(echo ${lines[0]} | jq .app.hash)"

  printf "password: %s\n" "${password}"
  printf "pwhash: %s\n" "${pwhash}"

  # Set app password hash
  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config/webserver/api/app_pwhash -d  "{\"config\":{\"webserver\":{\"api\":{\"app_pwhash\":${0}}}}}"' "${pwhash}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"config\":{\"webserver\":{\"api\":{\"app_pwhash\":${pwhash}}}},\"took\":"*"}" ]]

  # Login using app password is successful
  run bash -c 'curl -s -X POST 127.0.0.1/api/auth -d "{\"password\":${0}}" | jq .session.valid' "${password}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "true" ]]
}

@test "API authorization: Setting password" {
  # Password: ABC
  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config/webserver/api/password -d "{\"config\":{\"webserver\":{\"api\":{\"password\":\"ABC\"}}}}"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "{\"config\":{\"webserver\":{\"api\":{\"password\":\"********\"}}},\"took\":"*"}" ]]
}

@test "API authorization (with password): Incorrect password is rejected if password auth is enabled" {
  # Password: ABC
  run bash -c 'curl -s -X POST 127.0.0.1/api/auth -d "{\"password\":\"XXX\"}" | jq .session.valid'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "false" ]]
}

@test "API authorization (with password): Correct password is accepted" {
  session="$(curl -s -X POST 127.0.0.1/api/auth -d "{\"password\":\"ABC\"}")"
  printf "Session: %s\n" "${session}"
  run jq .session.valid <<< "${session}"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "true" ]]
}

@test "Test TLS/SSL server using self-signed certificate" {
  # -s: silent
  # -I: HEAD request
  # --cacert: use this CA certificate to verify the server certificate
  # --resolve: resolve pi.hole:443 to 127.0.0.1
  #            we need this line because curl is not using FTL as resolver
  #            and would otherwise not be able to resolve pi.hole
  run bash -c 'curl -sI --cacert /etc/pihole/test.crt --resolve pi.hole:443:127.0.0.1 https://pi.hole/'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "HTTP/1.1 "* ]]
  run bash -c 'curl -I --cacert /etc/pihole/test.crt --resolve pi.hole:443:127.0.0.1 https://pi.hole/'
}

@test "X.509 certificate parser returns expected result" {
  # We are getting the certificate from the config
  run bash -c './pihole-FTL --read-x509'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}"  == "Reading certificate from /etc/pihole/test.pem ..." ]]
  [[ "${lines[1]}"  == "Certificate (X.509):" ]]
  [[ "${lines[2]}"  == "  cert. version     : 3" ]]
  [[ "${lines[3]}"  == "  serial number     : 36:36:32:32:35:31:37:36:30:30:39:31:30:30:37" ]]
  [[ "${lines[4]}"  == "  issuer name       : CN=pi.hole, O=Pi-hole, C=DE" ]]
  [[ "${lines[5]}"  == "  subject name      : CN=pi.hole" ]]
  [[ "${lines[6]}"  == "  issued  on        : 2023-01-16 21:15:12" ]]
  [[ "${lines[7]}"  == "  expires on        : 2053-01-16 21:15:12" ]]
  [[ "${lines[8]}"  == "  signed using      : ECDSA with SHA256" ]]
  [[ "${lines[9]}"  == "  EC key size       : 384 bits" ]]
  [[ "${lines[10]}" == "  basic constraints : CA=false" ]]
  [[ "${lines[11]}" == "  subject alt name  :" ]]
  [[ "${lines[12]}" == "      dNSName : pi.hole" ]]
  [[ "${lines[13]}" == "Public key (PEM):" ]]
  [[ "${lines[14]}" == "-----BEGIN PUBLIC KEY-----" ]]
  [[ "${lines[15]}" == "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuH7sWfGRkvm5s5LVYTwbM6PjZmuK4KPh" ]]
  [[ "${lines[16]}" == "A5qaWfVqJw4jeEMkvyT4CKtiruLEBcqzimkBhP6dlMOUM/K0caRC5Jm46fMC9bV3" ]]
  [[ "${lines[17]}" == "74ibYXxiX4bkiu8m/GDjM5RgiS1D1x+U" ]]
  [[ "${lines[18]}" == "-----END PUBLIC KEY-----" ]]
  [[ "${lines[19]}" == "" ]]
}

@test "X.509 certificate parser returns expected result (with private key)" {
  # We are explicitly specifying the certificate file here
  run bash -c './pihole-FTL --read-x509-key /etc/pihole/test.pem'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}"  == "Reading certificate from /etc/pihole/test.pem ..." ]]
  [[ "${lines[1]}"  == "Certificate (X.509):" ]]
  [[ "${lines[2]}"  == "  cert. version     : 3" ]]
  [[ "${lines[3]}"  == "  serial number     : 36:36:32:32:35:31:37:36:30:30:39:31:30:30:37" ]]
  [[ "${lines[4]}"  == "  issuer name       : CN=pi.hole, O=Pi-hole, C=DE" ]]
  [[ "${lines[5]}"  == "  subject name      : CN=pi.hole" ]]
  [[ "${lines[6]}"  == "  issued  on        : 2023-01-16 21:15:12" ]]
  [[ "${lines[7]}"  == "  expires on        : 2053-01-16 21:15:12" ]]
  [[ "${lines[8]}"  == "  signed using      : ECDSA with SHA256" ]]
  [[ "${lines[9]}"  == "  EC key size       : 384 bits" ]]
  [[ "${lines[10]}" == "  basic constraints : CA=false" ]]
  [[ "${lines[11]}" == "  subject alt name  :" ]]
  [[ "${lines[12]}" == "      dNSName : pi.hole" ]]
  [[ "${lines[13]}" == "Private key:" ]]
  [[ "${lines[14]}" == "  Type: EC" ]]
  [[ "${lines[15]}" == "  Curve type: Short Weierstrass (y^2 = x^3 + a x + b)" ]]
  [[ "${lines[16]}" == "  Bitlen:  383 bit" ]]
  [[ "${lines[17]}" == "  Private key:" ]]
  [[ "${lines[18]}" == "    D = 0x465886D0D75BFCB108EB963F8A512ECE26847433DC7267230B8647A3B5794718D5E7DA52BC6733D651403AF99AA0740F"* ]]
  [[ "${lines[19]}" == "  Public key:" ]]
  [[ "${lines[20]}" == "    X = 0xB87EEC59F19192F9B9B392D5613C1B33A3E3666B8AE0A3E1039A9A59F56A270E23784324BF24F808AB62AEE2C405CAB3"* ]]
  [[ "${lines[21]}" == "    Y = 0x8A690184FE9D94C39433F2B471A442E499B8E9F302F5B577EF889B617C625F86E48AEF26FC60E3339460892D43D71F94"* ]]
  [[ "${lines[22]}" == "    Z = 0x01"* ]]
  [[ "${lines[23]}" == "Private key (PEM):" ]]
  [[ "${lines[24]}" == "-----BEGIN EC PRIVATE KEY-----" ]]
  [[ "${lines[25]}" == "MIGkAgEBBDBGWIbQ11v8sQjrlj+KUS7OJoR0M9xyZyMLhkejtXlHGNXn2lK8ZzPW" ]]
  [[ "${lines[26]}" == "UUA6+ZqgdA+gBwYFK4EEACKhZANiAAS4fuxZ8ZGS+bmzktVhPBszo+Nma4rgo+ED" ]]
  [[ "${lines[27]}" == "mppZ9WonDiN4QyS/JPgIq2Ku4sQFyrOKaQGE/p2Uw5Qz8rRxpELkmbjp8wL1tXfv" ]]
  [[ "${lines[28]}" == "iJthfGJfhuSK7yb8YOMzlGCJLUPXH5Q=" ]]
  [[ "${lines[29]}" == "-----END EC PRIVATE KEY-----" ]]
  [[ "${lines[30]}" == "Public key (PEM):" ]]
  [[ "${lines[31]}" == "-----BEGIN PUBLIC KEY-----" ]]
  [[ "${lines[32]}" == "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuH7sWfGRkvm5s5LVYTwbM6PjZmuK4KPh" ]]
  [[ "${lines[33]}" == "A5qaWfVqJw4jeEMkvyT4CKtiruLEBcqzimkBhP6dlMOUM/K0caRC5Jm46fMC9bV3" ]]
  [[ "${lines[34]}" == "74ibYXxiX4bkiu8m/GDjM5RgiS1D1x+U" ]]
  [[ "${lines[35]}" == "-----END PUBLIC KEY-----" ]]
  [[ "${lines[36]}" == "" ]]
}

@test "X.509 certificate parser can check if domain is included" {
  run bash -c './pihole-FTL --read-x509-key /etc/pihole/test.pem pi.hole'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "Reading certificate from /etc/pihole/test.pem ..." ]]
  [[ "${lines[1]}" == "Certificate matches domain pi.hole" ]]
  [[ "${lines[2]}" == "" ]]
  [[ $status == 0 ]]
  run bash -c './pihole-FTL --read-x509-key /etc/pihole/test.pem pi-hole.net'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "Reading certificate from /etc/pihole/test.pem ..." ]]
  [[ "${lines[1]}" == "Certificate does not match domain pi-hole.net" ]]
  [[ "${lines[2]}" == "" ]]
  [[ $status == 1 ]]
}

@test "Test embedded GZIP compressor" {
  run bash -c './pihole-FTL gzip test/pihole-FTL.db.sql'
  printf "Compression output:\n"
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  [[ ${lines[0]} == "Compressed test/pihole-FTL.db.sql (2.0KB) to test/pihole-FTL.db.sql.gz (689.0B), 66.0% size reduction" ]]
  printf "Uncompress (FTL) output:\n"
  run bash -c './pihole-FTL gzip test/pihole-FTL.db.sql.gz test/pihole-FTL.db.sql.1'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  [[ ${lines[0]} == "Uncompressed test/pihole-FTL.db.sql.gz (677.0B) to test/pihole-FTL.db.sql.1 (2.0KB), 199.3% size increase" ]]
  printf "Uncompress (gzip) output:\n"
  run bash -c 'gzip -dkc test/pihole-FTL.db.sql.gz > test/pihole-FTL.db.sql.2'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  printf "Remove generated GZIP file:\n"
  run bash -c 'rm test/pihole-FTL.db.sql.gz'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  printf "Compare uncompressed files (original vs. FTL uncompressed):\n"
  run bash -c 'cmp test/pihole-FTL.db.sql test/pihole-FTL.db.sql.1'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  printf "Compare uncompressed files (original vs. gzip uncompressed):\n"
  run bash -c 'cmp test/pihole-FTL.db.sql test/pihole-FTL.db.sql.2'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  printf "Remove generated files:\n"
  run bash -c 'rm test/pihole-FTL.db.sql.[1-2]'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "SHA256 checksum working" {
  run bash -c './pihole-FTL sha256sum test/test.pem'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "ce4c01340ef46bf3bc26831f7c53763d57c863528826aa795f1da5e16d6e7b2d  test/test.pem" ]]
}

@test "Internal IP -> name resolution works" {
  run bash -c "./pihole-FTL ptr 127.0.0.1 | tail -n1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "localhost" ]]
  run bash -c "./pihole-FTL ptr ::1 | tail -n1"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "localhost" ]]
}

@test "API validation" {
  run python3 test/api/checkAPI.py
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
}

@test "CLI config output as expected" {
  # Partial match printing
  run bash -c './pihole-FTL --config dns.upstream'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "dns.upstreams = [ 127.0.0.1#5555 ]" ]]

  # Exact match printing
  run bash -c './pihole-FTL --config dns.upstreams'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "[ 127.0.0.1#5555 ]" ]]
  run bash -c './pihole-FTL --config dns.piholePTR'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "PI.HOLE" ]]
  run bash -c './pihole-FTL --config dns.hosts'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "[ 1.1.1.1 abc-custom.com def-custom.de, 2.2.2.2 äste.com steä.com ]" ]]
  run bash -c './pihole-FTL --config webserver.port'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "80,[::]:80,443s,[::]:443s" ]]
}

@test "Create, verify and re-import Teleporter file via CLI" {
  run bash -c './pihole-FTL --teleporter'
  printf "%s\n" "${lines[@]}"
  [[ $status == 0 ]]
  # Get filename from last line printed by FTL
  filename="${lines[-1]}"
#  run bash -c 'zipinfo ${filename}'
#  printf "%s\n" "${lines[@]}"
#  [[ $status == 0 ]]
  run bash -c "./pihole-FTL --teleporter ${filename}"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[-3]}" == "Imported etc/pihole/pihole.toml" ]]
  [[ "${lines[-2]}" == "Imported etc/pihole/dhcp.leases" ]]
  [[ "${lines[-1]}" == "Imported etc/pihole/gravity.db" ]]
  [[ $status == 0 ]]
  run bash -c "rm ${filename}"
}

@test "Expected number of config file rotations" {
  run bash -c 'grep -c "INFO: Config file written to /etc/pihole/pihole.toml" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "3" ]]
  run bash -c 'grep -c "DEBUG_CONFIG: pihole.toml unchanged" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "3" ]]
  run bash -c 'grep -c "DEBUG_CONFIG: Config file written to /etc/pihole/dnsmasq.conf" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "DEBUG_CONFIG: dnsmasq.conf unchanged" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
  run bash -c 'grep -c "DEBUG_CONFIG: HOSTS file written to /etc/pihole/hosts/custom.list" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "DEBUG_CONFIG: custom.list unchanged" /var/log/pihole/FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "3" ]]
}
