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
  run bash -c 'grep -c "Compiled 2 whitelist and 1 blacklist regex filters" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Blacklisted domain is blocked" {
  run bash -c "dig blacklist-blocked.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Gravity domain is blocked" {
  run bash -c "dig gravity-blocked.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Gravity domain is blocked (TCP)" {
  run bash -c "dig gravity-blocked.test.pi-hole.net @127.0.0.1 +tcp +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Gravity domain + whitelist exact match is not blocked" {
  run bash -c "dig whitelisted.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Gravity domain + whitelist regex match is not blocked" {
  run bash -c "dig discourse.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Regex blacklist match is blocked" {
  run bash -c "dig regex5.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Regex blacklist mismatch is not blocked" {
  run bash -c "dig regexA.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Regex blacklist match + whitelist exact match is not blocked" {
  run bash -c "dig regex1.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Regex blacklist match + whitelist regex match is not blocked" {
  run bash -c "dig regex2.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Client 2: Gravity match matching unassociated whitelist is blocked" {
  run bash -c "dig whitelisted.test.pi-hole.net -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
}

@test "Client 2: Regex blacklist match matching unassociated whitelist is blocked" {
  run bash -c "dig regex1.test.pi-hole.net -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
}

@test "Same domain is not blocked for client 1 ..." {
  run bash -c "dig regex1.test.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "... or client 3" {
  run bash -c "dig regex1.test.pi-hole.net -b 127.0.0.3  @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Client 2: Unassociated blacklist match is not blocked" {
  run bash -c "dig blacklist-blocked.test.pi-hole.net -b 127.0.0.2 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Client 3: Exact blacklist domain is not blocked" {
  run bash -c "dig blacklist-blocked.test.pi-hole.net -b 127.0.0.3 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Client 3: Regex blacklist domain is not blocked" {
  run bash -c "dig regex1.test.pi-hole.net -b 127.0.0.3 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Client 3: Gravity domain is not blocked" {
  run bash -c "dig discourse.pi-hole.net -b 127.0.0.3 @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Google.com (A) is not blocked" {
  run bash -c "dig A google.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Google.com (AAAA) is not blocked (TCP query)" {
  run bash -c "dig AAAA google.com @127.0.0.1 +short +tcp"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "::" ]]
}

@test "Known host is resolved as expected" {
  run bash -c "dig ftl.pi-hole.net @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "139.59.170.52" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Statistics as expected" {
  run bash -c 'echo ">stats >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "domains_being_blocked 3" ]]
  [[ ${lines[2]} == "dns_queries_today 22" ]]
  [[ ${lines[3]} == "ads_blocked_today 6" ]]
  [[ ${lines[4]} == "ads_percentage_today 27.272728" ]]
  [[ ${lines[5]} == "unique_domains 12" ]]
  [[ ${lines[6]} == "queries_forwarded 9" ]]
  [[ ${lines[7]} == "queries_cached 7" ]]
  # Clients ever seen is commented out as CircleCI may have
  # more devices in its ARP cache so testing against a fixed
  # number of clients may not work in all cases
  #[[ ${lines[8]} == "clients_ever_seen 3" ]]
  #[[ ${lines[9]} == "unique_clients 3" ]]
  [[ ${lines[10]} == "dns_queries_all_types 22" ]]
  [[ ${lines[11]} == "reply_NODATA 0" ]]
  [[ ${lines[12]} == "reply_NXDOMAIN 0" ]]
  [[ ${lines[13]} == "reply_CNAME 0" ]]
  [[ ${lines[14]} == "reply_IP 20" ]]
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
  [[ ${lines[1]} == "0 15 127.0.0.1 "* ]]
  [[ ${lines[2]} == "1 4 127.0.0.3 "* ]]
  [[ ${lines[3]} == "2 3 127.0.0.2 "* ]]
  [[ ${lines[4]} == "" ]]
}

@test "Top Domains" {
  run bash -c 'echo ">top-domains (20) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *" 4 regex1.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 2 google.com"* ]]
  [[ "${lines[@]}" == *" 2 blacklist-blocked.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 2 discourse.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 version.ftl"* ]]
  [[ "${lines[@]}" == *" 1 version.bind"* ]]
  [[ "${lines[@]}" == *" 1 whitelisted.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 regexa.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 regex2.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 ftl.pi-hole.net"* ]]
  [[ "${lines[11]}" == "" ]]
}

@test "Top Ads" {
  run bash -c 'echo ">top-ads (20) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *" 2 gravity-blocked.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 blacklist-blocked.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 whitelisted.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 regex5.test.pi-hole.net"* ]]
  [[ "${lines[@]}" == *" 1 regex1.test.pi-hole.net"* ]]
  [[ ${lines[6]} == "" ]]
}

@test "Domain auditing, approved domains are not shown" {
  run bash -c 'echo ">top-domains for audit >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[@]} != *"google.com"* ]]
}

@test "Forward Destinations" {
  run bash -c 'echo ">forward-dest >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "-2 27.27 blocklist blocklist" ]]
  [[ ${lines[2]} == "-1 31.82 cache cache" ]]
  [[ ${lines[3]} == "0 40.91 "* ]]
  [[ ${lines[4]} == "" ]]
}

@test "Query Types" {
  run bash -c 'echo ">querytypes >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "A (IPv4): 86.36" ]]
  [[ ${lines[2]} == "AAAA (IPv6): 4.55" ]]
  [[ ${lines[3]} == "ANY: 0.00" ]]
  [[ ${lines[4]} == "SRV: 0.00" ]]
  [[ ${lines[5]} == "SOA: 0.00" ]]
  [[ ${lines[6]} == "PTR: 0.00" ]]
  [[ ${lines[7]} == "TXT: 9.09" ]]
  [[ ${lines[8]} == "NAPTR: 0.00" ]]
  [[ ${lines[9]} == "MX: 0.00" ]]
  [[ ${lines[10]} == "DS: 0.00" ]]
  [[ ${lines[11]} == "RRSIG: 0.00" ]]
  [[ ${lines[12]} == "DNSKEY: 0.00" ]]
  [[ ${lines[13]} == "OTHER: 0.00" ]]
  [[ ${lines[14]} == "" ]]
}

# Here and below: Acknowledge that there might be a host name after
# the IP address of the client (..."*"...)

@test "Get all queries" {
  run bash -c 'echo ">getallqueries >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"TXT version.ftl "?*" 3 0 6"* ]]
  [[ ${lines[2]} == *"TXT version.bind "?*" 3 0 6"* ]]
  [[ ${lines[3]} == *"A blacklist-blocked.test.pi-hole.net "?*" 5 0 4"* ]]
  [[ ${lines[4]} == *"A gravity-blocked.test.pi-hole.net "?*" 1 0 4"* ]]
  [[ ${lines[5]} == *"A gravity-blocked.test.pi-hole.net "?*" 1 0 4"* ]]
  [[ ${lines[6]} == *"A whitelisted.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[7]} == *"A discourse.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[8]} == *"A regex5.test.pi-hole.net "?*" 4 0 4"* ]]
  [[ ${lines[9]} == *"A regexa.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[10]} == *"A regex1.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[11]} == *"A regex2.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[12]} == *"A whitelisted.test.pi-hole.net 127.0.0.2 1 0 4"* ]]
  [[ ${lines[13]} == *"A regex1.test.pi-hole.net 127.0.0.2 4 0 4"* ]]
  [[ ${lines[14]} == *"A regex1.test.pi-hole.net 127.0.0.1 3 0 4"* ]]
  [[ ${lines[15]} == *"A regex1.test.pi-hole.net 127.0.0.3 3 0 4"* ]]
  [[ ${lines[16]} == *"A blacklist-blocked.test.pi-hole.net 127.0.0.2 2 0 4"* ]]
  [[ ${lines[17]} == *"A blacklist-blocked.test.pi-hole.net 127.0.0.3 3 0 4"* ]]
  [[ ${lines[18]} == *"A regex1.test.pi-hole.net 127.0.0.3 3 0 4"* ]]
  [[ ${lines[19]} == *"A discourse.pi-hole.net 127.0.0.3 3 0 4"* ]]
  [[ ${lines[20]} == *"A google.com "?*" 2 0 4"* ]]
  [[ ${lines[21]} == *"AAAA google.com "?*" 2 0 4"* ]]
  [[ ${lines[22]} == *"A ftl.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[23]} == "" ]]
}

@test "Get all queries (domain filtered)" {
  run bash -c 'echo ">getallqueries-domain regexa.test.pi-hole.net >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regexa.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[2]} == "" ]]
}

@test "Get all queries (domain + number filtered)" {
  run bash -c 'echo ">getallqueries-domain regexa.test.pi-hole.net (20) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regexa.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[2]} == "" ]]
}

@test "Get all queries (client filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"TXT version.ftl "?*" 3 0 6"* ]]
  [[ ${lines[2]} == *"TXT version.bind "?*" 3 0 6"* ]]
  [[ ${lines[3]} == *"A blacklist-blocked.test.pi-hole.net "?*" 5 0 4"* ]]
  [[ ${lines[4]} == *"A gravity-blocked.test.pi-hole.net "?*" 1 0 4"* ]]
  [[ ${lines[5]} == *"A gravity-blocked.test.pi-hole.net "?*" 1 0 4"* ]]
  [[ ${lines[6]} == *"A whitelisted.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[7]} == *"A discourse.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[8]} == *"A regex5.test.pi-hole.net "?*" 4 0 4"* ]]
  [[ ${lines[9]} == *"A regexa.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[10]} == *"A regex1.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[11]} == *"A regex2.test.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[12]} == *"A regex1.test.pi-hole.net "?*" 3 0 4"* ]]
  [[ ${lines[13]} == *"A google.com "?*" 2 0 4"* ]]
  [[ ${lines[14]} == *"AAAA google.com "?*" 2 0 4"* ]]
  [[ ${lines[15]} == *"A ftl.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[16]} == "" ]]
}

@test "Get all queries (client + number filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 (2) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"AAAA google.com "?*" 2 0 4"* ]]
  [[ ${lines[2]} == *"A ftl.pi-hole.net "?*" 2 0 4"* ]]
  [[ ${lines[3]} == "" ]]
}

@test "Recent blocked" {
  run bash -c 'echo ">recentBlocked >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "regex1.test.pi-hole.net" ]]
  [[ ${lines[2]} == "" ]]
}

@test "pihole-FTL.db schema as expected" {
  run bash -c 'sqlite3 /etc/pihole/pihole-FTL.db .dump'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT , additional_info TEXT);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE counters ( id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL );"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE IF NOT EXISTS \"network\" ( id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL, interface TEXT NOT NULL, name TEXT, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL, macVendor TEXT);"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE network_addresses ( network_id INTEGER NOT NULL, ip TEXT NOT NULL, lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)), UNIQUE(network_id,ip), FOREIGN KEY(network_id) REFERENCES network(id));"* ]]
  [[ "${lines[@]}" == *"CREATE INDEX idx_queries_timestamps ON queries (timestamp);"* ]]
}

@test "Fail on invalid argument" {
  run bash -c '/home/pihole/pihole-FTL abc'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL: invalid option -- 'abc'" ]]
  [[ ${lines[1]} == "Try '/home/pihole/pihole-FTL --help' for more information" ]]
}

@test "Help argument return help text" {
  run bash -c '/home/pihole/pihole-FTL help'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL - The Pi-hole FTL engine" ]]
  [[ ${lines[3]} == "Available arguments:" ]]
}

@test "No WARNING messages in pihole-FTL.log (besides known capability issues)" {
  run bash -c 'grep "WARNING:" /var/log/pihole-FTL.log | grep -c -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE"'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "No ERROR messages in pihole-FTL.log" {
  run bash -c 'grep -c "ERROR:" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "No FATAL messages in pihole-FTL.log" {
  run bash -c 'grep -c "FATAL:" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

# Regex tests
@test "Compiled blacklist regex as expected" {
  run bash -c 'grep -c "Compiling blacklist regex 0 (DB ID 6): regex\[0-9\].test.pi-hole.net" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Compiled whitelist regex as expected" {
  run bash -c 'grep -c "Compiling whitelist regex 0 (DB ID 3): regex2" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
  run bash -c 'grep -c "Compiling whitelist regex 1 (DB ID 4): discourse" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Number of compiled regex as expected" {
  run bash -c 'grep -c "Compiled 2 whitelist and 1 blacklist regex filters in" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "1" ]]
}

@test "Regex Test 1: \"regex7.test.pi-hole.net\" vs. [database regex]: MATCH" {
  run bash -c './pihole-FTL regex-test "regex7.test.pi-hole.net"'
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

# x86_64-musl is built on busybox which has a slightly different
# variant of ls displaying three, instead of one, spaces between the
# user and group names.

@test "Ownership and permissions of pihole-FTL.db correct" {
  run bash -c 'ls -l /etc/pihole/pihole-FTL.db'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == *"pihole pihole"* || ${lines[0]} == *"pihole   pihole"* ]]
  [[ ${lines[0]} == "-rw-r--r--"* ]]
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
  run bash -c 'grep -c "gravity blocked gravity-blocked.test.pi-hole.net is 0.0.0.0" /var/log/pihole.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "2" ]]
}

@test "Port file exists and contains expected API port" {
  run bash -c 'cat /run/pihole-FTL.port'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "4711" ]]
}
