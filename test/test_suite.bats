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

@test "Blacklisted domain is blocked" {
  run bash -c "dig blacklisted.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Gravity domain is blocked" {
  run bash -c "dig 0427d7.se @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Whitelisted domain is not blocked" {
  run bash -c "dig whitelisted.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Regex filter match is blocked" {
  run bash -c "dig regex5.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Regex filter mismatch is not blocked" {
  run bash -c "dig regexA.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Google.com (A) is not blocked" {
  run bash -c "dig A google.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
  [[ ${lines[1]} == "" ]]
}

@test "Google.com (AAAA) is not blocked (TCP query)" {
  run bash -c "dig AAAA google.com @127.0.0.1 +short +tcp"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "::" ]]
  [[ ${lines[1]} == "" ]]
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
  [[ ${lines[1]} == "domains_being_blocked 2" ]]
  [[ ${lines[2]} == "dns_queries_today 10" ]]
  [[ ${lines[3]} == "ads_blocked_today 3" ]]
  [[ ${lines[4]} == "ads_percentage_today 30.000000" ]]
  [[ ${lines[5]} == "unique_domains 9" ]]
  [[ ${lines[6]} == "queries_forwarded 5" ]]
  [[ ${lines[7]} == "queries_cached 2" ]]
  [[ ${lines[8]} == "clients_ever_seen 1" ]]
  [[ ${lines[9]} == "unique_clients 1" ]]
  [[ ${lines[10]} == "dns_queries_all_types 10" ]]
  [[ ${lines[11]} == "reply_NODATA 0" ]]
  [[ ${lines[12]} == "reply_NXDOMAIN 0" ]]
  [[ ${lines[13]} == "reply_CNAME 0" ]]
  [[ ${lines[14]} == "reply_IP 7" ]]
  [[ ${lines[15]} == "privacy_level 0" ]]
  [[ ${lines[16]} == "status enabled" ]]
  [[ ${lines[17]} == "" ]]
}

@test "Top Clients (descending, default)" {
  run bash -c 'echo ">top-clients >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 10 127.0.0.1 "* ]]
  [[ ${lines[2]} == "" ]]
}

@test "Top Clients (ascending)" {
  run bash -c 'echo ">top-clients asc >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 10 127.0.0.1 "* ]]
  [[ ${lines[2]} == "" ]]
}

# Here and below: It is not meaningful to assume a particular order
# here as the values are sorted before output. It is unpredictable in
# which order they may come out. While this has always been the same
# when compiling for glibc, the new musl build reveals that another
# library may have a different interpretation here.

@test "Top Domains (descending, default)" {
  run bash -c 'echo ">top-domains >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 2 google.com" ]]
  [[ "${lines[@]}" == *" 1 version.ftl"* ]]
  [[ "${lines[@]}" == *" 1 version.bind"* ]]
  [[ "${lines[@]}" == *" 1 whitelisted.com"* ]]
  [[ "${lines[@]}" == *" 1 regexa.com"* ]]
  [[ "${lines[@]}" == *" 1 ftl.pi-hole.net"* ]]
  [[ ${lines[7]} == "" ]]
}

@test "Top Domains (ascending)" {
  run bash -c 'echo ">top-domains asc >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *" 1 version.ftl"* ]]
  [[ "${lines[@]}" == *" 1 version.bind"* ]]
  [[ "${lines[@]}" == *" 1 whitelisted.com"* ]]
  [[ "${lines[@]}" == *" 1 regexa.com"* ]]
  [[ "${lines[@]}" == *" 1 ftl.pi-hole.net"* ]]
  [[ ${lines[6]} == "5 2 google.com" ]]
  [[ ${lines[7]} == "" ]]
}

@test "Top Ads (descending, default)" {
  run bash -c 'echo ">top-ads >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *" 1 blacklisted.com"* ]]
  [[ "${lines[@]}" == *" 1 0427d7.se"* ]]
  [[ "${lines[@]}" == *" 1 regex5.com"* ]]
  [[ ${lines[4]} == "" ]]
}

@test "Top Ads (ascending)" {
  run bash -c 'echo ">top-ads asc >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *" 1 blacklisted.com"* ]]
  [[ "${lines[@]}" == *" 1 0427d7.se"* ]]
  [[ "${lines[@]}" == *" 1 regex5.com"* ]]
  [[ ${lines[4]} == "" ]]
}

@test "Forward Destinations" {
  run bash -c 'echo ">forward-dest >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "-2 30.00 blocklist blocklist" ]]
  [[ ${lines[2]} == "-1 20.00 cache cache" ]]
  [[ ${lines[3]} == "0 50.00 "* ]]
  [[ ${lines[4]} == "" ]]
}

@test "Forward Destinations (unsorted)" {
  run bash -c 'echo ">forward-dest unsorted >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "-2 30.00 blocklist blocklist" ]]
  [[ ${lines[2]} == "-1 20.00 cache cache" ]]
  [[ ${lines[3]} == "0 50.00 "* ]]
  [[ ${lines[4]} == "" ]]
}

@test "Query Types" {
  run bash -c 'echo ">querytypes >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "A (IPv4): 70.00" ]]
  [[ ${lines[2]} == "AAAA (IPv6): 10.00" ]]
  [[ ${lines[3]} == "ANY: 0.00" ]]
  [[ ${lines[4]} == "SRV: 0.00" ]]
  [[ ${lines[5]} == "SOA: 0.00" ]]
  [[ ${lines[6]} == "PTR: 0.00" ]]
  [[ ${lines[7]} == "TXT: 20.00" ]]
  [[ ${lines[8]} == "" ]]
}

# Here and below: Acknowledge that there might be a host name after
# the IP address of the client (..."*"...)

@test "Get all queries" {
  run bash -c 'echo ">getallqueries >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"TXT version.ftl "*" 3 0 6"* ]]
  [[ ${lines[2]} == *"TXT version.bind "*" 3 0 6"* ]]
  [[ ${lines[3]} == *"A blacklisted.com "*" 5 0 4"* ]]
  [[ ${lines[4]} == *"A 0427d7.se "*" 1 0 4"* ]]
  [[ ${lines[5]} == *"A whitelisted.com "*" 2 0 4"* ]]
  [[ ${lines[6]} == *"A regex5.com "*" 4 0 4"* ]]
  [[ ${lines[7]} == *"A regexa.com "*" 2 0 7"* ]]
  [[ ${lines[8]} == *"A google.com "*" 2 0 4"* ]]
  [[ ${lines[9]} == *"AAAA google.com "*" 2 0 4"* ]]
  [[ ${lines[10]} == *"A ftl.pi-hole.net "*" 2 0 4"* ]]
  [[ ${lines[11]} == "" ]]
}

@test "Get all queries (domain filtered)" {
  run bash -c 'echo ">getallqueries-domain regexa.com >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regexa.com "*" 2 0 7"* ]]
  [[ ${lines[2]} == "" ]]
}

@test "Get all queries (domain + number filtered)" {
  run bash -c 'echo ">getallqueries-domain regexa.com (6) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regexa.com "*" 2 0 7"* ]]
  [[ ${lines[2]} == "" ]]
}

@test "Get all queries (client filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"TXT version.ftl "*" 3 0 6"* ]]
  [[ ${lines[2]} == *"TXT version.bind "*" 3 0 6"* ]]
  [[ ${lines[3]} == *"A blacklisted.com "*" 5 0 4"* ]]
  [[ ${lines[4]} == *"A 0427d7.se "*" 1 0 4"* ]]
  [[ ${lines[5]} == *"A whitelisted.com "*" 2 0 4"* ]]
  [[ ${lines[6]} == *"A regex5.com "*" 4 0 4"* ]]
  [[ ${lines[7]} == *"A regexa.com "*" 2 0 7"* ]]
  [[ ${lines[8]} == *"A google.com "*" 2 0 4"* ]]
  [[ ${lines[9]} == *"AAAA google.com "*" 2 0 4"* ]]
  [[ ${lines[10]} == *"A ftl.pi-hole.net "*" 2 0 4"* ]]
  [[ ${lines[11]} == "" ]]
}

@test "Get all queries (client + number filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 (2) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"AAAA google.com "*" 2 0 4"* ]]
  [[ ${lines[2]} == *"A ftl.pi-hole.net "*" 2 0 4"* ]]
  [[ ${lines[3]} == "" ]]
}

@test "Recent blocked" {
  run bash -c 'echo ">recentBlocked >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "regex5.com" ]]
  [[ ${lines[2]} == "" ]]
}

@test "pihole-FTL.db schema as expected" {
  run bash -c 'sqlite3 /etc/pihole/pihole-FTL.db .dump'
  printf "%s\n" "${lines[@]}"
  [[ "${lines[@]}" == *"CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE counters ( id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL );"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE network ( id INTEGER PRIMARY KEY NOT NULL, ip TEXT NOT NULL, hwaddr TEXT NOT NULL, interface TEXT NOT NULL, name TEXT, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL,macVendor TEXT);"* ]]
  [[ "${lines[@]}" == *"CREATE INDEX idx_queries_timestamps ON queries (timestamp);"* ]]
  [[ "${lines[@]}" == *"CREATE UNIQUE INDEX network_hwaddr_idx ON network(hwaddr);"* ]]
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
  run bash -c 'grep "WARNING:" /var/log/pihole-FTL.log | grep -c -v -E "CAP_NET_ADMIN|CAP_NET_RAW"'
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

# x86_64-musl is built on busybox which has a slightly different
# variant of ls displaying three, instead of one, spaces between the
# user and group names.

@test "Ownership and permissions of pihole-FTL.db correct" {
  run bash -c 'ls -l /etc/pihole/pihole-FTL.db'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == *"pihole pihole"* || ${lines[0]} == *"pihole   pihole"* ]]
  [[ ${lines[0]} == "-rw-r--r--"* ]]
}

@test "Final part of the tests: Kill pihole-FTL process" {
  run bash -c 'kill $(pidof pihole-FTL)'
  printf "%s\n" "${lines[@]}"
}
