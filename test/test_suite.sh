#!./test/libs/bats/bin/bats

load 'libs/bats-support/load'

@test "Version, Tag, Branch, Hash, Date is reported" {
  run bash -c 'echo ">version >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "version "* ]]
  [[ ${lines[2]} == "tag "* ]]
  [[ ${lines[3]} == "branch "* ]]
  [[ ${lines[4]} == "hash "* ]]
  [[ ${lines[5]} == "date "* ]]
}

@test "Blacklisted domain is blocked" {
  run bash -c "dig blacklisted.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
}

@test "Whitelisted domain is not blocked" {
  run bash -c "dig whitelisted.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Regex filter match is blocked" {
  run bash -c "dig regex5.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0.0.0.0" ]]
}

@test "Regex filter mismatch is not blocked" {
  run bash -c "dig regexA.com @127.0.0.1 +short"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} != "0.0.0.0" ]]
}

@test "Statistics as expected" {
  run bash -c 'echo ">stats >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "domains_being_blocked 45732" ]]
  [[ ${lines[2]} == "dns_queries_today 6" ]]
  [[ ${lines[3]} == "ads_blocked_today 2" ]]
  [[ ${lines[4]} == "ads_percentage_today 33.333332" ]]
  [[ ${lines[5]} == "unique_domains 6" ]]
  [[ ${lines[6]} == "queries_forwarded 2" ]]
  [[ ${lines[7]} == "queries_cached 2" ]]
  [[ ${lines[8]} == "clients_ever_seen 1" ]]
  [[ ${lines[9]} == "unique_clients 1" ]]
  [[ ${lines[10]} == "dns_queries_all_types 6" ]]
  [[ ${lines[11]} == "reply_NODATA 0" ]]
  [[ ${lines[12]} == "reply_NXDOMAIN 0" ]]
  [[ ${lines[13]} == "reply_CNAME 0" ]]
  [[ ${lines[14]} == "reply_IP 3" ]]
  [[ ${lines[15]} == "privacy_level 0" ]]
  [[ ${lines[16]} == "status enabled" ]]
}

@test "Top Clients (descending, default)" {
  run bash -c 'echo ">top-clients >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 6 127.0.0.1 " ]]
}

@test "Top Clients (ascending)" {
  run bash -c 'echo ">top-clients asc >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 6 127.0.0.1 " ]]
}

@test "Top Domains (descending, default)" {
  run bash -c 'echo ">top-domains >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 1 version.ftl" ]]
  [[ ${lines[2]} == "1 1 version.bind" ]]
  [[ ${lines[3]} == "2 1 whitelisted.com" ]]
  [[ ${lines[4]} == "3 1 regexa.com" ]]
}

@test "Top Domains (ascending)" {
  run bash -c 'echo ">top-domains asc >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 1 version.ftl" ]]
  [[ ${lines[2]} == "1 1 version.bind" ]]
  [[ ${lines[3]} == "2 1 whitelisted.com" ]]
  [[ ${lines[4]} == "3 1 regexa.com" ]]
}

@test "Top Ads (descending, default)" {
  run bash -c 'echo ">top-ads >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 1 blacklisted.com" ]]
  [[ ${lines[2]} == "1 1 regex5.com" ]]
}

@test "Top Ads (ascending)" {
  run bash -c 'echo ">top-ads asc >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "0 1 blacklisted.com" ]]
  [[ ${lines[2]} == "1 1 regex5.com" ]]
}

@test "Forward Destinations" {
  run bash -c 'echo ">forward-dest >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "-2 33.33 blocklist blocklist" ]]
  [[ ${lines[2]} == "-1 33.33 cache cache" ]]
  [[ ${lines[3]} == "0 33.33 127.0.0.11 " ]]
}

@test "Forward Destinations (unsorted)" {
  run bash -c 'echo ">forward-dest unsorted >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "-2 33.33 blocklist blocklist" ]]
  [[ ${lines[2]} == "-1 33.33 cache cache" ]]
  [[ ${lines[3]} == "0 33.33 127.0.0.11 " ]]
}

@test "Query Types" {
  run bash -c 'echo ">querytypes >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "A (IPv4): 66.67" ]]
  [[ ${lines[2]} == "AAAA (IPv6): 0.00" ]]
  [[ ${lines[3]} == "ANY: 0.00" ]]
  [[ ${lines[4]} == "SRV: 0.00" ]]
  [[ ${lines[5]} == "SOA: 0.00" ]]
  [[ ${lines[6]} == "PTR: 0.00" ]]
  [[ ${lines[7]} == "TXT: 33.33" ]]
}

@test "Get all queries" {
  run bash -c 'echo ">getallqueries >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"TXT version.ftl 127.0.0.1 3 0 6"* ]]
  [[ ${lines[2]} == *"TXT version.bind 127.0.0.1 3 0 6"* ]]
  [[ ${lines[3]} == *"A blacklisted.com 127.0.0.1 5 0 4"* ]]
  [[ ${lines[4]} == *"A whitelisted.com 127.0.0.1 2 0 4"* ]]
  [[ ${lines[5]} == *"A regex5.com 127.0.0.1 4 0 4"* ]]
  [[ ${lines[6]} == *"A regexa.com 127.0.0.1 2 0 7"* ]]
}

@test "Get all queries (domain filtered)" {
  run bash -c 'echo ">getallqueries-domain regexa.com >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regexa.com 127.0.0.1 2 0 7"* ]]
}

@test "Get all queries (domain + number filtered)" {
  run bash -c 'echo ">getallqueries-domain regexa.com (3) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regexa.com 127.0.0.1 2 0 7"* ]]
}

@test "Get all queries (client filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"TXT version.ftl 127.0.0.1 3 0 6"* ]]
  [[ ${lines[2]} == *"TXT version.bind 127.0.0.1 3 0 6"* ]]
  [[ ${lines[3]} == *"A blacklisted.com 127.0.0.1 5 0 4"* ]]
  [[ ${lines[4]} == *"A whitelisted.com 127.0.0.1 2 0 4"* ]]
  [[ ${lines[5]} == *"A regex5.com 127.0.0.1 4 0 4"* ]]
  [[ ${lines[6]} == *"A regexa.com 127.0.0.1 2 0 7"* ]]
}

@test "Get all queries (client + number filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 (2) >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == *"A regex5.com 127.0.0.1 4 0 4"* ]]
  [[ ${lines[2]} == *"A regexa.com 127.0.0.1 2 0 7"* ]]
}

@test "Recent blocked" {
  run bash -c 'echo ">recentBlocked >quit" | nc -v 127.0.0.1 4711'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[1]} == "regex5.com" ]]
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
  run bash -c './pihole-FTL-linux-x86_64 abc'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL: invalid option -- 'abc'" ]]
  [[ ${lines[1]} == "Try './pihole-FTL-linux-x86_64 --help' for more information" ]]
}

@test "Help argument return help text" {
  run bash -c './pihole-FTL-linux-x86_64 help'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL - The Pi-hole FTL engine" ]]
  [[ ${lines[3]} == "Available arguments:" ]]
}

@test "No FATAL messages in pihole-FTL.log" {
  run bash -c 'grep -c "FATAL" /var/log/pihole-FTL.log'
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "0" ]]
}

@test "Final part of the tests: Kill pihole-FTL process" {
  run bash -c 'kill $(pidof pihole-FTL-linux-x86_64)'
  printf "%s\n" "${lines[@]}"
}
