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

@test "Statistics" {
  run bash -c 'echo ">stats >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "domains_being_blocked -1" ]]
  [[ ${lines[2]} =~ "dns_queries_today 7" ]]
  [[ ${lines[3]} =~ "ads_blocked_today 2" ]]
  [[ ${lines[4]} =~ "ads_percentage_today 28.571428" ]]
  [[ ${lines[5]} =~ "unique_domains 6" ]]
  [[ ${lines[6]} =~ "queries_forwarded 3" ]]
  [[ ${lines[7]} =~ "queries_cached 2" ]]
  [[ ${lines[8]} == "clients_ever_seen 3" ]]
  [[ ${lines[9]} == "unique_clients 3" ]]
  [[ ${lines[10]} == "status unknown" ]]
}

@test "Top Clients (descending, default)" {
  run bash -c 'echo ">top-clients >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 4 192.168.2.208" ]]
  [[ ${lines[2]} =~ "1 2 127.0.0.1" ]]
  [[ ${lines[3]} =~ "2 1 10.8.0.2" ]]
}

@test "Top Clients (ascending)" {
  run bash -c 'echo ">top-clients asc >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 1 10.8.0.2" ]]
  [[ ${lines[2]} =~ "1 2 127.0.0.1" ]]
  [[ ${lines[3]} =~ "2 4 192.168.2.208" ]]
}

@test "Top Domains (descending, default)" {
  run bash -c 'echo ">top-domains >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 2 play.google.com" ]]
  [[ ${lines[2]} == "1 1 raspberrypi" ]]
  [[ ${lines[3]} == "2 1 checkip.dyndns.org" ]]
  [[ ${lines[4]} == "3 1 example.com" ]]
}

@test "Top Domains (ascending)" {
  run bash -c 'echo ">top-domains asc >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 1 raspberrypi" ]]
  [[ ${lines[2]} == "1 1 checkip.dyndns.org" ]]
  [[ ${lines[3]} == "2 1 example.com" ]]
  [[ ${lines[4]} == "3 2 play.google.com" ]]
}

@test "Top Ads (descending, default)" {
  run bash -c 'echo ">top-ads >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 1 blacklisted.com" ]]
  [[ ${lines[2]} == "1 1 addomain.com" ]]
}

@test "Top Ads (ascending)" {
  run bash -c 'echo ">top-ads asc >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 1 blacklisted.com" ]]
  [[ ${lines[2]} == "1 1 addomain.com" ]]
}

@test "Over Time" {
  run bash -c 'echo ">overTime >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "7 2" ]]
}

@test "Forward Destinations" {
  run bash -c 'echo ">forward-dest >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 57.14 ::1 local" ]]
  [[ ${lines[2]} =~ "1 28.57 2001:1608:10:25::9249:d69b" ]]
  [[ ${lines[3]} =~ "2 14.29 2620:0:ccd::2 resolver2.ipv6-sandbox.opendns.com" ]]
}

@test "Forward Destinations (unsorted)" {
  run bash -c 'echo ">forward-dest unsorted >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 28.57 2001:1608:10:25::9249:d69b" ]]
  [[ ${lines[2]} =~ "1 14.29 2620:0:ccd::2 resolver2.ipv6-sandbox.opendns.com" ]]
  [[ ${lines[3]} =~ "2 57.14 ::1 local" ]]
}

@test "Query Types" {
  run bash -c 'echo ">querytypes >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "A (IPv4): 71.43" ]]
  [[ ${lines[2]} == "AAAA (IPv6): 28.57" ]]
}

@test "Get all queries" {
  run bash -c 'echo ">getallqueries >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 raspberrypi" ]]
  [[ ${lines[2]} =~ "IPv4 checkip.dyndns.org" ]]
  [[ ${lines[3]} =~ "IPv4 example.com" ]]
  [[ ${lines[4]} =~ "IPv4 play.google.com" ]]
  [[ ${lines[5]} =~ "IPv6 play.google.com" ]]
  [[ ${lines[6]} =~ "IPv4 blacklisted.com" ]]
  [[ ${lines[7]} =~ "IPv4 addomain.com" ]]
}

@test "Get all queries (domain filtered)" {
  run bash -c 'echo ">getallqueries-domain play.google.com >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv4 play.google.com" ]]
  [[ ${lines[2]} =~ "IPv6 play.google.com" ]]
}

@test "Get all queries (domain + number filtered)" {
  run bash -c 'echo ">getallqueries-domain play.google.com (3) >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 play.google.com" ]]
}

@test "Get all queries (client filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 raspberrypi" ]]
  [[ ${lines[2]} =~ "IPv4 checkip.dyndns.org" ]]
}

@test "Get all queries (client + number filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 (6) >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv4 checkip.dyndns.org" ]]
}

@test "Memory" {
  run bash -c 'echo ">memory >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "memory allocated for internal data structure:" ]]
  [[ ${lines[2]} =~ "dynamically allocated allocated memory used for strings:" ]]
  [[ ${lines[3]} =~ "Sum:" ]]
}

@test "Get client ID" {
  run bash -c 'echo ">clientID >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
}

@test "Recent blocked" {
  run bash -c 'echo ">recentBlocked >quit" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "addomain.com" ]]
}

# @test "IPv6 socket connection" {
#   run bash -c 'echo ">recentBlocked" | nc -v ::1 4711'
#   echo "output: ${lines[@]}"
#   [[ ${lines[0]} == "Connection to ::1 4711 port [tcp/*] succeeded!" ]]
#   [[ ${lines[1]} == "addomain.com"
# }


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
  run bash -c 'kill $(pidof pihole-FTL)'
  printf "%s\n" "${lines[@]}"
}
