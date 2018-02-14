#!./test/libs/bats/bin/bats

load 'libs/bats-support/load'
# load 'libs/bats-assert/load'

@test "Version" {
  run bash -c 'echo ">version" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "version" ]]
  [[ ${lines[2]} =~ "tag" ]]
  [[ ${lines[3]} =~ "branch" ]]
  [[ ${lines[4]} =~ "date" ]]
  [[ ${lines[5]} == "---EOM---" ]]
}

@test "Statistics" {
  run bash -c 'echo ">stats" | nc -v 127.0.0.1 4711'
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
  [[ ${lines[11]} == "---EOM---" ]]
}

@test "Top Clients (descending, default)" {
  run bash -c 'echo ">top-clients" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 4 192.168.2.208" ]]
  [[ ${lines[2]} =~ "1 2 127.0.0.1" ]]
  [[ ${lines[3]} =~ "2 1 10.8.0.2" ]]
  [[ ${lines[4]} == "---EOM---" ]]
}

@test "Top Clients (ascending)" {
  run bash -c 'echo ">top-clients asc" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 1 10.8.0.2" ]]
  [[ ${lines[2]} =~ "1 2 127.0.0.1" ]]
  [[ ${lines[3]} =~ "2 4 192.168.2.208" ]]
  [[ ${lines[4]} == "---EOM---" ]]
}

@test "Top Domains (descending, default)" {
  run bash -c 'echo ">top-domains" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 2 play.google.com" ]]
  [[ ${lines[2]} == "1 1 raspberrypi" ]]
  [[ ${lines[3]} == "2 1 checkip.dyndns.org" ]]
  [[ ${lines[4]} == "3 1 example.com" ]]
  [[ ${lines[5]} == "---EOM---" ]]
}

@test "Top Domains (ascending)" {
  run bash -c 'echo ">top-domains asc" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 1 raspberrypi" ]]
  [[ ${lines[2]} == "1 1 checkip.dyndns.org" ]]
  [[ ${lines[3]} == "2 1 example.com" ]]
  [[ ${lines[4]} == "3 2 play.google.com" ]]
  [[ ${lines[5]} == "---EOM---" ]]
}

@test "Top Ads (descending, default)" {
  run bash -c 'echo ">top-ads" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 1 blacklisted.com" ]]
  [[ ${lines[2]} == "1 1 addomain.com" ]]
  [[ ${lines[3]} == "---EOM---" ]]
}

@test "Top Ads (ascending)" {
  run bash -c 'echo ">top-ads asc" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 1 blacklisted.com" ]]
  [[ ${lines[2]} == "1 1 addomain.com" ]]
  [[ ${lines[3]} == "---EOM---" ]]
}

@test "Over Time" {
  run bash -c 'echo ">overTime" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "7 2" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}

@test "Forward Destinations" {
  run bash -c 'echo ">forward-dest" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 57.14 ::1 local" ]]
  [[ ${lines[2]} =~ "1 28.57 2001:1608:10:25::9249:d69b" ]]
  [[ ${lines[3]} =~ "2 14.29 2620:0:ccd::2 resolver2.ipv6-sandbox.opendns.com" ]]
  [[ ${lines[4]} == "---EOM---" ]]
}

@test "Forward Destinations (unsorted)" {
  run bash -c 'echo ">forward-dest unsorted" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 28.57 2001:1608:10:25::9249:d69b" ]]
  [[ ${lines[2]} =~ "1 14.29 2620:0:ccd::2 resolver2.ipv6-sandbox.opendns.com" ]]
  [[ ${lines[3]} =~ "2 57.14 ::1 local" ]]
  [[ ${lines[4]} == "---EOM---" ]]
}

@test "Query Types" {
  run bash -c 'echo ">querytypes" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "A (IPv4): 71.43" ]]
  [[ ${lines[2]} == "AAAA (IPv6): 28.57" ]]
  [[ ${lines[3]} == "---EOM---" ]]
}

@test "Get all queries" {
  run bash -c 'echo ">getallqueries" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 raspberrypi" ]]
  [[ ${lines[2]} =~ "IPv4 checkip.dyndns.org" ]]
  [[ ${lines[3]} =~ "IPv4 example.com" ]]
  [[ ${lines[4]} =~ "IPv4 play.google.com" ]]
  [[ ${lines[5]} =~ "IPv6 play.google.com" ]]
  [[ ${lines[6]} =~ "IPv4 blacklisted.com" ]]
  [[ ${lines[7]} =~ "IPv4 addomain.com" ]]
  [[ ${lines[8]} == "---EOM---" ]]
}

@test "Get all queries (domain filtered)" {
  run bash -c 'echo ">getallqueries-domain play.google.com" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv4 play.google.com" ]]
  [[ ${lines[2]} =~ "IPv6 play.google.com" ]]
  [[ ${lines[3]} == "---EOM---" ]]
}

@test "Get all queries (domain + number filtered)" {
  run bash -c 'echo ">getallqueries-domain play.google.com (3)" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 play.google.com" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}

@test "Get all queries (client filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 raspberrypi" ]]
  [[ ${lines[2]} =~ "IPv4 checkip.dyndns.org" ]]
  [[ ${lines[3]} == "---EOM---" ]]
}

@test "Get all queries (client + number filtered)" {
  run bash -c 'echo ">getallqueries-client 127.0.0.1 (6)" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv4 checkip.dyndns.org" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}

@test "Memory" {
  run bash -c 'echo ">memory" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "memory allocated for internal data structure:" ]]
  [[ ${lines[2]} =~ "dynamically allocated allocated memory used for strings:" ]]
  [[ ${lines[3]} =~ "Sum:" ]]
  [[ ${lines[4]} == "---EOM---" ]]
}

@test "Get client ID" {
  run bash -c 'echo ">clientID" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}

@test "Recent blocked" {
  run bash -c 'echo ">recentBlocked" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "addomain.com" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}

# @test "IPv6 socket connection" {
#   run bash -c 'echo ">recentBlocked" | nc -v ::1 4711'
#   echo "output: ${lines[@]}"
#   [[ ${lines[0]} == "Connection to ::1 4711 port [tcp/*] succeeded!" ]]
#   [[ ${lines[1]} == "addomain.com" ]]
#   [[ ${lines[2]} == "---EOM---" ]]
# }

@test "DB test: Tables created and populated?" {
  run bash -c 'sqlite3 pihole-FTL.db .dump'
  echo "output: ${lines[@]}"
  [[ "${lines[@]}" == *"CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );"* ]]
  [[ "${lines[@]}" == *"INSERT INTO \"ftl\" VALUES(0,1);"* ]]
}

@test "Arguments check: Invalid option" {
  run bash -c './pihole-FTL abc'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL: invalid option -- 'abc'" ]]
  [[ ${lines[1]} == "Try './pihole-FTL --help' for more information" ]]
}

@test "Help argument return help text" {
  run bash -c './pihole-FTL help'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "pihole-FTL - The Pi-hole FTL engine" ]]
}

@test "Unix socket returning data" {
  run bash -c './socket-test travis'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Socket created" ]]
  [[ ${lines[1]} == "Connection established" ]]
  [[ ${lines[2]} == "d2 ff ff ff ff d2 00 00 00 07 d2 00 00 00 02 ca 41 e4 92 49 d2 00 00 00 06 d2 00 00 00 03 d2 00 00 00 02 d2 00 00 00 03 d2 00 00 00 03 cc 02 c1 " ]]
}

@test "Final part of the tests: Killing pihole-FTL process" {
  run bash -c 'echo ">kill" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "killed" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}
