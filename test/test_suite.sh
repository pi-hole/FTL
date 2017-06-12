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
  [[ ${lines[2]} =~ "dns_queries_today 5" ]]
  [[ ${lines[3]} =~ "ads_blocked_today 0" ]]
  [[ ${lines[4]} =~ "ads_percentage_today 0.000000" ]]
  [[ ${lines[5]} =~ "unique_domains 4" ]]
  [[ ${lines[6]} =~ "queries_forwarded 3" ]]
  [[ ${lines[7]} =~ "queries_cached 2" ]]
  [[ ${lines[8]} == "---EOM---" ]]
}

@test "Top Clients" {
  run bash -c 'echo ">top-clients" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 2 192.168.2.208" ]]
  [[ ${lines[2]} == "1 2 127.0.0.1 localhost" ]]
  [[ ${lines[3]} =~ "2 1 10.8.0.2" ]]
  [[ ${lines[4]} == "---EOM---" ]]
}

@test "Top Domains" {
  run bash -c 'echo ">top-domains" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "0 2 play.google.com" ]]
  [[ ${lines[2]} == "1 1 pi.hole" ]]
  [[ ${lines[3]} == "2 1 checkip.dyndns.org" ]]
  [[ ${lines[4]} == "3 1 raspberrypi" ]]
  [[ ${lines[5]} == "---EOM---" ]]
}

@test "Top Ads" {
  run bash -c 'echo ">top-ads" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "---EOM---" ]]
}

@test "Over Time" {
  run bash -c 'echo ">overTime" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "5 0" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}

@test "Forward Destinations" {
  run bash -c 'echo ">forward-dest" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "0 4 2001:1608:10:25::9249:d69b" ]]
  [[ ${lines[2]} =~ "1 4 2620:0:ccd::2 resolver2.ipv6-sandbox.opendns.com" ]]
  [[ ${lines[3]} =~ "2 2 2001:1608:10:25::1c04:b12f" ]]
  [[ ${lines[4]} =~ "3 2 2620:0:ccc::2 resolver1.ipv6-sandbox.opendns.com" ]]
  [[ ${lines[5]} =~ "4 2 ::1 local" ]]
  [[ ${lines[6]} == "---EOM---" ]]
}

@test "Query Types" {
  run bash -c 'echo ">querytypes" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} == "A (IPv4): 3" ]]
  [[ ${lines[2]} == "AAAA (IPv6): 2" ]]
  [[ ${lines[3]} == "---EOM---" ]]
}

@test "Get all queries" {
  run bash -c 'echo ">getallqueries" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 raspberrypi localhost 3" ]]
  [[ ${lines[2]} =~ "IPv4 checkip.dyndns.org localhost 2" ]]
  [[ ${lines[3]} =~ "IPv4 pi.hole" ]]
  [[ ${lines[4]} =~ "IPv4 play.google.com" ]]
  [[ ${lines[5]} =~ "IPv6 play.google.com" ]]
  [[ ${lines[6]} == "---EOM---" ]]
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
  run bash -c 'echo ">getallqueries-domain play.google.com (1)" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 play.google.com" ]]
  [[ ${lines[2]} == "---EOM---" ]]
}

@test "Get all queries (client filtered)" {
  run bash -c 'echo ">getallqueries-client localhost" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv6 raspberrypi localhost 3" ]]
  [[ ${lines[2]} =~ "IPv4 checkip.dyndns.org localhost 2" ]]
  [[ ${lines[3]} == "---EOM---" ]]
}

@test "Get all queries (client + number filtered)" {
  run bash -c 'echo ">getallqueries-client localhost (4)" | nc -v 127.0.0.1 4711'
  echo "output: ${lines[@]}"
  [[ ${lines[0]} == "Connection to 127.0.0.1 4711 port [tcp/*] succeeded!" ]]
  [[ ${lines[1]} =~ "IPv4 checkip.dyndns.org localhost 2" ]]
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
  [[ ${lines[1]} == "---EOM---" ]]
}

@test "DB test: Tables created and populated?" {
  run bash -c 'sqlite3 pihole-FTL.db .dump'
  echo "output: ${lines[@]}"
  [[ "${lines[@]}" == *"CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );"* ]]
  [[ "${lines[@]}" == *"CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );"* ]]
  [[ "${lines[@]}" == *"INSERT INTO \"ftl\" VALUES(0,1);"* ]]
}

@test "HTTP server: FTL responding correctly to HEAD request" {
  run bash -c "curl --head 127.0.0.1:4747"
  echo "output: ${lines[@]}"
  echo "curl exit code: ${status}"
  [[ ${lines[0]} == "HTTP/1.0 200 OK" ]]
  [[ ${lines[1]} == "Server: FTL" ]]
  [[ ${lines[2]} == "" ]]
}

@test "HTTP server: FTL responding correctly to GET request" {
  run bash -c "curl 127.0.0.1:4747"
  echo "output: ${lines[@]}"
  echo "curl exit code: ${status}"
  [[ "${status}" -eq 0 ]]
}
