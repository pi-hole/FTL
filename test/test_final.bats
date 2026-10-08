#!/usr/bin/env bats
# Final log validation and FTL termination tests.
# This file runs AFTER both test_suite.bats and the pytest API tests
# to catch any unexpected log messages produced during the entire run.

# Load BATS libraries for enhanced testing capabilities
bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

@test "No WARNING messages in FTL.log (besides known warnings)" {
  run bash -c 'grep "WARNING:" /var/log/pihole/FTL.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|API: Config item is invalid|API: Config item validation failed|API: Not found|API: Config items set via environment variables|API: Rate-limiting login attempts|API: You need to specify both|API: No request body data|API: Invalid request|API: Rate-limiting 2FA token requests|2FA code has already been used|API: Reused 2FA token|(Teleporter import skipped )|(format_dnsmasq_warn_message\(\): Buffer too small to hold plain message)"'
  refute_output
}

@test "No ERROR messages in FTL.log (besides known/intended errors)" {
  run bash -c 'grep "ERROR: " /var/log/pihole/FTL.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Teleporter: dns\.(hostRecord|cnameRecords|hosts|revServers)(\[|:))"'
  refute_output
}

@test "No CRIT messages in FTL.log (besides error due to starting FTL more than once)" {
  run bash -c 'grep "CRIT:" /var/log/pihole/FTL.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "No \"DB not available\" messages in FTL.log" {
  run bash -c 'grep -c "database not available" /var/log/pihole/FTL.log'
  assert_line --index 0 "0"
}

@test "Expected number of config file rotations" {
  # BATS:   1x pihole.toml write (dns.reply.host API PATCH)
  # BATS:   2x pihole.toml writes (CLI password set/remove processes)
  # pytest: 3x pihole.toml writes (password, app_pwhash, serve_all via API)
  # pytest: 2x pihole.toml writes (dns/hosts config array PUT + DELETE)
  # pytest: 2x pihole.toml writes (excludeDomains config array PUT + DELETE)
  # pytest: 2x pihole.toml writes (excludeDomains DEL character PATCH + restore)
  # pytest: 2x pihole.toml writes (dns/blocking disable + enable)
  # pytest: 4x pihole.toml writes (config PATCH round-trips: bool + int, change + restore each)
  # pytest: 2x pihole.toml writes (auth stress test password set + remove)
  # pytest: 2x pihole.toml writes (TOTP stress test secret set + remove)
  # pytest: 2x pihole.toml writes (auth security test password set + remove)
  # pytest: 2x pihole.toml writes (auth security test TOTP secret set + remove)
  # pytest: 2x pihole.toml writes (top_domains exclude filter set + reset)
  # pytest: 3x pihole.toml writes (v5 Teleporter import migration, restart + ZIP restore)
  run bash -c 'grep -c "INFO: Config file written to /etc/pihole/pihole.toml" /var/log/pihole/FTL.log'
  printf "pihole.toml write count: %s\n" "${lines[0]}"
  # On RISCV64, pytest is skipped (too slow), so only BATS writes occur
  if [[ "${CI_ARCH}" == "linux/riscv64" ]]; then
      assert_line --index 0 "1"
  else
    [[ ${lines[0]} == "31" ]]
  fi
  # CLI password set/remove trigger inotify reload but result in
  # "pihole.toml unchanged" as the in-memory config already matches
  run bash -c 'grep -c "pihole.toml unchanged" /var/log/pihole/FTL.log'
  printf "pihole.toml unchanged count: %s\n" "${lines[0]}"
  [[ ${lines[0]} -ge 2 ]]
  assert_success
  run bash -c 'grep -c "DEBUG_CONFIG: Config file written to /etc/pihole/dnsmasq.conf" /var/log/pihole/FTL.log'
  printf "dnsmasq.conf write count: %s\n" "${lines[0]}"
  assert_line --index 0 "1"
  run bash -c 'grep -c "DEBUG_CONFIG: HOSTS file written to /etc/pihole/hosts/custom.list" /var/log/pihole/FTL.log'
  printf "custom.list write count: %s\n" "${lines[0]}"
  # On RISCV64, pytest is skipped, so only BATS writes occur (5x)
  # Otherwise, pytest dns/hosts config array PUT + DELETE add 2 more (7x)
  if [[ "${CI_ARCH}" == "linux/riscv64" ]]; then
    assert_line --index 0 "5"
  else
    assert_line --index 0 "7"
  fi
}

@test "Blocking enabled through the config drops the verdicts recorded while it was off" {
  # PATCH /api/config and pihole.toml (written with --config here) change the
  # blocking status without /api/dns/blocking. Runs after the config file
  # rotations are counted, each change writes pihole.toml
  blocked="$(dig +short +tries=1 +time=2 gravity.ftl @127.0.0.1)"
  dig +short +tries=1 +time=2 -b 127.0.0.35 a.ftl @127.0.0.1 > /dev/null
  results=""
  for via in api cli; do
    for state in false true; do
      logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
      if [[ "${via}" == "api" ]]; then
        curl -s -X PATCH -d "{\"config\":{\"dns\":{\"blocking\":{\"active\":${state}}}}}" 127.0.0.1/api/config > /dev/null
      else
        ./pihole-FTL --config dns.blocking.active "${state}" > /dev/null
      fi
      # The lists are reloaded and the verdicts reset after a change
      run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
      results="${results} ${via}-${state}:${status}:$(dig +short +tries=1 +time=2 -b 127.0.0.35 denied.ftl @127.0.0.1)"
    done
  done
  printf "blocked: %s, results:%s\n" "${blocked}" "${results}"
  [[ -n "${blocked}" && "${blocked}" != "192.168.1.3" ]]
  [[ "${results}" == " api-false:0:192.168.1.3 api-true:0:${blocked} cli-false:0:192.168.1.3 cli-true:0:${blocked}" ]]
}

@test "Query with ID 0 has been saved to the database" {
  # FTL exports queries from in-memory DB to disk after a configurable
  # delay (default 30s). Poll up to 60s for the export to complete.
  for i in $(seq 1 30); do
    run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db "SELECT COUNT(*) FROM queries WHERE id=0;"'
    if [[ ${lines[0]} == "1" ]]; then
      break
    fi
    sleep 2
  done
  assert_line --index 0 "1"
}

@test "Reimporting more alias-clients than the clients array holds" {
  # 600 new alias-clients are added under one lock, more than one allocation
  # step of the clients array on any architecture. Runs late as they change
  # the client counts
  run ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<600) INSERT INTO aliasclient (id, name) SELECT x, 'alias-' || x FROM c;"
  assert_success

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN+3 "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'Imported 601 alias-clients' /var/log/pihole/FTL.log 10 $logsize_before"
  assert_success

  run bash -c "tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'Trying to access client ID'"
  assert_line --index 0 "0"
  run bash -c 'kill -0 "$(cat /run/pihole-FTL.pid)"'
  assert_success
}

@test "Flushing the logs keeps older history and the overTime window" {
  # Runs after the ID 0 check above as the flush deletes the last 24 hours.
  now=$(date +%s)
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"INSERT INTO query_storage (id,timestamp,type,status,domain,client) VALUES (-10,$((now-5*86400)),1,2,0,0),(-11,$((now-3600)),1,2,0,0);\""
  assert_success
  run bash -c 'curl -s -X POST 127.0.0.1/api/action/flush/logs | jq -r .status'
  assert_line --index 0 "success"
  run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "SELECT group_concat(id) FROM query_storage WHERE id < 0;"'
  assert_line --index 0 "-10"
  # The overTime window still ends now and covers the past 24 hours
  run bash -c "curl -s 127.0.0.1/api/history | jq '.history[0].timestamp < $((now-23*3600)) and .history[-1].timestamp < $((now+2*3600))'"
  assert_line --index 0 "true"
  # Leave no negative ID behind, the ids of the restart with database.DBimport
  # disabled below would otherwise continue from it
  run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "DELETE FROM query_storage WHERE id < 0;"'
  assert_success
}

@test "A new client's MAC address is looked up on its first query" {
  # hwlen starts at -1, which must compare below 1 on every architecture
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run dig +tries=1 +time=2 -b 127.0.0.41 A hwlen-lookup.ftl @127.0.0.1
  run bash -c "tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'find_mac(\"127.0.0.41\")'"
  assert_output "1"
}

@test "A failed MAC lookup is not repeated right away, and not done for ECS clients" {
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  for name in mac-1 mac-2; do
    dig +short +tries=1 +time=2 -b 127.0.0.32 "${name}.ftl" @127.0.0.1 > /dev/null
    dig +short +tries=1 +time=2 +subnet=10.0.32.1/32 "${name}-ecs.ftl" @127.0.0.1 > /dev/null
  done
  # A TCP worker only searches the ARP cache it inherited, its miss must not
  # keep the main process from asking the kernel on the next UDP query
  dig +short +tries=1 +time=2 +tcp -b 127.0.0.34 mac-tcp.ftl @127.0.0.1 > /dev/null
  dig +short +tries=1 +time=2 -b 127.0.0.34 mac-udp-1.ftl @127.0.0.1 > /dev/null
  dig +short +tries=1 +time=2 -b 127.0.0.34 mac-udp-2.ftl @127.0.0.1 > /dev/null
  run bash -c "tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'find_mac(\"127.0.0.32\")'"
  assert_output "1"
  run bash -c "tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'find_mac(\"10.0.32.1\")'"
  assert_output "0"
  run bash -c "tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'find_mac(\"127.0.0.34\")'"
  assert_output "2"
}

@test "Gravity action streams NUL bytes, reports a failure and refuses a second run" {
  # Stand-in for pihole -g: output with a NUL byte in it, then fail after a moment
  if [ -e /usr/local/bin/pihole ]; then
    mv /usr/local/bin/pihole /usr/local/bin/pihole.test-backup
  fi
  rm -f /tmp/gravity_started
  printf '#!/bin/sh\ntouch /tmp/gravity_started\nprintf "before\\000after\\n"\nsleep 2\nexit 3\n' > /usr/local/bin/pihole
  chmod +x /usr/local/bin/pihole
  curl -s -X POST 127.0.0.1/api/action/gravity -o /tmp/gravity_first.out &
  first=$!
  for i in $(seq 1 50); do
    [ -e /tmp/gravity_started ] && break
    sleep 0.1
  done
  run bash -c 'curl -s -o /tmp/gravity_second.out -w "%{http_code}" -X POST 127.0.0.1/api/action/gravity'
  wait "${first}"
  # Once the first run is done, a new one is accepted again
  third=$(curl -s -o /dev/null -w "%{http_code}" -X POST 127.0.0.1/api/action/gravity)
  rm -f /usr/local/bin/pihole
  if [ -e /usr/local/bin/pihole.test-backup ]; then
    mv /usr/local/bin/pihole.test-backup /usr/local/bin/pihole
  fi
  assert_output "409"
  [ "${third}" = "200" ]
  run jq -r .error.key /tmp/gravity_second.out
  assert_output "gravity_running"
  run bash -c 'tr "\000" "|" < /tmp/gravity_first.out'
  assert_output --partial "before|after"
  assert_output --partial "Gravity failed"
}

@test "FTL terminates with message" {
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  # Kill pihole-FTL after having completed all tests
  pid=$(cat /run/pihole-FTL.pid)
  printf "Killing pihole-FTL with PID %s\n" "$pid"

  run bash -c "kill $pid"
  assert_success

  # Wait until pihole-FTL has terminated
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
}

@test "Shutdown reason logged at INFO level (#2818)" {
  # Verify the shutdown path now logs at INFO level instead of DEBUG-only
  run bash -c 'grep "INFO: Shutting down (exit code" /var/log/pihole/FTL.log'
  assert_success
}

@test "SIGTERM source re-logged near final termination message (#2818)" {
  # Verify the SIGTERM sender is re-logged during cleanup so it appears
  # near the "FTL terminated" message even in truncated logs
  run bash -c 'grep "INFO: Terminated by" /var/log/pihole/FTL.log'
  assert_success

  # Verify ordering: "Terminated by" must appear AFTER "Shutting down" and
  # BEFORE the final "FTL terminated" message
  run bash -c 'grep -n "Shutting down (exit code\|Terminated by\|FTL terminated after" /var/log/pihole/FTL.log | tail -3'
  assert_line --partial --index 0 "Shutting down (exit code"
  assert_line --partial --index 1 "Terminated by"
  assert_line --partial --index 2 "FTL terminated after"
}

@test "A gravity database swapped in right after a restart is loaded (#3162)" {
  # Swap like pihole -g: drop the tables of the database FTL has just opened,
  # then move the new one in. It carries the same timestamp here, so only the
  # file itself tells the two apart
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success

  logsize_swap=$(stat -c%s /var/log/pihole/FTL.log)
  cp -p /etc/pihole/gravity.db /etc/pihole/gravity_temp.db
  printf ".timeout 30000\nDROP TABLE IF EXISTS gravity;\nDROP TABLE IF EXISTS antigravity;\nVACUUM;\n" | ./pihole-FTL sqlite3 -ni /etc/pihole/gravity.db
  mv /etc/pihole/gravity.db /tmp/gravity_swapped_out.db
  mv /etc/pihole/gravity_temp.db /etc/pihole/gravity.db

  run bash -c "./pihole-FTL wait-for 'Gravity database has been replaced, reloading now' /var/log/pihole/FTL.log 5 $logsize_swap"
  assert_success
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 5 $logsize_swap"
  assert_success
  rm -f /tmp/gravity_swapped_out.db

  dig A swap.special.gravity.ftl @127.0.0.1 +tries=1 +time=2 > /dev/null
  run bash -c 'grep -c "gravity blocked swap.special.gravity.ftl is" /var/log/pihole/pihole.log'
  assert_output "1"
  run bash -c "tail -c +$((logsize_swap + 1)) /var/log/pihole/FTL.log | grep -c 'no such table'"
  assert_output "0"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
}

@test "Pi-hole PTR records are generated once per address, however it is spelled" {
  # Start FTL afresh so no record exists yet, and ask for a non-canonical
  # spelling first: the record must still answer the canonical name. Further
  # spellings (leading zeros, extra leading labels) must not add records
  addr=$(ip -4 -o address show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
  [ -n "${addr}" ]
  IFS=. read -r a b c d <<< "${addr}"
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  for i in $(seq 1 30); do
    if dig A ptr.ftl @127.0.0.1 +tries=1 +time=1 > /dev/null; then
      break
    fi
    sleep 1
  done

  dig +tries=1 +time=2 PTR "0${d}.0${c}.0${b}.0${a}.in-addr.arpa" @127.0.0.1 > /dev/null
  run dig +tries=1 +time=2 -x "${addr}" @127.0.0.1 +short
  assert_output "pi.hole."
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  for name in "00${d}.${c}.${b}.${a}" "9.${d}.${c}.${b}.${a}" "7.9.${d}.${c}.${b}.${a}" "${d}.${c}.${b}.${a}"; do
    dig +tries=1 +time=2 PTR "${name}.in-addr.arpa" @127.0.0.1 > /dev/null
  done
  run bash -c "tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'Generating PTR record'"
  assert_output "0"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
}
