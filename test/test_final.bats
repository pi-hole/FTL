#!/usr/bin/env bats
# Final log validation and FTL termination tests.
# This file runs AFTER both test_suite.bats and the pytest API tests
# to catch any unexpected log messages produced during the entire run.

# Load BATS libraries for enhanced testing capabilities
bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

@test "No WARNING messages in FTL.log (besides known warnings)" {
  run bash -c 'grep "WARNING:" /var/log/pihole/FTL.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|API: Config item is invalid|API: Config item validation failed|API: Not found|API: Config items set via environment variables|API: Rate-limiting login attempts|API: You need to specify both|API: No request body data|API: Invalid request|API: Rate-limiting 2FA token requests|2FA code has already been used|API: Reused 2FA token|(Teleporter import skipped )|(Ignoring malformed TLS entry .(44s3|443xs|192\.168\.1\.256:443s). in webserver\.port)|(format_dnsmasq_warn_message\(\): Buffer too small to hold plain message)"'
  refute_output
}

@test "No ERROR messages in FTL.log (besides known/intended errors)" {
  run bash -c 'grep "ERROR: " /var/log/pihole/FTL.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Teleporter: dns\.(hostRecord|cnameRecords|hosts|revServers)(\[|:))|(FOREIGN KEY constraint failed; \[INSERT INTO domainlist_by_group )|(Invalid value: dns\.hosts\[1\]: invalid hostname)|(----> dns\.hosts\[1\] has been removed)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)|(Could not extract a TLS port from .80o,\[::\]:80o,8081r,192\.168\.1\.256:443s,44s3.)"'
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
  # BATS:   2x pihole.toml writes (webserver.interface.boxed PATCH + restore around a TCP worker fork)
  # BATS:   2x pihole.toml writes (CLI password set/remove processes)
  # BATS:   1x pihole.toml write (invalid dns.hosts entry removed on reload)
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
  # pytest: 2x pihole.toml writes (excludeClients cleared + restored around the sorted query log tests)
  # pytest: 3x pihole.toml writes (v5 Teleporter import migration, restart + ZIP restore)
  # pytest: 4x pihole.toml writes (v5 setupVars.conf import twice, migration + restart each)
  # dotdoh.bats: 2x pihole.toml writes (encrypted setup + plaintext teardown)
  # dotdoh.bats: 2x pihole.toml writes (debug.dotdoh enable + disable)
  # dotdoh_server.bats: 1x pihole.toml write (reset dns.reply.host force to default)
  # webserver_acl.bats: 6x pihole.toml writes (three ACLs + restore, proxy ACL + restore)
  # webserver_tls_ports.bats: 7x pihole.toml writes (six port lists + restore)
  # pytest: 6x pihole.toml writes (v5 Teleporter import: migration, restart and restoring the config, twice)
  run bash -c 'grep -c "INFO: Config file written to /etc/pihole/pihole.toml" /var/log/pihole/FTL.log'
  printf "pihole.toml write count: %s\n" "${lines[0]}"
  # On RISCV64, pytest AND both encrypted-DNS suites are skipped (too
  # slow), leaving the dns.reply.host PATCH, the boxed PATCH + restore, the
  # removed dns.hosts entry and webserver_acl.bats. The CLI password
  # set/remove do not write: the in-memory config already matches, so they
  # log "pihole.toml unchanged" - which the next assertion below counts.
  if [[ "${CI_ARCH}" == "linux/riscv64" ]]; then
    assert_line --index 0 "17"
  else
    [[ ${lines[0]} == "64" ]]
  fi
  # CLI password set/remove trigger inotify reload but result in
  # "pihole.toml unchanged" as the in-memory config already matches
  run bash -c 'grep -c "pihole.toml unchanged" /var/log/pihole/FTL.log'
  printf "pihole.toml unchanged count: %s\n" "${lines[0]}"
  [[ ${lines[0]} -ge 2 ]]
  assert_success
  # One more than the deterministic baseline: the randomised DoT/DoH loopback
  # tuples change the encrypted-upstream config on every (re)start. Those tuples
  # need dns.upstreams to hold encrypted entries, which only the dotdoh suites
  # arrange - on riscv64 they are skipped, leaving a single write.
  # pytest adds one more: the ZIP restore drops the reverse server of the v5
  # setupVars.conf import again
  run bash -c 'grep -c "DEBUG_CONFIG: Config file written to /etc/pihole/dnsmasq.conf" /var/log/pihole/FTL.log'
  printf "dnsmasq.conf write count: %s\n" "${lines[0]}"
  if [[ "${CI_ARCH}" == "linux/riscv64" ]]; then
    assert_line --index 0 "1"
  else
    assert_line --index 0 "5"
  fi
  run bash -c 'grep -c "DEBUG_CONFIG: HOSTS file written to /etc/pihole/hosts/custom.list" /var/log/pihole/FTL.log'
  printf "custom.list write count: %s\n" "${lines[0]}"
  # On RISCV64, pytest is skipped, so only BATS writes occur (7x)
  # Otherwise, pytest dns/hosts config array PUT + DELETE add 2 more, and
  # the config restore after the first v5 Teleporter import clears dns.hosts (10x)
  if [[ "${CI_ARCH}" == "linux/riscv64" ]]; then
    assert_line --index 0 "7"
  else
    assert_line --index 0 "10"
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

@test "A regex in no group, or only in a disabled group, applies to no client" {
  # 127.0.0.1 joins the disabled group 1 for this test, a regex only in that
  # group must still not apply to it. The control regex is in the default group
  ./pihole-FTL sqlite3 /etc/pihole/gravity.db ".timeout 5000" \
    "INSERT INTO client_by_group (client_id,group_id) VALUES (1,1);" \
    "INSERT INTO domainlist (type,domain) VALUES (3,'^control-regex\.ftl$'),(3,'^nogroup-regex\.ftl$'),(3,'^disabledgroup-regex\.ftl$');" \
    "DELETE FROM domainlist_by_group WHERE domainlist_id IN (SELECT id FROM domainlist WHERE domain IN ('^nogroup-regex\.ftl$','^disabledgroup-regex\.ftl$'));" \
    "INSERT INTO domainlist_by_group (domainlist_id,group_id) SELECT id,1 FROM domainlist WHERE domain = '^disabledgroup-regex\.ftl$';"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
  reloaded=$status
  blocked="$(dig +short +tries=1 +time=2 gravity.ftl @127.0.0.1)"
  results=""
  for name in control nogroup disabledgroup; do
    results="${results} ${name}:$(dig +short +tries=1 +time=2 ${name}-regex.ftl @127.0.0.1)"
  done

  ./pihole-FTL sqlite3 /etc/pihole/gravity.db ".timeout 5000" \
    "DELETE FROM client_by_group WHERE client_id = 1 AND group_id = 1;" \
    "DELETE FROM domainlist WHERE domain IN ('^control-regex\.ftl$','^nogroup-regex\.ftl$','^disabledgroup-regex\.ftl$');"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
  assert_success

  printf "reload: %s, blocked: %s, results:%s\n" "${reloaded}" "${blocked}" "${results}"
  [[ "${reloaded}" == "0" && -n "${blocked}" ]]
  [[ "${results}" == " control:${blocked} nogroup: disabledgroup:" ]]
}

@test "Query with ID 0 has been saved to the database" {
  # FTL stores a query on disk at the first export after it is 30 s old.
  # Poll up to 60s for the export to complete.
  for i in $(seq 1 30); do
    run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db "SELECT COUNT(*) FROM queries WHERE id=0;"'
    if [[ ${lines[0]} == "1" ]]; then
      break
    fi
    sleep 2
  done
  assert_line --index 0 "1"
}

@test "New clients skip the alias-client lookup when no alias-client is configured" {
  # Reimport without the alias-client of the test database, then put it back
  # for the reimport test below
  saved="$(./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".mode insert aliasclient" "SELECT * FROM aliasclient;")"
  [[ -n "${saved}" ]]
  ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "DELETE FROM aliasclient;"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN+3 "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'Imported 0 alias-clients' /var/log/pihole/FTL.log 30 ${logsize_before}"
  imported=$status

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  dig +short +tries=1 +time=2 -b 127.0.0.33 alias-lookup.ftl @127.0.0.1 > /dev/null
  lookups="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'Looking for the alias-client for client 127.0.0.33' || true)"
  queries="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'query "alias-lookup.ftl" from lo/127.0.0.33#' || true)"

  ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "${saved}"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN+3 "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'Imported 1 alias-client' /var/log/pihole/FTL.log 30 ${logsize_before}"
  assert_success

  printf "reimport: %s, queries: %s, lookups: %s\n" "${imported}" "${queries}" "${lookups}"
  [[ "${imported}" == "0" ]]
  [[ "${queries}" -ge 1 ]]
  [[ "${lookups}" == "0" ]]
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

@test "A client's first group lookup leaves the DNS cache alone, a group change resets it" {
  # Without regex filters, a new client's groups are looked up on its first
  # query rather than when the client is created. The regex entries are
  # disabled for this test and enabled again before the checks below
  ids="$(./pihole-FTL sqlite3 /etc/pihole/gravity.db "SELECT group_concat(id) FROM domainlist WHERE type IN (2,3) AND enabled = 1;")"
  [[ -n "${ids}" ]]
  ./pihole-FTL sqlite3 /etc/pihole/gravity.db ".timeout 5000" "UPDATE domainlist SET enabled = 0 WHERE id IN (${ids});"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'Compiled 0 allow and 0 deny regex' /var/log/pihole/FTL.log 60 ${logsize_before}"
  assert_success

  blocked="$(dig +short +tries=1 +time=2 gravity.ftl @127.0.0.1)"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  first="$(dig +short +tries=1 +time=2 -b 127.0.0.31 denied.ftl @127.0.0.1)"
  # The MAC puts the client into group 4, which holds no lists
  second="$(dig +short +tries=1 +time=2 -b 127.0.0.31 +ednsopt=65001:aabbccddeeff denied.ftl @127.0.0.1)"
  resets="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'Resetting per-client DNS cache for client ID' || true)"

  ./pihole-FTL sqlite3 /etc/pihole/gravity.db ".timeout 5000" "UPDATE domainlist SET enabled = 1 WHERE id IN (${ids});"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 60 ${logsize_before}"
  assert_success

  printf "blocked: %s, first: %s, second: %s, resets: %s\n" "${blocked}" "${first}" "${second}" "${resets}"
  [[ -n "${blocked}" && "${blocked}" != "192.168.1.3" ]]
  [[ "${first}" == "${blocked}" ]]
  [[ "${second}" == "192.168.1.3" ]]
  [[ "${resets}" == "1" ]]
}

@test "An answer from the cache does not look up its CNAME target again until the lists change" {
  # The upstream answer checks memo-target-1.ftl, the answer from the cache
  # (one check per address record) reuses that result
  blocked="$(dig +short +tries=1 +time=2 gravity.ftl @127.0.0.1)"
  first="$(dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-1.ftl @127.0.0.1)"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  cached="$(dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-1.ftl @127.0.0.1)"
  log="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log)"
  lookups="$(grep -c 'domain_in_list("memo-target-1.ftl"' <<< "${log}" || true)"
  known="$(grep -c 'memo-target-1.ftl is known as not to be blocked (CNAME target)' <<< "${log}" || true)"

  # Denying the target reloads the lists, the next answer from the cache checks it again
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X POST 127.0.0.1/api/domains/deny/exact -d '{"domain":"memo-target-1.ftl"}'
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
  reloaded=$status
  denied="$(dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-1.ftl @127.0.0.1)"
  again="$(dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-1.ftl @127.0.0.1)"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X DELETE 127.0.0.1/api/domains/deny/exact/memo-target-1.ftl
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"

  printf "blocked: %s, first: %s, cached: %s, lookups: %s, known: %s, reloaded: %s, denied: %s, again: %s\n" \
         "${blocked}" "${first//$'\n'/ }" "${cached//$'\n'/ }" "${lookups}" "${known}" "${reloaded}" "${denied//$'\n'/ }" "${again}"
  [[ -n "${blocked}" && "${blocked}" != *"192.168.6."* ]]
  [[ "${first}" == *"192.168.6.4"* && "${cached}" == *"192.168.6.4"* ]]
  [[ "${lookups}" == "0" && "${known}" -gt 0 ]]
  [[ "${reloaded}" == "0" ]]
  [[ "${denied}" != *"192.168.6."* ]]
  [[ "${again}" == "${blocked}" ]]
}

@test "A remembered CNAME target is blocked by a deny regex added later" {
  blocked="$(dig +short +tries=1 +time=2 gravity.ftl @127.0.0.1)"
  dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-2.ftl @127.0.0.1 > /dev/null
  cached="$(dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-2.ftl @127.0.0.1)"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X POST 127.0.0.1/api/domains/deny/regex -d '{"domain":"^memo-target-2\\.ftl$"}'
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
  reloaded=$status
  denied="$(dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-2.ftl @127.0.0.1)"
  again="$(dig +short +tries=1 +time=2 -b 127.0.0.42 cname-memo-2.ftl @127.0.0.1)"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X POST 127.0.0.1/api/domains:batchDelete -d '[{"item":"^memo-target-2\\.ftl$","type":"deny","kind":"regex"}]'
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"

  printf "blocked: %s, cached: %s, reloaded: %s, denied: %s, again: %s\n" \
         "${blocked}" "${cached//$'\n'/ }" "${reloaded}" "${denied//$'\n'/ }" "${again}"
  [[ "${cached}" == *"192.168.6.5"* ]]
  [[ "${reloaded}" == "0" ]]
  [[ "${denied}" != *"192.168.6.5"* ]]
  [[ "${again}" == "${blocked}" ]]
}

@test "A remembered CNAME target is checked again for a client that moved to other groups" {
  # memo-target-3.ftl is denied in group 4 only. The MAC address puts the
  # client into that group, which does not reload the lists
  blocked="$(dig +short +tries=1 +time=2 gravity.ftl @127.0.0.1)"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X POST 127.0.0.1/api/domains/deny/exact -d '{"domain":"memo-target-3.ftl","groups":[4]}'
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
  reloaded=$status
  dig +short +tries=1 +time=2 -b 127.0.0.43 cname-memo-3.ftl @127.0.0.1 > /dev/null
  cached="$(dig +short +tries=1 +time=2 -b 127.0.0.43 cname-memo-3.ftl @127.0.0.1)"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  moved="$(dig +short +tries=1 +time=2 -b 127.0.0.43 +ednsopt=65001:aabbccddeeff cname-memo-3.ftl @127.0.0.1)"
  again="$(dig +short +tries=1 +time=2 -b 127.0.0.43 +ednsopt=65001:aabbccddeeff cname-memo-3.ftl @127.0.0.1)"
  reloads="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'deny regex for' || true)"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X DELETE 127.0.0.1/api/domains/deny/exact/memo-target-3.ftl
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"

  printf "blocked: %s, reloaded: %s, cached: %s, moved: %s, again: %s, reloads: %s\n" \
         "${blocked}" "${reloaded}" "${cached//$'\n'/ }" "${moved//$'\n'/ }" "${again}" "${reloads}"
  [[ "${reloaded}" == "0" ]]
  [[ "${cached}" == *"192.168.6.6"* ]]
  [[ "${moved}" != *"192.168.6.6"* ]]
  [[ "${again}" == "${blocked}" ]]
  [[ "${reloads}" == "0" ]]
}

@test "A CNAME target is blocked again after blocking was disabled and enabled" {
  blocked="$(dig +short +tries=1 +time=2 gravity.ftl @127.0.0.1)"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X POST 127.0.0.1/api/domains/deny/exact -d '{"domain":"memo-target-4.ftl"}'
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
  before="$(dig +short +tries=1 +time=2 -b 127.0.0.44 cname-memo-4.ftl @127.0.0.1)"

  # Each change flushes the cache and reloads the lists, the second answer
  # comes from the cache
  results=""
  for state in false true; do
    logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
    curl -s -o /dev/null -X POST 127.0.0.1/api/dns/blocking -d "{\"blocking\":${state}}"
    run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"
    first="$(dig +short +tries=1 +time=2 -b 127.0.0.44 cname-memo-4.ftl @127.0.0.1)"
    second="$(dig +short +tries=1 +time=2 -b 127.0.0.44 cname-memo-4.ftl @127.0.0.1)"
    results="${results} ${state}:${status}:${first//$'\n'/,}/${second//$'\n'/,}"
  done

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null -X DELETE 127.0.0.1/api/domains/deny/exact/memo-target-4.ftl
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_before}"

  printf "blocked: %s, before: %s, results:%s\n" "${blocked}" "${before}" "${results}"
  [[ "${before}" == "${blocked}" ]]
  [[ "${results}" == " false:0:memo-target-4.ftl.,192.168.6.7/memo-target-4.ftl.,192.168.6.7 true:0:${blocked}/${blocked}" ]]
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

@test "Clients in recycled slots do not make the clients array longer" {
  # The regex reload logs the length of the clients array. 50 clients, a
  # flush that recycles all clients, 50 other clients: the second 50 reuse
  # recycled slots, so the array has to stay as long as it was
  for i in $(seq 1 50); do
    dig +short +tries=1 +time=2 -b 127.0.2.${i} slots.ftl @127.0.0.1 > /dev/null
  done
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  before="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -o 'deny regex for [0-9]* client' | head -n 1 | grep -o '[0-9]*')"

  # The flush keeps the queries of the current second, which would keep
  # their clients from being recycled
  sleep 2
  run bash -c 'curl -s -X POST 127.0.0.1/api/action/flush/logs | jq -r .status'
  assert_line --index 0 "success"
  for i in $(seq 1 50); do
    dig +short +tries=1 +time=2 -b 127.0.3.${i} slots.ftl @127.0.0.1 > /dev/null
  done
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  kill -SIGRTMIN "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  after="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -o 'deny regex for [0-9]* client' | head -n 1 | grep -o '[0-9]*')"

  printf "clients array before: %s, after: %s\n" "${before}" "${after}"
  [[ -n "${before}" && "${before}" == "${after}" ]]
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

@test "The reply to a duplicate of a query in flight is not logged as an unknown reply" {
  # test/slow_upstream.py answers delayed.ftl after 1.5 s. dnsmasq forwards
  # the first of two identical queries and attaches the second one to it
  python3 test/slow_upstream.py 5559 1.5 > "${BATS_TEST_TMPDIR}/slow_upstream.out" 2>&1 3>&- &
  pid=$!
  for i in $(seq 1 50); do
    grep -q ready "${BATS_TEST_TMPDIR}/slow_upstream.out" && break
    sleep 0.1
  done
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  dnsmasq_before=$(stat -c%s /var/log/pihole/pihole.log)
  dig +short +tries=1 +time=5 dup.delayed.ftl @127.0.0.1 > "${BATS_TEST_TMPDIR}/first.out" &
  first=$!
  dig +short +tries=1 +time=5 dup.delayed.ftl @127.0.0.1 > "${BATS_TEST_TMPDIR}/second.out" &
  second=$!
  wait "${first}" "${second}" || true
  kill "${pid}"
  # dnsmasq runs the FTL hook for the reply to the second query and logs
  # "reply query is duplicate" only after it has answered that client
  run bash -c "./pihole-FTL wait-for 'reply query is duplicate' /var/log/pihole/pihole.log 5 ${dnsmasq_before}"

  answers="$(cat "${BATS_TEST_TMPDIR}/first.out" "${BATS_TEST_TMPDIR}/second.out")"
  duplicates="$(tail -c +$((dnsmasq_before + 1)) /var/log/pihole/pihole.log | grep -c 'reply query is duplicate' || true)"
  # debug.flags, which the warning needs, also logs each line FTL gets from
  # dnsmasq
  hooked="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'Processing FTL hook from .*name: "query"' || true)"
  unknown="$(tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'Unknown upstream REPLY' || true)"
  statuses="$(curl -s '127.0.0.1/api/queries?domain=dup.delayed.ftl' | jq -c '[.queries[].status] | sort')"
  printf "answers: %s, duplicate replies: %s, hooked: %s, unknown replies: %s, statuses: %s\n" \
         "${answers//$'\n'/ }" "${duplicates}" "${hooked}" "${unknown}" "${statuses}"
  [[ "${answers}" == $'192.168.7.1\n192.168.7.1' ]]
  [[ "${duplicates}" == "1" ]]
  [[ "${hooked}" == "1" ]]
  [[ "${unknown}" == "0" ]]
  # The second one keeps the status it got when dnsmasq attached it
  [[ "${statuses}" == '["FORWARDED","IN_PROGRESS"]' ]]
}

@test "Setting ntp.sync.interval to 0 disables the NTP sync right away" {
  # FTL restarts and does not start the sync at all, instead of a sync that
  # is already running going on without any pause between the rounds
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null --max-time 10 -X PATCH http://127.0.0.1/api/config \
       -d '{"config":{"ntp":{"sync":{"interval":0}}}}' || true
  # Wait for the end of the restart, the NTP line comes earlier in it
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 60 $logsize_before"
  assert_success
  run bash -c "tail -c +$((logsize_before + 1)) /var/log/pihole/FTL.log | grep -c 'NTP sync is disabled'"
  assert_output "1"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null --max-time 10 -X PATCH http://127.0.0.1/api/config \
       -d '{"config":{"ntp":{"sync":{"interval":3600}}}}' || true
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 60 $logsize_before"
  assert_success
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

# Start FTL as on a first start: the suite's pihole.toml and its backups are
# put aside, and FTL runs on ports and files of its own with only the FTLCONF_
# variables below and in $1. Nothing here or in first_start_stop fails, so the
# suite's files are always put back before a test checks what it collected
first_start=/tmp/ftlconf-first-start
first_start_ftl() {
  rm -rf "${first_start}"
  mkdir -p "${first_start}/suite"
  touch "${first_start}/FTL.log"
  chown -R pihole:pihole "${first_start}"
  mv /etc/pihole/pihole.toml /etc/pihole/config_backups "${first_start}/suite/" || true
  cp -p /etc/pihole/dnsmasq.conf /etc/pihole/hosts/custom.list "${first_start}/suite/" || true
  unset "${!FTLCONF_@}"
  first_start_cli="$(FTLCONF_dns_port=5397 ./pihole-FTL --config dns.port 2> /dev/null || true)"
  su pihole -s /bin/sh -c "FTLCONF_files_log_ftl=${first_start}/FTL.log FTLCONF_files_log_webserver=${first_start}/webserver.log FTLCONF_files_log_dnsmasq=${first_start}/pihole.log FTLCONF_files_database=${first_start}/pihole-FTL.db FTLCONF_dns_port=5397 FTLCONF_webserver_port=127.0.0.1:8097 FTLCONF_misc_etc_dnsmasq_d=false FTLCONF_ntp_ipv4_active=false FTLCONF_ntp_ipv6_active=false FTLCONF_ntp_sync_active=false $1 /home/pihole/pihole-FTL" || true
  ./pihole-FTL wait-for ' -> Known forward destinations' "${first_start}/FTL.log" 60 0 > /dev/null || true
  for i in $(seq 1 60); do
    curl -s -f -m 1 -o /dev/null http://127.0.0.1:8097/api/config/dns/port && break
    sleep 0.5
  done
}

# Stop it, keep the pihole.toml it wrote and put the suite's files back
first_start_stop() {
  kill "$(cat /run/pihole-FTL.pid)" || true
  ./pihole-FTL wait-for '########## FTL terminated after' "${first_start}/FTL.log" 30 0 > /dev/null || true
  cp /etc/pihole/pihole.toml "${first_start}/pihole.toml" 2> /dev/null || true
  for f in pihole.toml config_backups; do
    if [[ -e "${first_start}/suite/${f}" ]]; then
      rm -rf "/etc/pihole/${f}"
      mv "${first_start}/suite/${f}" /etc/pihole/ || true
    fi
  done
  cp -p "${first_start}/suite/dnsmasq.conf" /etc/pihole/dnsmasq.conf || true
  cp -p "${first_start}/suite/custom.list" /etc/pihole/hosts/custom.list || true
}

@test "FTLCONF_ variables apply when FTL starts without pihole.toml" {
  first_start_ftl "FTLCONF_misc_privacylevel=2 FTLCONF_dns_upstreams='127.0.0.1#5555;127.0.0.2' FTLCONF_debug_config=true FTLCONF_debug_database=true"
  dns="$(dig +tries=1 +time=2 -p 5397 CHAOS TXT version.FTL @127.0.0.1 | grep -oE 'status: [A-Z]+' || true)"
  level="$(curl -s -m 5 http://127.0.0.1:8097/api/config/misc/privacylevel | jq -c '.config.misc.privacylevel' || true)"
  upstreams="$(curl -s -m 5 http://127.0.0.1:8097/api/config/dns/upstreams | jq -c '.config.dns.upstreams' || true)"
  # Only what the environment sets is forced
  forced="$(curl -s -m 5 'http://127.0.0.1:8097/api/config/misc/privacylevel?detailed=true' | jq -r '.config.misc.privacylevel.flags.env_var' || true)"
  unforced="$(curl -s -m 5 'http://127.0.0.1:8097/api/config/dns/blocking/mode?detailed=true' | jq -r '.config.dns.blocking.mode.flags.env_var' || true)"
  first_start_stop

  printf "DNS on port 5397: %s, privacy level: %s, upstreams: %s, forced: %s/%s, CLI: %s\n" "${dns}" "${level}" "${upstreams}" "${forced}" "${unforced}" "${first_start_cli}"
  [[ "${dns}" == "status: NOERROR" ]]
  [[ "${level}" == "2" ]]
  [[ "${upstreams}" == '["127.0.0.1#5555","127.0.0.2"]' ]]
  [[ "${forced}" == "true" && "${unforced}" == "false" ]]
  # pihole-FTL --config still shows the plain defaults without a file
  [[ "${first_start_cli}" == "53" ]]
  # The new pihole.toml has them too, as forced through the environment
  run grep -c -x -E '#   - (dns\.port|webserver\.port|misc\.privacylevel|dns\.upstreams)' "${first_start}/pihole.toml"
  assert_output "4"
  # The log lists the variables, and the debug flags are on from the start,
  # debug.config already while the other variables are read
  run grep -c "FTLCONF environment variables found" "${first_start}/FTL.log"
  [[ ${lines[0]} -ge 1 ]]
  run grep -c "DEBUG_CONFIG: ENV FTLCONF_misc_privacylevel = 2" "${first_start}/FTL.log"
  [[ ${lines[0]} -ge 1 ]]
  run grep -c "DEBUG_DATABASE: " "${first_start}/FTL.log"
  [[ ${lines[0]} -ge 1 ]]
}

@test "FTL writes the first pihole.toml when misc.readOnly is set through the environment" {
  # Read-only mode keeps an existing file as it is, there is none yet
  first_start_ftl "FTLCONF_misc_readOnly=true FTLCONF_misc_privacylevel=2"
  level="$(curl -s -m 5 http://127.0.0.1:8097/api/config/misc/privacylevel | jq -c '.config.misc.privacylevel' || true)"
  read_only="$(curl -s -m 5 http://127.0.0.1:8097/api/config/misc/readOnly | jq -c '.config.misc.readOnly' || true)"
  # Once it is there, it is kept: disabling blocking writes no config
  before="$(sha256sum /etc/pihole/pihole.toml 2> /dev/null || true)"
  blocking="$(curl -s -m 5 -X POST http://127.0.0.1:8097/api/dns/blocking -d '{"blocking":false}' | jq -r '.blocking' || true)"
  after="$(sha256sum /etc/pihole/pihole.toml 2> /dev/null || true)"
  first_start_stop

  printf "privacy level: %s, read-only: %s, blocking: %s\n" "${level}" "${read_only}" "${blocking}"
  [[ "${level}" == "2" && "${read_only}" == "true" ]]
  [[ "${blocking}" == "disabled" && -n "${before}" && "${before}" == "${after}" ]]
  run grep -c -x -E '#   - (misc\.privacylevel|misc\.readOnly)' "${first_start}/pihole.toml"
  assert_output "2"
  run grep -c "checksum of /etc/pihole/pihole.toml" "${first_start}/FTL.log"
  assert_output "0"
}

@test "Queries older than database.maxDBdays are deleted in the first nightly window after the start" {
  # Start FTL at 03:50 local time, after the random cleaning minute (03:10 to
  # 03:49), with 25000 queries older than 91 days in the database. They are
  # deleted 10000 at a time
  read -r hour minute <<< "$(date -u '+%H %M')"
  off=$(( (230 - 10#${hour} * 60 - 10#${minute} + 1440) % 1440 ))
  tz=$(printf 'TST-%02d:%02d' $((off / 60)) $((off % 60)))
  run bash -c "TZ=${tz} date +%H"
  assert_output "03"
  now=$(date +%s)
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<25000) INSERT INTO query_storage (id,timestamp,type,status,domain,client) SELECT -100-x,$((now-100*86400))+x,1,2,0,0 FROM c;\""
  assert_success

  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "su pihole -s /bin/sh -c 'TZ=${tz} /home/pihole/pihole-FTL'"
  assert_success
  run bash -c "./pihole-FTL wait-for ' MB, deleted ' /var/log/pihole/FTL.log 60 $logsize_restart"
  logged=$status
  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.maxdbdays.log

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success

  batches=$(grep -c "Deleted [0-9]* queries with timestamp" /tmp/FTL.maxdbdays.log || true)
  total=$(grep -o " MB, deleted [0-9]* of" /tmp/FTL.maxdbdays.log | head -n 1 || true)
  run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "SELECT COUNT(*) FROM query_storage WHERE id <= -100;"'
  remaining=${lines[0]}
  ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "DELETE FROM query_storage WHERE id <= -100;"
  printf "batches: %s, logged: %s, left: %s\n" "${batches}" "${total}" "${remaining}"
  assert_equal "${logged}" "0"
  assert_equal "${remaining}" "0"
  assert_equal "${total}" " MB, deleted 25000 of"
  [[ ${batches} -ge 3 ]]

  # Its part of the log up to the end of the deletion
  run bash -c 'grep "WARNING:" /tmp/FTL.maxdbdays.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.maxdbdays.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.maxdbdays.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "Queries are stored with their own domain when database.DBimport is disabled" {
  # Restart FTL without importing the history. New domains must continue the
  # IDs of domain_by_id on disk instead of reusing those of older domains
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c "FTLCONF_database_DBimport=false /home/pihole/pihole-FTL"'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success

  for i in $(seq 1 30); do
    if dig A dbimport-off.ftl @127.0.0.1 +tries=1 +time=1 > /dev/null; then
      break
    fi
    sleep 1
  done

  # The final export on termination stores them on disk
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success

  # The log checks above ran before this restart, check its part of the log
  # with the same exclusions
  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.dbimport-off.log
  run bash -c 'grep "WARNING:" /tmp/FTL.dbimport-off.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.dbimport-off.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.dbimport-off.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output

  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \"SELECT COUNT(*) FROM queries WHERE domain = 'dbimport-off.ftl';\""
  printf "disk queries for dbimport-off.ftl: %s\n" "${lines[0]}"
  [[ ${lines[0]} -ge 1 ]]
}

@test "Queries go to disk as the query log shows them, with their list IDs and the totals" {
  # The final export at the stop stores the queries, a restart reads them back
  ids_before=$(./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "SELECT IFNULL(MAX(id), -1) FROM query_storage;")
  totals_before=$(./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "SELECT (SELECT value FROM counters WHERE id = 0) || ' ' || (SELECT value FROM counters WHERE id = 1);")
  read -r total_before blocked_before <<< "${totals_before}"
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  for i in $(seq 1 30); do
    if dig A export-start.ftl @127.0.0.1 +tries=1 +time=1 > /dev/null; then
      break
    fi
    sleep 1
  done

  # Blocked by gravity, the exact denylist, a deny regex and through a CNAME,
  # allowed by the exact allowlist, an allow regex and antigravity, and one
  # on no list
  first=$(date +%s)
  for domain in gravity.ftl denied.ftl regex5.ftl cname-1.ftl allowed.ftl gravity-allowed.ftl antigravity.ftl a.ftl; do
    dig A "${domain}" -b 127.0.0.77 @127.0.0.1 +tries=1 +time=2 > /dev/null
  done
  # A query keeps the list ID of its verdict when the lists are reloaded
  # right after it
  logsize_reload=$(stat -c%s /var/log/pihole/FTL.log)
  dig A gravity.ftl -b 127.0.0.78 @127.0.0.1 +tries=1 +time=2 > /dev/null
  kill -SIGRTMIN "$(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for 'deny regex for' /var/log/pihole/FTL.log 10 ${logsize_reload}"
  assert_success

  rows() {
    for client in 127.0.0.77 127.0.0.78; do
      curl -s "127.0.0.1/api/queries?client_ip=${client}&length=100$1"
    done | jq -sc '[.[].queries[] | [.id, .domain, .client.ip, .client.name, .status, .type, .reply.type, .dnssec, .list_id, .ede.code, .cname, .upstream]] | sort'
  }
  # None of them is ready yet, unless a slow runner took close to the 30 s
  # until the first one is
  if (( $(date +%s) - first < 25 )); then
    run rows "&disk=true"
    assert_output "[]"
  fi
  memory=$(rows "")
  run jq -c '[.[] | [.[1], .[8] != null]]' <<< "${memory}"
  assert_output '[["gravity.ftl",true],["denied.ftl",true],["regex5.ftl",true],["cname-1.ftl",true],["allowed.ftl",true],["gravity-allowed.ftl",true],["antigravity.ftl",true],["a.ftl",false],["gravity.ftl",true]]'

  # The final export stores them. The totals count what is stored, and the
  # time of the newest query is that of the newest row
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"SELECT (SELECT value FROM counters WHERE id = 0) - ${total_before} - COUNT(*), (SELECT value FROM counters WHERE id = 1) - ${blocked_before} - COUNT(*) FILTER (WHERE status IN (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)), ABS((SELECT value FROM ftl WHERE id = 1) - MAX(timestamp)) < 0.001, COUNT(*) > 9 FROM query_storage WHERE id > ${ids_before};\""
  printf "total and blocked beyond the rows stored, newest timestamp, rows: %s\n" "${lines[0]}"
  assert_output "0|0|1|1"

  # On disk they are what the query log showed before the stop
  logsize_import=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for 'queries from the long-term database' /var/log/pihole/FTL.log 30 $logsize_import"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_import"
  assert_success
  disk=$(rows "&disk=true")
  printf "in memory before the stop: %s\non disk: %s\n" "${memory}" "${disk}"
  assert_equal "${disk}" "${memory}"
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success

  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.export.log
  run bash -c 'grep "WARNING:" /tmp/FTL.export.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.export.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.export.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "A query stored after its client was renamed keeps the name it was made with" {
  # The test configuration resolves no client names. This instance resolves
  # 127.0.0.23 through dns.hosts and renames it between two of its queries.
  # The final export at the stop stores them with a third one, made after the
  # rename and more than one chunk of the export later
  cp -p /etc/pihole/pihole.toml /tmp/pihole.toml.rename
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c "FTLCONF_database_DBimport=false FTLCONF_resolver_resolveIPv4=true FTLCONF_resolver_refreshNames=ALL /home/pihole/pihole-FTL"'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  hosts=$(curl -s 127.0.0.1/api/config/dns/hosts | jq -c '.config.dns.hosts')
  # Point 127.0.0.23 at a name, then wait until FTL's client has it
  set_name() {
    [[ "$(curl -s -o /dev/null -w '%{http_code}' -X PATCH 127.0.0.1/api/config -d "$(jq -c --arg host "127.0.0.23 $1" '{config: {dns: {hosts: (. + [$host])}}}' <<< "${hosts}")")" == "200" ]] || return 1
    for i in $(seq 1 30); do
      [[ "$(dig -x 127.0.0.23 @127.0.0.1 +short)" == "$1." ]] && break
      sleep 1
    done
    kill -SIGRTMIN+4 "$(cat /run/pihole-FTL.pid)"
    for i in $(seq 1 30); do
      [[ "$(curl -s '127.0.0.1/api/stats/top_clients?count=1000' | jq -r '.clients[] | select(.ip == "127.0.0.23") | .name')" == "$1" ]] && return 0
      sleep 1
    done
    return 1
  }
  first=$(date +%s)
  dig A one.rename.ftl -b 127.0.0.23 @127.0.0.1 +tries=1 +time=2 > /dev/null
  run set_name old-rename.ftl
  assert_success
  dig A two.rename.ftl -b 127.0.0.23 @127.0.0.1 +tries=1 +time=2 > /dev/null
  run set_name new-rename.ftl
  assert_success
  stored() {
    ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "SELECT d.domain, IFNULL(c.name, '') FROM query_storage q JOIN domain_by_id d ON d.id = q.domain JOIN client_by_id c ON c.id = q.client WHERE d.domain GLOB '*.rename.ftl' ORDER BY q.id;"
  }
  # Not stored before the rename, unless a slow runner took close to the
  # 30 s until the first one is ready
  if (( $(date +%s) - first < 25 )); then
    run stored
    refute_output
  fi
  # The rows found for the first two do not serve the third one, which gets
  # the row of the current name
  for i in $(seq 1 70); do
    echo "A pad-${i}.chunk.ftl -b 127.0.0.24 @127.0.0.1 +tries=1 +time=2"
  done | dig -f - > /dev/null
  dig A three.rename.ftl -b 127.0.0.23 @127.0.0.1 +tries=1 +time=2 > /dev/null
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  run stored
  assert_output "one.rename.ftl|
two.rename.ftl|old-rename.ftl
three.rename.ftl|new-rename.ftl"

  cp -p /tmp/pihole.toml.rename /etc/pihole/pihole.toml
  ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "DELETE FROM query_storage WHERE client IN (SELECT id FROM client_by_id WHERE ip IN ('127.0.0.23', '127.0.0.24')); DELETE FROM client_by_id WHERE ip IN ('127.0.0.23', '127.0.0.24'); DELETE FROM domain_by_id WHERE domain GLOB '*.rename.ftl' OR domain GLOB '*.chunk.ftl';"
}

@test "Garbage collection removes old queries when webserver.api.maxHistory is 0" {
  # The garbage collector runs once per minute then and keeps only the
  # queries that can still receive a reply or are not stored yet. The export
  # runs every 45 s here, so the collector also runs between two exports. All
  # of them reach the disk, and a rate-limited client stays limited when none
  # of its queries is left
  # With debug.gc, each run replaces the string dump of the run before
  rm -f /tmp/stringdump.txt
  su pihole -s /bin/sh -c 'echo "String dump starting at an earlier run" > /tmp/stringdump.txt'
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  logsize_dnsmasq=$(stat -c%s /var/log/pihole/pihole.log)
  run bash -c 'su pihole -s /bin/sh -c "FTLCONF_webserver_api_maxHistory=0 FTLCONF_database_DBinterval=45 FTLCONF_dns_rateLimit_count=250 FTLCONF_dns_rateLimit_interval=3600 /home/pihole/pihole-FTL"'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  for i in $(seq 1 30); do
    if dig A maxhistory-zero-0.ftl @127.0.0.1 +tries=1 +time=1 > /dev/null; then
      break
    fi
    sleep 1
  done

  # 127.0.0.2 exceeds the rate limit
  for i in $(seq 1 251); do
    dig A "ratelimit-${i}.ftl" -b 127.0.0.2 @127.0.0.1 +tries=1 +time=1 > /dev/null || true
  done
  run bash -c "dig A ratelimit-0.ftl -b 127.0.0.2 @127.0.0.1 +tries=1 +time=1 | grep -oE 'status: [A-Z]+'"
  assert_output "status: REFUSED"
  limited=$(date +%s)

  # One query per second until a run whose cutoff lies past the burst has
  # removed queries, the second run after it does at the latest
  for i in $(seq 1 150); do
    dig A "maxhistory-zero-${i}.ftl" @127.0.0.1 +tries=1 +time=1 > /dev/null || true
    if tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log | awk -v t="${limited}" '
         /GC starting, mintime:/ { match($0, /\([0-9]+\)/); past = substr($0, RSTART + 1, RLENGTH - 2) + 0 >= t }
         /GC removed [1-9][0-9]* queries/ { if(past) done = 1 }
         END { exit !done }'; then
      break
    fi
    sleep 1
  done
  run bash -c "tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log | grep -E 'GC (starting|removed)'"
  printf "%s\n" "${lines[@]}"
  assert_output --regexp "GC removed [1-9][0-9]* queries"

  # The file holds one complete dump, the earlier one is gone
  run bash -c "./pihole-FTL wait-for 'Summary:' /tmp/stringdump.txt 30 0"
  assert_success
  run grep -c "^String dump starting at" /tmp/stringdump.txt
  assert_output "1"

  # None of the queries of 127.0.0.2 is left in memory, it is still limited
  run bash -c "dig A ratelimit-after.ftl -b 127.0.0.2 @127.0.0.1 +tries=1 +time=1 | grep -oE 'status: [A-Z]+'"
  assert_output "status: REFUSED"

  # The final export on termination stores what is left in memory
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  sent=$(tail -c +$((logsize_dnsmasq + 1)) /var/log/pihole/pihole.log | grep -cE "query\[A\] maxhistory-zero-[0-9]+\.ftl ")
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \"SELECT COUNT(*) FROM queries WHERE domain GLOB 'maxhistory-zero-*.ftl';\""
  printf "queries sent: %s, stored on disk: %s\n" "${sent}" "${lines[0]}"
  [[ ${sent} -ge 1 ]]
  assert_equal "${lines[0]}" "${sent}"

  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.maxhistory-zero.log
  run bash -c 'grep "WARNING:" /tmp/FTL.maxhistory-zero.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.maxhistory-zero.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.maxhistory-zero.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
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

@test "Raising misc.privacylevel at runtime hides known domains and clients in the database, and stores nothing at level 3" {
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  for i in $(seq 1 30); do
    if dig A privacy-known.ftl @127.0.0.1 +tries=1 +time=1 > /dev/null; then
      break
    fi
    sleep 1
  done

  # Raising the level does not restart FTL. Every query from the next full
  # second on carries the new level
  run bash -c 'curl -s -o /dev/null -w "%{http_code}" -X PATCH http://127.0.0.1/api/config -H "Content-Type: application/json" -d "{\"config\":{\"misc\":{\"privacylevel\":1}}}"'
  assert_output "200"
  level1=$(( $(date +%s) + 1 ))
  sleep 2
  dig A privacy-known.ftl @127.0.0.1 +tries=1 +time=2 > /dev/null
  run bash -c 'curl -s -o /dev/null -w "%{http_code}" -X PATCH http://127.0.0.1/api/config -H "Content-Type: application/json" -d "{\"config\":{\"misc\":{\"privacylevel\":2}}}"'
  assert_output "200"
  level2=$(( $(date +%s) + 1 ))
  sleep 2
  dig A privacy-known.ftl @127.0.0.1 +tries=1 +time=2 > /dev/null
  run bash -c 'curl -s -o /dev/null -w "%{http_code}" -X PATCH http://127.0.0.1/api/config -H "Content-Type: application/json" -d "{\"config\":{\"misc\":{\"privacylevel\":3}}}"'
  assert_output "200"
  level3=$(( $(date +%s) + 1 ))
  sleep 2
  dig A privacy-known.ftl @127.0.0.1 +tries=1 +time=2 > /dev/null
  sleep 2

  # The final export on termination stores everything on disk
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  run ./pihole-FTL --config misc.privacylevel 0
  assert_success

  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \"SELECT (SELECT COUNT(*) FROM queries WHERE domain = 'privacy-known.ftl'), (SELECT COUNT(*) FROM queries WHERE timestamp >= ${level1} AND domain = 'privacy-known.ftl'), (SELECT COUNT(*) FROM queries WHERE timestamp >= ${level1} AND domain = 'hidden'), (SELECT COUNT(*) FROM queries WHERE timestamp >= ${level2} AND client = '127.0.0.1'), (SELECT COUNT(*) FROM queries WHERE timestamp >= ${level2} AND client = '0.0.0.0'), (SELECT COUNT(*) FROM queries WHERE timestamp >= ${level3});\""
  printf "named, named after level 1, hidden, client after level 2, hidden client, after level 3: %s\n" "${lines[0]}"
  IFS='|' read -r named named_hidden hidden client_shown client_hidden level3_stored <<< "${lines[0]}"
  [[ ${named} -ge 1 ]]
  [[ ${named_hidden} == 0 ]]
  [[ ${hidden} -ge 2 ]]
  [[ ${client_shown} == 0 ]]
  [[ ${client_hidden} -ge 1 ]]
  [[ ${level3_stored} == 0 ]]

  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.privacylevel.log
  run bash -c 'grep "ERROR: " /tmp/FTL.privacylevel.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.privacylevel.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
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

@test "Query IDs are kept across a restart and continue above the imported ones" {
  # The TCP queries are created in forked TCP workers, which number them from
  # the same counter as the main process
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for 'queries from the long-term database' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  for i in $(seq 1 30); do
    if dig A udp-1.ids.ftl @127.0.0.1 +tries=1 +time=1 > /dev/null; then
      break
    fi
    sleep 1
  done
  dig +tcp A tcp-1.ids.ftl @127.0.0.1 +tries=1 +time=2 > /dev/null
  dig A udp-2.ids.ftl @127.0.0.1 +tries=1 +time=2 > /dev/null
  before=$(curl -s "127.0.0.1/api/queries?domain=*.ids.ftl&length=100" | jq -c '.queries')

  # The final export on termination stores them on disk
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db "SELECT MAX(id) FROM query_storage;"'
  maxid=${lines[0]}

  logsize_import=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for 'queries from the long-term database' /var/log/pihole/FTL.log 30 $logsize_import"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_import"
  assert_success
  imported=$(curl -s "127.0.0.1/api/queries?domain=*.ids.ftl&length=100" | jq -c '.queries')
  for i in $(seq 1 30); do
    if dig A udp-3.ids.ftl @127.0.0.1 +tries=1 +time=1 > /dev/null; then
      break
    fi
    sleep 1
  done
  dig +tcp A tcp-2.ids.ftl @127.0.0.1 +tries=1 +time=2 > /dev/null
  sleep 2
  all=$(curl -s "127.0.0.1/api/queries?domain=*.ids.ftl&length=100" | jq -c '[.queries[] | [.id, .domain]]')

  # Page through all of them two at a time, from the new queries into the
  # imported ones
  cursor=$(curl -s "127.0.0.1/api/queries?domain=*.ids.ftl&length=2" | jq '.cursor')
  paged="[]"
  for start in $(seq 0 2 98); do
    page=$(curl -s "127.0.0.1/api/queries?domain=*.ids.ftl&length=2&start=${start}&cursor=${cursor}" | jq -c '[.queries[] | [.id, .domain]]')
    if [[ "${page}" == "[]" ]]; then
      break
    fi
    paged=$(jq -cn --argjson a "${paged}" --argjson b "${page}" '$a + $b')
  done

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success

  printf "disk max ID: %s\nbefore: %s\nimported: %s\nall: %s\npaged: %s\n" "${maxid}" "${before}" "${imported}" "${all}" "${paged}"
  # The imported queries are the same as before the restart, IDs included
  [[ "${before}" != "[]" ]]
  assert_equal "${imported}" "${before}"
  # The new queries, also the one over TCP, continue above the highest ID on
  # disk, the imported ones are at or below it
  run jq -n --argjson all "${all}" --argjson max "${maxid}" '
    def ids($name): [$all[] | select(.[1] == $name + ".ids.ftl") | .[0]];
    ([ids("udp-1", "tcp-1", "udp-2", "udp-3", "tcp-2")] | all(length > 0)) and
    ([ids("udp-1", "tcp-1", "udp-2")[]] | all(. <= $max)) and
    ([ids("udp-3", "tcp-2")[]] | all(. > $max))'
  assert_output "true"
  # Paging with the cursor walks across both without a gap or a duplicate
  assert_equal "${paged}" "${all}"
  run jq -n --argjson all "${all}" '[$all[][0]] | . == (unique | reverse)'
  assert_output "true"

  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.query-ids.log
  run bash -c 'grep "WARNING:" /tmp/FTL.query-ids.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.query-ids.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.query-ids.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "A query stored with type 100 (DNS type 0) is imported into shared memory" {
  # Unmapped query types are stored as 100 + the DNS type, so 100 is a query
  # of type 0, written like this by older versions. It shows as TYPE0
  now=$(date +%s)
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"INSERT OR IGNORE INTO domain_by_id (domain) VALUES ('type0.import.ftl'); INSERT OR IGNORE INTO client_by_id (ip, name) VALUES ('10.0.100.0', ''); INSERT INTO query_storage (timestamp, type, status, domain, client) SELECT $((now - 60)), 100, 3, d.id, c.id FROM domain_by_id d, client_by_id c WHERE d.domain = 'type0.import.ftl' AND c.ip = '10.0.100.0' AND c.name = '';\""
  assert_success

  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for 'queries from the long-term database' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "curl -s '127.0.0.1/api/queries?domain=type0.import.ftl' | jq -c '[.queries[] | [.type, .client.ip]]'"
  assert_output '[["TYPE0","10.0.100.0"]]'
  # It is counted in shared memory as well: every row read from the disk
  # is imported, the domain is in the top list with its one query, and the
  # query types count it as OTHER, as the long-term statistics do
  run bash -c "curl -s '127.0.0.1/api/stats/top_domains?count=100000' | jq -c '[.domains[] | select(.domain == \"type0.import.ftl\") | .count]'"
  assert_output '[1]'
  other=$(./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "SELECT COUNT(*) FROM query_storage WHERE type >= 100 AND timestamp > $((now - 86400));")
  run bash -c "curl -s 127.0.0.1/api/stats/query_types | jq '.types.OTHER'"
  assert_output "${other}"
  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.type0.log
  disk=$(grep -oE 'from the long-term database \([0-9]+ rows read' /tmp/FTL.type0.log | grep -oE '[0-9]+')
  shm=$(grep -oE 'Imported [0-9]+ queries from the long-term database' /tmp/FTL.type0.log | grep -oE '[0-9]+')
  printf "imported from disk: %s, into shared memory: %s\n" "${disk}" "${shm}"
  [[ -n "${disk}" ]]
  assert_equal "${shm}" "${disk}"

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "DELETE FROM query_storage WHERE type = 100; DELETE FROM domain_by_id WHERE domain = 'type0.import.ftl'; DELETE FROM client_by_id WHERE ip = '10.0.100.0';"

  # No "TYPE should not be 100" and no rows missing from the import
  run bash -c 'grep "WARNING:" /tmp/FTL.type0.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.type0.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.type0.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "Rows the history import skips leave nothing behind in shared memory" {
  # One row for each check that makes the import skip a row, next to two rows
  # it imports, type 0 being the lowest mapped type. A domain or client ID
  # without a row in its linking table reads as NULL. Only the two imported
  # rows are counted, and only the forwarded one adds its upstream, not the
  # one skipped for its negative reply time. This runs on a copy of the
  # database that holds only these rows
  db=/etc/pihole/import-skip.db
  rm -f "${db}"
  run ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" ".backup ${db}"
  assert_success
  chown pihole:pihole "${db}"
  now=$(date +%s)
  sql="DELETE FROM query_storage; DELETE FROM aliasclient;
  CREATE TEMP TABLE r (domain TEXT, ip TEXT, type INTEGER, status INTEGER, reply INTEGER, rtime REAL, dnssec INTEGER, fwd TEXT, missing TEXT);
  INSERT INTO r VALUES
    ('imported-a.import-skip.ftl',    '10.0.201.1',  1,     2,  4,  0.01, 0,  '10.0.201.54#53', NULL),
    ('imported-0.import-skip.ftl',    '10.0.201.2',  0,     3,  1,  0.0,  0,  NULL, NULL),
    ('type-50.import-skip.ftl',       '10.0.201.3',  50,    2,  4,  0.01, 0,  NULL, NULL),
    ('type-negative.import-skip.ftl', '10.0.201.4',  -1,    2,  4,  0.01, 0,  NULL, NULL),
    ('type-65636.import-skip.ftl',    '10.0.201.5',  65636, 2,  4,  0.01, 0,  NULL, NULL),
    ('status.import-skip.ftl',        '10.0.201.6',  1,     99, 4,  0.01, 0,  NULL, NULL),
    ('reply.import-skip.ftl',         '10.0.201.7',  1,     2,  99, 0.01, 0,  NULL, NULL),
    ('dnssec.import-skip.ftl',        '10.0.201.8',  1,     2,  4,  0.01, 99, NULL, NULL),
    ('reply-time.import-skip.ftl',    '10.0.201.9',  1,     2,  4,  -1.0, 0,  '10.0.201.53#53', NULL),
    ('domain.import-skip.ftl',        '10.0.201.10', 1,     2,  4,  0.01, 0,  NULL, 'domain'),
    ('client.import-skip.ftl',        '10.0.201.11', 1,     2,  4,  0.01, 0,  NULL, 'client');
  INSERT OR IGNORE INTO domain_by_id (domain) SELECT domain FROM r;
  INSERT OR IGNORE INTO client_by_id (ip, name) SELECT ip, '' FROM r;
  INSERT OR IGNORE INTO forward_by_id (forward) SELECT fwd FROM r WHERE fwd IS NOT NULL;
  INSERT INTO query_storage (timestamp, type, status, domain, client, forward, reply_type, reply_time, dnssec)
    SELECT $((now - 60)), r.type, r.status,
           CASE r.missing WHEN 'domain' THEN 2147483000 ELSE d.id END,
           CASE r.missing WHEN 'client' THEN 2147483000 ELSE c.id END,
           f.id, r.reply, r.rtime, r.dnssec
    FROM r JOIN domain_by_id d ON d.domain = r.domain
           JOIN client_by_id c ON c.ip = r.ip AND c.name = ''
           LEFT JOIN forward_by_id f ON f.forward = r.fwd;"
  run ./pihole-FTL sqlite3 "${db}" ".timeout 5000" "${sql}"
  assert_success

  # The counters are logged once the import has closed its gaps
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "su pihole -s /bin/sh -c 'FTLCONF_files_database=${db} /home/pihole/pihole-FTL'"
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  sums=$(curl -s 127.0.0.1/api/stats/summary | jq -c '[.queries.total, ([.queries.status[]] | add), ([.queries.replies[]] | add)]')
  clients=$(curl -s '127.0.0.1/api/stats/top_clients?count=100000' | jq -c '[.clients[] | select(.ip | startswith("10.0.201.")) | [.ip, .count]] | sort')
  upstreams=$(tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log | grep -oE 'New upstream server: 10\.0\.201\.[0-9]+:[0-9]+' || true)

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  rm -f "${db}" "${db}-journal" "${db}-wal" "${db}-shm"

  # Every query has one status and one reply type, and the skipped rows count
  # neither for a client nor add an upstream
  printf "total, status and reply sums: %s\nclients: %s\nupstreams: %s\n" "${sums}" "${clients}" "${upstreams}"
  assert_equal "$(jq 'unique | length' <<< "${sums}")" "1"
  assert_equal "${clients}" '[["10.0.201.1",1],["10.0.201.2",1]]'
  assert_equal "${upstreams}" "New upstream server: 10.0.201.54:53"
}

@test "Queries keep the client name they were made with, in memory, on disk and after a restart" {
  # The test configuration resolves no client names. This instance resolves
  # 127.0.0.20 through dns.hosts, which names it old-name.ftl after its first
  # query and renames it to new-name.ftl after its second
  cp -p /etc/pihole/pihole.toml /tmp/pihole.toml.names
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  # Without the history of the earlier tests, the resolver has only the names
  # of this test to look up
  run bash -c 'su pihole -s /bin/sh -c "FTLCONF_database_DBimport=false FTLCONF_resolver_resolveIPv4=true FTLCONF_resolver_refreshNames=ALL /home/pihole/pihole-FTL"'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  patch() {
    [[ "$(curl -s -o /dev/null -w '%{http_code}' -X PATCH 127.0.0.1/api/config -d "{\"config\": $1}")" == "200" ]]
  }
  hosts=$(curl -s 127.0.0.1/api/config/dns/hosts | jq -c '.config.dns.hosts')
  # Point 127.0.0.20 at a name, then wait until FTL's client has it
  set_name() {
    patch "$(jq -c --arg host "127.0.0.20 $1" '{dns: {hosts: (. + [$host])}}' <<< "${hosts}")" || return 1
    for i in $(seq 1 30); do
      [[ "$(dig -x 127.0.0.20 @127.0.0.1 +short)" == "$1." ]] && return 0
      sleep 1
    done
    return 1
  }
  wait_for_name() {
    for i in $(seq 1 30); do
      [[ "$(curl -s '127.0.0.1/api/stats/top_clients?count=1000' | jq -r '.clients[] | select(.ip == "127.0.0.20") | .name')" == "$1" ]] && return 0
      sleep 1
    done
    return 1
  }
  names() {
    curl -s "127.0.0.1/api/queries?domain=*.names.ftl$1" | jq -c '[.queries[] | [.domain, .client.name]]'
  }
  # Output, filter, column search and sort all go by the name a query was
  # made with. Without the exclusion regex of the test configuration, which
  # needs the name, so that a filter by IP alone does not look it up
  check_names() {
    run names "$1"
    assert_output '[["three.names.ftl","new-name.ftl"],["two.names.ftl","old-name.ftl"],["one.names.ftl",null]]'
    run names "&client_name=old-name.ftl$1"
    assert_output '[["two.names.ftl","old-name.ftl"]]'
    run names "&columns%5B4%5D%5Bdata%5D=client&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=old-name$1"
    assert_output '[["two.names.ftl","old-name.ftl"]]'
    run bash -c "curl -s '127.0.0.1/api/queries?domain=*.names.ftl&columns%5B5%5D%5Bdata%5D=client.name&order%5B0%5D%5Bcolumn%5D=5&order%5B0%5D%5Bdir%5D=asc$1' | jq -c '[.queries[] | .client.name]'"
    assert_output '[null,"new-name.ftl","old-name.ftl"]'
    run names "&client_ip=127.0.0.20$1"
    assert_output "$(names "$1")"
  }
  run patch '{"webserver": {"api": {"excludeClients": []}}}'
  assert_success

  run set_name old-name.ftl
  assert_success
  dig A one.names.ftl -b 127.0.0.20 @127.0.0.1 +tries=1 +time=2 > /dev/null
  run wait_for_name old-name.ftl
  assert_success
  dig A two.names.ftl -b 127.0.0.20 @127.0.0.1 +tries=1 +time=2 > /dev/null
  run set_name new-name.ftl
  assert_success
  kill -SIGRTMIN+4 "$(cat /run/pihole-FTL.pid)"
  run wait_for_name new-name.ftl
  assert_success
  dig A three.names.ftl -b 127.0.0.20 @127.0.0.1 +tries=1 +time=2 > /dev/null
  check_names ""

  # The final export on termination stores them with these names, the import
  # gives them back. On disk and in memory alike
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  # Plus two queries of 127.0.0.21 with IDs right after each other, stored
  # with different names
  now=$(date +%s)
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"INSERT OR IGNORE INTO client_by_id (ip, name) VALUES ('127.0.0.21', 'row-a.ftl'), ('127.0.0.21', 'row-b.ftl'); INSERT OR IGNORE INTO domain_by_id (domain) VALUES ('a.rows.ftl'), ('b.rows.ftl'); INSERT INTO query_storage (timestamp, type, status, domain, client) SELECT $((now - 10)) + (n = 'b'), 1, 3, (SELECT id FROM domain_by_id WHERE domain = n || '.rows.ftl'), (SELECT id FROM client_by_id WHERE ip = '127.0.0.21' AND name = 'row-' || n || '.ftl') FROM (SELECT 'a' AS n UNION ALL SELECT 'b') ORDER BY n;\""
  assert_success
  logsize_import=$(stat -c%s /var/log/pihole/FTL.log)
  # The names come from the import, this instance resolves none. The API
  # writes above put some of the first instance's settings into pihole.toml
  run bash -c 'su pihole -s /bin/sh -c "FTLCONF_database_DBimport=true FTLCONF_resolver_resolveIPv4=false FTLCONF_resolver_refreshNames=NONE /home/pihole/pihole-FTL"'
  assert_success
  run bash -c "./pihole-FTL wait-for 'queries from the long-term database' /var/log/pihole/FTL.log 30 $logsize_import"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_import"
  assert_success
  for disk in "" "&disk=true"; do
    check_names "${disk}"
    run bash -c "curl -s '127.0.0.1/api/queries?domain=*.rows.ftl${disk}' | jq -c '[.queries[] | [.domain, .client.name]]'"
    assert_output '[["b.rows.ftl","row-b.ftl"],["a.rows.ftl","row-a.ftl"]]'
  done
  # And so do the exclusion regexes
  run patch '{"webserver": {"api": {"excludeClients": ["^old-name\\.ftl$"]}}}'
  assert_success
  for disk in "" "&disk=true"; do
    run names "${disk}"
    assert_output '[["three.names.ftl","new-name.ftl"],["one.names.ftl",null]]'
  done

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  cp -p /tmp/pihole.toml.names /etc/pihole/pihole.toml
  ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "DELETE FROM query_storage WHERE client IN (SELECT id FROM client_by_id WHERE ip IN ('127.0.0.20', '127.0.0.21')); DELETE FROM client_by_id WHERE ip IN ('127.0.0.20', '127.0.0.21'); DELETE FROM domain_by_id WHERE domain GLOB '*.names.ftl' OR domain GLOB '*.rows.ftl';"

  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.names.log
  run bash -c 'grep "WARNING:" /tmp/FTL.names.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.names.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.names.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "Sessions are restored and earlier messages flushed when FTL starts" {
  # An expired session is deleted and a valid one restored and removed from
  # the database. Of the messages only those of type TELEPORTER_SKIPPED stay
  now=$(date +%s)
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"DELETE FROM session; INSERT INTO session (login_at, valid_until, remote_addr, user_agent, sid, csrf, tls_login, tls_mixed, app, cli) VALUES (${now}, $((now + 3600)), '127.0.0.1', 'bats', 'restore-sid', 'restore-csrf', 0, 0, 0, 0), ($((now - 7200)), $((now - 3600)), '127.0.0.1', 'bats', 'expired-sid', 'expired-csrf', 0, 0, 0, 0); INSERT INTO message (timestamp, type, message) VALUES (${now}, 'TELEPORTER_SKIPPED', 'restart.kept'), (${now}, 'LOAD', 'restart.flushed');\""
  assert_success

  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for ' -> Known forward destinations' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log | grep -c 'Restored 1 API session from the database'"
  assert_output "1"
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"SELECT (SELECT COUNT(*) FROM session), (SELECT group_concat(message) FROM message WHERE message GLOB 'restart.*');\""
  assert_output "0|restart.kept"

  # The restored session is stored again on termination
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  assert_success
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"SELECT group_concat(sid) FROM session; DELETE FROM session; DELETE FROM message WHERE message GLOB 'restart.*';\""
  assert_output "restore-sid"

  tail -c +$((logsize_restart + 1)) /var/log/pihole/FTL.log > /tmp/FTL.startup-db.log
  run bash -c 'grep "WARNING:" /tmp/FTL.startup-db.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for ([a-z0-9-]+\.)*(ftl|icloud\.com|apple-dns\.net|in-addr\.arpa|ip6\.arpa),)|(nameserver 127.0.0.1 refused to do a recursive query)|(Ignoring malformed TLS entry .(44s3|443xs). in webserver\.port)"'
  refute_output
  run bash -c 'grep "ERROR: " /tmp/FTL.startup-db.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)|(Terminator: bind\(\) to 192\.0\.2\.1#9444 failed)"'
  refute_output
  run bash -c 'grep "CRIT:" /tmp/FTL.startup-db.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "Long domains of imported queries fill several string blocks of one request" {
  # 600 domains of 608 bytes: the strings of 64 rows are more than a block
  # keeps free, so a chunk has to end early for a new block
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \".timeout 5000\" \"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 600) INSERT INTO domain_by_id (domain) SELECT printf('%04d-%s.blocks.ftl', x, hex(zeroblob(296))) FROM c; INSERT OR IGNORE INTO client_by_id (ip, name) VALUES ('10.0.6.0', ''); INSERT INTO query_storage (timestamp, type, status, domain, client) SELECT $(( $(date +%s) - 60 )), 1, 3, d.id, c.id FROM domain_by_id d, client_by_id c WHERE d.domain LIKE '%.blocks.ftl' AND c.ip = '10.0.6.0' ORDER BY d.id;\""
  assert_success
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for 'queries from the long-term database' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  reply=$(curl -s "127.0.0.1/api/queries?domain=*.blocks.ftl&length=1000" | jq -c '[(.queries | length), ([.queries[]?.domain | length] | unique), ([.queries[]?.domain[0:4]] | unique | length), .recordsFiltered]')

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  stopped=${status}
  ./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db ".timeout 5000" "DELETE FROM query_storage WHERE domain IN (SELECT id FROM domain_by_id WHERE domain LIKE '%.blocks.ftl'); DELETE FROM domain_by_id WHERE domain LIKE '%.blocks.ftl'; DELETE FROM client_by_id WHERE ip = '10.0.6.0';"
  assert_equal "${stopped}" "0"

  printf "rows, domain lengths, distinct domains, recordsFiltered: %s\n" "${reply}"
  assert_equal "${reply}" "[600,[608],600,600]"
}

@test "The in-memory query log has a null cursor before the first query" {
  # FTL starts on a new database, so there is no query a cursor could point to
  for f in /etc/pihole/pihole-FTL.db /etc/pihole/pihole-FTL.db-wal /etc/pihole/pihole-FTL.db-shm; do
    if [[ -e "${f}" ]]; then mv "${f}" "${f}.kept"; fi
  done
  logsize_restart=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'su pihole -s /bin/sh -c /home/pihole/pihole-FTL'
  assert_success
  run bash -c "./pihole-FTL wait-for 'queries from the long-term database' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  run bash -c "./pihole-FTL wait-for 'Web server ports:' /var/log/pihole/FTL.log 30 $logsize_restart"
  assert_success
  reply=$(curl -s "127.0.0.1/api/queries" | jq -c '[.cursor, .recordsTotal, (.queries | length)]')

  # The database of the suite comes back also if FTL does not stop in time.
  # Not in the shell of the kill: FTL logs the command line of the process
  # that signals it, which would hold the string waited for
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "kill $(cat /run/pihole-FTL.pid)"
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  stopped=${status}
  rm -f /etc/pihole/pihole-FTL.db /etc/pihole/pihole-FTL.db-wal /etc/pihole/pihole-FTL.db-shm
  for f in /etc/pihole/pihole-FTL.db /etc/pihole/pihole-FTL.db-wal /etc/pihole/pihole-FTL.db-shm; do
    if [[ -e "${f}.kept" ]]; then mv "${f}.kept" "${f}"; fi
  done
  assert_equal "${stopped}" "0"

  printf "cursor, recordsTotal, rows: %s\n" "${reply}"
  assert_equal "${reply}" "[null,0,0]"
}
