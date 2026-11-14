#!/usr/bin/env bats
# A temporary blocking status (set with a timer) is kept in memory only, a
# permanent one in pihole.toml. Run after pytest, as the restarts perturb the
# query statistics the API tests assert on.

bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

FTL_URL="http://127.0.0.1"
FTL_LOG="/var/log/pihole/FTL.log"

set_blocking() {  # $1 = JSON payload
  curl -s -X POST "${FTL_URL}/api/dns/blocking" -d "$1"
}

toml_active() {
  sed -n "/^  \[dns.blocking\]/,/active =/p" /etc/pihole/pihole.toml | grep "active ="
}

# Restart FTL through the API and wait until the new process has started
restart_ftl() {
  local before
  before=$(stat -c%s "$FTL_LOG")
  curl -s -o /dev/null --max-time 10 -X POST "${FTL_URL}/api/action/restartdns" || true
  ./pihole-FTL wait-for "########## FTL started" "$FTL_LOG" 30 "$before"
}

# Poll GET /api/dns/blocking until it matches $1, for at most 30 seconds
wait_for_blocking() {
  local i
  for i in $(seq 1 150); do
    curl -s --max-time 2 "${FTL_URL}/api/dns/blocking" | grep -q "$1" && return 0
    sleep 0.2
  done
  curl -s --max-time 2 "${FTL_URL}/api/dns/blocking" >&2
  return 1
}

@test "A temporary blocking status does not change pihole.toml" {
  run set_blocking '{"blocking":false,"timer":60}'
  assert_output --partial '"blocking":"disabled","timer":'
  run toml_active
  assert_output --partial "active = true"

  # Ending it early is a permanent change to the status pihole.toml has anyway
  before=$(stat -c%s "$FTL_LOG")
  run set_blocking '{"blocking":true}'
  assert_output --partial '"blocking":"enabled","timer":null'
  run ./pihole-FTL wait-for "Flushing cache and re-reading config" "$FTL_LOG" 3 "$before"
  assert_success
}

@test "A config change masked by a temporary status does not reload" {
  run set_blocking '{"blocking":false,"timer":60}'
  assert_output --partial '"blocking":"disabled","timer":'
  before=$(stat -c%s "$FTL_LOG")
  curl -s -o /dev/null -X PATCH -d '{"config":{"dns":{"blocking":{"active":false}}}}' "${FTL_URL}/api/config"
  run ./pihole-FTL wait-for "Flushing cache and re-reading config" "$FTL_LOG" 3 "$before"
  assert_failure

  before=$(stat -c%s "$FTL_LOG")
  run set_blocking '{"blocking":true}'
  assert_output --partial '"blocking":"enabled","timer":null'
  run ./pihole-FTL wait-for "Flushing cache and re-reading config" "$FTL_LOG" 3 "$before"
  assert_success
  run toml_active
  assert_output --partial "active = true"
}

@test "A temporary disable keeps the DNS cache, its end flushes it" {
  before=$(stat -c%s "$FTL_LOG")
  run set_blocking '{"blocking":false,"timer":60}'
  assert_output --partial '"blocking":"disabled","timer":'
  run ./pihole-FTL wait-for "Blocking status is disabled" "$FTL_LOG" 3 "$before"
  assert_success
  run bash -c "tail -c +$((before + 1)) $FTL_LOG | grep -c 'Flushing cache' || true"
  assert_output "0"

  before=$(stat -c%s "$FTL_LOG")
  run set_blocking '{"blocking":true}'
  assert_output --partial '"blocking":"enabled","timer":null'
  run ./pihole-FTL wait-for "Flushing cache and re-reading config" "$FTL_LOG" 3 "$before"
  assert_success
}

@test "Flipping the setting under a temporary status does not reload" {
  # The timer returns to the opposite of the requested status, so the setting is
  # flipped to disabled while the temporary status keeps blocking enabled
  before=$(stat -c%s "$FTL_LOG")
  run set_blocking '{"blocking":true,"timer":60}'
  assert_output --partial '"blocking":"enabled","timer":'
  run toml_active
  assert_output --partial "active = false"

  run set_blocking '{"blocking":true}'
  assert_output --partial '"blocking":"enabled","timer":null'
  run toml_active
  assert_output --partial "active = true"
  run ./pihole-FTL wait-for "Flushing cache and re-reading config" "$FTL_LOG" 3 "$before"
  assert_failure
  run bash -c "tail -c +$((before + 1)) $FTL_LOG | grep -c 'Blocking status is disabled' || true"
  assert_output "0"
}

@test "A temporary blocking status ends when FTL restarts" {
  run set_blocking '{"blocking":false,"timer":300}'
  assert_output --partial '"blocking":"disabled"'
  run restart_ftl
  assert_success
  run wait_for_blocking '"blocking":"enabled","timer":null'
  assert_success
}

@test "A permanent blocking status survives an FTL restart" {
  run set_blocking '{"blocking":false}'
  assert_output --partial '"blocking":"disabled","timer":null'
  run toml_active
  assert_output --partial "active = false"
  run restart_ftl
  assert_success
  run wait_for_blocking '"blocking":"disabled","timer":null'
  assert_success

  run set_blocking '{"blocking":true}'
  assert_output --partial '"blocking":"enabled","timer":null'
}

@test "A config change while FTL starts does not break the TLS certificate" {
  # Each change restarts FTL, the next one arrives while the new process loads
  # the certificate and installs the changed config at the same time
  before=$(stat -c%s "$FTL_LOG")
  for value in true false true false; do
    logsize=$(stat -c%s "$FTL_LOG")
    run ./pihole-FTL --config dns.expandHosts "$value"
    assert_success
    run ./pihole-FTL wait-for "Parsed config file /etc/pihole/pihole.toml successfully" "$FTL_LOG" 30 "$logsize"
    assert_success
  done
  run ./pihole-FTL wait-for "dotdoh: DoQ server listening" "$FTL_LOG" 30 "$logsize"
  assert_success
  run ./pihole-FTL wait-for "dotdoh: DoT server listening" "$FTL_LOG" 30 "$logsize"
  assert_success

  run bash -c "tail -c +$((before + 1)) $FTL_LOG | grep -cE 'dotdoh: could not load|Terminator: loading' || true"
  assert_output "0"
}
