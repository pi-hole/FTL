#!/usr/bin/env bats
# FTL re-enables blocking on every (re)start. Run after pytest, as the restart
# perturbs the query statistics the API tests assert on.

bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

FTL_URL="http://127.0.0.1"
FTL_LOG="/var/log/pihole/FTL.log"

# Restart FTL through the API and wait for the startup warning
restart_and_expect_enabled() {
  local before
  before=$(stat -c%s "$FTL_LOG")
  curl -s -o /dev/null --max-time 10 -X POST "${FTL_URL}/api/action/restartdns" || true
  ./pihole-FTL wait-for "Blocking was disabled, enabling it on startup" "$FTL_LOG" 30 "$before"
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

@test "Blocking disabled with a timer is enabled again after a restart" {
  run curl -s -X POST "${FTL_URL}/api/dns/blocking" -d '{"blocking":false,"timer":300}'
  assert_output --partial '"blocking":"disabled"'
  run restart_and_expect_enabled
  assert_success
  run wait_for_blocking '"blocking":"enabled","timer":null'
  assert_success
}

@test "Blocking disabled without a timer is enabled again after a restart" {
  run curl -s -X POST "${FTL_URL}/api/dns/blocking" -d '{"blocking":false}'
  assert_output --partial '"blocking":"disabled"'
  run restart_and_expect_enabled
  assert_success
  run wait_for_blocking '"blocking":"enabled","timer":null'
  assert_success
  run bash -c 'sed -n "/^  \[dns.blocking\]/,/active =/p" /etc/pihole/pihole.toml | grep "active ="'
  assert_output --partial "active = true"
}
