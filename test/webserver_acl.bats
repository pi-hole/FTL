#!/usr/bin/env bats
# webserver.acl end-to-end tests for the TLS terminator.
#
# The terminator owns the HTTPS port and reaches the CivetWeb backend from
# 127.0.0.1, so it must apply webserver.acl to the real client itself. Clients
# are sourced from 127.0.0.1 and 127.0.0.2 (the whole 127.0.0.0/8 is loopback)
# so one address can be allowed while the other is refused.
#
# Each ACL change restarts FTL, so this file runs after the pytest API tests.
#
# DoH follows dns.listeningMode, not the ACL. A client the ACL refuses but
# dns.listeningMode (LOCAL here, which admits 127.0.0.2) allows still gets
# through the TLS handshake for DoH, and a 403 for anything else.

bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

TLS="--cacert /etc/pihole/test.crt --resolve pi.hole:443:127.0.0.1"

# PATCH webserver.acl from source address $2 and block until the restart it
# triggers has brought the terminator back up
set_acl() {  # $1 = ACL, $2 = source address
  local before
  before=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null --max-time 10 --interface "$2" -X PATCH "http://127.0.0.1/api/config" \
       -H "Content-Type: application/json" \
       -d "{\"config\":{\"webserver\":{\"acl\":\"$1\"}}}" || true
  ./pihole-FTL wait-for "TLS terminator listening" /var/log/pihole/FTL.log 30 "$before"
}

# HTTP status of a GET from source address $1, "000" when refused before the
# TLS handshake
status_from() {  # $1 = source address, $2.. = curl arguments
  local src=$1
  shift
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 --interface "$src" "$@"
}

teardown_file() {
  # Restore the empty ACL from whichever source the current ACL still admits
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --interface 127.0.0.2 http://127.0.0.1/api/auth)
  if [[ "$code" == "200" ]]; then
    set_acl "" 127.0.0.2
  else
    set_acl "" 127.0.0.1
  fi
}

@test "webserver.acl: a localhost-only ACL refuses other clients over HTTPS too" {
  set_acl "+127.0.0.1,+[::1]" 127.0.0.1
  run status_from 127.0.0.2 http://127.0.0.1/api/auth
  assert_output "000"
  run status_from 127.0.0.2 --http1.1 $TLS https://pi.hole/api/auth
  assert_output "403"
  run status_from 127.0.0.2 --http2 $TLS https://pi.hole/api/auth
  assert_output "403"
  run status_from 127.0.0.1 --http1.1 $TLS https://pi.hole/api/auth
  assert_output "200"
  run status_from 127.0.0.1 --http2 $TLS https://pi.hole/api/auth
  assert_output "200"
}

@test "webserver.acl: an ACL refusing 127.0.0.1 still serves allowed clients over HTTPS" {
  set_acl "+127.0.0.2" 127.0.0.1
  run status_from 127.0.0.2 --http1.1 $TLS https://pi.hole/api/auth
  assert_output "200"
  run status_from 127.0.0.2 --http2 $TLS https://pi.hole/api/auth
  assert_output "200"
  run status_from 127.0.0.2 http://127.0.0.1/api/auth
  assert_output "200"
  # 127.0.0.1 itself stays refused, on HTTPS and on plain HTTP
  run status_from 127.0.0.1 --http1.1 $TLS https://pi.hole/api/auth
  assert_output "403"
  run status_from 127.0.0.1 http://127.0.0.1/api/auth
  assert_output "403"
}

@test "webserver.acl: a client the ACL refuses still gets DoH answers" {
  local dns a
  a="${BATS_FILE_TMPDIR}/acl_doh_a.bin"
  # The previous test left an ACL admitting only 127.0.0.2
  set_acl "+127.0.0.1,+[::1]" 127.0.0.2
  dns=$(python3 test/dotdoh_query.py emiturl a.ftl)
  for proto in --http2 --http1.1; do
    rm -f "$a"
    run curl -s --max-time 5 "$proto" $TLS --interface 127.0.0.2 \
             "https://pi.hole/dns-query?dns=${dns}" --output "$a"
    assert_success
    run python3 test/dotdoh_query.py check "$a" "192.168.1.1"
    assert_output "OK"
  done
  # The same client still gets a 403 for anything but DoH
  run status_from 127.0.0.2 --http2 $TLS https://pi.hole/api/auth
  assert_output "403"
}
