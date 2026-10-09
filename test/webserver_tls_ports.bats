#!/usr/bin/env bats
# webserver.port combinations for the TLS terminator: several secure entries,
# address-scoped and IPv4/IPv6 entries on one port, an optional entry that
# cannot be bound, and secure entries that are all malformed.
#
# Changing webserver.port restarts FTL, so this file runs after the pytest API
# tests.

bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

PORTS="80o,443os,[::]:80o,[::]:443os,8081r"

# PATCH webserver.port and block until the restart it triggers has logged $2,
# by default the terminator coming back up. LOG_OFFSET is where FTL.log stood
# before the change.
set_ports() {  # $1 = webserver.port, $2 = log line to wait for
  LOG_OFFSET=$(stat -c%s /var/log/pihole/FTL.log)
  curl -s -o /dev/null --max-time 10 -X PATCH "http://127.0.0.1/api/config" \
       -H "Content-Type: application/json" \
       -d "{\"config\":{\"webserver\":{\"port\":\"$1\"}}}" || true
  ./pihole-FTL wait-for "${2:-TLS terminator listening}" /var/log/pihole/FTL.log 60 "$LOG_OFFSET"
}

# Wait for the HTTP/3 listener the log line $1 names since the last set_ports
wait_h3() {  # $1 = "HTTP/3 (QUIC) listening on UDP port <port>"
  ./pihole-FTL wait-for "$1" /var/log/pihole/FTL.log 60 "$LOG_OFFSET"
}

# HTTP status of GET https://pi.hole:$2/api/auth sent to address $1, "000" when
# nothing listens there
status_at() {  # $1 = address, $2 = port, $3.. = curl arguments
  local addr=$1 port=$2
  shift 2
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 --cacert /etc/pihole/test.crt \
       --resolve "pi.hole:${port}:${addr}" "$@" "https://pi.hole:${port}/api/auth"
}

# Alt-Svc header of an HTTP/2 GET https://pi.hole:$2/api/auth sent to address $1
altsvc_at() {  # $1 = address, $2 = port
  curl -s -D - -o /dev/null --max-time 5 --http2 --cacert /etc/pihole/test.crt \
       --resolve "pi.hole:$2:$1" "https://pi.hole:$2/api/auth" | grep -i '^alt-svc'
}

# True if this environment has an IPv6 loopback (some CI containers do not)
ipv6_loopback_available() {
  python3 -c 'import socket; socket.socket(socket.AF_INET6).bind(("::1", 0))' 2>/dev/null
}

setup_file() {
  # The list test/pihole.toml sets, restored at the end
  ./pihole-FTL --config webserver.port | head -n 1 > "${BATS_FILE_TMPDIR}/ports"
}

teardown_file() {
  if [[ -f "${BATS_FILE_TMPDIR}/holder.pid" ]]; then
    kill "$(cat "${BATS_FILE_TMPDIR}/holder.pid")" 2>/dev/null || true
  fi
  set_ports "$(cat "${BATS_FILE_TMPDIR}/ports")"
}

@test "webserver.port: every secure entry is served, not only the first" {
  set_ports "$PORTS,4443s,127.0.0.2:9443s"
  for proto in --http1.1 --http2; do
    run status_at 127.0.0.1 443 "$proto"
    assert_output "200"
    run status_at 127.0.0.1 4443 "$proto"
    assert_output "200"
    run status_at 127.0.0.2 9443 "$proto"
    assert_output "200"
  done
  # 9443 is scoped to 127.0.0.2
  run status_at 127.0.0.1 9443 --http2
  assert_output "000"
  # HTTP/2 clients are pointed to HTTP/3 on the port they connected to, and
  # HTTP/3 works on both added entries (DoH, as curl in CI has no HTTP/3)
  wait_h3 "HTTP/3 (QUIC) listening on UDP port 9443"
  run altsvc_at 127.0.0.1 4443
  assert_output --partial 'h3=":4443"'
  run altsvc_at 127.0.0.2 9443
  assert_output --partial 'h3=":9443"'
  run python3 test/dotdoh_query.py doh3 127.0.0.1 4443 a.ftl 192.168.1.1
  assert_output "OK"
  run python3 test/dotdoh_query.py doh3 127.0.0.2 9443 a.ftl 192.168.1.1
  assert_output "OK"
}

@test "webserver.port: an optional TLS entry that cannot be bound does not stop the others" {
  # Another process holds 5443, the first and optional TLS entry
  python3 -c 'import socket, time
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", 5443))
s.listen()
time.sleep(120)' > /dev/null 2>&1 3>&- &
  echo $! > "${BATS_FILE_TMPDIR}/holder.pid"
  run bash -c 'for _ in $(seq 1 300); do netstat -ltn | grep -q ":5443 " && exit 0; sleep 0.1; done; exit 1'
  assert_success
  set_ports "80o,[::]:80o,8081r,5443os,[::]:5443os,4443s"
  run status_at 127.0.0.1 4443 --http2
  assert_output "200"
  # The HTTPS port the web interface is told about is the one that is served
  run bash -c 'curl -s http://127.0.0.1/api/info/login | jq .https_port'
  assert_output "4443"
  # and the 'r' port redirects there
  run bash -c 'curl -s -o /dev/null -w "%{redirect_url}" http://127.0.0.1:8081/admin/'
  assert_output "https://pi.hole:4443/admin/"
  kill "$(cat "${BATS_FILE_TMPDIR}/holder.pid")"
  rm -f "${BATS_FILE_TMPDIR}/holder.pid"
}

@test "webserver.port: IPv4 and IPv6 entries on one port, and an IPv4 entry before a wildcard" {
  set_ports "80o,[::]:80o,8081r,0.0.0.0:4443s,[::]:4443s,127.0.0.1:9443s,9443s"
  run status_at 127.0.0.1 4443 --http2
  assert_output "200"
  # The wildcard 9443 covers 127.0.0.1:9443 and every other address
  run status_at 127.0.0.2 9443 --http2
  assert_output "200"
  if ipv6_loopback_available; then
    run status_at "[::1]" 4443 --http2
    assert_output "200"
    run status_at "[::1]" 9443 --http2
    assert_output "200"
  fi
  wait_h3 "HTTP/3 (QUIC) listening on UDP port 9443"
  run python3 test/dotdoh_query.py doh3 127.0.0.1 4443 a.ftl 192.168.1.1
  assert_output "OK"
  if ipv6_loopback_available; then
    run python3 test/dotdoh_query.py doh3 ::1 4443 a.ftl 192.168.1.1
    assert_output "OK"
  fi
}

@test "webserver.port: a bare TLS entry after two address-scoped ones on its port" {
  set_ports "80o,[::]:80o,8081r,0.0.0.0:4443s,[::]:4443s,4443s"
  run status_at 127.0.0.1 4443 --http2
  assert_output "200"
  if ipv6_loopback_available; then
    run status_at "[::1]" 4443 --http2
    assert_output "200"
  fi
  # The bare entry serves both halves, so neither half is bound on its own
  run bash -c "tail -c +$((LOG_OFFSET + 1)) /var/log/pihole/FTL.log | grep 'Terminator: bind'"
  refute_output
}

@test "webserver.port: TLS entries that are all malformed leave the plaintext ports up" {
  # No TLS entry is usable, so the terminator does not start
  set_ports "80o,[::]:80o,8081r,192.168.1.256:443s,44s3" "Web server ports:"
  run curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/api/auth
  assert_output "200"
  if ipv6_loopback_available; then
    run curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://[::1]/api/auth"
    assert_output "200"
  fi
  # The redirect entry has no TLS port to send clients to
  run curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8081/admin/
  assert_output "503"
}
