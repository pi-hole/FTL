#!/usr/bin/env bats
# Encrypted-upstream (DoT/DoH) end-to-end tests.
#
# Prerequisites, provided by test/run.sh:
#   - pdns_recursor serving the .ftl test zone on 127.0.0.1:5555
#   - test/dotdoh_shim.py running (DoT on :8853, DoH on :8443), terminating
#     TLS with test/test.pem (CN/SAN "pi.hole", signed by test/test_ca.crt)
#
# dns.upstreams and dns.upstreamCA are RESTART_FTL settings. We switch both to
# the encrypted test upstream in ONE atomic API request, so FTL restarts exactly
# once and comes up with a consistent state (dotdoh armed AND the generated
# dnsmasq.conf pointing at the proxy). Doing it as two separate CLI changes would
# race the two restarts against each other.

bats_load_library 'bats-support'
bats_load_library 'bats-assert'
bats_load_library 'bats-file'
load 'bats_helper.bash'

FTL_URL="http://127.0.0.1"

# The shim (started by run.sh, or ensure_shim below) appends every decrypted
# query length here; used to confirm FTL padded the encrypted query. Default so
# a standalone bats run works too; run.sh exports the same path.
export SHIM_PAD_LOG="${SHIM_PAD_LOG:-/tmp/dotdoh_pad.log}"

# PATCH the given dns config object ($1) in one atomic request and block until
# the self-restart it triggers has produced the readiness marker ($2) past the
# pre-change log offset, using pihole-FTL wait-for as the rest of the suite does.
api_patch_dns() {  # $1 = JSON object for "dns", $2 = readiness log marker
  local before
  before=$(stat -c%s /var/log/pihole/FTL.log)
  # --max-time: the config change restarts FTL mid-request, so the connection is
  # dropped and curl must not hang waiting on the reply. wait-for below is what
  # actually blocks until the restart has completed.
  curl -s -o /dev/null --max-time 10 -X PATCH "${FTL_URL}/api/config" \
       -H "Content-Type: application/json" \
       -d "{\"config\":{\"dns\":$1}}" || true
  ./pihole-FTL wait-for "$2" /var/log/pihole/FTL.log 30 "$before"
}

ensure_shim() {
  if ! pgrep -f dotdoh_shim.py >/dev/null 2>&1; then
    python3 test/dotdoh_shim.py &
  fi
  # pgrep only proves the process exists, not that it is accepting yet. Wait
  # until both TLS ports actually accept a connection so setup_file cannot race
  # a still-starting shim, which otherwise made the E2E test flaky. Fail loudly
  # if a port never comes up instead of letting it surface as a later, harder
  # to diagnose DNS failure.
  local port i ready
  for port in 8853 8443; do
    ready=""
    for i in $(seq 1 50); do
      if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        exec 3>&-
        ready=1
        break
      fi
      sleep 0.2
    done
    if [ -z "$ready" ]; then
      echo "dotdoh shim TLS port ${port} never became ready" >&2
      return 1
    fi
  done
}

# Succeed if the shim recorded at least one query of the given transport whose
# length is a positive multiple of 128 - i.e. FTL padded it (RFC 8467). An
# unpadded query for the test name is well under 128 octets.
assert_padded() {  # $1 = transport (dot|doh)
  local t len
  while read -r t len; do
    if [ "$t" = "$1" ] && [ "$len" -ge 128 ] && [ $((len % 128)) -eq 0 ]; then
      return 0
    fi
  done < "$SHIM_PAD_LOG"
  echo "no padded $1 query (multiple of 128) in $SHIM_PAD_LOG:" >&2
  cat "$SHIM_PAD_LOG" >&2 2>/dev/null || true
  return 1
}

# The randomised loopback tuple the proxy actually bound for an upstream, read
# from its "armed on <ip#port>" log line. Sets $tuple_ip and $tuple_port.
armed_tuple() {  # $1 = DoT | DoH
  local t
  t="$(grep -oE "dotdoh: $1 upstream [^ ]+ armed on 127(\.[0-9]+){3}#[0-9]+" /var/log/pihole/FTL.log \
       | grep -oE '127(\.[0-9]+){3}#[0-9]+' | tail -1)"
  tuple_ip="${t%#*}"
  tuple_port="${t#*#}"
}

# Fire $2 concurrent dig queries at the proxy's randomised listener and succeed
# only if every one resolved to the expected answer. This is the meaningful
# concurrency test: the worker pool and per-upstream connection pool must serve
# many in-flight exchanges at once without racing or dropping.
run_concurrent() {  # $1 = DoT|DoH, $2 = number of queries
  local n="$2" tmp i ok=0 tuple_ip tuple_port
  armed_tuple "$1"
  tmp="$(mktemp -d)"
  for i in $(seq 1 "$n"); do
    ( dig +short +tries=1 +time=8 "@${tuple_ip}" -p "$tuple_port" a.ftl > "${tmp}/${i}" 2>&1 ) &
  done
  wait
  for i in $(seq 1 "$n"); do
    grep -q "192.168.1.1" "${tmp}/${i}" && ok=$((ok + 1))
  done
  rm -rf "$tmp"
  echo "$ok/$n resolved"
  [ "$ok" -eq "$n" ]
}

# Set a non-RESTART_FTL config value (e.g. a debug flag) live, no restart.
set_debug_dotdoh() {  # $1 = true|false
  curl -s -o /dev/null --max-time 10 -X PATCH "${FTL_URL}/api/config" \
       -H "Content-Type: application/json" \
       -d "{\"config\":{\"debug\":{\"dotdoh\":$1}}}" || true
}

setup_file() {
  ensure_shim || return 1
  # The DoH upstream is armed last, so waiting for it means both listeners are up.
  api_patch_dns "{\"upstreamCA\":\"$(pwd)/test/test_ca.crt\",\"upstreams\":[\"tls://pi.hole@127.0.0.1#8853\",\"https://pi.hole@127.0.0.1#8443/dns-query\"]}" \
                "dotdoh: DoH upstream pi.hole armed"
}

teardown_file() {
  # Restore the plaintext upstream. It arms no proxy, so wait instead for the
  # regex recompile that every (re)start logs to know FTL is back up.
  api_patch_dns "{\"upstreamCA\":\"\",\"upstreams\":[\"127.0.0.1#5555\"]}" \
                "deny regex for"
}

@test "dotdoh-client: a malformed tls:// upstream is rejected by the validator" {
  run bash -c './pihole-FTL --config dns.upstreams "[\"tls://\"]"'
  assert_failure
}

@test "dotdoh-client: both the DoT and DoH upstreams were armed" {
  run bash -c 'grep -E "dotdoh: (DoT|DoH) upstream .* armed" /var/log/pihole/FTL.log'
  assert_output --partial "DoT upstream"
  assert_output --partial "DoH upstream"
}

# Query the proxy listeners directly. This is the meaningful end-to-end unit: the
# proxy re-encrypts the plaintext DNS it receives to the shim over TLS and hands
# back the answer. Going via dnsmasq instead would only add a trivial plaintext
# UDP hop and, worse, .ftl is pinned to the plaintext recursor by a server=/ftl/
# rule in 01-pihole-tests.conf, so it would never traverse the proxy at all.
@test "dotdoh-client: a query resolves through the DoT proxy path" {
  armed_tuple DoT
  run bash -c "dig +short +tries=1 +time=5 @${tuple_ip} -p ${tuple_port} a.ftl"
  assert_output --partial "192.168.1.1"
}

@test "dotdoh-client: a query resolves through the DoH proxy path" {
  armed_tuple DoH
  run bash -c "dig +short +tries=1 +time=5 @${tuple_ip} -p ${tuple_port} a.ftl"
  assert_output --partial "192.168.1.1"
}

@test "dotdoh-client: the DoT-forwarded query is padded (RFC 8467)" {
  armed_tuple DoT
  run bash -c "dig +short +tries=1 +time=5 @${tuple_ip} -p ${tuple_port} a.ftl"
  assert_output --partial "192.168.1.1"
  run assert_padded dot
  assert_success
}

@test "dotdoh-client: the DoH-forwarded query is padded (RFC 8467)" {
  armed_tuple DoH
  run bash -c "dig +short +tries=1 +time=5 @${tuple_ip} -p ${tuple_port} a.ftl"
  assert_output --partial "192.168.1.1"
  run assert_padded doh
  assert_success
}

@test "dotdoh-client: the DoH exchange uses HTTP/1.1" {
  run bash -c "dig +short +tries=1 +time=5 @127.47.11.2 -p 5302 a.ftl"
  assert_output --partial "192.168.1.1"
  # The shim records the request-line HTTP version it received from FTL's DoH
  # client. DoH-over-HTTP/2 and DoH3/DoQ are out of scope for this client.
  run bash -c "grep -F 'doh-proto HTTP/1.1' \"$SHIM_PAD_LOG\""
  assert_success
}

@test "dotdoh-client: many concurrent queries over the DoT proxy all resolve" {
  run run_concurrent DoT 25
  assert_success
  assert_output --partial "25/25 resolved"
}

@test "dotdoh-client: many concurrent queries over the DoH proxy all resolve" {
  run run_concurrent DoH 25
  assert_success
  assert_output --partial "25/25 resolved"
}

@test "dotdoh-client: debug.dotdoh emits a per-upstream statistics summary" {
  set_debug_dotdoh true
  # Generate some traffic so the counters are non-zero.
  armed_tuple DoT
  for i in $(seq 1 10); do
    dig +short +tries=1 +time=5 @"${tuple_ip}" -p "${tuple_port}" a.ftl >/dev/null 2>&1
  done
  # The summary is emitted periodically (~10 s) by whichever worker is idle.
  # Wait for one that reflects our queries to appear in the log.
  local found=""
  for _ in $(seq 1 20); do
    if grep -qE "dotdoh\[pi.hole\]:.*queries=[1-9]" /var/log/pihole/FTL.log; then
      found=1
      break
    fi
    sleep 1
  done
  set_debug_dotdoh false
  [ -n "$found" ]
}
