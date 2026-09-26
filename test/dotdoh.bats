#!/usr/bin/env bats
# Encrypted-upstream (DoT/DoH) end-to-end tests.
#
# Prerequisites, provided by test/run.sh:
#   - pdns_recursor serving the .ftl test zone on 127.0.0.1:5555
#   - test/dotdoh_shim.py running, terminating TLS with test/test.pem (CN/SAN
#     "pi.hole", signed by test/test_ca.crt):
#       DoT   on :8853, DoH on :8443 (HTTP/2 via ALPN, else HTTP/1.1),
#       DoH1  on :8445 (HTTP/1.1 only), DoH3 on :8444 (HTTP/3, needs aioquic) and
#       DoQ   on :8854 (RFC 9250, needs aioquic)
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

# The shim touches this file once its HTTP/3 (QUIC) listener is bound; the DoH3
# test waits on it. Default so a standalone bats run works; run.sh exports it.
export SHIM_H3_READY="${SHIM_H3_READY:-/tmp/dotdoh_h3_ready}"

# Same for the shim's DoQ (QUIC) listener, which the DoQ test waits on.
export SHIM_DOQ_READY="${SHIM_DOQ_READY:-/tmp/dotdoh_doq_ready}"

# The shim's own stdout/stderr, so the DoH3 test can show why the HTTP/3 listener
# did not come up (aioquic missing, or an aioquic error). Default for a standalone
# bats run; run.sh exports the same path.
export SHIM_LOG="${SHIM_LOG:-/tmp/dotdoh_shim.log}"

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
    python3 test/dotdoh_shim.py >"$SHIM_LOG" 2>&1 &
  fi
  # pgrep only proves the process exists, not that it is accepting yet. Wait
  # until both TLS ports actually accept a connection so setup_file cannot race
  # a still-starting shim, which otherwise made the E2E test flaky. Fail loudly
  # if a port never comes up instead of letting it surface as a later, harder
  # to diagnose DNS failure.
  local port i ready
  for port in 8853 8443 8445; do
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
  # The HTTP/3 (QUIC) listener readiness is checked by the DoH3 test itself, not
  # here: gating the whole setup on it would drop the DoT/DoH/DoH2 tests (and
  # their config writes) too. See the DoH3 test for the loud, no-skip requirement.
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

# dig target ("@IP -p PORT") of the Nth (1-based, config order) armed upstream,
# read from FTL's log. The proxy binds a randomised loopback tuple per process
# (127.0.0.0/8 + random port), so the port cannot be assumed - the deterministic
# 5300+N is only a getrandom-failure fallback. The last seven "armed on" lines are
# this run's seven upstreams (DoT, DoH/h2, DoH/h1.1, DoH3, DoQ, DoQ via quic://,
# DoQ with a mismatched certificate name).
proxy_at() {  # $1 = 1-based slot -> "@IP -p PORT"
  local t
  t=$(grep -oE "armed on 127\.[0-9.]+#[0-9]+" /var/log/pihole/FTL.log |
      tail -n 7 | sed -n "${1}p" | grep -oE "127\.[0-9.]+#[0-9]+")
  echo "@${t%#*} -p ${t#*#}"
}

# Block until the shim's QUIC listener marker $1 appears, else fail loudly with
# the shim log. QUIC listeners are UDP, which ensure_shim's TCP probe cannot see.
wait_for_quic_shim() {  # $1 = readiness marker path, $2 = human name
  local _
  for _ in $(seq 1 50); do
    [ -f "$1" ] && return 0
    sleep 0.2
  done
  echo "$2 shim listener never became ready. Shim log:" >&2
  cat "$SHIM_LOG" >&2 2>/dev/null || echo "(no shim log at $SHIM_LOG)" >&2
  return 1
}

# Fire $2 concurrent dig queries at the Nth upstream's proxy listener and succeed
# only if every one resolved. This exercises the worker pool and per-upstream
# connection pool serving many in-flight exchanges at once without racing.
run_concurrent() {  # $1 = 1-based slot (1=DoT, 2=DoH), $2 = number of queries
  local idx="$1" n="$2" tmp i ok=0 at
  at=$(proxy_at "$idx")
  tmp="$(mktemp -d)"
  for i in $(seq 1 "$n"); do
    ( dig +short +tries=1 +time=8 $at a.ftl > "${tmp}/${i}" 2>&1 ) &
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
  # Arm four encrypted upstreams in a fixed order; each takes the next proxy slot,
  # so proxy_at reads their randomised loopback tuples back in this order:
  #   1  DoT           (tls://,   shim :8853)
  #   2  DoH over h2   (https://, shim :8443, ALPN "h2")
  #   3  DoH over h1.1 (https://, shim :8445, ALPN "http/1.1")
  #   4  DoH3 over h3  (h3://,    shim :8444, QUIC)
  #   5  DoQ           (doq://,   shim :8854, QUIC)
  #   6  DoQ via quic:// (the AdGuard/dnsproxy spelling of the same scheme)
  #   7  DoQ to a name the shim certificate does not carry (must fail closed)
  # Slot 7 is armed last and is the only upstream whose verify name is
  # "wrong.pi.hole", so its (unique) armed marker means FTL accepted every
  # upstream. This only arms the config; the shim's QUIC listeners are UDP and not
  # covered by ensure_shim's TCP checks, so the DoH3 and DoQ tests wait on their
  # readiness markers before querying.
  api_patch_dns "{\"upstreamCA\":\"$(pwd)/test/test_ca.crt\",\"upstreams\":[\"tls://pi.hole@127.0.0.1#8853\",\"https://pi.hole@127.0.0.1#8443/dns-query\",\"https://pi.hole@127.0.0.1#8445/dns-query\",\"h3://pi.hole@127.0.0.1#8444/dns-query\",\"doq://pi.hole@127.0.0.1#8854\",\"quic://pi.hole@127.0.0.1#8854\",\"doq://wrong.pi.hole@127.0.0.1#8854\"]}" \
                "dotdoh: DoQ upstream wrong.pi.hole armed"
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
  run bash -c "dig +short +tries=1 +time=5 $(proxy_at 1) a.ftl"
  assert_output --partial "192.168.1.1"
}

@test "dotdoh-client: a query resolves through the DoH proxy path" {
  run bash -c "dig +short +tries=1 +time=5 $(proxy_at 2) a.ftl"
  assert_output --partial "192.168.1.1"
}

@test "dotdoh-client: the DoT-forwarded query is padded (RFC 8467)" {
  run bash -c "dig +short +tries=1 +time=5 $(proxy_at 1) a.ftl"
  assert_output --partial "192.168.1.1"
  run assert_padded dot
  assert_success
}

@test "dotdoh-client: the DoH-forwarded query is padded (RFC 8467)" {
  run bash -c "dig +short +tries=1 +time=5 $(proxy_at 2) a.ftl"
  assert_output --partial "192.168.1.1"
  run assert_padded doh
  assert_success
}

@test "dotdoh-client: the DoH exchange negotiates HTTP/2 (ALPN h2)" {
  run bash -c "dig +short +tries=1 +time=5 $(proxy_at 2) a.ftl"
  assert_output --partial "192.168.1.1"
  # The :8443 shim offers ALPN "h2,http/1.1"; FTL's DoH client offers the same,
  # so the exchange upgrades to HTTP/2 and the shim records the negotiated
  # protocol. This is the auto-negotiation path for existing https:// upstreams.
  run bash -c "grep -F 'doh-proto HTTP/2' \"$SHIM_PAD_LOG\""
  assert_success
}

@test "dotdoh-client: the DoH exchange falls back to HTTP/1.1" {
  run bash -c "dig +short +tries=1 +time=5 $(proxy_at 3) a.ftl"
  assert_output --partial "192.168.1.1"
  # The :8445 shim offers only ALPN "http/1.1", so FTL's DoH client - which
  # offers "h2,http/1.1" - falls back to the HTTP/1.1 framing. The shim records
  # the request-line HTTP version it received.
  run bash -c "grep -F 'doh-proto HTTP/1.1' \"$SHIM_PAD_LOG\""
  assert_success
}

@test "dotdoh-client: a query resolves over the DoH3 (HTTP/3) proxy path" {
  # HTTP/3 is required, never skipped: the shim publishes SHIM_H3_READY once its
  # aioquic QUIC listener is bound (a UDP listener a TCP probe cannot observe).
  # Wait for it and fail loudly if it never appears (e.g. aioquic missing from the
  # image), so a missing dependency surfaces here instead of being silently
  # skipped - without holding the DoT/DoH/DoH2 tests hostage in setup_file.
  wait_for_quic_shim "$SHIM_H3_READY" "DoH3 HTTP/3" || false
  run bash -c "dig +short +tries=1 +time=8 $(proxy_at 4) a.ftl"
  assert_output --partial "192.168.1.1"
  run bash -c "grep -F 'doh3-proto HTTP/3' \"$SHIM_PAD_LOG\""
  assert_success
}

@test "dotdoh-client: a query resolves over the DoQ (RFC 9250) proxy path" {
  # Like DoH3 this is required, never skipped: a missing aioquic must surface
  # here rather than silently drop DoQ coverage.
  wait_for_quic_shim "$SHIM_DOQ_READY" "DoQ" || false
  run bash -c "dig +short +tries=1 +time=8 $(proxy_at 5) a.ftl"
  assert_output --partial "192.168.1.1"
  run bash -c "grep -F 'doq-proto DoQ' \"$SHIM_PAD_LOG\""
  assert_success
}

@test "dotdoh-client: the DoQ query carries Message ID 0 (RFC 9250)" {
  # RFC 9250 Sec. 4.2.1: the DNS Message ID MUST be 0 on a QUIC stream. The shim
  # records the ID it received; every DoQ query must show 0. That the answer is
  # still accepted (the test above) proves FTL maps dnsmasq's ID back afterwards.
  wait_for_quic_shim "$SHIM_DOQ_READY" "DoQ" || false
  run bash -c "dig +short +tries=1 +time=8 $(proxy_at 5) a.ftl"
  assert_output --partial "192.168.1.1"
  run bash -c "grep -c '^doq-msgid 0$' \"$SHIM_PAD_LOG\""
  assert_success
  run bash -c "grep -v '^doq-msgid 0$' \"$SHIM_PAD_LOG\" | grep '^doq-msgid ' || true"
  assert_output ""
}

@test "dotdoh-client: the quic:// alias resolves over the same DoQ transport" {
  # "quic://" is what AdGuard and dnsproxy configs use, so a copy-pasted resolver
  # address has to work. It must arm and resolve exactly like doq://.
  wait_for_quic_shim "$SHIM_DOQ_READY" "DoQ" || false
  run bash -c "dig +short +tries=1 +time=8 $(proxy_at 6) a.ftl"
  assert_output --partial "192.168.1.1"
}

@test "dotdoh-client: a DoQ upstream with a mismatched certificate name fails closed" {
  # The single most important property of an encrypted upstream: the QUIC handshake
  # verifies the certificate against the configured name, and a mismatch drops the
  # query rather than falling back to an unverified - or plaintext - answer. Slot 7
  # points at the same shim as slot 5 but verifies "wrong.pi.hole", which the shim
  # certificate (CN/SAN "pi.hole") does not carry, so the handshake must abort.
  wait_for_quic_shim "$SHIM_DOQ_READY" "DoQ" || false
  run bash -c "dig +short +tries=1 +time=5 $(proxy_at 7) a.ftl"
  refute_output --partial "192.168.1.1"
}

@test "dotdoh-client: the DoQ-forwarded query is padded (RFC 8467)" {
  wait_for_quic_shim "$SHIM_DOQ_READY" "DoQ" || false
  run bash -c "dig +short +tries=1 +time=8 $(proxy_at 5) a.ftl"
  assert_output --partial "192.168.1.1"
  run assert_padded doq
  assert_success
}

@test "dotdoh-client: many concurrent queries over the DoT proxy all resolve" {
  run run_concurrent 1 25
  assert_success
  assert_output --partial "25/25 resolved"
}

@test "dotdoh-client: many concurrent queries over the DoH proxy all resolve" {
  run run_concurrent 2 25
  assert_success
  assert_output --partial "25/25 resolved"
}

@test "dotdoh-client: debug.dotdoh emits a per-upstream statistics summary" {
  set_debug_dotdoh true
  # Generate some traffic so the counters are non-zero. Never abort the test on a
  # dig hiccup: the summary check below is the real assertion, and set_debug false
  # must still run so debug.dotdoh is restored (and its write counted).
  for i in $(seq 1 10); do
    dig +short +tries=1 +time=5 $(proxy_at 1) a.ftl >/dev/null 2>&1 || true
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
