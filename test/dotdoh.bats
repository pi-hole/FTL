#!/usr/bin/env bats
# Encrypted-upstream (DoT/DoH) end-to-end tests.
#
# Prerequisites, provided by test/run.sh:
#   - pdns_recursor serving the .ftl test zone on 127.0.0.1:5555
#   - test/dotdoh_shim.py running, terminating TLS with test/test.pem (CN/SAN
#     "pi.hole", signed by test/test_ca.crt):
#       DoT   on :8853, DoH on :8443 (HTTP/2 via ALPN, else HTTP/1.1),
#       DoH1  on :8445 (HTTP/1.1 only), and DoH3 on :8444 (HTTP/3, needs aioquic)
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

# PATCH a dns config object without waiting for the restart it may trigger, for
# callers that issue several changes and wait for the collected restart once.
api_patch_dns_async() {  # $1 = JSON object for "dns"
  curl -s -o /dev/null --max-time 10 -X PATCH "${FTL_URL}/api/config" \
       -H "Content-Type: application/json" \
       -d "{\"config\":{\"dns\":$1}}" || true
}

# PATCH a misc config object. Nothing under misc used here is RESTART_FTL, so
# this takes effect live and needs no wait.
api_patch_misc() {  # $1 = JSON object for "misc"
  curl -s -o /dev/null --max-time 10 -X PATCH "${FTL_URL}/api/config" \
       -H "Content-Type: application/json" \
       -d "{\"config\":{\"misc\":$1}}" || true
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
# 5300+N is only a getrandom-failure fallback. The last four "armed on" lines are
# this run's four upstreams (DoT, DoH/h2, DoH/h1.1, DoH3).
proxy_tuple() {  # $1 = 1-based slot -> "IP#PORT"
  grep -oE "armed on 127\.[0-9.]+#[0-9]+" /var/log/pihole/FTL.log |
    tail -n 4 | sed -n "${1}p" | grep -oE "127\.[0-9.]+#[0-9]+"
}

proxy_at() {  # $1 = 1-based slot -> "@IP -p PORT"
  local t
  t=$(proxy_tuple "$1")
  echo "@${t%#*} -p ${t#*#}"
}

# Number of TCP connections the proxy serves at once: its worker count (from the
# log) minus the quarter reserved for UDP
proxy_tcp_cap() {
  local workers
  workers=$(grep -oE "armed, [0-9]+ worker" /var/log/pihole/FTL.log | tail -n 1 | grep -oE "[0-9]+")
  echo $(( workers - (workers / 4 > 0 ? workers / 4 : 1) ))
}

# Wait up to 8 s until no TCP connection to the first two proxy listeners is
# established (an idle kept-open one is closed after 5 s), read from /proc/net/tcp
# as the image has neither ss nor netstat
wait_proxy_tcp_idle() {
  local p1 p2 n i
  p1=$(printf "%04X" "$(proxy_tuple 1 | cut -d'#' -f2)")
  p2=$(printf "%04X" "$(proxy_tuple 2 | cut -d'#' -f2)")
  for i in $(seq 1 80); do
    n=$(awk -v a=":$p1" -v b=":$p2" '$4 == "01" && (substr($2, 9) == a || substr($2, 9) == b)' /proc/net/tcp | wc -l)
    [ "$n" -eq 0 ] && return 0
    sleep 0.1
  done
  echo "$n TCP connections to the proxy still established" >&2
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
  # The h3:// upstream is armed last, so its (unique) armed marker means FTL
  # accepted every upstream. This only arms the config; the shim's h3 listener is
  # UDP and not covered by ensure_shim's TCP checks, so the DoH3 test itself waits
  # on SHIM_H3_READY before querying.
  api_patch_dns "{\"upstreamCA\":\"$(pwd)/test/test_ca.crt\",\"upstreams\":[\"tls://pi.hole@127.0.0.1#8853\",\"https://pi.hole@127.0.0.1#8443/dns-query\",\"https://pi.hole@127.0.0.1#8445/dns-query\",\"h3://pi.hole@127.0.0.1#8444/dns-query\"]}" \
                "dotdoh: DoH3 upstream pi.hole armed"
}

teardown_file() {
  # Restore the plaintext upstream. It arms no proxy, so wait instead for the
  # regex recompile that every (re)start logs to know FTL is back up.
  #
  # Both keys are RESTART_FTL settings and we write them in two separate
  # requests on purpose: with misc.restart_delay armed, FTL has to collect them
  # into a single restart rather than racing two against each other, which is
  # what setup_file avoids by batching them into one request.
  api_patch_misc "{\"restart_delay\":2}"

  local before restarts
  before=$(stat -c%s /var/log/pihole/FTL.log)
  api_patch_dns_async "{\"upstreamCA\":\"\"}"
  api_patch_dns_async "{\"upstreams\":[\"127.0.0.1#5555\"]}"
  ./pihole-FTL wait-for "deny regex for" /var/log/pihole/FTL.log 30 "$before"

  restarts=$(tail -c "+$((before + 1))" /var/log/pihole/FTL.log | grep -c "Restarting FTL" || true)
  [ "$restarts" -eq 1 ] || \
    echo "expected 1 restart for the two changes, got $restarts" >&2
  [ "$restarts" -eq 1 ]

  api_patch_misc "{\"restart_delay\":1}"
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
  local ready=""
  for _ in $(seq 1 50); do
    [ -f "$SHIM_H3_READY" ] && { ready=1; break; }
    sleep 0.2
  done
  if [ -z "$ready" ]; then
    echo "DoH3 shim HTTP/3 listener never became ready. Shim log:" >&2
    cat "$SHIM_LOG" >&2 2>/dev/null || echo "(no shim log at $SHIM_LOG)" >&2
    false
  fi
  run bash -c "dig +short +tries=1 +time=8 $(proxy_at 4) a.ftl"
  assert_output --partial "192.168.1.1"
  run bash -c "grep -F 'doh3-proto HTTP/3' \"$SHIM_PAD_LOG\""
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

# Client A's dnsmasq TCP worker keeps its connection to the proxy open between
# queries. When the proxy closes that connection after its 5 s idle timeout, A's
# worker must see EOF and reconnect at once, even though client B's worker was
# forked while that connection was open. Otherwise A's next query stalls for
# dnsmasq's 10 s TCP timeout.
@test "dotdoh-client: a TCP worker sees the proxy's idle close despite later forks" {
  run python3 -c '
import random, socket, struct, time
tag = "%08x" % random.getrandbits(32)
def ask(s, name):
    m = struct.pack(">HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0)
    m += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    m += struct.pack(">HH", 1, 1)
    s.sendall(struct.pack(">H", len(m)) + m)
    t = time.monotonic()
    n = struct.unpack(">H", s.recv(2))[0]
    while n > 0:
        n -= len(s.recv(n))
    return time.monotonic() - t
a = socket.create_connection(("127.0.0.1", 53), timeout=20)
ask(a, "a1-%s.dnssec" % tag)
b = socket.create_connection(("127.0.0.1", 53), timeout=20)
ask(b, "b-%s.dnssec" % tag)
time.sleep(6)
print("%.1f" % ask(a, "a2-%s.dnssec" % tag))
'
  assert_success
  echo "second query on A took ${output} s"
  [[ "${output%%.*}" -lt 8 ]]
}

@test "dotdoh-client: kept-open TCP clients beyond the proxy's TCP slots are all answered" {
  # Every TCP client gets its own dnsmasq child, which keeps its connection to
  # the proxy open between queries. Open more such clients than the proxy serves
  # at once, so the last ones have to wait for a slot instead of being refused.
  # .ftl is pinned to the plaintext recursor, so use names outside it to go
  # through the proxy. The cap is at most 48 (64 workers), so n stays clear of
  # dnsmasq's limit of 60 TCP children.
  local n
  n=$(( $(proxy_tcp_cap) + 4 ))
  if [ "$n" -gt 56 ]; then
    echo "$n TCP clients would come too close to dnsmasq's 60 TCP children" >&2
    return 1
  fi
  run python3 test/dotdoh_query.py tcpkeep 127.0.0.1 53 "$n" "tk${RANDOM}.dotdoh-test"
  assert_output --partial "${n}/${n} answered"
}

@test "dotdoh-client: idle proxy connections give their TCP slot up to a waiter on another upstream" {
  # Fill every TCP slot with idle connections to the DoT listener, each answered
  # once, then query the DoH listener. One idle connection must give its slot up
  # to the waiter, at once instead of after its 5 s idle timeout.
  wait_proxy_tcp_idle
  run python3 test/dotdoh_query.py tcpcross "$(proxy_tuple 1)" "$(proxy_tuple 2)" "$(proxy_tcp_cap)" a.ftl
  assert_output --regexp "^waiter rcode 0 after (0|1|2)\.[0-9]+ s, 1 idle closed$"
}

@test "dotdoh-client: idle proxy connections keep their TCP slot while one is free" {
  # Same with one slot left free: the waiter takes it and no idle connection closes
  wait_proxy_tcp_idle
  run python3 test/dotdoh_query.py tcpcross "$(proxy_tuple 1)" "$(proxy_tuple 2)" "$(( $(proxy_tcp_cap) - 1 ))" a.ftl
  assert_output --regexp "^waiter rcode 0 after 0\.[0-9]+ s, 0 idle closed$"
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
