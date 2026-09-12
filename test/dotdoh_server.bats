#!/usr/bin/env bats
# Inbound (server-side) DoT/DoH end-to-end tests.
#
# These exercise FTL terminating encrypted DNS from downstream clients:
#   - DoH: an HTTPS POST of application/dns-message to /dns-query on the pi.hole
#     webserver (port 443, TLS by the repo test cert, CN/SAN "pi.hole").
#   - DoT: raw TLS + 2-byte length-prefixed DNS on port 853.
#   - DoQ: QUIC + the same 2-byte length-prefixed DNS on UDP port 853 (RFC 9250),
#     one query per bidirectional stream.
#
# The point of the inbound server is that the query is attributed to the real
# downstream client, carried into dnsmasq via a private EDNS option that is
# trusted only when the query source is loopback. To prove that end to end we
# source both clients from 127.0.0.2 (the whole 127.0.0.0/8 is loopback) and
# then assert via the API that the query was attributed to 127.0.0.2 - not to
# 127.0.0.1, which is what a naive "attribute to the connection source" would
# record for the loopback handoff.

bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

FTL_URL="http://127.0.0.1"
CLIENT="127.0.0.2"
DOMAIN="a.ftl"
EXPECT_IP="192.168.1.1"

# True if this environment has an IPv6 loopback (some CI containers do not). Used
# to skip the IPv6 case rather than fail it where IPv6 is simply unavailable.
ipv6_loopback_available() {
  python3 -c 'import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
try:
    s.bind(("::1", 0))
except OSError:
    sys.exit(1)' 2>/dev/null
}

setup_file() {
  # An earlier suite (test_suite.bats) leaves dns.reply.host.force4/force6 = true,
  # pinning pi.hole/<hostname> to a fixed IP. The pi.hole tests below exercise the
  # DEFAULT (force off), where the answer is interface-derived and an encrypted
  # client's connected address applies - so restore the default for this file.
  local before
  before=$(stat -c%s /var/log/pihole/FTL.log 2>/dev/null || echo 0)
  curl -s -X PATCH http://127.0.0.1/api/config \
    -d '{"config":{"dns":{"reply":{"host":{"force4":false,"IPv4":"","force6":false,"IPv6":""}}}}}' >/dev/null 2>&1
  ./pihole-FTL wait-for 'INFO: Config file written to /etc/pihole/pihole.toml' \
    /var/log/pihole/FTL.log 5 "$before" >/dev/null 2>&1 || true
}

@test "dotdoh-server: the inbound DoT listener came up on port 853" {
  run bash -c 'grep -F "dotdoh: DoT server listening on port 853" /var/log/pihole/FTL.log'
  assert_success
}

@test "dotdoh-server: a DoH query resolves and returns the expected answer" {
  local ca q a
  ca="$(pwd)/test/test_ca.crt"
  q="${BATS_FILE_TMPDIR}/doh_q.bin"
  a="${BATS_FILE_TMPDIR}/doh_a.bin"
  python3 test/dotdoh_query.py emit "$DOMAIN" "$q"
  # --interface binds the source address, so FTL sees the query coming from
  # $CLIENT. --resolve maps the cert name to loopback; --cacert trusts our test CA.
  run curl -s --cacert "$ca" --resolve "pi.hole:443:127.0.0.1" \
           --interface "$CLIENT" \
           -H 'content-type: application/dns-message' \
           --data-binary "@$q" \
           "https://pi.hole/dns-query" --output "$a"
  assert_success
  run python3 test/dotdoh_query.py check "$a" "$EXPECT_IP"
  assert_output "OK"
}

@test "dotdoh-server: a DoH GET query resolves and returns the expected answer" {
  local ca dns a
  ca="$(pwd)/test/test_ca.crt"
  a="${BATS_FILE_TMPDIR}/doh_get_a.bin"
  # RFC 8484 GET: the query is base64url in the ?dns= parameter, no body.
  dns=$(python3 test/dotdoh_query.py emiturl "$DOMAIN")
  run curl -s --cacert "$ca" --resolve "pi.hole:443:127.0.0.1" \
           --interface "$CLIENT" \
           "https://pi.hole/dns-query?dns=${dns}" --output "$a"
  assert_success
  run python3 test/dotdoh_query.py check "$a" "$EXPECT_IP"
  assert_output "OK"
}

@test "dotdoh-server: a DoH answer carries a Cache-Control max-age (RFC 8484)" {
  local ca q; ca="$(pwd)/test/test_ca.crt"; q="${BATS_FILE_TMPDIR}/cc_q.bin"
  python3 test/dotdoh_query.py emit "$DOMAIN" "$q"
  run curl -s -D - -o /dev/null --cacert "$ca" --resolve "pi.hole:443:127.0.0.1" \
           --interface "$CLIENT" -H 'content-type: application/dns-message' \
           --data-binary "@$q" "https://pi.hole/dns-query"
  # curl negotiates HTTP/2 with the terminator, which lowercases header names, so
  # match case-insensitively.
  run bash -c 'grep -iqF "cache-control: private, max-age=" <<< "$1"' _ "$output"
  assert_success
}

@test "dotdoh-server: a DoH POST over HTTP/2 resolves and is attributed to the client" {
  # The front terminator serves HTTP/2 (ALPN h2) and reverse-proxies to the DoH
  # handler over the loopback backend, conveying the real client and the HTTPS
  # marking via PROXY v2, so DoH works over h2 with no DoH-specific h2 code.
  local ca q a ver i out
  ca="$(pwd)/test/test_ca.crt"
  q="${BATS_FILE_TMPDIR}/h2_q.bin"
  a="${BATS_FILE_TMPDIR}/h2_a.bin"
  python3 test/dotdoh_query.py emit "$DOMAIN" "$q"
  ver=$(curl -s --http2 --cacert "$ca" --resolve "pi.hole:443:127.0.0.1" \
             --interface "$CLIENT" -H 'content-type: application/dns-message' \
             --data-binary "@$q" -o "$a" -w '%{http_version}' \
             "https://pi.hole/dns-query")
  # Confirm it really was HTTP/2, not a silent fallback to 1.1.
  [[ "$ver" == "2" ]] || { echo "http_version=$ver, expected 2"; false; }
  run python3 test/dotdoh_query.py check "$a" "$EXPECT_IP"
  assert_output "OK"
  # The real client (not the loopback backend) must be recorded, proving the
  # terminator forwarded the client address over h2.
  for i in $(seq 1 10); do
    out=$(curl -s "${FTL_URL}/api/queries?client_ip=${CLIENT}")
    grep -qF "$DOMAIN" <<< "$out" && break
    sleep 0.3
  done
  run bash -c 'grep -F "$1" <<< "$2"' _ "$DOMAIN" "$out"
  assert_success
}

@test "dotdoh-server: a DoH POST over HTTP/3 resolves (RFC 8484 over h3)" {
  # The front terminator serves HTTP/3 (ALPN h3, OpenSSL QUIC) ahead of CivetWeb, so
  # DoH works over h3 with no DoH-specific code. curl in CI is built without HTTP/3,
  # so an aioquic client drives the QUIC listener directly; skip if aioquic is absent.
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  run python3 test/dotdoh_query.py doh3 127.0.0.1 443 "$DOMAIN" "$EXPECT_IP"
  assert_output "OK"
}

@test "dotdoh-server: the DoT listener presents the expected certificate" {
  # The DoH curl cases validate the full chain against the test CA; over DoT the
  # keyUsage-less test CA is rejected by OpenSSL >= 4.0, so we assert the listener
  # presents exactly the pi.hole leaf certificate instead of the wrong/self-signed one.
  local crt; crt="$(pwd)/test/test.crt"
  run python3 test/dotdoh_query.py dotcert 127.0.0.1 853 "$CLIENT" "$crt"
  assert_output "OK"
}

@test "dotdoh-server: the inbound DoQ listener came up on UDP port 853" {
  run bash -c 'grep -F "dotdoh: DoQ server listening on UDP port 853" /var/log/pihole/FTL.log'
  assert_success
}

@test "dotdoh-server: a DoQ query resolves and returns the expected answer" {
  # curl cannot speak DoQ (it is not HTTP), so an aioquic client drives FTL's QUIC
  # listener directly; skip cleanly where aioquic is not installed.
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  run python3 test/dotdoh_query.py doq 127.0.0.1 853 "$DOMAIN" "$CLIENT" "$EXPECT_IP"
  assert_output "OK"
}

@test "dotdoh-server: a DoQ query is attributed to the real downstream client" {
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  # 127.0.0.4 is used by no other test, so a.ftl showing up under it can only
  # have come from this DoQ query. If the private EDNS client option survived the
  # loopback handoff, the API lists it there - not under 127.0.0.1, which is what
  # a naive "attribute to the handoff source" would record.
  local src="127.0.0.4" i out
  run python3 test/dotdoh_query.py doq 127.0.0.1 853 "$DOMAIN" "$src" "$EXPECT_IP"
  assert_output "OK"
  for i in $(seq 1 10); do
    out=$(curl -s "${FTL_URL}/api/queries?client_ip=${src}")
    grep -qF "$DOMAIN" <<< "$out" && break
    sleep 0.3
  done
  run bash -c 'grep -F "$1" <<< "$2"' _ "$DOMAIN" "$out"
  assert_success
}

@test "dotdoh-server: several DoQ queries multiplex over one QUIC connection" {
  # RFC 9250 Sec. 4.2: each query gets its own bidirectional stream on the same
  # connection, so this exercises concurrent per-stream resolves in the reactor.
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  run python3 test/dotdoh_query.py doqmulti 127.0.0.1 853 "$DOMAIN" "$CLIENT" "$EXPECT_IP" 5
  assert_output "OK"
}

@test "dotdoh-server: the DoQ listener rejects a client not offering the doq ALPN" {
  # QUIC mandates ALPN and RFC 9250 defines exactly one token for DoQ, so a client
  # offering "h3" instead must not be served.
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  run python3 test/dotdoh_query.py doqalpn 127.0.0.1 853 h3 "$CLIENT"
  assert_output "OK"
}

@test "dotdoh-server: the DoQ listener survives a malformed (non-DNS) query" {
  # Send garbage framed as a DoQ message, then confirm the listener still serves a
  # normal query - i.e. bad input did not crash or wedge the reactor.
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  run python3 test/dotdoh_query.py doqgarbage 127.0.0.1 853 "$CLIENT"
  assert_output "OK"
  run python3 test/dotdoh_query.py doq 127.0.0.1 853 "$DOMAIN" "$CLIENT" "$EXPECT_IP"
  assert_output "OK"
}

@test "dotdoh-server: a DoQ query over IPv6 resolves" {
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  ipv6_loopback_available || skip "IPv6 loopback not available in this environment"
  # A name of its own, not $DOMAIN: the DoT-over-IPv6 test below proves attribution
  # by finding a.ftl under ::1, and querying a.ftl from ::1 here would satisfy that
  # assertion on this test's evidence instead of its own.
  run python3 test/dotdoh_query.py doq ::1 853 allowed.ftl ::1 192.168.1.4
  assert_output "OK"
}

@test "dotdoh-server: a DoT query resolves and returns the expected answer" {
  local ca
  ca="$(pwd)/test/test_ca.crt"
  run python3 test/dotdoh_query.py dot 127.0.0.1 853 "$DOMAIN" "$CLIENT" "$ca" "$EXPECT_IP"
  assert_output "OK"
}

@test "dotdoh-server: a DoT query over IPv6 resolves and is attributed to the v6 client" {
  ipv6_loopback_available || skip "IPv6 loopback not available in this environment"
  local ca out i
  ca="$(pwd)/test/test_ca.crt"
  # Dial the DoT listener over IPv6 (::1). ::1 is the only IPv6 loopback address,
  # so it is both the client source and the target here.
  run python3 test/dotdoh_query.py dot ::1 853 "$DOMAIN" ::1 "$ca" "$EXPECT_IP"
  assert_output "OK"
  # Attribution must record the v6 client (::1). A failed private-EDNS handoff
  # would instead record 127.0.0.1 - the IPv4 loopback source of the internal
  # DNS connection - so seeing a.ftl under ::1 proves the v6 client survived.
  for i in $(seq 1 10); do
    out=$(curl -s "${FTL_URL}/api/queries?client_ip=::1")
    if grep -qF "$DOMAIN" <<< "$out"; then
      break
    fi
    sleep 0.3
  done
  run bash -c 'grep -F "$1" <<< "$2"' _ "$DOMAIN" "$out"
  assert_success
}

@test "dotdoh-server: DoH over plaintext HTTP is refused (426)" {
  # DoH is DNS-over-HTTPS; serving it on the cleartext port would leak the
  # client's "encrypted" queries. The handler rejects a non-TLS request.
  local q; q="${BATS_FILE_TMPDIR}/err_q.bin"
  python3 test/dotdoh_query.py emit "$DOMAIN" "$q"
  run curl -s -o /dev/null -w '%{http_code}' --interface "$CLIENT" \
           -H 'content-type: application/dns-message' --data-binary "@$q" \
           "http://127.0.0.1/dns-query"
  assert_output "426"
}

@test "dotdoh-server: DoH rejects a non-POST/GET method (405)" {
  local ca; ca="$(pwd)/test/test_ca.crt"
  run curl -s -o /dev/null -w '%{http_code}' --cacert "$ca" \
           --resolve "pi.hole:443:127.0.0.1" --interface "$CLIENT" \
           -X PUT "https://pi.hole/dns-query"
  assert_output "405"
}

@test "dotdoh-server: DoH POST rejects a wrong Content-Type (415)" {
  local ca q; ca="$(pwd)/test/test_ca.crt"; q="${BATS_FILE_TMPDIR}/err_q.bin"
  python3 test/dotdoh_query.py emit "$DOMAIN" "$q"
  run curl -s -o /dev/null -w '%{http_code}' --cacert "$ca" \
           --resolve "pi.hole:443:127.0.0.1" --interface "$CLIENT" \
           -H 'content-type: text/plain' --data-binary "@$q" \
           "https://pi.hole/dns-query"
  assert_output "415"
}

@test "dotdoh-server: DoH GET rejects a malformed dns parameter (400)" {
  local ca; ca="$(pwd)/test/test_ca.crt"
  # '.' is not a base64url character, so decoding fails.
  run curl -s -o /dev/null -w '%{http_code}' --cacert "$ca" \
           --resolve "pi.hole:443:127.0.0.1" --interface "$CLIENT" \
           "https://pi.hole/dns-query?dns=...."
  assert_output "400"
}

@test "dotdoh-server: a fresh DoT connection per query keeps being answered" {
  # Regression test for the loopback-socket pool. dnsmasq forks a child per TCP
  # connection, so before the pool a client that opened a DoT connection per
  # query forked one child per query; the child slots ran out after ~45 queries
  # and from then on FTL read queries and never answered them (measured: 83.7%
  # answered, and every unanswered query in the connection-per-query phase).
  # 100 iterations is a bit over twice that threshold, and costs ~5 s - almost
  # all of it the client's TLS handshakes, not FTL.
  local ca i
  ca="$(pwd)/test/test_ca.crt"
  for i in $(seq 1 100); do
    run python3 test/dotdoh_query.py dot 127.0.0.1 853 "$DOMAIN" "$CLIENT" "$ca" "$EXPECT_IP"
    if [ "$output" != "OK" ]; then
      echo "fresh-connection DoT query $i of 100 was not answered: $output" >&2
      false
    fi
  done
}

@test "dotdoh-server: a DoT connection is reused for multiple queries (keep-alive)" {
  # Real DoT clients (RFC 7858) send several queries over one connection.
  local ca
  ca="$(pwd)/test/test_ca.crt"
  run python3 test/dotdoh_query.py dotmulti 127.0.0.1 853 "$DOMAIN" "$CLIENT" "$ca" "$EXPECT_IP" 5
  assert_output "OK"
}

@test "dotdoh-server: the DoT listener survives a malformed (non-DNS) query" {
  # Send garbage framed as a DoT message, then confirm the listener still serves
  # a normal query - i.e. bad input did not crash or wedge the worker/listener.
  local ca
  ca="$(pwd)/test/test_ca.crt"
  run python3 test/dotdoh_query.py dotgarbage 127.0.0.1 853 "$CLIENT" "$ca"
  assert_output "OK"
  run python3 test/dotdoh_query.py dot 127.0.0.1 853 "$DOMAIN" "$CLIENT" "$ca" "$EXPECT_IP"
  assert_output "OK"
}

@test "dotdoh-server: DoH POST with an empty body is rejected (400)" {
  local ca
  ca="$(pwd)/test/test_ca.crt"
  run curl -s -o /dev/null -w '%{http_code}' --cacert "$ca" \
           --resolve "pi.hole:443:127.0.0.1" --interface "$CLIENT" \
           -H 'content-type: application/dns-message' --data-binary '' \
           "https://pi.hole/dns-query"
  assert_output "400"
}

@test "dotdoh-server: DoH GET without a dns parameter is rejected (400)" {
  local ca
  ca="$(pwd)/test/test_ca.crt"
  run curl -s -o /dev/null -w '%{http_code}' --cacert "$ca" \
           --resolve "pi.hole:443:127.0.0.1" --interface "$CLIENT" \
           "https://pi.hole/dns-query?foo=bar"
  assert_output "400"
}

@test "dotdoh-server: DoH HEAD is rejected (405)" {
  local ca
  ca="$(pwd)/test/test_ca.crt"
  run curl -s -o /dev/null -w '%{http_code}' --cacert "$ca" \
           --resolve "pi.hole:443:127.0.0.1" --interface "$CLIENT" \
           -I "https://pi.hole/dns-query"
  assert_output "405"
}

@test "dotdoh-server: inbound queries are attributed to the real downstream client" {
  # The DoH and DoT queries above were both sourced from $CLIENT. If the private
  # EDNS client option survives the loopback handoff, the API must list a.ftl for
  # that client. A short retry covers the tiny window before it is queryable.
  local i out
  for i in $(seq 1 10); do
    out=$(curl -s "${FTL_URL}/api/queries?client_ip=${CLIENT}")
    if echo "$out" | grep -q "$DOMAIN"; then
      break
    fi
    sleep 0.3
  done
  # Pass values as positional args so JSON contents cannot break the quoting.
  run bash -c 'grep -F "$1" <<< "$2"' _ "$DOMAIN" "$out"
  assert_success
  run bash -c 'grep -F "$1" <<< "$2"' _ "$CLIENT" "$out"
  assert_success
}

@test "dotdoh-server: a forged client-attribution EDNS option is rejected (HMAC gate)" {
  # A loopback query may carry the Pi-hole-private client option, but FTL trusts it
  # only when its per-run HMAC verifies. Forge it (claim 8.8.8.8, bogus MAC) sent
  # straight to the DNS port from $CLIENT: FTL must reject the forgery and attribute
  # the query to the real source ($CLIENT), never to the spoofed 8.8.8.8. Without
  # the HMAC check the query would instead be logged under 8.8.8.8.
  local d="forged-mac.ftl" i out
  run python3 test/dotdoh_query.py forge 127.0.0.1 53 "$d" "$CLIENT" 8.8.8.8
  assert_output "OK"
  # The real source must be recorded (short retry for the queryable window)...
  for i in $(seq 1 10); do
    out=$(curl -s "${FTL_URL}/api/queries?client_ip=${CLIENT}")
    if echo "$out" | grep -q "$d"; then break; fi
    sleep 0.3
  done
  run bash -c 'grep -F "$1" <<< "$2"' _ "$d" "$out"
  assert_success
  # ...and the spoofed client must NOT be, proving the HMAC gate held.
  out=$(curl -s "${FTL_URL}/api/queries?client_ip=8.8.8.8")
  run bash -c 'grep -F "$1" <<< "$2"' _ "$d" "$out"
  assert_failure
}

# The next two tests verify pi.hole/<hostname> over encrypted DNS answers with the
# address the client actually connected to (conveyed as a MAC-verified private
# EDNS option), not the loopback address of our internal forward. They connect to
# 127.0.0.3 - a DIFFERENT loopback address than the 127.0.0.1 forward - so the
# expected answer (127.0.0.3) can only come from the conveyed destination. Without
# the fix pi.hole would resolve to 127.0.0.1 here and both would fail.

@test "dotdoh-server: pi.hole over DoT resolves to the address the client connected to" {
  local ca; ca="$(pwd)/test/test_ca.crt"
  run python3 test/dotdoh_query.py dot 127.0.0.3 853 pi.hole "$CLIENT" "$ca" 127.0.0.3
  assert_output "OK"
}

@test "dotdoh-server: pi.hole over DoH resolves to the address the client connected to" {
  local ca a; ca="$(pwd)/test/test_ca.crt"; a="${BATS_FILE_TMPDIR}/pihole_doh.bin"
  local q="${BATS_FILE_TMPDIR}/pihole_q.bin"
  python3 test/dotdoh_query.py emit pi.hole "$q"
  # --resolve maps pi.hole:443 to 127.0.0.3, so curl connects there; the terminator
  # conveys 127.0.0.3 as the PROXY v2 destination.
  run curl -s --cacert "$ca" --resolve "pi.hole:443:127.0.0.3" \
           --interface "$CLIENT" -H 'content-type: application/dns-message' \
           --data-binary "@$q" "https://pi.hole/dns-query" --output "$a"
  assert_success
  run python3 test/dotdoh_query.py check "$a" 127.0.0.3
  assert_output "OK"
}

@test "dotdoh-server: pi.hole over DoQ resolves to an address the client can reach" {
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  run python3 test/dotdoh_query.py doq 127.0.0.1 853 pi.hole "$CLIENT" 127.0.0.1
  assert_output "OK"
}

@test "dotdoh-server: pi.hole AAAA over a v4 DoQ transport returns NODATA, not loopback" {
  # This is what proves the connected-address hint reaches dnsmasq over DoQ.
  # OpenSSL's QUIC API exposes no per-connection local address, so the listener
  # derives the address this client reached it on from the route back to it and
  # conveys it as the private EDNS destination option. With the hint present the
  # family the client did NOT connect over is suppressed (NODATA); without it the
  # AAAA record is filled from the loopback handoff's interface and ::1 leaks to
  # the client. The DoT listener is asserted the same way, further down.
  python3 -c 'import aioquic' 2>/dev/null || skip "aioquic not installed"
  run python3 test/dotdoh_query.py doqnodata 127.0.0.1 853 pi.hole "$CLIENT"
  assert_output "OK"
}

# A cross-family query (AAAA over a v4 transport) has no conveyed address of the
# requested family. The internal forward is the loopback, so the only alternative
# would be 127.0.0.1 - which must NOT leak as a AAAA/A answer. We return NODATA
# instead of the wrong loopback address (the wider multi-address pi.hole design is
# a separate topic that also affects plain DNS).

@test "dotdoh-server: pi.hole AAAA over a v4 DoT transport returns NODATA, not loopback" {
  local ca; ca="$(pwd)/test/test_ca.crt"
  run python3 test/dotdoh_query.py dotnodata 127.0.0.3 853 pi.hole "$CLIENT" "$ca"
  assert_output "OK"
}

# A CNAME targeting pi.hole (cnameRecords has "pihole.mydomain.net,pi.hole") must
# localise the same way as a direct query: the synthesised pi.hole A in the chain
# also uses the connected address, not the loopback forward's. It is reached under
# the original, non-pi.hole query name, so it exercises the separate cache-record
# path (FTL_CNAME -> update_pihole_cache_record).

@test "dotdoh-server: a CNAME to pi.hole over DoT localises to the connected address" {
  local ca; ca="$(pwd)/test/test_ca.crt"
  run python3 test/dotdoh_query.py dot 127.0.0.3 853 pihole.mydomain.net "$CLIENT" "$ca" 127.0.0.3
  assert_output "OK"
}

@test "dotdoh-server: a CNAME to pi.hole over DoH localises to the connected address" {
  local ca a q; ca="$(pwd)/test/test_ca.crt"
  a="${BATS_FILE_TMPDIR}/cname_doh.bin"; q="${BATS_FILE_TMPDIR}/cname_q.bin"
  python3 test/dotdoh_query.py emit pihole.mydomain.net "$q"
  run curl -s --cacert "$ca" --resolve "pi.hole:443:127.0.0.3" \
           --interface "$CLIENT" -H 'content-type: application/dns-message' \
           --data-binary "@$q" "https://pi.hole/dns-query" --output "$a"
  assert_success
  run python3 test/dotdoh_query.py check "$a" 127.0.0.3
  assert_output "OK"
}
