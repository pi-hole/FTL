#!/bin/bash
# Dedicated end-to-end test for the in-process TLS terminator.
#
# The terminator binds the public TLS port, terminates TLS (OpenSSL), advertises
# ALPN "h2", and forwards plaintext HTTP/1.1 to CivetWeb on a loopback backend.
# CivetWeb is built NO_SSL, so every TLS request goes through the terminator. The
# regular suite covers the plain HTTP/1.1 port; this script starts a throwaway
# FTL instance and covers the terminator directly (HTTP/2, HTTP/1.1 fall-through,
# POST bodies, CSP header survival, PROXY-v2 client-IP, HTTP/1.0 and HTTP/3).
#
# Run with:  ./build.sh ci test-http2   (after the regular test series)

set -u

RET=0
BODY=$(mktemp)
trap 'rm -f "${BODY}"' EXIT

# Shared curl invocations. --resolve maps pi.hole to the loopback terminator
# (curl does not use FTL as its resolver), --cacert trusts the repo test cert.
COMMON=(--cacert /etc/pihole/test.crt --resolve pi.hole:443:127.0.0.1)
H2=(curl -s --http2 "${COMMON[@]}")
H1=(curl -s --http1.1 "${COMMON[@]}")

# check <description> <expected> <actual>
check() {
  if [[ "$3" == "$2" ]]; then
    printf 'PASS  %-52s -> %s\n' "$1" "$3"
  else
    printf 'FAIL  %-52s -> %s (wanted %s)\n' "$1" "$3" "$2"
    RET=1
  fi
}

# ---------------------------------------------------------------------------
# Minimal environment setup (mirrors the essential parts of test/run.sh)
# ---------------------------------------------------------------------------
if ! id -u pihole &> /dev/null; then
  useradd -m -s /usr/sbin/nologin pihole
fi

while pidof -s pihole-FTL > /dev/null; do
  kill "$(pidof -s pihole-FTL)"; sleep 1
done

rm -rf /etc/pihole /etc/dnsmasq.d /var/log/pihole /dev/shm/FTL-*
mkdir -p /home/pihole /etc/pihole /run/pihole /var/log/pihole /etc/pihole/config_backups /var/www/html
: > /var/log/pihole/FTL.log
: > /var/log/pihole/webserver.log
touch /run/pihole-FTL.pid /etc/pihole/dhcp.leases
chown -R pihole:pihole /etc/pihole /run/pihole /var/log/pihole
chown pihole:pihole /run/pihole-FTL.pid

cp ./pihole-FTL /home/pihole/pihole-FTL
chmod +x /home/pihole/pihole-FTL
setcap CAP_NET_BIND_SERVICE+eip /home/pihole/pihole-FTL

./pihole-FTL sqlite3 /etc/pihole/gravity.db < test/gravity.db.sql
./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db < test/pihole-FTL.db.sql
chown pihole:pihole /etc/pihole/gravity.db /etc/pihole/pihole-FTL.db
cp test/test.pem /etc/pihole/test.pem
cp test/test.crt /etc/pihole/test.crt
cp test/pihole.toml /etc/pihole/pihole.toml
chown pihole:pihole /etc/pihole/pihole.toml

# Set a known API password for this run only, so the POST-body test is
# unambiguous: a wrong password only yields session.valid=false if the JSON body
# reached the backend (an empty payload gives a "no password found" error).
export FTLCONF_webserver_api_password="terminator-secret"

# ---------------------------------------------------------------------------
# Start FTL
# ---------------------------------------------------------------------------
if ! su pihole -s /bin/sh -c /home/pihole/pihole-FTL; then
  echo "pihole-FTL failed to start"; exit 1
fi
sleep 2

echo "=================== TLS terminator ==================="
grep -a "TLS terminator listening" /var/log/pihole/FTL.log || true
echo

echo "======================== checks ========================="

# (1) A body-less GET over HTTP/2: curl reports the negotiated version and
# status, and the body is captured for the JSON-integrity checks below.
ver_code="$("${H2[@]}" -o "${BODY}" -w '%{http_version} %{http_code}' \
            https://pi.hole/api/info/client)"
check "GET /api/info/client over HTTP/2 (version + status)" "2 200" "${ver_code}"

# The captured body must be well-formed JSON (proves the response survived the
# h2 -> plaintext -> h2 round trip intact, not just the status line).
if jq -e . "${BODY}" > /dev/null 2>&1; then
  json="ok"
else
  json="broken"
fi
check "HTTP/2 response body is valid JSON" "ok" "${json}"

# (5) Client-IP forwarding via PROXY protocol v2: the backend must see the real
# client (127.0.0.1), not an empty or garbage address from a broken v2 header.
remote_addr="$(jq -r '.remote_addr // empty' "${BODY}" 2> /dev/null)"
check "Client address forwarded via PROXY protocol v2" "127.0.0.1" "${remote_addr}"

# (4) The default Content-Security-Policy header is long enough to need a
# multi-byte HPACK string length. Require the full value (down to the trailing
# form-action 'self') to survive HTTP/2; a broken length prefix desyncs HEADERS.
if "${H2[@]}" -D - -o /dev/null https://pi.hole/ \
     | grep -qi "^content-security-policy:.*form-action 'self'"; then
  csp="ok"
else
  csp="missing"
fi
check "Content-Security-Policy intact over HTTP/2" "ok" "${csp}"

# The terminator advertises its HTTP/3 endpoint to h2 clients via Alt-Svc, so an
# h3-capable browser upgrades from this h2 connection to HTTP/3 on the same port
# (the h3 listener is up in this build, so the header must be present).
if "${H2[@]}" -D - -o /dev/null https://pi.hole/ \
     | grep -qiE "^alt-svc:.*h3="; then
  altsvc="ok"
else
  altsvc="missing"
fi
check "Alt-Svc advertises HTTP/3 over HTTP/2" "ok" "${altsvc}"

# (3) A POST with a body is served over HTTP/2 (not downgraded) and reaches the
# backend: the wrong password yields valid=false only if the JSON body was parsed.
post_ver="$("${H2[@]}" -o "${BODY}" -w '%{http_version}' -X POST \
            -H 'Content-Type: application/json' \
            -d '{"password":"wrong"}' https://pi.hole/api/auth)"
check "POST /api/auth served over HTTP/2 (not downgraded)" "2" "${post_ver}"
# Read the field directly: jq's // treats a literal false as empty, so
# '.session.valid // empty' would blank out the false we are checking for. A
# wrong password yields valid=false only when the JSON body reached the backend.
valid="$(jq -r '.session.valid' "${BODY}" 2> /dev/null)"
check "POST body forwarded to backend (wrong password rejected)" "false" "${valid}"

# (2) Plain HTTP/1.1 clients are unaffected (ALPN fall-through to http/1.1).
check "HTTP/1.1 client still served (ALPN fall-through)" "1.1 200" \
  "$("${H1[@]}" -o /dev/null -w '%{http_version} %{http_code}' \
     https://pi.hole/api/info/client)"

# (6) HTTP/1.0 clients are served too: the terminator's HTTP/1.1 splice relay
# forwards the older request unchanged (response version is up to the backend).
h10_code="$(curl -s --http1.0 "${COMMON[@]}" -o "${BODY}" -w '%{http_code}' \
            https://pi.hole/api/info/client)"
check "HTTP/1.0 client served over TLS (status)" "200" "${h10_code}"
if jq -e . "${BODY}" > /dev/null 2>&1; then j10="ok"; else j10="broken"; fi
check "HTTP/1.0 response body is valid JSON" "ok" "${j10}"

# (7) HTTP/3 (QUIC) over the terminator's UDP :443. Needs a curl built with
# HTTP/3; where the image lacks it (the stock CI image does), skip these checks
# rather than fail - the h3 server is still exercised by the DoH3 bats test and
# by local runs with an HTTP/3-capable curl.
if ! curl --version 2>/dev/null | grep -qiw HTTP3; then
  echo "SKIP  HTTP/3 checks - curl in this image has no HTTP/3 support"
else
  h3="$(curl -s --http3 "${COMMON[@]}" -o "${BODY}" \
        -w '%{http_version} %{http_code}' https://pi.hole/api/info/client 2>/dev/null)"
  check "GET /api/info/client over HTTP/3 (version + status)" "3 200" "${h3}"
  if jq -e . "${BODY}" > /dev/null 2>&1; then j3="ok"; else j3="broken"; fi
  check "HTTP/3 response body is valid JSON" "ok" "${j3}"
  h3addr="$(jq -r '.remote_addr // empty' "${BODY}" 2> /dev/null)"
  check "Client address forwarded over HTTP/3 (PROXY v2)" "127.0.0.1" "${h3addr}"
fi

echo

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
kill "$(cat /run/pihole-FTL.pid 2> /dev/null)" 2> /dev/null
rm -f /home/pihole/pihole-FTL

echo "========================================================="
if [[ ${RET} -eq 0 ]]; then
  echo "TLS terminator test: PASS"
else
  echo "TLS terminator test: FAIL (see per-check results above)"
fi
exit ${RET}
