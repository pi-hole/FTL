#!/bin/bash
# Dedicated end-to-end test for the in-process TLS terminator.
#
# The terminator binds the public TLS port, terminates TLS (OpenSSL), advertises
# ALPN "h2", and forwards plaintext HTTP/1.1 to CivetWeb on a loopback backend.
# CivetWeb itself is built with NO_SSL now, so every TLS request - HTTP/2 and
# HTTP/1.1 alike - goes through the terminator. The regular suite exercises the
# plain HTTP/1.1 port; this script starts a throwaway FTL instance and covers
# the terminator directly:
#   - a body-less GET is served over HTTP/2 (version 2, status 200, JSON intact),
#   - HTTP/1.1 clients keep working via ALPN fall-through,
#   - a POST carrying a body is served over HTTP/2 and the body reaches the
#     backend (wrong password -> a valid session response with valid=false),
#   - the long default Content-Security-Policy header survives HPACK encoding,
#   - the real client address is forwarded via PROXY protocol v2 (the JSON
#     reflects 127.0.0.1, not an empty or garbage value).
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

# Set a known API password for this run only. /api/auth and /api/info/client do
# not require authentication, but a configured password makes the POST-body test
# unambiguous: a wrong password can only yield session.valid=false if the JSON
# body actually reached the backend (an empty payload would instead be answered
# with a "no password found in JSON payload" error).
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

# (1) A body-less GET is served over HTTP/2. curl reports the negotiated
# version and status; the body is captured for the JSON-integrity checks below.
# A corrupt HEADERS block would make curl abort with an empty version.
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
# client (127.0.0.1 over loopback), not an empty or garbage address. A broken
# PROXY v2 header would leave remote_addr unset or corrupted.
remote_addr="$(jq -r '.remote_addr // empty' "${BODY}" 2> /dev/null)"
check "Client address forwarded via PROXY protocol v2" "127.0.0.1" "${remote_addr}"

# (4) The default Content-Security-Policy header is long enough to need a
# multi-byte HPACK string length. Require the full value (down to the trailing
# form-action 'self') to survive over HTTP/2; a broken length prefix would
# desync the HEADERS block and curl would abort.
if "${H2[@]}" -D - -o /dev/null https://pi.hole/ \
     | grep -qi "^content-security-policy:.*form-action 'self'"; then
  csp="ok"
else
  csp="missing"
fi
check "Content-Security-Policy intact over HTTP/2" "ok" "${csp}"

# (3) A POST carrying a body is served over HTTP/2 (not downgraded) and the body
# reaches the backend. The wrong password yields a valid session response with
# valid=false, which is only possible if the JSON body was forwarded and parsed.
post_ver="$("${H2[@]}" -o "${BODY}" -w '%{http_version}' -X POST \
            -d '{"password":"wrong"}' https://pi.hole/api/auth)"
check "POST /api/auth served over HTTP/2 (not downgraded)" "2" "${post_ver}"
valid="$(jq -r '.session.valid // empty' "${BODY}" 2> /dev/null)"
check "POST body forwarded to backend (wrong password rejected)" "false" "${valid}"

# (2) Plain HTTP/1.1 clients are unaffected (ALPN fall-through to http/1.1).
check "HTTP/1.1 client still served (ALPN fall-through)" "1.1 200" \
  "$("${H1[@]}" -o /dev/null -w '%{http_version} %{http_code}' \
     https://pi.hole/api/info/client)"

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
